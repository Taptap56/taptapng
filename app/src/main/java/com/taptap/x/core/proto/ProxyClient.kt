package com.taptap.x.core.proto

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Common stream/client contract for the in-app proxy protocols (M2).
 *
 * A [ProxyClient] opens one proxied byte stream to [targetHost]:[targetPort]
 * per [dial] call. The target is sent inside the protocol header — it is
 * never resolved locally first. Each [dial] returns a fresh [ProxyStream];
 * streams stay open independently — v1.0.6: dialling again must NOT close
 * the previous stream (the old `dial(){ close() }` killed the first
 * session whenever two apps connected at once, because every client
 * kept a single shared `stream` field). [close] closes every stream
 * this client opened that has not been closed individually yet.
 *
 * Implementations must never log credentials (UUID, password, keys).
 */
interface ProxyStream {
    val input: InputStream
    val output: OutputStream
    fun close()
}

interface ProxyClient {
    /**
     * Open one proxied byte stream to [targetHost]:[targetPort].
     *
     * [probeBody] (v1.0.8): bytes written right after the protocol
     * header and BEFORE the response header is read — probe dials
     * only. xray-core VMess/VLESS servers flush their response
     * header only once data flows from the dispatch target, so a
     * probe that sends no body deadlocks into a read timeout (the
     * probe target is the entry itself, a TLS server that speaks
     * only when spoken to). Relay dials MUST pass null: any extra
     * bytes there would corrupt the app's first data.
     */
    fun dial(targetHost: String, targetPort: Int, probeBody: ByteArray? = null): ProxyStream
    fun close()
}

/**
 * A [ProxyStream] over one socket. Closing the output first lets
 * protocol streams emit their termination record / WS Close frame
 * before the socket goes away; the socket itself is closed last.
 */
class SocketProxyStream(
    private val socket: Socket,
    override val input: InputStream,
    override val output: OutputStream,
) : ProxyStream {
    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { socket.close() }
    }
}

/**
 * One transport ladder's byte stream (M3): either a socket ladder
 * (TCP → TLS → WS, [Transport.open]) or a DNSTT ladder (smux stream
 * → TLS → WS, [com.taptap.x.core.slowdns.SlowDnsTransport.open]).
 * [clearHandshakeTimeout] mirrors the socket's `soTimeout = 0` once
 * the protocol handshake has succeeded — for a smux stream it clears
 * the stream's read deadline instead.
 */
class LadderStream(
    val input: InputStream,
    val output: OutputStream,
    private val onClose: () -> Unit,
    private val onHandshakeDone: () -> Unit,
) {
    fun close() = onClose()
    fun clearHandshakeTimeout() = onHandshakeDone()
}

/**
 * A [ProxyStream] over arbitrary (input, output) streams (M3). Same
 * close order as [SocketProxyStream] (output, input, transport) —
 * for the socket path this is behaviour-identical to
 * SocketProxyStream. The protocol clients wrap their body streams
 * here ([com.taptap.x.core.proto.VmessClient] /
 * [com.taptap.x.core.proto.VlessClient]) so the same code serves
 * both the socket ladder and the DNSTT ladder.
 */
class StreamProxyStream(
    override val input: InputStream,
    override val output: OutputStream,
    private val onClose: () -> Unit,
) : ProxyStream {
    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { onClose() }
    }
}

/**
 * A [ProxyStream] that removes itself from [registry] when closed
 * (v1.0.6). The owning client registers every stream it returns;
 * [ProxyClient.close] closes whatever is still registered. Without
 * the self-removal the registry would keep every closed stream
 * alive for the whole VPN session.
 */
class TrackedProxyStream(
    private val inner: ProxyStream,
    private val registry: MutableSet<ProxyStream>,
) : ProxyStream {
    override val input: InputStream get() = inner.input
    override val output: OutputStream get() = inner.output
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    init {
        registry.add(this)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            registry.remove(this)
            inner.close()
        }
    }
}

/** Read exactly [n] bytes or throw EOFException. Shared by all protocols. */
fun InputStream.readExactBytes(n: Int): ByteArray {
    val out = ByteArray(n)
    var filled = 0
    while (filled < n) {
        val r = read(out, filled, n - filled)
        if (r == -1) throw java.io.EOFException("Stream terpotong (EOF), butuh $n byte, dapat $filled")
        filled += r
    }
    return out
}

/**
 * InputStream that runs [onFirstRead] exactly once, before the first
 * read (v1.0.12). The VMess/VLESS response header is read lazily
 * through it: the xray-core server only flushes its response header
 * once data flows from the dispatch target, so a relay dial that
 * reads the header before the app has sent any body deadlocks into
 * a 10 s timeout (taptapx-7.txt: every forwarder dial died at
 * "VMess gagal: Read timed out", zero "DIAL ... ok"). xray-core's
 * own client runs the two directions concurrently (outbound.go:
 * task.Run(requestDone, responseDone)) — the header read must never
 * precede the body write. The hook runs on the reading thread (the
 * forwarder's relay thread); the socket's handshake SO_TIMEOUT still
 * bounds it, and the hook clears it once the header arrives. All
 * other operations delegate untouched; [available] does NOT trigger
 * the hook.
 */
class LazyHeaderInputStream(
    private val rawIn: InputStream,
    private val onFirstRead: () -> Unit,
) : InputStream() {

    private val done = AtomicBoolean(false)

    private fun ensureHeader() {
        if (done.compareAndSet(false, true)) onFirstRead()
    }

    override fun read(): Int {
        ensureHeader()
        return rawIn.read()
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        ensureHeader()
        return rawIn.read(b, off, len)
    }

    override fun available(): Int = rawIn.available()

    override fun close() {
        runCatching { rawIn.close() }
    }
}

/**
 * OutputStream that calls [onFirstWrite] once with the size of the
 * first non-empty write (v1.0.12). The forwarder writes the app's
 * first data through it, so the phone log can prove a body was
 * actually sent ("VLESS body 512B untuk ...") instead of only
 * showing the dial stages. Empty writes do not trigger it; [flush]
 * does not trigger it either — the log means bytes went on the
 * wire, not that a buffer was flushed.
 */
class FirstWriteLoggingOutputStream(
    private val rawOut: OutputStream,
    private val onFirstWrite: (Int) -> Unit,
) : OutputStream() {

    private val done = AtomicBoolean(false)

    override fun write(b: Int) = write(byteArrayOf(b.toByte()))

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len > 0 && done.compareAndSet(false, true)) onFirstWrite(len)
        rawOut.write(b, off, len)
    }

    override fun flush() = rawOut.flush()

    override fun close() {
        runCatching { rawOut.close() }
    }
}
