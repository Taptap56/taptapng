package com.taptap.x.core.proto

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

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
    fun dial(targetHost: String, targetPort: Int): ProxyStream
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
