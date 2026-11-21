package com.taptap.ng.core.slowdns

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.AddrCodec
import com.taptap.ng.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLParameters
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * TLS over an arbitrary byte stream (M3), for the inner TLS handshake
 * of a SlowDNS entry: the TLS ClientHello runs over the DNSTT smux
 * stream, not over a Socket — so [com.taptap.ng.core.proto.TlsUtil]
 * (SSLSocket-based) cannot be used here. This drives an [SSLEngine]
 * in client mode over the given (input, output) pair.
 *
 * SNI / ALPN / insecure semantics match TlsUtil exactly:
 * - SNI = item.sni, or the proxy address when empty; an IP-literal
 *   SNI is skipped (SNIHostName rejects IPs).
 * - ALPN = item.alpn (comma-separated) when set; `SSLParameters
 *   .applicationProtocols` needs API 29+ and is silently ignored on
 *   older runtimes.
 * - insecure = trust-all certificates (same meaning as v2rayNG
 *   "allowInsecure"). No hostname verification is done either way.
 *
 * Timeouts: the handshake read blocks on [input] — the caller bounds
 * it with the stream's read deadline (SlowDNS transport sets 10 s
 * during the handshake, like Transport.HANDSHAKE_TIMEOUT_MS) and the
 * DialWatchdog. There is no socket SO_TIMEOUT on a stream transport.
 */
object TlsEngine {

    private val trustAllContext: SSLContext by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }
    }

    /**
     * Run the TLS handshake over (input, output) and return the
     * encrypted (tlsInput, tlsOutput) pair. Throws on handshake
     * failure. The returned streams own the underlying pair: closing
     * them closes the underlying streams.
     */
    fun wrap(input: InputStream, output: OutputStream, item: ProfileItem): Pair<InputStream, OutputStream> {
        val context = if (item.insecure) trustAllContext else SSLContext.getDefault()
        val engine = context.createSSLEngine(item.address, item.port)
        engine.useClientMode = true
        val params = SSLParameters()
        val sni = item.sni.ifBlank { item.address }
        if (!AddrCodec.isIpLiteral(sni)) {
            runCatching { params.serverNames = listOf(SNIHostName(sni)) }
        }
        if (item.alpn.isNotBlank()) {
            val protocols = item.alpn.split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toTypedArray()
            if (protocols.isNotEmpty()) {
                runCatching { params.applicationProtocols = protocols }
            }
        }
        engine.sslParameters = params
        val session = TlsSession(engine, input, output)
        try {
            session.handshake()
        } catch (e: Exception) {
            runCatching { session.close() }
            throw IOException("TLS gagal: ${e.message}", e)
        }
        // v1.0.2 (XVEON order): name the negotiated version —
        // "TLS established: TLSv1.3" — not just "TLS ok".
        DialLog.log("TLS", "TLS established: ${engine.session.protocol}")
        return session.inputStream to session.outputStream
    }

    /**
     * One TLS session over a stream pair: owns the engine, the net
     * buffers, and the decrypted-data buffer. The handshake runs
     * synchronously in [handshake]; afterwards [inputStream] /
     * [outputStream] serve application data.
     */
    internal class TlsSession(
        private val engine: SSLEngine,
        private val netIn: InputStream,
        private val netOut: OutputStream,
    ) {
        private val packetSize = maxOf(engine.session.packetBufferSize, 18432)
        private val appSize = maxOf(engine.session.applicationBufferSize, 16384)
        // Net bytes read from the peer, not yet unwrapped.
        private val netBuffer = ByteBuffer.allocate(packetSize)
        // Decrypted app bytes, not yet consumed by the reader.
        private val appBuffer = ByteBuffer.allocate(appSize)
        @Volatile private var closed = false

        init {
            // Buffers start empty: position 0, limit 0 (nothing to read).
            netBuffer.limit(0)
            appBuffer.limit(0)
        }

        val inputStream: InputStream = TlsInputStream()
        val outputStream: OutputStream = TlsOutputStream()

        fun handshake() {
            engine.beginHandshake()
            val empty = ByteBuffer.allocate(0)
            var status = engine.handshakeStatus
            while (status != SSLEngineResult.HandshakeStatus.FINISHED &&
                status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
            ) {
                when (status) {
                    SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                        val out = ByteBuffer.allocate(packetSize)
                        val result = engine.wrap(empty, out)
                        if (result.status == SSLEngineResult.Status.CLOSED) {
                            throw IOException("TLS ditutup saat handshake")
                        }
                        out.flip()
                        if (out.hasRemaining()) {
                            val bytes = ByteArray(out.remaining())
                            out.get(bytes)
                            netOut.write(bytes)
                            netOut.flush()
                        }
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                        if (!fillNetBuffer()) throw IOException("TLS ditutup saat handshake")
                        val result = engine.unwrap(netBuffer, appBuffer)
                        when (result.status) {
                            SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                                // Need more net data: keep what is left
                                // and read again (fillNetBuffer compacts).
                                if (!fillNetBuffer()) throw IOException("TLS ditutup saat handshake")
                            }
                            SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                                // App buffer too small (should not happen
                                // at handshake time: no app data yet).
                                throw IOException("TLS buffer app terlalu kecil")
                            }
                            SSLEngineResult.Status.CLOSED -> {
                                throw IOException("TLS ditutup saat handshake")
                            }
                            else -> Unit
                        }
                        status = result.handshakeStatus
                    }
                    SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                        var task = engine.delegatedTask
                        while (task != null) {
                            task.run()
                            task = engine.delegatedTask
                        }
                        status = engine.handshakeStatus
                    }
                    else -> throw IOException("TLS handshake status tidak dikenal: $status")
                }
            }
            // Any app data unwrapped during the handshake stays buffered.
            appBuffer.flip()
        }

        /** Read more net bytes into [netBuffer] (compacting first). Returns false on EOF. */
        private fun fillNetBuffer(): Boolean {
            netBuffer.compact()
            val read = ByteArray(packetSize - netBuffer.position())
            val n = netIn.read(read)
            if (n == -1) {
                netBuffer.flip()
                return false
            }
            netBuffer.put(read, 0, n)
            netBuffer.flip()
            return true
        }

        fun close() {
            if (closed) return
            closed = true
            runCatching { engine.closeOutbound() }
            runCatching { netIn.close() }
            runCatching { netOut.close() }
        }

        private inner class TlsInputStream : InputStream() {
            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n == -1) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (closed) return -1
                while (true) {
                    if (appBuffer.hasRemaining()) {
                        val n = minOf(len, appBuffer.remaining())
                        appBuffer.get(b, off, n)
                        return n
                    }
                    if (engine.isInboundDone) return -1
                    // Unwrap more: need net data first.
                    if (!netBuffer.hasRemaining() && !fillNetBuffer()) return -1
                    appBuffer.clear()
                    val result = engine.unwrap(netBuffer, appBuffer)
                    when (result.status) {
                        SSLEngineResult.Status.OK -> {
                            appBuffer.flip()
                            // Loop: serve from appBuffer (or unwrap again
                            // when the unwrap produced no app bytes, e.g.
                            // a handshake / alert record).
                        }
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            appBuffer.flip() // keep it empty; read more net data
                            if (!fillNetBuffer()) return -1
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            // App buffer (16K+) is smaller than one
                            // record's plaintext: grow is not supported
                            // — a conforming peer never sends this.
                            throw IOException("TLS record terlalu besar")
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            appBuffer.flip()
                            if (!appBuffer.hasRemaining()) return -1
                        }
                    }
                }
            }

            override fun available(): Int = appBuffer.remaining()

            override fun close() = runCatching { this@TlsSession.close() }.let {}
        }

        private inner class TlsOutputStream : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (closed) throw IOException("TLS ditutup")
                var remaining = len
                var pos = off
                while (remaining > 0) {
                    val app = ByteBuffer.wrap(b, pos, remaining)
                    val out = ByteBuffer.allocate(packetSize)
                    val result = engine.wrap(app, out)
                    if (result.status == SSLEngineResult.Status.CLOSED) {
                        throw IOException("TLS ditutup saat tulis")
                    }
                    val consumed = remaining - app.remaining()
                    pos += consumed
                    remaining = app.remaining()
                    out.flip()
                    if (out.hasRemaining()) {
                        val bytes = ByteArray(out.remaining())
                        out.get(bytes)
                        netOut.write(bytes)
                    }
                    if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        // Packet buffer too small for one wrap: retry
                        // with the same app bytes (loop) — the engine
                        // consumed nothing, so this terminates.
                        if (consumed == 0) throw IOException("TLS buffer paket terlalu kecil")
                    }
                }
            }

            override fun flush() = netOut.flush()

            override fun close() {
                // Send close_notify, then close the underlying pair.
                runCatching {
                    val out = ByteBuffer.allocate(packetSize)
                    engine.closeOutbound()
                    val result = engine.wrap(ByteBuffer.allocate(0), out)
                    out.flip()
                    if (out.hasRemaining()) {
                        val bytes = ByteArray(out.remaining())
                        out.get(bytes)
                        netOut.write(bytes)
                        netOut.flush()
                    }
                    result
                }
                runCatching { this@TlsSession.close() }
            }
        }
    }
}
