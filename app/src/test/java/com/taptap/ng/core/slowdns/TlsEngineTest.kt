package com.taptap.ng.core.slowdns

import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * TlsEngine tests (M3): the engine must complete a real TLS handshake
 * over a plain stream pair and then carry application data both ways.
 * The server is a real SSLEngine (server mode) with a self-signed
 * test certificate (test-tls.p12, test-only password "taptapx-test");
 * the client trusts all (insecure=true, like a SlowDNS entry with
 * "allow insecure"). The pair is cross-wired piped streams, never a
 * socket: JVM loopback TLS is intercepted in the dev VM and the same
 * test failed on the CI runner over a socket pair.
 */
class TlsEngineTest {

    private fun testItem(): ProfileItem = ProfileItem(
        remarks = "TLS test",
        address = "127.0.0.1",
        port = 443,
        tls = true,
        insecure = true,
    )

    private fun serverContext(): SSLContext {
        val ks = KeyStore.getInstance("PKCS12")
        val res: InputStream = javaClass.classLoader
            .getResourceAsStream("test-tls.p12")
            ?: throw IllegalStateException("test-tls.p12 tidak ada di test resources")
        res.use { ks.load(it, "taptapx-test".toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "taptapx-test".toCharArray())
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, null)
        }
    }

    @Test
    fun `handshake and echo over a stream pair`() {
        // No sockets: JVM loopback TLS is intercepted (the dev VM
        // resets even a plain SSLSocket handshake, and the CI runner
        // failed the same test at the read). TlsEngine only needs a
        // stream pair, so drive it over an in-memory queue channel —
        // an unbounded queue cannot deadlock on a full pipe buffer,
        // and reads are bounded (15 s) so a stalled handshake fails
        // fast instead of hanging CI. The server side is a real
        // SSLEngine (server mode, test certificate) driven by the
        // same TlsSession wrapper.
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        var serverReceived = ""
        var serverError: Throwable? = null
        val serverThread = Thread({
            try {
                serverSession.handshake()
                val buf = ByteArray(1024)
                val n = serverSession.inputStream.read(buf)
                serverReceived = buf.copyOf(n).toString(Charsets.UTF_8)
                serverSession.outputStream.write(
                    "balasan:$serverReceived".toByteArray(Charsets.UTF_8),
                )
                serverSession.outputStream.flush()
            } catch (e: Throwable) {
                serverError = e
            }
        }, "tls-test-server").apply { isDaemon = true }
        serverThread.start()

        val (tlsIn, tlsOut) = TlsEngine.wrap(serverToClient.input, clientToServer.output, testItem())
        tlsOut.write("halo-tls".toByteArray(Charsets.UTF_8))
        tlsOut.flush()
        val reply = ByteArray(1024)
        val n = tlsIn.read(reply)
        val text = reply.copyOf(n).toString(Charsets.UTF_8)
        assertEquals("balasan:halo-tls", text)
        assertEquals("halo-tls", serverReceived)
        if (serverError != null) throw AssertionError("Server TLS gagal: $serverError", serverError)
        tlsIn.close()
        tlsOut.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive)
    }

    /**
     * In-memory byte channel (M3 test only): an unbounded queue of
     * chunks; reads block up to [readTimeoutMs] then throw
     * SocketTimeoutException, so a stalled peer fails fast instead
     * of hanging the test (and CI) forever.
     */
    private class QueueChannel(private val readTimeoutMs: Long = 15_000) {
        private val queue = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        val input: InputStream = object : InputStream() {
            private var current: ByteArray? = null
            private var pos = 0
            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n == -1) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                while (current == null || pos >= current!!.size) {
                    if (closed.get() && queue.isEmpty()) return -1
                    val chunk = queue.poll(readTimeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                        ?: throw java.net.SocketTimeoutException(
                            "QueueChannel baca menggantung > ${readTimeoutMs}ms",
                        )
                    if (chunk.isEmpty()) return -1 // EOF marker
                    current = chunk
                    pos = 0
                }
                val cur = current!!
                val take = minOf(len, cur.size - pos)
                cur.copyInto(b, off, pos, pos + take)
                pos += take
                return take
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                queue.offer(b.copyOfRange(off, off + len))
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }
    }

    @Test
    fun `handshake fails against a plain server`() {
        // A server that speaks plain TCP (no TLS) must make the
        // handshake fail fast instead of hanging.
        val plain = ServerSocket(0)
        val port = plain.localPort
        val serverThread = Thread({
            plain.use { ss ->
                val s = ss.accept()
                s.use { sock ->
                    sock.soTimeout = 5_000
                    // Read the ClientHello bytes, then close without
                    // answering (a plain server never completes TLS).
                    runCatching { sock.getInputStream().read(ByteArray(4096)) }
                }
            }
        }, "tls-test-plain-server").apply { isDaemon = true }
        serverThread.start()
        val client = Socket()
        client.connect(InetSocketAddress("127.0.0.1", port), 5_000)
        client.soTimeout = 5_000
        try {
            val result = runCatching {
                TlsEngine.wrap(client.getInputStream(), client.getOutputStream(), testItem())
            }
            assertTrue(result.isFailure, "Handshake ke server polos harus gagal")
        } finally {
            runCatching { client.close() }
            runCatching { plain.close() }
            serverThread.join(5_000)
        }
    }
}
