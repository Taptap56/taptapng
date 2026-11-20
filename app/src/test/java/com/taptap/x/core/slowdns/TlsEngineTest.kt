package com.taptap.x.core.slowdns

import com.taptap.x.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
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
        // fails the same test at the read). TlsEngine only needs a
        // stream pair, so drive it over cross-wired piped streams;
        // the server side is a real SSLEngine (server mode, test
        // certificate) driven by the same TlsSession wrapper.
        val clientToServer = PipedInputStream(65536)
        val clientOut = PipedOutputStream(clientToServer)
        val serverToClient = PipedInputStream(65536)
        val serverOut = PipedOutputStream(serverToClient)
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer, serverOut)
        var serverReceived = ""
        val serverThread = Thread({
            serverSession.handshake()
            val buf = ByteArray(1024)
            val n = serverSession.inputStream.read(buf)
            serverReceived = buf.copyOf(n).toString(Charsets.UTF_8)
            serverSession.outputStream.write(
                "balasan:$serverReceived".toByteArray(Charsets.UTF_8),
            )
            serverSession.outputStream.flush()
        }, "tls-test-server").apply { isDaemon = true }
        serverThread.start()

        val (tlsIn, tlsOut) = TlsEngine.wrap(serverToClient, clientOut, testItem())
        tlsOut.write("halo-tls".toByteArray(Charsets.UTF_8))
        tlsOut.flush()
        val reply = ByteArray(1024)
        val n = tlsIn.read(reply)
        val text = reply.copyOf(n).toString(Charsets.UTF_8)
        assertEquals("balasan:halo-tls", text)
        assertEquals("halo-tls", serverReceived)
        tlsIn.close()
        tlsOut.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive)
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
