package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.slowdns.TlsEngine
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Onering TLS tests (M4, v1.0.23): a REAL Bouncy Castle client
 * handshakes against a REAL JDK SSLEngine server (test-tls.p12)
 * over an in-memory channel — no sockets (JVM loopback TLS is
 * intercepted in the dev VM and on the CI runner, see TlsEngineTest).
 *
 * This proves the two things a unit test of the extension bytes
 * alone cannot: (1) the 0xff00 extension is the FIRST extension in
 * the ClientHello the client actually sends, with the real domain
 * in the standard SNI; (2) the handshake COMPLETES — i.e. the
 * extension is part of the transcript BC hashes, so the server's
 * Finished verification passes (the property a post-hoc ClientHello
 * patch would break on both TLS 1.2 and 1.3).
 */
class OneringTlsTest {

    private fun oneringItem(insecure: Boolean = true, sni: String = "support.zoom.us") = ProfileItem(
        remarks = "Onering test",
        address = "127.0.0.1",
        port = 443,
        tls = true,
        insecure = insecure,
        network = "ws",
        sni = sni,
        oneringEnabled = true,
        oneringBug = "live.iflix.com",
    )

    private fun loadKeystore(): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        val res: InputStream = javaClass.classLoader
            .getResourceAsStream("test-tls.p12")
            ?: throw IllegalStateException("test-tls.p12 tidak ada di test resources")
        res.use { ks.load(it, "taptapx-test".toCharArray()) }
        return ks
    }

    private fun serverContext(): SSLContext {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(loadKeystore(), "taptapx-test".toCharArray())
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, null)
        }
    }

    private fun testTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(loadKeystore())
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    /** OutputStream that records every byte written (ClientHello capture). */
    private class RecordingOutputStream(private val delegate: OutputStream) : OutputStream() {
        val captured = ByteArrayOutputStream()
        @Synchronized
        override fun write(b: Int) {
            captured.write(b)
            delegate.write(b)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            captured.write(b, off, len)
            delegate.write(b, off, len)
        }

        override fun flush() = delegate.flush()
        override fun close() = delegate.close()
    }

    /** Parse the first TLS record's ClientHello extensions, in wire order. */
    private fun parseClientHelloExtensions(captured: ByteArray): List<Pair<Int, ByteArray>> {
        assertTrue(captured.size > 50, "terlalu sedikit byte terekam: ${captured.size}")
        assertEquals(0x16, captured[0].toInt() and 0xFF, "record pertama harus handshake")
        assertEquals(0x01, captured[5].toInt() and 0xFF, "handshake pertama harus ClientHello")
        var pos = 9 // body: version(2) + random(32)
        pos += 2 + 32
        val sessionLen = captured[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        val suitesLen = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
        pos += 2 + suitesLen
        val compLen = captured[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extLen = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
        pos += 2
        val extEnd = pos + extLen
        assertTrue(extEnd <= captured.size, "panjang extensions melewati byte terekam")
        val out = mutableListOf<Pair<Int, ByteArray>>()
        while (pos < extEnd) {
            val type = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
            val len = ((captured[pos + 2].toInt() and 0xFF) shl 8) or (captured[pos + 3].toInt() and 0xFF)
            out += type to captured.copyOfRange(pos + 4, pos + 4 + len)
            pos += 4 + len
        }
        assertEquals(extEnd, pos, "parse extensions tidak pas di ujung blok")
        return out
    }

    /** The SNI extension data holds a server_name_list; return its first host_name. */
    private fun parseSniHost(data: ByteArray): String {
        val listLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        assertEquals(data.size - 2, listLen, "list_len SNI tidak konsisten")
        assertEquals(0, data[2].toInt() and 0xFF, "SNI harus host_name")
        val hostLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        return data.copyOfRange(5, 5 + hostLen).toString(Charsets.US_ASCII)
    }

    private fun runHandshake(item: ProfileItem, trustManager: X509TrustManager? = null): ByteArray {
        val logBefore = DialLog.lines().size
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val recording = RecordingOutputStream(clientToServer.output)
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
        }, "onering-test-server").apply { isDaemon = true }
        serverThread.start()

        val (tlsIn, tlsOut) = OneringTls.wrap(serverToClient.input, recording, item, trustManager)
        // v1.0.2 (XVEON order): the wrap logs the negotiated version.
        assertTrue(
            DialLog.lines().drop(logBefore).any { it.contains("TLS established: TLSv1.3") },
            "log harus ada 'TLS established: TLSv1.3': ${DialLog.lines().drop(logBefore)}",
        )
        tlsOut.write("halo-onering".toByteArray(Charsets.UTF_8))
        tlsOut.flush()
        val reply = ByteArray(1024)
        val n = tlsIn.read(reply)
        assertEquals("balasan:halo-onering", reply.copyOf(n).toString(Charsets.UTF_8))
        assertEquals("halo-onering", serverReceived)
        if (serverError != null) throw AssertionError("Server TLS gagal: $serverError", serverError)
        tlsIn.close()
        tlsOut.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "thread server masih hidup sesudah close")
        return recording.captured.toByteArray()
    }

    @Test
    fun `ClientHello carries 0xff00 first and SNI real, handshake completes`() {
        val captured = runHandshake(oneringItem())
        val extensions = parseClientHelloExtensions(captured)
        assertTrue(extensions.isNotEmpty(), "ClientHello tanpa extensions")
        val (firstType, firstData) = extensions[0]
        assertEquals(
            OneringHello.EXTENSION_TYPE, firstType,
            "ekstensi pertama harus 0xff00, dapat 0x${firstType.toString(16)}",
        )
        assertEquals("live.iflix.com", OneringHello.parseBugExtensionData(firstData))
        val sni = extensions.firstOrNull { it.first == 0x0000 }
            ?: throw AssertionError("tidak ada ekstensi SNI di ClientHello")
        assertEquals("support.zoom.us", parseSniHost(sni.second))
        // The bug must NOT leak into the standard SNI.
        assertTrue(extensions.none { it.first == 0x0000 && parseSniHost(it.second) == "live.iflix.com" })
    }

    @Test
    fun `handshake completes with platform certificate validation`() {
        // insecure=false + trust manager trusting the test keystore:
        // the BC client must validate the chain exactly like the
        // SSLSocket path does — chain check AND hostname check
        // against the SNI (v1.0.20). The test cert is issued for
        // localhost, so the SNI here must be localhost, not the
        // default support.zoom.us (that mismatch is covered by the
        // hostname-mismatch test below).
        val captured = runHandshake(oneringItem(insecure = false, sni = "localhost"), testTrustManager())
        val extensions = parseClientHelloExtensions(captured)
        assertEquals(OneringHello.EXTENSION_TYPE, extensions[0].first)
    }

    @Test
    fun `handshake fails when the server cert is not trusted`() {
        // insecure=false with the PLATFORM trust manager: the
        // self-signed test cert must be rejected, not silently trusted.
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        val serverThread = Thread({
            runCatching { serverSession.handshake() }
        }, "onering-test-server-untrusted").apply { isDaemon = true }
        serverThread.start()
        try {
            assertThrows(Exception::class.java) {
                OneringTls.wrap(serverToClient.input, clientToServer.output, oneringItem(insecure = false))
            }
        } finally {
            runCatching { serverSession.close() }
            serverThread.join(5_000)
        }
    }

    /**
     * v1.0.20: X509ExtendedTrustManager that records WHICH
     * checkServerTrusted overload the BC client calls, delegating
     * the real validation to the platform test trust manager.
     * Proves the client calls the hostname-aware 3-arg overload
     * with the SNI — the call Android's NetworkSecurityTrustManager
     * requires once a <domain-config> exists (the 2-arg call is
     * refused there and broke every Onering entry in v1.0.19).
     */
    private class RecordingExtendedTrustManager(
        private val delegate: X509TrustManager,
    ) : X509ExtendedTrustManager() {
        var twoArgCalls = 0
        var threeArgCalls = 0
        var threeArgHostname: String? = null

        private fun extendedDelegate(): X509ExtendedTrustManager =
            delegate as X509ExtendedTrustManager

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            delegate.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            twoArgCalls++
            delegate.checkServerTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, host: String) {
            threeArgCalls++
            threeArgHostname = host
            extendedDelegate().checkServerTrusted(chain, authType, host)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) =
            extendedDelegate().checkServerTrusted(chain, authType, engine)

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) =
            extendedDelegate().checkServerTrusted(chain, authType, socket)

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }

    /**
     * v1.0.20: plain (non-extended) X509TrustManager that records
     * its 2-arg calls and delegates validation to the platform
     * test trust manager. Proves the fallback path: when the
     * TrustManager is not an X509ExtendedTrustManager, the client
     * still validates (2-arg) instead of crashing on a cast.
     */
    private class RecordingPlainTrustManager(
        private val delegate: X509TrustManager,
    ) : X509TrustManager {
        var twoArgCalls = 0

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            delegate.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            twoArgCalls++
            delegate.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }

    @Test
    fun `hostname aware three arg overload is called with SNI`() {
        // v1.0.20 regression test: the BC client must call
        // checkServerTrusted(chain, authType, hostname) with the
        // SNI, never the 2-arg overload Android refuses once a
        // <domain-config> exists. SNI localhost matches the test
        // cert (CN/SAN localhost), so the handshake must complete.
        val recording = RecordingExtendedTrustManager(testTrustManager())
        runHandshake(oneringItem(insecure = false, sni = "localhost"), recording)
        assertEquals(1, recording.threeArgCalls, "overload 3-arg harus dipanggil tepat 1x")
        assertEquals("localhost", recording.threeArgHostname)
        assertEquals(0, recording.twoArgCalls, "overload 2-arg tidak boleh dipanggil")
    }

    @Test
    fun `fallback to two arg when trust manager is not extended`() {
        // v1.0.20: a plain X509TrustManager (not extended) must
        // still validate through the 2-arg call — no blind cast,
        // no crash, handshake completes.
        val recording = RecordingPlainTrustManager(testTrustManager())
        runHandshake(oneringItem(insecure = false, sni = "localhost"), recording)
        assertEquals(1, recording.twoArgCalls, "overload 2-arg harus dipanggil tepat 1x")
    }

    @Test
    fun `handshake fails when hostname does not match certificate`() {
        // v1.0.20: hostname IS verified against the SNI now. The
        // test cert is issued for localhost; SNI support.zoom.us
        // must be rejected, not silently trusted. Same harness
        // shape as the untrusted-cert test above.
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        val serverThread = Thread({
            runCatching { serverSession.handshake() }
        }, "onering-test-server-hostname-mismatch").apply { isDaemon = true }
        serverThread.start()
        try {
            assertThrows(Exception::class.java) {
                OneringTls.wrap(
                    serverToClient.input,
                    clientToServer.output,
                    oneringItem(insecure = false, sni = "support.zoom.us"),
                    testTrustManager(),
                )
            }
        } finally {
            runCatching { serverSession.close() }
            serverThread.join(5_000)
        }
    }

    @Test
    fun `wrap rejects a blank bug domain`() {
        val item = oneringItem().copy(oneringBug = "  ")
        assertThrows(IllegalArgumentException::class.java) {
            OneringTls.wrap(
                java.io.ByteArrayInputStream(ByteArray(0)),
                ByteArrayOutputStream(),
                item,
            )
        }
    }

    /**
     * In-memory byte channel (copied from TlsEngineTest, M3): an
     * unbounded queue of chunks; reads block up to [readTimeoutMs]
     * then throw SocketTimeoutException, so a stalled peer fails
     * fast instead of hanging the test (and CI) forever.
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
}
