package com.taptap.ng.core.proto

import com.taptap.ng.core.slowdns.TlsEngine
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Hello Go tests (v1.0.1): the Bouncy Castle client from
 * GoHelloTls handshakes against a REAL JDK SSLEngine server
 * (test-tls.p12) over an in-memory channel — no sockets (JVM
 * loopback TLS is intercepted in the dev VM and on the CI
 * runner, see TlsEngineTest) — and the ClientHello it actually
 * sends is compared field by field against the reference Hello
 * of a real Go 1.27.1 crypto/tls client (test resources
 * hello127-noalpn.bin / hello127-alpn.bin, captured 2026-11-21
 * by a local Go program dialling a raw TCP server; the libv2ray
 * core in the v2rayNG build is go1.27.1, main module `go 1.27`).
 *
 * What is asserted exactly: cipher-suite list AND order,
 * extension SET, non-empty extension order, SNI, ALPN, supported
 * groups, signature algorithms, signature_algorithms_cert,
 * supported_versions, key_share groups + lengths, legacy_version,
 * session-id length, and that the handshake COMPLETES (the Hello
 * is part of the transcript BC hashes, so Finished passes).
 *
 * KNOWN DEVIATION (asserted, not hidden): Bouncy Castle writes
 * zero-length extensions FIRST, so extended_master_secret (0x0017)
 * and signed_certificate_timestamp (0x0012) — which Go writes
 * 4th/5th — come out first here, in Go's relative order (EMS
 * before SCT). The test asserts captured == [0x0017, 0x0012] +
 * Go's non-empty extensions in Go's order, and the extension SET
 * is identical.
 */
class GoHelloTlsTest {

    private fun goHelloItem(alpn: String = "", insecure: Boolean = true) = ProfileItem(
        remarks = "Hello Go test",
        address = "front.wetv.vip",
        port = 443,
        tls = true,
        insecure = insecure,
        network = "ws",
        sni = "front.wetv.vip",
        alpn = alpn,
        goHelloEnabled = true,
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

    private fun loadReference(name: String): ByteArray {
        val res: InputStream = javaClass.classLoader.getResourceAsStream(name)
            ?: throw IllegalStateException("$name tidak ada di test resources")
        return res.use { it.readAllBytes() }
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

    private fun u16(b: ByteArray, pos: Int): Int =
        ((b[pos].toInt() and 0xFF) shl 8) or (b[pos + 1].toInt() and 0xFF)

    /** A parsed ClientHello (first TLS record of the capture). */
    private data class ClientHello(
        val legacyVersion: Int,
        val sessionIdLength: Int,
        val cipherSuites: List<Int>,
        val extensions: List<Pair<Int, ByteArray>>,
    )

    private fun parseClientHello(captured: ByteArray): ClientHello {
        assertTrue(captured.size > 50, "terlalu sedikit byte terekam: ${captured.size}")
        assertEquals(0x16, captured[0].toInt() and 0xFF, "record pertama harus handshake")
        assertEquals(0x01, captured[5].toInt() and 0xFF, "handshake pertama harus ClientHello")
        var pos = 9 // record header (5) + handshake header (4)
        val legacyVersion = u16(captured, pos)
        pos += 2 + 32 // legacy_version + random
        val sessionLen = captured[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        val suitesLen = u16(captured, pos)
        pos += 2
        val suites = (0 until suitesLen / 2).map { u16(captured, pos + it * 2) }
        pos += suitesLen
        val compLen = captured[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extLen = u16(captured, pos)
        pos += 2
        val extEnd = pos + extLen
        assertTrue(extEnd <= captured.size, "panjang extensions melewati byte terekam")
        val out = mutableListOf<Pair<Int, ByteArray>>()
        while (pos < extEnd) {
            val type = u16(captured, pos)
            val len = u16(captured, pos + 2)
            out += type to captured.copyOfRange(pos + 4, pos + 4 + len)
            pos += 4 + len
        }
        assertEquals(extEnd, pos, "parse extensions tidak pas di ujung blok")
        return ClientHello(legacyVersion, sessionLen, suites, out)
    }

    /** The SNI extension data holds a server_name_list; return its first host_name. */
    private fun parseSniHost(data: ByteArray): String {
        val listLen = u16(data, 0)
        assertEquals(data.size - 2, listLen, "list_len SNI tidak konsisten")
        assertEquals(0, data[2].toInt() and 0xFF, "SNI harus host_name")
        val hostLen = u16(data, 3)
        return data.copyOfRange(5, 5 + hostLen).toString(Charsets.US_ASCII)
    }

    /** A u16-list extension (supported_groups, signature_algorithms):
     *  2-byte length prefix + u16 entries. */
    private fun parseU16List(data: ByteArray): List<Int> {
        val len = u16(data, 0)
        assertEquals(data.size - 2, len, "list_len tidak konsisten")
        return (0 until len / 2).map { u16(data, 2 + it * 2) }
    }

    /** supported_versions client data: 1-byte length + u16 versions. */
    private fun parseVersions(data: ByteArray): List<Int> {
        val len = data[0].toInt() and 0xFF
        assertEquals(data.size - 1, len, "versions len tidak konsisten")
        return (0 until len / 2).map { u16(data, 1 + it * 2) }
    }

    /** key_share client data: 2-byte length + (group, key_len, key)
     *  entries — keys are random, so only group + length are returned. */
    private fun parseKeyShare(data: ByteArray): List<Pair<Int, Int>> {
        val len = u16(data, 0)
        assertEquals(data.size - 2, len, "key_share len tidak konsisten")
        val out = mutableListOf<Pair<Int, Int>>()
        var pos = 2
        while (pos < data.size) {
            val group = u16(data, pos)
            val keyLen = u16(data, pos + 2)
            out += group to keyLen
            pos += 4 + keyLen
        }
        assertEquals(data.size, pos, "parse key_share tidak pas di ujung")
        return out
    }

    /** ALPN client data: 2-byte length + (len, name) entries. */
    private fun parseAlpn(data: ByteArray): List<String> {
        val len = u16(data, 0)
        assertEquals(data.size - 2, len, "ALPN len tidak konsisten")
        val out = mutableListOf<String>()
        var pos = 2
        while (pos < data.size) {
            val n = data[pos].toInt() and 0xFF
            out += data.copyOfRange(pos + 1, pos + 1 + n).toString(Charsets.US_ASCII)
            pos += 1 + n
        }
        assertEquals(data.size, pos, "parse ALPN tidak pas di ujung")
        return out
    }

    /**
     * Compare a captured BC ClientHello against the Go reference
     * bytes, field by field. `withAlpn` selects the reference
     * variant (hello127-alpn.bin has ALPN http/1.1).
     */
    private fun assertMatchesGoReference(captured: ByteArray, reference: ByteArray, withAlpn: Boolean) {
        val got = parseClientHello(captured)
        val ref = parseClientHello(reference)

        assertEquals(0x0303, got.legacyVersion, "legacy_version harus TLS 1.2 (0x0303)")
        assertEquals(32, got.sessionIdLength, "session id harus 32 byte acak (compatibility mode)")
        assertEquals(ref.cipherSuites, got.cipherSuites, "cipher suites harus sama persis (list + urutan)")

        // Extension SET identical; the two zero-length extensions
        // (0x0017, 0x0012) are first here (BC writes empties first)
        // instead of 4th/5th as in Go — relative order kept.
        assertEquals(ref.extensions.map { it.first }.toSet(), got.extensions.map { it.first }.toSet(),
            "extension SET harus sama dengan Go")
        val gotEmpty = got.extensions.filter { it.second.isEmpty() }.map { it.first }
        assertEquals(listOf(0x0017, 0x0012), gotEmpty, "ekstensi kosong harus [EMS, SCT] di depan")
        val refNonEmpty = ref.extensions.filter { it.second.isNotEmpty() }.map { it.first }
        val gotNonEmpty = got.extensions.filter { it.second.isNotEmpty() }.map { it.first }
        assertEquals(refNonEmpty, gotNonEmpty, "urutan ekstensi non-kosong harus sama dengan Go")

        // Every deterministic extension's bytes must match Go's.
        val gotByType = got.extensions.toMap()
        val refByType = ref.extensions.toMap()
        for ((type, refData) in refByType) {
            if (type == 0x0033) continue // key_share: keys are random
            val gotData = gotByType[type]
                ?: throw AssertionError("ekstensi 0x${type.toString(16)} hilang")
            assertArrayEquals(refData, gotData, "ekstensi 0x${type.toString(16)} harus sama dengan Go")
        }

        assertEquals("front.wetv.vip", parseSniHost(gotByType.getValue(0x0000)))
        if (withAlpn) {
            assertEquals(listOf("http/1.1"), parseAlpn(gotByType.getValue(0x0010)))
        } else {
            assertFalse(gotByType.containsKey(0x0010), "tanpa ALPN tidak boleh ada ekstensi 0x0010")
        }
        assertEquals(GoHelloTls.SUPPORTED_GROUPS.toList(), parseU16List(gotByType.getValue(0x000a)))
        assertEquals(GoHelloTls.SIGNATURE_ALGORITHMS.toList(), parseU16List(gotByType.getValue(0x000d)))
        assertEquals(GoHelloTls.SIGNATURE_ALGORITHMS_CERT.toList(), parseU16List(gotByType.getValue(0x0032)))
        assertEquals(listOf(0x0304, 0x0303), parseVersions(gotByType.getValue(0x002b)))
        assertEquals(
            listOf(0x11ec to 1216, 0x001d to 32),
            parseKeyShare(gotByType.getValue(0x0033)),
            "key_share harus [X25519MLKEM768 (1216 B) + X25519 (32 B)] seperti Go 1.27",
        )
    }

    /** Run a real BC-GoHello handshake against the JDK test server;
     *  returns the captured ClientHello bytes + negotiated protocol. */
    private fun runHandshake(
        item: ProfileItem,
        trustManager: X509TrustManager? = null,
    ): Pair<ByteArray, String> {
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
        }, "gohello-test-server").apply { isDaemon = true }
        serverThread.start()

        val hs = GoHelloTls.wrap(serverToClient.input, recording, item, trustManager)
        hs.output.write("halo-go".toByteArray(Charsets.UTF_8))
        hs.output.flush()
        val reply = ByteArray(1024)
        val n = hs.input.read(reply)
        assertEquals("balasan:halo-go", reply.copyOf(n).toString(Charsets.UTF_8))
        assertEquals("halo-go", serverReceived)
        if (serverError != null) throw AssertionError("Server TLS gagal: $serverError", serverError)
        hs.input.close()
        hs.output.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "thread server masih hidup sesudah close")
        return recording.captured.toByteArray() to hs.protocol
    }

    @Test
    fun `Go Hello matches the Go 1 27 reference without ALPN`() {
        val (captured, protocol) = runHandshake(goHelloItem())
        assertEquals("TLS 1.3", protocol)
        assertMatchesGoReference(captured, loadReference("hello127-noalpn.bin"), withAlpn = false)
    }

    @Test
    fun `Go Hello matches the Go 1 27 reference with ALPN`() {
        val (captured, protocol) = runHandshake(goHelloItem(alpn = "http/1.1"))
        assertEquals("TLS 1.3", protocol)
        assertMatchesGoReference(captured, loadReference("hello127-alpn.bin"), withAlpn = true)
    }

    @Test
    fun `handshake completes with platform certificate validation`() {
        // insecure=false + trust manager trusting the test keystore:
        // the BC client must validate the chain exactly like the
        // SSLSocket path does (no hostname check, chain check yes).
        val (captured, _) = runHandshake(goHelloItem(insecure = false), testTrustManager())
        val extensions = parseClientHello(captured).extensions
        assertTrue(extensions.any { it.first == 0x002b }, "harus ada supported_versions")
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
        }, "gohello-test-server-untrusted").apply { isDaemon = true }
        serverThread.start()
        try {
            assertThrows(Exception::class.java) {
                GoHelloTls.wrap(serverToClient.input, clientToServer.output, goHelloItem(insecure = false))
            }
        } finally {
            runCatching { serverSession.close() }
            serverThread.join(5_000)
        }
    }

    @Test
    fun `isGoHello follows the chip`() {
        assertTrue(GoHelloTls.isGoHello(goHelloItem()))
        assertFalse(GoHelloTls.isGoHello(goHelloItem().copy(goHelloEnabled = false)))
    }

    @Test
    fun `Go Hello wins over Onering in tlsKind`() {
        val both = goHelloItem().copy(oneringEnabled = true, oneringBug = "live.iflix.com")
        assertEquals(Transport.TlsKind.GO_HELLO, Transport.tlsKind(both))
        val oneringOnly = goHelloItem().copy(goHelloEnabled = false, oneringEnabled = true, oneringBug = "live.iflix.com")
        assertEquals(Transport.TlsKind.ONERING, Transport.tlsKind(oneringOnly))
        val plain = goHelloItem().copy(goHelloEnabled = false)
        assertEquals(Transport.TlsKind.JVM, Transport.tlsKind(plain))
    }

    /**
     * In-memory byte channel (copied from OneringTlsTest, M4): an
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
