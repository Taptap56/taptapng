package com.taptap.ng.core

import com.taptap.ng.core.proto.TlsUtil
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [PemicuManager] (M5, v1.0.24).
 *
 * The pure helpers (clamp / target / due / format) run without any
 * network. The dial tests use a real local TCP server on loopback
 * (plain TCP loopback works — see SshClientTest) with an injected
 * fake TLS handshake: a real SSLSocket handshake cannot run on
 * loopback in the dev VM or CI (see TlsEngineTest), so the
 * handshake step is the seam [PemicuManager.primeDial] takes as a
 * parameter, and the fake records the host it was asked to secure
 * (the SNI) and returns a protocol. The TCP connect, protect rule,
 * address iteration, and failure paths are all real.
 */
class PemicuManagerTest {

    private val fakeHandshake: (Socket, String, Int) -> String =
        { _, _, _ -> "TLSv1.3" }

    @AfterEach
    fun tearDown() {
        PemicuManager.stop()
        PemicuManager.protectSocket = null
        TunnelState.up = false
        TunnelState.appBypass = false
        DialLog.clear()
    }

    private fun itemWithPemicu(
        domain: String = "chat.sociomile.com",
        port: Int? = null,
        interval: Int? = null,
        enabled: Boolean = true,
    ) = ProfileItem(
        remarks = "Pemicu test",
        address = "203.0.113.99",
        port = 9999,
        pemicuEnabled = enabled,
        pemicuDomain = domain,
        pemicuPort = port,
        pemicuInterval = interval,
    )

    /** A closed loopback port: bind an ephemeral port, then close it. */
    private fun closedPort(): Int {
        val s = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = s.localPort
        s.close()
        return port
    }

    private fun waitForLog(
        substring: String,
        timeoutMs: Long = 5_000,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (DialLog.lines().any { it.contains(substring) }) return true
            Thread.sleep(100)
        }
        return DialLog.lines().any { it.contains(substring) }
    }

    // --- clamp ---

    @Test
    fun `clampInterval defaults to 15 and clamps to 5 to 300`() {
        assertEquals(15, PemicuManager.clampInterval(null))
        assertEquals(5, PemicuManager.clampInterval(0))
        assertEquals(5, PemicuManager.clampInterval(4))
        assertEquals(5, PemicuManager.clampInterval(5))
        assertEquals(60, PemicuManager.clampInterval(60))
        assertEquals(300, PemicuManager.clampInterval(300))
        assertEquals(300, PemicuManager.clampInterval(999))
    }

    @Test
    fun `clampPort defaults to 443 and clamps to 1 to 65535`() {
        assertEquals(443, PemicuManager.clampPort(null))
        assertEquals(443, PemicuManager.clampPort(0))
        assertEquals(443, PemicuManager.clampPort(70000))
        assertEquals(443, PemicuManager.clampPort(-1))
        assertEquals(1, PemicuManager.clampPort(1))
        assertEquals(8443, PemicuManager.clampPort(8443))
        assertEquals(65535, PemicuManager.clampPort(65535))
    }

    // --- targetFromProfile ---

    @Test
    fun `targetFromProfile returns null when the chip is off`() {
        assertNull(PemicuManager.targetFromProfile(itemWithPemicu(enabled = false)))
    }

    @Test
    fun `targetFromProfile returns null when the domain is blank`() {
        assertNull(PemicuManager.targetFromProfile(itemWithPemicu(domain = "   ")))
        assertNull(PemicuManager.targetFromProfile(itemWithPemicu(domain = "")))
    }

    @Test
    fun `targetFromProfile never reads the entry address or port`() {
        // The entry points at a bogus address:port; the target must
        // still be the prime domain on the prime port (443 default),
        // never 203.0.113.99:9999.
        val target = PemicuManager.targetFromProfile(itemWithPemicu())
        assertNotNull(target)
        assertEquals("chat.sociomile.com", target!!.host)
        assertEquals(443, target.port)
        assertEquals(15, target.intervalSec)
    }

    @Test
    fun `targetFromProfile clamps port and interval`() {
        val target = PemicuManager.targetFromProfile(
            itemWithPemicu(port = 70000, interval = 1),
        )
        assertNotNull(target)
        assertEquals(443, target!!.port)
        assertEquals(5, target.intervalSec)
        val target2 = PemicuManager.targetFromProfile(
            itemWithPemicu(port = 8443, interval = 60),
        )
        assertEquals(8443, target2!!.port)
        assertEquals(60, target2.intervalSec)
    }

    @Test
    fun `buildTargets deduplicates by host and port`() {
        val a = itemWithPemicu(domain = "chat.sociomile.com")
        val b = itemWithPemicu(domain = "CHAT.SOCIOMILE.COM")
        val c = itemWithPemicu(domain = "support.zoom.us")
        val d = itemWithPemicu(domain = "support.zoom.us", port = 8443)
        val targets = PemicuManager.buildTargets(listOf(a, b, c, d))
        assertEquals(3, targets.size)
        assertEquals("chat.sociomile.com", targets[0].host)
        assertEquals("support.zoom.us", targets[1].host)
        assertEquals(8443, targets[2].port)
    }

    @Test
    fun `dueTargets returns never-primed hosts at once and respects the interval`() {
        val target = PemicuManager.PemicuTarget("chat.sociomile.com", 443, 15)
        val now = 1_000_000L
        // Never primed: due at once.
        assertEquals(listOf(target), PemicuManager.dueTargets(listOf(target), emptyMap(), now))
        // Primed 5 s ago with a 15 s interval: not due.
        val recent = mapOf(target.key() to (now - 5_000L))
        assertEquals(emptyList<PemicuManager.PemicuTarget>(), PemicuManager.dueTargets(listOf(target), recent, now))
        // Primed 15 s ago: due again.
        val elapsed = mapOf(target.key() to (now - 15_000L))
        assertEquals(listOf(target), PemicuManager.dueTargets(listOf(target), elapsed, now))
    }

    @Test
    fun `msUntilNextDue sleeps until the next prime, not one second`() {
        // v1.0.25: the loop sleeps until the next prime falls due
        // instead of polling every second.
        val target = PemicuManager.PemicuTarget("chat.sociomile.com", 443, 15)
        val now = 1_000_000L
        // Never primed: due at once -> min sleep (1 s), never 0 (no spin).
        assertEquals(1_000L, PemicuManager.msUntilNextDue(listOf(target), emptyMap(), now))
        // Primed 5 s ago, 15 s interval -> 10 s left.
        assertEquals(
            10_000L,
            PemicuManager.msUntilNextDue(
                listOf(target), mapOf(target.key() to (now - 5_000L)), now,
            ),
        )
        // Primed 14 s ago -> 1 s left (min sleep).
        assertEquals(
            1_000L,
            PemicuManager.msUntilNextDue(
                listOf(target), mapOf(target.key() to (now - 14_000L)), now,
            ),
        )
        // Primed just now, 15 s interval -> the full interval.
        assertEquals(
            15_000L,
            PemicuManager.msUntilNextDue(
                listOf(target), mapOf(target.key() to now), now,
            ),
        )
        // Two targets: the earliest due wins.
        val other = PemicuManager.PemicuTarget("support.zoom.us", 443, 300)
        val last = mapOf(
            target.key() to (now - 5_000L),
            other.key() to (now - 100_000L),
        )
        assertEquals(10_000L, PemicuManager.msUntilNextDue(listOf(target, other), last, now))
        // No targets: idle sleep (5 s), so edits are picked up soon.
        assertEquals(5_000L, PemicuManager.msUntilNextDue(emptyList(), emptyMap(), now))
    }

    @Test
    fun `formatPrimeResult shapes`() {
        val target = PemicuManager.PemicuTarget("chat.sociomile.com", 443, 15)
        val ok = PemicuManager.PrimeResult.Ok(
            target = target, ip = "104.21.8.162", isV4 = true,
            tcpMs = 120, tlsProtocol = "TLSv1.3", totalMs = 212,
            bypassOk = true, localAddr = "10.0.0.1",
        )
        assertEquals(
            // v1.0.4: baris PRIME OK membawa IP hasil resolve —
            // log 09:35 tidak bisa bilang edge mana yang menggantung.
            "PRIME OK chat.sociomile.com:443 104.21.8.162 212ms",
            PemicuManager.formatPrimeResult(ok),
        )
        val failed = PemicuManager.PrimeResult.Failed(target, "Connection refused")
        assertEquals(
            "PRIME GAGAL chat.sociomile.com:443 (Connection refused)",
            PemicuManager.formatPrimeResult(failed),
        )
        val failedWithIp = PemicuManager.PrimeResult.Failed(
            target, "Read timed out", "104.21.8.162",
        )
        assertEquals(
            "PRIME GAGAL chat.sociomile.com:443 104.21.8.162 (Read timed out)",
            PemicuManager.formatPrimeResult(failedWithIp),
        )
    }

    // --- primeDial ---

    @Test
    fun `primeDial fails fast on a refused connection and never throws`() {
        val port = closedPort()
        val target = PemicuManager.PemicuTarget("127.0.0.1", port, 15)
        val result = PemicuManager.primeDial(target, protect = null, tlsHandshake = fakeHandshake)
        assertTrue(result is PemicuManager.PrimeResult.Failed, "expected Failed, got $result")
        val error = (result as PemicuManager.PrimeResult.Failed).error
        assertTrue(error.contains("refused", ignoreCase = true), "error: $error")
    }

    @Test
    fun `primeDial succeeds against a local TCP server and secures the prime domain`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val accepted = mutableListOf<Socket>()
        val acceptThread = Thread({
            runCatching { accepted += server.accept() }
        }, "pemicu-test-accept").apply { isDaemon = true; start() }
        try {
            var securedHost: String? = null
            val handshake: (Socket, String, Int) -> String = { _, host, _ ->
                securedHost = host
                "TLSv1.3"
            }
            val target = PemicuManager.PemicuTarget("127.0.0.1", server.localPort, 15)
            val result = PemicuManager.primeDial(
                target, protect = null, tlsHandshake = handshake,
            )
            assertTrue(result is PemicuManager.PrimeResult.Ok, "expected Ok, got $result")
            val ok = result as PemicuManager.PrimeResult.Ok
            assertTrue(ok.isV4)
            assertEquals("127.0.0.1", ok.ip)
            assertEquals("TLSv1.3", ok.tlsProtocol)
            assertTrue(ok.tcpMs >= 0)
            assertTrue(ok.totalMs >= ok.tcpMs)
            // The handshake was asked to secure the PRIME domain —
            // never the entry's address (the entry is not even read).
            assertEquals("127.0.0.1", securedHost)
            acceptThread.join(2_000)
            assertEquals(1, accepted.size)
        } finally {
            accepted.forEach { runCatching { it.close() } }
            server.close()
        }
    }

    @Test
    fun `primeDial tries the next address when the first refuses`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val acceptThread = Thread({
            runCatching { server.accept()?.close() }
        }, "pemicu-test-accept2").apply { isDaemon = true; start() }
        try {
            // 127.0.0.2 refuses (nothing listens there); 127.0.0.1
            // accepts — the dial must fall through to the second.
            val resolve: (String, Int) -> List<InetAddress> = { _, port ->
                listOf(
                    InetAddress.getByName("127.0.0.2"),
                    InetAddress.getByName("127.0.0.1"),
                )
            }
            val target = PemicuManager.PemicuTarget("example.com", server.localPort, 15)
            val result = PemicuManager.primeDial(
                target, protect = null, resolve = resolve, tlsHandshake = fakeHandshake,
            )
            assertTrue(result is PemicuManager.PrimeResult.Ok, "expected Ok, got $result")
            assertEquals("127.0.0.1", (result as PemicuManager.PrimeResult.Ok).ip)
        } finally {
            server.close()
        }
    }

    @Test
    fun `primeDial stops trying new addresses after the total deadline`() {
        // v1.0.4: worst case tadinya (TCP 5 dtk + TLS 10 dtk) × jumlah
        // alamat — probe bisa menunggu 30 dtk+. Alamat pertama
        // (127.0.0.1) menggantung di TLS (fake tidur 1200 ms);
        // deadline 500 ms — alamat kedua (127.0.0.2, sehat) TIDAK
        // boleh dicoba. Gagal pada kode v1.0.3 (yang mencoba alamat
        // kedua dan mengembalikan Ok). Kedua server memakai port yang
        // sama (satu target port) di dua IP loopback berbeda.
        val blackhole = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = blackhole.localPort
        val good = ServerSocket(port, 1, InetAddress.getByName("127.0.0.2"))
        val held = mutableListOf<Socket>()
        val blackholeThread = Thread({
            try {
                while (true) held += blackhole.accept()
            } catch (_: Exception) {
                // Server ditutup.
            }
        }, "pemicu-test-deadline-bh").apply { isDaemon = true; start() }
        var goodAccepts = java.util.concurrent.atomic.AtomicInteger(0)
        val goodThread = Thread({
            try {
                while (true) {
                    good.accept()?.close()
                    goodAccepts.incrementAndGet()
                }
            } catch (_: Exception) {
                // Server ditutup.
            }
        }, "pemicu-test-deadline-good").apply { isDaemon = true; start() }
        try {
            val handshake: (Socket, String, Int) -> String = { socket, _, _ ->
                if (socket.inetAddress.hostAddress == "127.0.0.1") {
                    Thread.sleep(1200)
                    throw java.net.SocketTimeoutException("TLS menggantung")
                }
                "TLSv1.3"
            }
            val resolve: (String, Int) -> List<InetAddress> = { _, _ ->
                listOf(
                    InetAddress.getByName("127.0.0.1"),
                    InetAddress.getByName("127.0.0.2"),
                )
            }
            val target = PemicuManager.PemicuTarget("example.com", port, 15)
            val start = System.currentTimeMillis()
            val result = PemicuManager.primeDial(
                target, protect = null, resolve = resolve,
                tlsHandshake = handshake, deadlineMs = 500,
            )
            val elapsed = System.currentTimeMillis() - start
            assertTrue(result is PemicuManager.PrimeResult.Failed, "expected Failed, got $result")
            assertEquals(
                0, goodAccepts.get(),
                "alamat kedua tidak boleh dicoba sesudah deadline habis",
            )
            assertTrue(elapsed < 3000, "dial harus berhenti di deadline, bukan mencoba lagi: $elapsed ms")
        } finally {
            held.forEach { runCatching { it.close() } }
            blackhole.close()
            good.close()
        }
    }

    @Test
    fun `primeDial reports a TLS handshake failure`() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val acceptThread = Thread({
            runCatching { server.accept()?.close() }
        }, "pemicu-test-accept3").apply { isDaemon = true; start() }
        try {
            val handshake: (Socket, String, Int) -> String = { _, _, _ ->
                throw SSLException("handshake gagal")
            }
            val target = PemicuManager.PemicuTarget("127.0.0.1", server.localPort, 15)
            val result = PemicuManager.primeDial(
                target, protect = null, tlsHandshake = handshake,
            )
            assertTrue(result is PemicuManager.PrimeResult.Failed, "expected Failed, got $result")
            assertTrue(
                (result as PemicuManager.PrimeResult.Failed).error.contains("handshake"),
                "error: ${result.error}",
            )
        } finally {
            server.close()
        }
    }

    // --- Prime dial Hello shape (v1.0.2: Hello Go is gone) ---

    /** Parse the first TLS record's ClientHello: cipher suites +
     *  extension types (wire order) + SNI host, if present. */
    private fun parseHello(captured: ByteArray): Triple<List<Int>, List<Int>, String?> {
        assertTrue(captured.size > 50, "terlalu sedikit byte terekam: ${captured.size}")
        assertEquals(0x16, captured[0].toInt() and 0xFF, "record pertama harus handshake")
        assertEquals(0x01, captured[5].toInt() and 0xFF, "handshake pertama harus ClientHello")
        var pos = 9 + 2 + 32 // record + handshake header + legacy_version + random
        val sessionLen = captured[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        val suitesLen = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
        pos += 2
        val suites = (0 until suitesLen / 2).map {
            ((captured[pos + it * 2].toInt() and 0xFF) shl 8) or
                (captured[pos + it * 2 + 1].toInt() and 0xFF)
        }
        pos += suitesLen
        val compLen = captured[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extLen = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
        pos += 2
        val extEnd = pos + extLen
        val types = mutableListOf<Int>()
        var sni: String? = null
        while (pos < extEnd) {
            val type = ((captured[pos].toInt() and 0xFF) shl 8) or (captured[pos + 1].toInt() and 0xFF)
            val len = ((captured[pos + 2].toInt() and 0xFF) shl 8) or (captured[pos + 3].toInt() and 0xFF)
            types += type
            if (type == 0x0000) {
                val hostLen = ((captured[pos + 7].toInt() and 0xFF) shl 8) or
                    (captured[pos + 8].toInt() and 0xFF)
                sni = captured.copyOfRange(pos + 9, pos + 9 + hostLen).toString(Charsets.US_ASCII)
            }
            pos += 4 + len
        }
        return Triple(suites, types, sni)
    }

    /** Run primeDial (DEFAULT handshake — no fake) against a local
     *  TCP server that captures the first TLS record, then closes.
     *  The handshake cannot complete against a capture-only server,
     *  so the result is Failed either way; the assertion is on the
     *  captured ClientHello bytes. */
    private fun captureFirstRecord(host: String): ByteArray {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val captured = ByteArrayOutputStream()
        val acceptThread = Thread({
            runCatching {
                val s = server.accept()
                s.soTimeout = 5_000
                val inp = java.io.DataInputStream(s.getInputStream())
                val header = ByteArray(5)
                inp.readFully(header)
                val len = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
                val body = ByteArray(len)
                inp.readFully(body)
                captured.write(header)
                captured.write(body)
                s.close()
            }
        }, "pemicu-test-capture").apply { isDaemon = true; start() }
        try {
            val resolve: (String, Int) -> List<InetAddress> = { _, _ ->
                listOf(InetAddress.getByName("127.0.0.1"))
            }
            val target = PemicuManager.PemicuTarget(host, server.localPort, 15)
            PemicuManager.primeDial(target, protect = null, resolve = resolve)
            acceptThread.join(10_000)
            return captured.toByteArray()
        } finally {
            server.close()
        }
    }

    @Test
    fun `primeDial sends a JVM Hello with SNI equal to the prime host`() {
        // v1.0.2: Hello Go is gone — the prime dial is always the
        // plain JVM SSLSocket Hello (v1.0.0 behavior). The SNI must
        // still be the prime domain itself, never the entry address.
        // parseHello already asserts the first record is a TLS
        // ClientHello (content type 0x16, handshake type 0x01).
        val (_, _, sni) = parseHello(captureFirstRecord("front.wetv.vip"))
        assertEquals("front.wetv.vip", sni)
    }

    @Test
    fun `default ClientHello already carries the session ticket extension`() {
        // v1.0.4 (review Claude): panggilan reflection XVEON dengan
        // boolean=true DIINFERENSI sebagai setUseSessionTickets(true)
        // — verifikasi dex tidak menemukan panggilan itu, dan default
        // JVM sudah mengirim ekstensi 0x0023 (session_ticket). Tes
        // ini mengunci fakta itu: bila default berhenti mengirimnya,
        // panggilan itu harus ditinjau ulang — sampai saat itu, tidak
        // ada kode mati yang ditambahkan.
        val (_, types, _) = parseHello(captureFirstRecord("front.wetv.vip"))
        assertTrue(
            types.contains(0x0023),
            "ClientHello harus membawa session_ticket (0x0023): $types",
        )
    }

    // --- Prime trust-all context (v1.0.4, robustness) ---

    /** Server SSLContext dengan sertifikat self-signed test-tls.p12
     *  (pola yang sama dengan TlsEngineTest; password khusus tes). */
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

    /** Drive sepasang SSLEngine client/server sampai handshake
     *  selesai, hanya dengan buffer in-memory (tanpa socket — TLS
     *  loopback JVM di-reset di lingkungan tes). Pola standar:
     *  NEED_WRAP/NEED_UNWRAP bergantian, dua arah. */
    private fun driveHandshake(client: SSLEngine, server: SSLEngine) {
        val appEmpty = ByteBuffer.allocate(0)
        val appBuf = ByteBuffer.allocate(16384)
        val cNet = ByteBuffer.allocate(32768)
        val sNet = ByteBuffer.allocate(32768)
        client.beginHandshake()
        server.beginHandshake()
        var guard = 0
        while (guard++ < 200) {
            var progress = false
            when (client.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    cNet.clear()
                    client.wrap(appEmpty, cNet)
                    cNet.flip()
                    progress = true
                }
                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (sNet.hasRemaining()) {
                        appBuf.clear()
                        client.unwrap(sNet, appBuf)
                        progress = true
                    }
                }
                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    client.delegatedTask?.run()
                    progress = true
                }
                else -> Unit
            }
            when (server.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    sNet.clear()
                    server.wrap(appEmpty, sNet)
                    sNet.flip()
                    progress = true
                }
                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (cNet.hasRemaining()) {
                        appBuf.clear()
                        server.unwrap(cNet, appBuf)
                        progress = true
                    }
                }
                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    server.delegatedTask?.run()
                    progress = true
                }
                else -> Unit
            }
            val done = { e: SSLEngine ->
                e.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED ||
                    e.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
            }
            if (done(client) && done(server)) return
            if (!progress) {
                throw AssertionError(
                    "handshake macet: client=${client.handshakeStatus} server=${server.handshakeStatus}",
                )
            }
        }
        throw AssertionError("handshake tidak selesai dalam $guard langkah")
    }

    @Test
    fun `prime trust-all context completes a handshake the default context refuses`() {
        // v1.0.4 (robustness, BUKAN perbaikan 09:35): prime dial
        // memakai trust-all — ia hanya perlu mengirim ClientHello,
        // bukan membaca data aplikasi. Server memakai sertifikat
        // self-signed: konteks default MENOLAK (kontrol — membuktikan
        // tes ini diskriminatif), konteks trust-all produksi MENERIMA.
        val newServer = {
            serverContext().createSSLEngine().apply { useClientMode = false }
        }
        assertThrows(SSLException::class.java) {
            driveHandshake(SSLContext.getDefault().createSSLEngine(), newServer())
        }
        driveHandshake(TlsUtil.trustAllContext.createSSLEngine(), newServer())
    }

    @Test
    fun `primeDial reports a resolve failure instead of throwing`() {
        val target = PemicuManager.PemicuTarget("example.com", 443, 15)
        val resolve: (String, Int) -> List<InetAddress> = { _, _ ->
            throw java.io.IOException("DNS mati")
        }
        val result = PemicuManager.primeDial(
            target, protect = null, resolve = resolve, tlsHandshake = fakeHandshake,
        )
        assertTrue(result is PemicuManager.PrimeResult.Failed, "expected Failed, got $result")
        assertTrue(
            (result as PemicuManager.PrimeResult.Failed).error.contains("resolve"),
            "error: ${result.error}",
        )
    }

    @Test
    fun `primeDial fails when protect refuses while the TUN is up`() {
        TunnelState.up = true
        TunnelState.appBypass = false
        val target = PemicuManager.PemicuTarget("127.0.0.1", closedPort(), 15)
        val result = PemicuManager.primeDial(
            target, protect = { false }, tlsHandshake = fakeHandshake,
        )
        assertTrue(result is PemicuManager.PrimeResult.Failed, "expected Failed, got $result")
        assertTrue(
            (result as PemicuManager.PrimeResult.Failed).error.contains("protect"),
            "error: ${result.error}",
        )
    }

    @Test
    fun `primeDial proceeds when protect refuses but the app is disallowed`() {
        TunnelState.up = true
        TunnelState.appBypass = true
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val acceptThread = Thread({
            runCatching { server.accept()?.close() }
        }, "pemicu-test-accept4").apply { isDaemon = true; start() }
        try {
            val target = PemicuManager.PemicuTarget("127.0.0.1", server.localPort, 15)
            val result = PemicuManager.primeDial(
                target, protect = { false }, tlsHandshake = fakeHandshake,
            )
            assertTrue(result is PemicuManager.PrimeResult.Ok, "expected Ok, got $result")
            assertFalse((result as PemicuManager.PrimeResult.Ok).bypassOk)
        } finally {
            server.close()
        }
    }

    // --- primeNow / loop ---

    @Test
    fun `primeNow logs PRIME GAGAL for a dead target and does not throw`() {
        DialLog.clear()
        val item = itemWithPemicu(domain = "127.0.0.1", port = closedPort())
        PemicuManager.primeNow(item)
        assertTrue(waitForLog("PRIME GAGAL 127.0.0.1:"), "log: ${DialLog.lines()}")
    }

    @Test
    fun `primeNow does nothing when the profile must not be primed`() {
        DialLog.clear()
        PemicuManager.primeNow(itemWithPemicu(domain = ""))
        Thread.sleep(500)
        assertTrue(DialLog.lines().none { it.contains("PRIME") }, "log: ${DialLog.lines()}")
    }

    @Test
    fun `primeNowSync records lastPrime so the loop does not prime twice`() {
        // v1.0.4: primeNowSync tidak mengisi lastPrime — tick pertama
        // loop langsung mem-prime lagi sesaat setelah connect (prime
        // ganda). Port tertutup: dial gagal cepat, tapi lastPrime
        // harus tetap tercatat (dicatat apa pun hasilnya, seperti
        // loop yang mencatat saat launch).
        val port = closedPort()
        val item = itemWithPemicu(domain = "127.0.0.1", port = port)
        PemicuManager.primeNowSync(item)
        val at = PemicuManager.lastPrimeAt("127.0.0.1:$port")
        assertNotNull(at, "lastPrime harus terisi sesudah primeNowSync")
        assertTrue(
            System.currentTimeMillis() - at!! < 10_000,
            "lastPrime harus baru, bukan angka lama",
        )
    }

    @Test
    fun `loop primes once at start and stops on stop`() {
        DialLog.clear()
        val target = PemicuManager.PemicuTarget("127.0.0.1", closedPort(), 5)
        PemicuManager.start { listOf(target) }
        try {
            assertTrue(waitForLog("PRIME GAGAL 127.0.0.1:"), "log: ${DialLog.lines()}")
            assertTrue(PemicuManager.isLoopRunning)
        } finally {
            PemicuManager.stop()
        }
        val countAfterStop = DialLog.lines().count { it.contains("PRIME GAGAL") }
        Thread.sleep(2_000)
        assertEquals(
            countAfterStop,
            DialLog.lines().count { it.contains("PRIME GAGAL") },
            "loop kept dialling after stop: ${DialLog.lines()}",
        )
        assertTrue(
            DialLog.lines().any { it.contains("loop prime berhenti") },
            "log: ${DialLog.lines()}",
        )
    }

    @Test
    fun `loop does not dial when the target list is empty`() {
        DialLog.clear()
        PemicuManager.start { emptyList() }
        try {
            Thread.sleep(2_000)
            assertTrue(
                DialLog.lines().none { it.contains("PRIME OK") || it.contains("PRIME GAGAL") },
                "log: ${DialLog.lines()}",
            )
        } finally {
            PemicuManager.stop()
        }
    }

    @Test
    fun `loop wakes about once per interval, not once per second`() {
        // v1.0.25: the loop sleeps until the next prime falls due
        // instead of polling every second. A 5 s interval target on
        // a closed port primes at t=0 and again at t=5 s — in that
        // window the loop must tick twice, not ~6 times (old 1 s
        // tick). The second PRIME GAGAL also proves the prime still
        // fires on time.
        DialLog.clear()
        val target = PemicuManager.PemicuTarget("127.0.0.1", closedPort(), 5)
        val before = PemicuManager.loopTickCount
        PemicuManager.start { listOf(target) }
        try {
            assertTrue(waitForLog("PRIME GAGAL 127.0.0.1:"), "log: ${DialLog.lines()}")
            val deadline = System.currentTimeMillis() + 12_000
            while (DialLog.lines().count { it.contains("PRIME GAGAL") } < 2
                && System.currentTimeMillis() < deadline
            ) {
                Thread.sleep(100)
            }
            assertEquals(
                2,
                DialLog.lines().count { it.contains("PRIME GAGAL") },
                "log: ${DialLog.lines()}",
            )
            val ticks = PemicuManager.loopTickCount - before
            assertTrue(ticks <= 3, "loop ticked $ticks times in about 5 s")
        } finally {
            PemicuManager.stop()
        }
    }

    @Test
    fun `stop does not clear in-flight keys`() {
        // v1.0.4 (2e): stop() mengosongkan inFlight padahal thread
        // prime lama masih jalan — start cepat sesudahnya bisa
        // mendial host yang sama dua kali. Kunci harus bertahan
        // sampai thread lama selesai dan menghapusnya sendiri.
        // Dialnya stuck di resolve (~3 dtk ke server DNS diam),
        // jadi stop() tidak bisa membangunkannya — asersi ini
        // deterministik, bukan balapan waktu.
        val silent = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        PemicuManager.stop()
        try {
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = silent.localPort
            val target = PemicuManager.PemicuTarget("probe.invalid", 443, 300)
            PemicuManager.start { listOf(target) }
            val deadline = System.currentTimeMillis() + 5000
            while (!PemicuManager.inFlightKeys().contains(target.key()) &&
                System.currentTimeMillis() < deadline
            ) {
                Thread.sleep(10)
            }
            assertTrue(
                PemicuManager.inFlightKeys().contains(target.key()),
                "key harus in-flight dulu",
            )
            PemicuManager.stop()
            assertTrue(
                PemicuManager.inFlightKeys().contains(target.key()),
                "key harus bertahan sesudah stop() — thread lama masih jalan",
            )
        } finally {
            DnsResolver.dnsServer = oldServer
            DnsResolver.dnsPort = oldPort
            silent.close()
            PemicuManager.stop()
        }
    }
}
