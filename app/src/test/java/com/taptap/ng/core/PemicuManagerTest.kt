package com.taptap.ng.core

import com.taptap.ng.core.proto.GoHelloTls
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SSLException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
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
    fun `targetFromProfile carries the Hello Go chip`() {
        // v1.0.1: the flag only selects the Hello shape — the
        // target (host/port/interval) is unchanged.
        val on = PemicuManager.targetFromProfile(itemWithPemicu().copy(goHelloEnabled = true))
        assertNotNull(on)
        assertTrue(on!!.goHello)
        assertEquals("chat.sociomile.com", on.host)
        val off = PemicuManager.targetFromProfile(itemWithPemicu())
        assertNotNull(off)
        assertFalse(off!!.goHello)
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
        assertEquals("PRIME OK chat.sociomile.com:443 212ms", PemicuManager.formatPrimeResult(ok))
        val failed = PemicuManager.PrimeResult.Failed(target, "Connection refused")
        assertEquals(
            "PRIME GAGAL chat.sociomile.com:443 (Connection refused)",
            PemicuManager.formatPrimeResult(failed),
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

    // --- Hello Go (v1.0.1): prime dial Hello shape ---

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
    private fun captureFirstRecord(host: String, goHello: Boolean): ByteArray {
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
            val target = PemicuManager.PemicuTarget(host, server.localPort, 15, goHello = goHello)
            PemicuManager.primeDial(target, protect = null, resolve = resolve)
            acceptThread.join(10_000)
            return captured.toByteArray()
        } finally {
            server.close()
        }
    }

    @Test
    fun `primeDial sends a Go shaped Hello when the chip is on`() {
        val (suites, types, sni) = parseHello(captureFirstRecord("front.wetv.vip", goHello = true))
        assertEquals(GoHelloTls.CIPHER_SUITES.toList(), suites, "cipher suites harus urutan Go")
        assertTrue(types.contains(0x002b), "harus ada supported_versions")
        assertTrue(types.contains(0x0033), "harus ada key_share")
        assertTrue(types.contains(0x000a), "harus ada supported_groups")
        assertTrue(types.contains(0x000d), "harus ada signature_algorithms")
        assertTrue(types.contains(0x0032), "harus ada signature_algorithms_cert")
        assertFalse(types.contains(0x0016), "Go tidak mengirim encrypt_then_mac")
        assertEquals("front.wetv.vip", sni)
    }

    @Test
    fun `primeDial sends a JVM Hello when the chip is off`() {
        val (suites, _, sni) = parseHello(captureFirstRecord("front.wetv.vip", goHello = false))
        // The JVM (Conscrypt) Hello is a different shape from Go's:
        // the cipher list must NOT be Go's list (v1.0.0 behavior).
        assertTrue(suites != GoHelloTls.CIPHER_SUITES.toList(), "JVM Hello harus beda dari Go")
        assertEquals("front.wetv.vip", sni)
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
}
