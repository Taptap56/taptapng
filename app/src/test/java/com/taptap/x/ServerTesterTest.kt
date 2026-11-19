package com.taptap.x

import com.taptap.x.core.ServerTester
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class ServerTesterTest {

    @Test
    fun `tcp test succeeds against localhost listener`() {
        ServerSocket(0).use { server ->
            val port = server.localPort
            val ms = ServerTester.testTcp("127.0.0.1", port)
            assertTrue(ms >= 0, "expected >= 0 ms, got $ms")
        }
    }

    @Test
    fun `tcp test fails on closed port and bad input`() {
        // Port 1 is (practically) never listening on localhost.
        assertEquals(-1, ServerTester.testTcp("127.0.0.1", 1, timeoutMs = 1000))
        assertEquals(-1, ServerTester.testTcp("", 443))
        assertEquals(-1, ServerTester.testTcp("127.0.0.1", 0))
        assertEquals(-1, ServerTester.testTcp("127.0.0.1", 70000))
    }

    @Test
    fun `real ping answers localhost`() {
        val ms = ServerTester.testRealPing("127.0.0.1")
        assertTrue(ms >= 0, "expected >= 0 ms, got $ms")
    }

    @Test
    fun `tcp test fails fast when protect refuses the socket`() {
        // v1.0.4: when the VPN is up the service sets a protect hook
        // (VpnService.protect); a refused protect must fail fast
        // instead of dialling through the tunnel.
        ServerSocket(0).use { server ->
            val port = server.localPort
            ServerTester.protectSocket = { false }
            try {
                assertEquals(-1, ServerTester.testTcp("127.0.0.1", port))
            } finally {
                ServerTester.protectSocket = null
            }
        }
    }

    @Test
    fun `tcp test succeeds when protect allows the socket`() {
        ServerSocket(0).use { server ->
            val port = server.localPort
            ServerTester.protectSocket = { true }
            try {
                val ms = ServerTester.testTcp("127.0.0.1", port)
                assertTrue(ms >= 0, "expected >= 0 ms, got $ms")
            } finally {
                ServerTester.protectSocket = null
            }
        }
    }

    @Test
    fun `tcp test fails fast on unresolvable host`() {
        // v1.0.5: host yang tidak bisa di-resolve harus kembali -1
        // dengan cepat, bukan menggantung di resolver sistem tanpa
        // timeout (gejala v1.0.4: delay test "Timeout" selamanya).
        val start = System.nanoTime()
        assertEquals(-1, ServerTester.testTcp("tidak-ada.invalid", 443, timeoutMs = 500))
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(elapsedMs < 10_000, "testTcp menggantung $elapsedMs ms")
    }

    @Test
    fun `real ping overload falls back to TCP connect on localhost`() {
        // Overload baru: ICMP dulu, bila gagal TCP connect ke port
        // entry. Di localhost ICMP biasanya menjawab duluan — tes ini
        // memastikan overload mengembalikan angka, bukan -1.
        ServerSocket(0).use { server ->
            val port = server.localPort
            val ms = ServerTester.testRealPing("127.0.0.1", port)
            assertTrue(ms >= 0, "expected >= 0 ms, got $ms")
        }
    }

    @Test
    fun `tcpConnectMs succeeds to localhost listener and fails on closed port`() {
        // Fallback TCP-nya sendiri, diuji langsung: sukses ke listener,
        // -1 ke port tertutup (ICMP localhost selalu menjawab, jadi
        // jalur ini tidak bisa diuji lewat overload di localhost).
        ServerSocket(0).use { server ->
            val port = server.localPort
            val ok = ServerTester.tcpConnectMs(
                java.net.InetAddress.getByName("127.0.0.1"), port, 1000,
            )
            assertTrue(ok >= 0, "expected >= 0 ms, got $ok")
            val closed = ServerTester.tcpConnectMs(
                java.net.InetAddress.getByName("127.0.0.1"), 1, 1000,
            )
            assertEquals(-1, closed)
        }
    }

    // ---- v1.0.6, fix C: the delay label reports its own stage ----

    @Test
    fun `tcp detailed reports protect gagal when the hook refuses`() {
        // v1.0.5 showed a bare "Timeout" for this case — the phone
        // could not tell the protect hook from a dead network.
        ServerSocket(0).use { server ->
            val port = server.localPort
            ServerTester.protectSocket = { false }
            try {
                val r = ServerTester.testTcpDetailed("127.0.0.1", port)
                assertEquals(-1, r.ms)
                assertEquals("protect gagal", r.failureStage)
            } finally {
                ServerTester.protectSocket = null
            }
        }
    }

    @Test
    fun `tcp detailed reports TCP gagal on a closed port`() {
        val r = ServerTester.testTcpDetailed("127.0.0.1", 1, timeoutMs = 1000)
        assertEquals(-1, r.ms)
        assertEquals("TCP gagal", r.failureStage)
    }

    @Test
    fun `tcp detailed reports DNS gagal for an unresolvable host`() {
        val start = System.nanoTime()
        val r = ServerTester.testTcpDetailed("tidak-ada.invalid", 443, timeoutMs = 500)
        assertEquals(-1, r.ms)
        assertEquals("DNS gagal", r.failureStage)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(elapsedMs < 10_000, "testTcpDetailed menggantung $elapsedMs ms")
    }

    @Test
    fun `tcp detailed succeeds against localhost listener with no stage`() {
        ServerSocket(0).use { server ->
            val port = server.localPort
            val r = ServerTester.testTcpDetailed("127.0.0.1", port)
            assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms}")
            assertEquals(null, r.failureStage)
        }
    }

    @Test
    fun `real ping overload fails for unreachable host`() {
        // 192.0.2.1 (TEST-NET-1) tidak bisa dijangkau: ICMP gagal dan
        // TCP connect gagal → -1, tetap cepat.
        val start = System.nanoTime()
        assertEquals(-1, ServerTester.testRealPing("192.0.2.1", 443, timeoutMs = 500))
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(elapsedMs < 10_000, "testRealPing menggantung $elapsedMs ms")
    }

    @Test
    fun `real ping overload fails for unresolvable host`() {
        assertEquals(-1, ServerTester.testRealPing("tidak-ada.invalid", 443, timeoutMs = 500))
    }
}
