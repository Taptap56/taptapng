package com.taptap.x

import com.taptap.x.core.ServerTester
import com.taptap.x.core.TunnelState
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.core.proto.SpeedStats
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.SocketTimeoutException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

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
        // instead of dialling through the tunnel. v1.0.7: the refusal
        // is only enforced while the TUN is up (TunnelState.up).
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = true
            ServerTester.protectSocket = { false }
            try {
                assertEquals(-1, ServerTester.testTcp("127.0.0.1", port))
            } finally {
                ServerTester.protectSocket = null
                TunnelState.up = false
            }
        }
    }

    @Test
    fun `tcp test ignores a refusing protect hook while the TUN is down`() {
        // v1.0.7: during start (probe window) protect() returns false
        // because no TUN exists yet — the test must go direct instead
        // of reporting a false failure. Fails on v1.0.6 code (-1).
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = false
            ServerTester.protectSocket = { false }
            try {
                val ms = ServerTester.testTcp("127.0.0.1", port)
                assertTrue(ms >= 0, "expected >= 0 ms, got $ms")
            } finally {
                ServerTester.protectSocket = null
                TunnelState.up = false
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
        // v1.0.7: only enforced while the TUN is up.
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = true
            ServerTester.protectSocket = { false }
            try {
                val r = ServerTester.testTcpDetailed("127.0.0.1", port)
                assertEquals(-1, r.ms)
                assertEquals("protect gagal", r.failureStage)
            } finally {
                ServerTester.protectSocket = null
                TunnelState.up = false
            }
        }
    }

    @Test
    fun `tcp detailed proceeds when protect refuses but the app is disallowed`() {
        // v1.0.9: on this phone protect() returns false once the TUN
        // is up, so every delay test read "protect gagal" even though
        // a plain TCP connect succeeds (taptapx-6.txt 04:18). While
        // the app is disallowed from the VPN the socket bypasses at
        // the routing level, so the test measures a real direct
        // delay. Fails on v1.0.8 code (ms -1, stage "protect gagal").
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = true
            TunnelState.appBypass = true
            ServerTester.protectSocket = { false }
            try {
                val r = ServerTester.testTcpDetailed("127.0.0.1", port)
                assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms}")
                assertEquals(null, r.failureStage)
            } finally {
                ServerTester.protectSocket = null
                TunnelState.appBypass = false
                TunnelState.up = false
            }
        }
    }

    @Test
    fun `tcp detailed ignores a refusing protect hook while the TUN is down`() {
        // v1.0.7: same gate as testTcp — a refused hook pre-TUN must
        // not produce a "protect gagal" stage. Fails on v1.0.6 code.
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = false
            ServerTester.protectSocket = { false }
            try {
                val r = ServerTester.testTcpDetailed("127.0.0.1", port)
                assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms}")
                assertEquals(null, r.failureStage)
            } finally {
                ServerTester.protectSocket = null
                TunnelState.up = false
            }
        }
    }

    @Test
    fun `tcpConnectMs ignores a refusing protect hook while the TUN is down`() {
        // v1.0.7: the tcpConnectMsDetailed fallback has its own
        // protect check — it needs the same gate. Fails on v1.0.6.
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = false
            ServerTester.protectSocket = { false }
            try {
                val ok = ServerTester.tcpConnectMs(
                    java.net.InetAddress.getByName("127.0.0.1"), port, 1000,
                )
                assertTrue(ok >= 0, "expected >= 0 ms, got $ok")
            } finally {
                ServerTester.protectSocket = null
                TunnelState.up = false
            }
        }
    }

    @Test
    fun `tcpConnectMs proceeds when protect refuses but the app is disallowed`() {
        // v1.0.9: same tolerance as testTcpDetailed, second call
        // site (the real-ping TCP fallback). Fails on v1.0.8 code
        // (ms -1, stage "protect gagal").
        ServerSocket(0).use { server ->
            val port = server.localPort
            TunnelState.up = true
            TunnelState.appBypass = true
            ServerTester.protectSocket = { false }
            try {
                val r = ServerTester.tcpConnectMsDetailed(
                    java.net.InetAddress.getByName("127.0.0.1"), port, 3000,
                )
                assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms}")
                assertEquals(null, r.failureStage)
            } finally {
                ServerTester.protectSocket = null
                TunnelState.appBypass = false
                TunnelState.up = false
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

    // ---- v1.0.13, fix B: real ping through the proxy ----

    /** Fake proxy: records dials + written bytes, answers the HTTP
     * GET with a 204 (like generate_204). */
    private class HttpEchoProxy(
        private val response: String =
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    ) : ProxyClient {
        val dialed = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Int>>())
        val written = ByteArrayOutputStream()
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats? = null,
        ): ProxyStream {
            dialed.add(targetHost to targetPort)
            val input = ByteArrayInputStream(response.toByteArray(Charsets.UTF_8))
            return object : ProxyStream {
                override val input: InputStream = input
                override val output: OutputStream = written
                override fun close() = Unit
            }
        }

        override fun close() = Unit
    }

    private fun vmessItem() = ProfileItem(
        remarks = "T",
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
    )

    @Test
    fun `real ping through proxy measures the round trip, not the TCP connect`() {
        // v1.0.13, fix B: the old testRealPingDetailed only measured
        // a TCP connect to the entry (ICMP never answers on a
        // non-root phone) — the user reported the number "kayanya
        // ping tcp bukan ping asli". The real ping dials THROUGH
        // the proxy and GETs the delay-test URL. Fails on v1.0.12
        // code (no such function — the row showed a TCP time).
        val proxy = HttpEchoProxy()
        val r = ServerTester.testRealPingThroughProxy(
            vmessItem(), "http://www.gstatic.com/generate_204",
            clientFactory = { proxy },
        )
        assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms} stage=${r.failureStage}")
        assertEquals(null, r.failureStage)
        assertEquals(listOf("www.gstatic.com" to 80), proxy.dialed)
        val sent = proxy.written.toString(Charsets.UTF_8.name())
        assertTrue(sent.startsWith("GET /generate_204 HTTP/1.1"), "expected an HTTP GET, got: $sent")
        assertTrue(sent.contains("Host: www.gstatic.com"), "GET must carry the Host header: $sent")
    }

    @Test
    fun `real ping through proxy reports the proxy stage when the dial fails`() {
        // A proxy dial that fails (bad UUID / closed window) must
        // show its stage — never a TCP number. Fails on v1.0.12
        // code (the row showed a TCP connect time for a dead entry).
        val failing = object : ProxyClient {
override fun dial(
                targetHost: String,
                targetPort: Int,
                probeBody: ByteArray?,
                stats: SpeedStats? = null,
            ): ProxyStream =
                throw SocketTimeoutException("VMess gagal: Read timed out")

            override fun close() = Unit
        }
        val r = ServerTester.testRealPingThroughProxy(
            vmessItem(), "http://www.gstatic.com/generate_204",
            clientFactory = { failing },
        )
        assertEquals(-1, r.ms)
        assertEquals("VMess gagal", r.failureStage)
    }

    @Test
    fun `real ping through proxy cannot run for SSH entries`() {
        // SSH has no proxy client — the caller falls back to TCP
        // only on this stage (see CANNOT_RUN_STAGE).
        val ssh = ProfileItem(
            remarks = "S",
            configType = ConfigType.SSH,
            address = "1.2.3.4",
            port = 22,
            username = "u",
        )
        val r = ServerTester.testRealPingThroughProxy(
            ssh, "http://www.gstatic.com/generate_204",
        )
        assertEquals(-1, r.ms)
        assertEquals(ServerTester.CANNOT_RUN_STAGE, r.failureStage)
    }

    @Test
    fun `parseDelayUrl splits host port path`() {
        assertEquals(
            Triple("www.gstatic.com", 80, "/generate_204"),
            ServerTester.parseDelayUrl("http://www.gstatic.com/generate_204"),
        )
        assertEquals(
            Triple("www.gstatic.com", 80, "/generate_204"),
            ServerTester.parseDelayUrl("https://www.gstatic.com/generate_204"),
        )
        assertEquals(
            Triple("example.com", 8080, "/x"),
            ServerTester.parseDelayUrl("http://example.com:8080/x"),
        )
        assertEquals(Triple("example.com", 80, "/"), ServerTester.parseDelayUrl("example.com"))
        assertEquals(null, ServerTester.parseDelayUrl(""))
        assertEquals(null, ServerTester.parseDelayUrl("http://"))
        assertEquals(null, ServerTester.parseDelayUrl("http://example.com:abc/x"))
    }
}
