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
}
