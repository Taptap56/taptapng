package com.taptap.x.proto

import com.taptap.x.core.TunnelState
import com.taptap.x.core.proto.Transport
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.net.InetAddress
import java.net.ServerSocket
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression tests for the v1.0.6 phone report (taptapx-4.txt,
 * 2026-11-20 03:19): every probe dial failed instantly with
 * IllegalStateException "protect() gagal". The probe runs BEFORE the
 * TUN is established, and VpnService.protect() returns false when
 * there is no VPN yet (nothing to bypass) — so the unconditional
 * protect check in Transport.open threw before any network I/O.
 * v1.0.7 gates protect enforcement on TunnelState.up: pre-TUN dials
 * go direct, post-TUN dials must still be protected.
 *
 * The TUN-down tests FAIL on v1.0.6 code (the dial throws
 * "protect() gagal" without ever connecting); the TUN-up tests
 * guard the old behaviour (a dial that cannot bypass a live TUN
 * must still fail fast instead of looping into the tunnel).
 */
class ProtectGateTest {

    private fun plainTcpItem(port: Int) = ProfileItem(
        configType = ConfigType.VMESS,
        address = "127.0.0.1", port = port,
        uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
        network = "tcp", tls = false,
    )

    /** Local listener that accepts one connection, then closes it. */
    private fun listener(): Pair<ServerSocket, Int> {
        val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val t = Thread {
            try {
                server.accept().close()
            } catch (_: Exception) {
                // Server closed.
            }
        }
        t.isDaemon = true
        t.start()
        return server to port
    }

    @Test
    fun `probe dial with TUN down ignores a refusing protect hook`() {
        val (server, port) = listener()
        TunnelState.up = false
        Transport.protectSocket = { false }
        try {
            val stream = Transport.open(plainTcpItem(port))
            stream.close()
        } finally {
            Transport.protectSocket = null
            TunnelState.up = false
        }
        runCatching { server.close() }
    }

    @Test
    fun `probe dial with TUN down logs that it goes direct`() {
        val (server, port) = listener()
        TunnelState.up = false
        Transport.protectSocket = { false }
        try {
            val before = com.taptap.x.core.DialLog.lines().size
            val stream = Transport.open(plainTcpItem(port))
            stream.close()
            assertTrue(
                com.taptap.x.core.DialLog.lines().drop(before)
                    .any { it.contains("langsung tanpa protect") },
                "DialLog must record the skipped pre-TUN protect",
            )
        } finally {
            Transport.protectSocket = null
            TunnelState.up = false
        }
        runCatching { server.close() }
    }

    @Test
    fun `forwarder dial with TUN up still fails when protect refuses`() {
        val (server, port) = listener()
        TunnelState.up = true
        Transport.protectSocket = { false }
        try {
            val e = assertThrows(IllegalStateException::class.java) {
                Transport.open(plainTcpItem(port))
            }
            assertTrue(e.message!!.contains("protect() gagal"), "pesan: ${e.message}")
        } finally {
            Transport.protectSocket = null
            TunnelState.up = false
        }
        runCatching { server.close() }
    }

    @Test
    fun `forwarder dial with TUN up proceeds when protect allows`() {
        val (server, port) = listener()
        TunnelState.up = true
        Transport.protectSocket = { true }
        try {
            val stream = Transport.open(plainTcpItem(port))
            stream.close()
        } finally {
            Transport.protectSocket = null
            TunnelState.up = false
        }
        runCatching { server.close() }
    }

    @Test
    fun `forwarder dial with TUN up proceeds when protect refuses but the app is disallowed`() {
        // v1.0.9 (taptapx-6.txt, 2026-11-20 04:18): on this phone
        // protect() returns false once the TUN is up, and the old
        // fail-fast starved the forwarder — no dial ever happened,
        // so no app traffic flowed ("Vpn naik internet ga jalan",
        // 04:21). v2rayNG disallows its own package from the VPN, so
        // its sockets bypass at the routing level even when protect()
        // refuses. While TunnelState.appBypass is true the refusal
        // is non-fatal and the dial continues (logged as PROTECT).
        // Fails on v1.0.8 code (throws "protect() gagal").
        val (server, port) = listener()
        TunnelState.up = true
        TunnelState.appBypass = true
        Transport.protectSocket = { false }
        try {
            val before = com.taptap.x.core.DialLog.lines().size
            val stream = Transport.open(plainTcpItem(port))
            stream.close()
            assertTrue(
                com.taptap.x.core.DialLog.lines().drop(before)
                    .any { it.contains("lanjut via disallow aplikasi") },
                "DialLog must record the continued dial",
            )
        } finally {
            Transport.protectSocket = null
            TunnelState.appBypass = false
            TunnelState.up = false
        }
        runCatching { server.close() }
    }
}
