package com.taptap.x.core

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Delay tests for the server list (v2rayNG's "Test TCP delays" /
 * "Test real delays"). Pure JVM code, covered by unit tests against
 * a localhost server socket.
 */
object ServerTester {

    /**
     * Optional socket protector (VpnService.protect), set by the
     * service while the tunnel is up and cleared on stop. v1.0.4:
     * without it, a delay test run while the VPN is connected sends
     * its socket through the TUN, so the test dials THROUGH the
     * proxy (TLS to the entry, which hangs when the window is closed)
     * and always reports "Timeout" — even though a plain TCP connect
     * to the server would succeed. Protecting the socket measures the
     * real direct TCP delay, like v2rayNG.
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    /** TCP connect timing in ms, or -1 on failure. */
    fun testTcp(host: String, port: Int, timeoutMs: Int = 3000): Long {
        if (host.isBlank() || port !in 1..65535) return -1
        val start = System.nanoTime()
        return try {
            Socket().use { socket ->
                // Bypass our own TUN when the service set the hook;
                // a refused protect fails fast instead of nesting.
                if (protectSocket?.invoke(socket) == false) return -1
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            (System.nanoTime() - start) / 1_000_000
        } catch (_: Exception) {
            -1
        }
    }

    /**
     * Real ping (ICMP when the process may send it, TCP echo fallback
     * otherwise — same behaviour as InetAddress.isReachable on Android).
     * Returns ms, or -1 when the host does not answer.
     */
    fun testRealPing(host: String, timeoutMs: Int = 3000): Long {
        if (host.isBlank()) return -1
        val start = System.nanoTime()
        return try {
            val reachable = InetAddress.getByName(host).isReachable(timeoutMs)
            if (reachable) (System.nanoTime() - start) / 1_000_000 else -1
        } catch (_: Exception) {
            -1
        }
    }
}
