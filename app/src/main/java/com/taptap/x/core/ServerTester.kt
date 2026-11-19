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
     * Delay-test result (v1.0.6, fix C). [ms] >= 0 on success;
     * [failureStage] names WHERE the test died on failure, so the
     * row label never shows a bare "Timeout" again — v1.0.5 showed
     * "Timeout" even for an IP literal while the VPN was up, and
     * nobody could tell whether DNS, TCP, or the protect hook had
     * failed.
     */
    data class TestResult(val ms: Long, val failureStage: String?)

    /**
     * Map a test failure to its stage. DNS failures carry our own
     * "DNS gagal" tag from DnsResolver; a refused protect is its
     * own stage (the socket never left the phone).
     */
    fun stageOf(e: Exception): String = when (e) {
        is java.net.SocketTimeoutException -> "TCP timeout"
        is java.net.ConnectException -> "TCP gagal"
        is java.io.IOException ->
            if (e.message?.startsWith("DNS gagal") == true) "DNS gagal" else "TCP gagal"
        else -> "TCP gagal"
    }

    /**
     * Optional socket protector (VpnService.protect), set by the
     * service while the tunnel is up and cleared on stop. v1.0.4:
     * without it, a delay test run while the VPN is connected sends
     * its socket through the TUN, so the test dials THROUGH the
     * proxy (TLS to the entry, which hangs when the window is closed)
     * and always reports "Timeout" — even though a plain TCP connect
     * to the server would succeed. Protecting the socket measures the
     * real direct TCP delay, like v2rayNG. The refusal is only
     * enforced while [TunnelState.up]: before establish() protect()
     * returns false (no VPN yet), so a test run during start goes
     * direct instead of reporting a false "protect gagal" (v1.0.7).
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    /** TCP connect timing in ms, or -1 on failure. */
    fun testTcp(host: String, port: Int, timeoutMs: Int = 3000): Long =
        testTcpDetailed(host, port, timeoutMs).ms

    /** TCP connect timing with the failure stage (v1.0.6, fix C). */
    fun testTcpDetailed(host: String, port: Int, timeoutMs: Int = 3000): TestResult {
        if (host.isBlank() || port !in 1..65535) return TestResult(-1, null)
        val start = System.nanoTime()
        return try {
            Socket().use { socket ->
                // Bypass our own TUN when the service set the hook
                // and the TUN is up; a refused protect fails fast
                // instead of nesting. While the TUN is down the hook
                // is ignored (protect() returns false pre-establish).
                if (TunnelState.up && protectSocket?.invoke(socket) == false) {
                    return TestResult(-1, "protect gagal")
                }
                // Resolve dulu lewat DNS langsung (bypass TUN),
                // fallback ke resolver sistem bila gagal. Dulu
                // InetSocketAddress(host, port) di sini memanggil
                // resolver sistem tanpa timeout — saat VPN naik
                // lookup-nya masuk TUN dan menggantung sampai
                // resolver menyerah, jadi delay test selalu "Timeout"
                // (laporan HP v1.0.4, 2026-11-20 01:50).
                val target = DnsResolver.resolveWithSystemFallback(host, port, timeoutMs)
                socket.connect(InetSocketAddress(target, port), timeoutMs)
            }
            TestResult((System.nanoTime() - start) / 1_000_000, null)
        } catch (e: Exception) {
            TestResult(-1, stageOf(e))
        }
    }

    /**
     * Real ping (ICMP when the process may send it, TCP echo fallback
     * otherwise — same behaviour as InetAddress.isReachable on Android).
     * Returns ms, or -1 when the host does not answer.
     *
     * PERINGATAN: di HP non-root fungsi ini SELALU -1 — isReachable
     * butuh raw socket ICMP (butuh root) dan fallback TCP echo port 7
     * tertutup di mana-mana. Untuk pengukuran yang benar-benar jalan
     * di HP, pakai overload [testRealPing(host, port, timeoutMs)]:
     * fallback-nya TCP connect ke port entry itu sendiri.
     * Fungsi ini dipertahankan apa adanya untuk kompatibilitas
     * (MainViewModel.testAll(true) masih memanggilnya — perlu diubah
     * ke overload baru, lihat overload di bawah).
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

    /**
     * Real ping dengan fallback TCP: coba ICMP dulu (isReachable);
     * bila gagal, ukur TCP connect ke port entry itu sendiri.
     * TCP connect ke port entry mengukur keterjangkauan yang sama
     * seperti test TCP — bedanya ini dipakai untuk "Test real delays"
     * v2rayNG, yang di HP harus tetap memberi angka walau ICMP
     * tidak pernah bisa. Host di-resolve dulu lewat [DnsResolver]
     * agar lookup-nya tidak menggantung lewat TUN (lihat [testTcp]).
     * Returns ms, atau -1 bila ICMP dan TCP sama-sama gagal.
     */
    fun testRealPing(host: String, port: Int, timeoutMs: Int = 3000): Long =
        testRealPingDetailed(host, port, timeoutMs).ms

    /** Real-ping overload with the failure stage (v1.0.6, fix C). */
    fun testRealPingDetailed(host: String, port: Int, timeoutMs: Int = 3000): TestResult {
        if (host.isBlank() || port !in 1..65535) return TestResult(-1, null)
        return try {
            val target = DnsResolver.resolveWithSystemFallback(host, port, timeoutMs)
            val start = System.nanoTime()
            if (target.isReachable(timeoutMs)) {
                return TestResult((System.nanoTime() - start) / 1_000_000, null)
            }
            tcpConnectMsDetailed(target, port, timeoutMs)
        } catch (e: Exception) {
            TestResult(-1, stageOf(e))
        }
    }

    /** TCP connect ke [address]:[port], ukur ms atau -1 bila gagal.
     *  Dipakai sebagai fallback [testRealPing] saat ICMP tidak bisa. */
    internal fun tcpConnectMs(address: InetAddress, port: Int, timeoutMs: Int): Long =
        tcpConnectMsDetailed(address, port, timeoutMs).ms

    /** TCP-connect fallback with the failure stage (v1.0.6, fix C). */
    internal fun tcpConnectMsDetailed(
        address: InetAddress,
        port: Int,
        timeoutMs: Int,
    ): TestResult {
        val start = System.nanoTime()
        return try {
            Socket().use { socket ->
                if (TunnelState.up && protectSocket?.invoke(socket) == false) {
                    return TestResult(-1, "protect gagal")
                }
                socket.connect(InetSocketAddress(address, port), timeoutMs)
            }
            TestResult((System.nanoTime() - start) / 1_000_000, null)
        } catch (e: Exception) {
            TestResult(-1, stageOf(e))
        }
    }
}
