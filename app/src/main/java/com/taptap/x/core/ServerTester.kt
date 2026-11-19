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
            (System.nanoTime() - start) / 1_000_000
        } catch (_: Exception) {
            -1
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
    fun testRealPing(host: String, port: Int, timeoutMs: Int = 3000): Long {
        if (host.isBlank() || port !in 1..65535) return -1
        val start = System.nanoTime()
        return try {
            val target = DnsResolver.resolveWithSystemFallback(host, port, timeoutMs)
            if (target.isReachable(timeoutMs)) {
                return (System.nanoTime() - start) / 1_000_000
            }
            tcpConnectMs(target, port, timeoutMs)
        } catch (_: Exception) {
            -1
        }
    }

    /** TCP connect ke [address]:[port], ukur ms atau -1 bila gagal.
     *  Dipakai sebagai fallback [testRealPing] saat ICMP tidak bisa. */
    internal fun tcpConnectMs(address: InetAddress, port: Int, timeoutMs: Int): Long {
        val start = System.nanoTime()
        return try {
            Socket().use { socket ->
                if (protectSocket?.invoke(socket) == false) return -1
                socket.connect(InetSocketAddress(address, port), timeoutMs)
            }
            (System.nanoTime() - start) / 1_000_000
        } catch (_: Exception) {
            -1
        }
    }
}
