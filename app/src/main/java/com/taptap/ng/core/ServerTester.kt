package com.taptap.ng.core

import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyClientFactory
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

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

    /** Stage tags Transport / protocol clients put in failure
     * messages ("VMess gagal: ...") — kept verbatim by [stageOf]. */
    private val STAGE_TAGS = listOf(
        "DNS gagal", "TCP gagal", "TLS gagal", "WS gagal",
        "VMess gagal", "VLESS gagal", "Trojan gagal", "SS gagal",
        "SSH gagal",
    )

    /**
     * Map a test failure to its stage. DNS failures carry our own
     * "DNS gagal" tag from DnsResolver; a refused protect is its
     * own stage (the socket never left the phone).
     *
     * v1.0.13: a stage tag already in the message ("VMess gagal",
     * "WS gagal", ...) is kept verbatim — the real ping dials
     * through the proxy, so a "VMess gagal" must reach the row
     * label instead of collapsing to "TCP timeout". The TCP test
     * never produces these tags, so its stages are unchanged.
     */
    fun stageOf(e: Exception): String {
        val msg = e.message
        if (msg != null) {
            STAGE_TAGS.firstOrNull { msg.startsWith(it) }?.let { return it }
        }
        return when (e) {
            is java.net.SocketTimeoutException -> "TCP timeout"
            is java.net.ConnectException -> "TCP gagal"
            is java.io.IOException ->
                if (e.message?.startsWith("DNS gagal") == true) "DNS gagal" else "TCP gagal"
            else -> "TCP gagal"
        }
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
     * v1.0.9: the refusal is ALSO non-fatal while
     * [TunnelState.appBypass] — the app is disallowed from the VPN,
     * so the socket bypasses at the routing level anyway (on this
     * phone protect() returns false once the TUN is up, and the old
     * fail-fast made every delay test read "protect gagal").
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    /**
     * v1.0.9: true when a refused protect must abort the test. The
     * refusal is only fatal while the TUN is up AND the app is NOT
     * disallowed from the VPN: when [TunnelState.appBypass] is true,
     * the socket bypasses at the routing level anyway (v2rayNG
     * pattern), so the test continues and measures a real direct
     * delay instead of reporting a false "protect gagal" — on this
     * phone protect() returns false once the TUN is up
     * (taptapng-6.txt 04:18). While the TUN is down the hook is not
     * invoked at all (protect() returns false pre-establish, v1.0.7).
     */
    private fun mustAbortOnProtectRefusal(socket: Socket): Boolean {
        if (!TunnelState.up) return false
        if (protectSocket?.invoke(socket) != false) return false
        if (TunnelState.appBypass) {
            DialLog.log("PROTECT", "protect() gagal — delay test lanjut via disallow aplikasi")
            return false
        }
        return true
    }

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
                // instead of nesting — unless the app is disallowed
                // from the VPN (v1.0.9), in which case the socket
                // bypasses at the routing level anyway. While the TUN
                // is down the hook is ignored (protect() returns false
                // pre-establish).
                if (mustAbortOnProtectRefusal(socket)) {
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
                if (mustAbortOnProtectRefusal(socket)) {
                    return TestResult(-1, "protect gagal")
                }
                socket.connect(InetSocketAddress(address, port), timeoutMs)
            }
            TestResult((System.nanoTime() - start) / 1_000_000, null)
        } catch (e: Exception) {
            TestResult(-1, stageOf(e))
        }
    }

    // ---- Real ping through the proxy (v1.0.13, fix B) ----

    /**
     * Default delay-test URL for the real ping: the v2rayNG
     * default, as plain HTTP. The proxy stream is a raw byte
     * stream, so the ping is a plain HTTP GET (no TLS over the
     * stream); the generate_204 endpoint answers over HTTP, and
     * any HTTP response (204 / 200 / 301) proves the round-trip.
     */
    const val DEFAULT_REAL_PING_URL = "http://www.gstatic.com/generate_204"

    /**
     * Failure stage meaning "the real ping cannot run for this
     * entry" (SSH — no proxy client — or an unparseable URL).
     * Callers fall back to the TCP test ONLY on this stage; a
     * proxy dial that FAILS is a real failure and is reported
     * with its stage, never hidden behind a TCP number.
     */
    const val CANNOT_RUN_STAGE = "tidak bisa ping"

    /** Parsed delay-test URL: host, port, path. The scheme is
     * ignored for transport — the ping is always a plain HTTP GET
     * (see [DEFAULT_REAL_PING_URL]) — only host / port / path are
     * used. Null when the URL has no usable host. */
    fun parseDelayUrl(url: String): Triple<String, Int, String>? {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) return null
        val lower = trimmed.lowercase()
        val stripped = when {
            lower.startsWith("https://") -> trimmed.substring(8)
            lower.startsWith("http://") -> trimmed.substring(7)
            else -> trimmed
        }
        if (stripped.isEmpty()) return null
        val slash = stripped.indexOf('/')
        val hostPort = if (slash >= 0) stripped.substring(0, slash) else stripped
        val path = if (slash >= 0) stripped.substring(slash) else "/"
        val colon = hostPort.lastIndexOf(':')
        val host = if (colon >= 0) hostPort.substring(0, colon) else hostPort
        val port = if (colon >= 0) {
            hostPort.substring(colon + 1).toIntOrNull() ?: return null
        } else {
            80
        }
        if (host.isBlank() || port !in 1..65535 || !path.startsWith("/")) return null
        return Triple(host, port, path)
    }

    /**
     * Real ping (v1.0.13, fix B): the FULL round-trip through the
     * proxy — dial the entry (VMess/VLESS/Trojan/SS via
     * [ProxyClientFactory]), send an HTTP GET to the delay-test
     * URL as the body, and time until the HTTP response header
     * arrives. This is v2rayNG's "Test real delays". The old
     * [testRealPingDetailed] only measured a TCP connect to the
     * entry (ICMP never answers on a non-root phone), so the
     * number on the row was a TCP ping, not a real ping (user
     * report 2026-11-20 08:58:59). The HTTP GET is the body, so
     * it unblocks the server's response-header flush (v1.0.12
     * lazy header) exactly like the probe body does.
     *
     * [clientFactory] is injectable so tests can run against a
     * fake proxy instead of a real server.
     */
    fun testRealPingThroughProxy(
        item: ProfileItem,
        delayTestUrl: String,
        timeoutMs: Int = 10_000,
        clientFactory: (ProfileItem) -> ProxyClient = ProxyClientFactory::create,
    ): TestResult {
        val target = parseDelayUrl(delayTestUrl.ifBlank { DEFAULT_REAL_PING_URL })
            ?: return TestResult(-1, CANNOT_RUN_STAGE)
        val (host, port, path) = target
        val start = System.nanoTime()
        // Bound the whole dial (DNS + TCP + TLS + WS + protocol)
        // with a watchdog, like the forwarder does — without it a
        // stuck stage could hang past every socket timeout.
        val watchdog = DialWatchdog(timeoutMs.toLong())
        Transport.setThreadWatchdog(watchdog)
        try {
            watchdog.start()
            val client = clientFactory(item)
            try {
                val stream = client.dial(host, port)
                try {
                    val req =
                        "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
                    stream.output.write(req.toByteArray(Charsets.UTF_8))
                    stream.output.flush()
                    // Bound the response read: the lazy header
                    // clears the socket timeout to 0 (blocking)
                    // once it arrives, so a target that never
                    // answers would hang forever without this. A
                    // timer thread closes the stream at the
                    // deadline; the read then fails as a timeout.
                    val closer = thread(name = "real-ping-timeout", isDaemon = true) {
                        try {
                            Thread.sleep(timeoutMs.toLong())
                            runCatching { stream.close() }
                        } catch (_: InterruptedException) {
                            // Read finished in time; nothing to close.
                        }
                    }
                    try {
                        val header = readHttpResponseHeader(stream.input)
                        if (!header.startsWith("HTTP/")) {
                            return TestResult(-1, "ping gagal")
                        }
                        return TestResult((System.nanoTime() - start) / 1_000_000, null)
                    } finally {
                        closer.interrupt()
                    }
                } finally {
                    runCatching { stream.close() }
                }
            } finally {
                runCatching { client.close() }
            }
        } catch (e: Exception) {
            val failure = Transport.preferWatchdogFailure(e)
            return TestResult(-1, stageOf(failure))
        } finally {
            watchdog.stop()
            Transport.setThreadWatchdog(null)
        }
    }

    /** Read until the HTTP response header is complete (\r\n\r\n),
     * EOF, or 8 KiB. Returns the header text (may be empty). */
    private fun readHttpResponseHeader(input: java.io.InputStream): String {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        while (out.size() < 8192) {
            val n = try {
                input.read(buf)
            } catch (_: Exception) {
                break
            }
            if (n == -1) break
            if (n > 0) {
                out.write(buf, 0, n)
                val text = out.toString(Charsets.UTF_8.name())
                if (text.contains("\r\n\r\n")) return text
            }
        }
        return out.toString(Charsets.UTF_8.name())
    }
}
