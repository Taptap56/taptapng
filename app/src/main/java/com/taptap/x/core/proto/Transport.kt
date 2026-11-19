package com.taptap.x.core.proto

import com.taptap.x.core.DialLog
import com.taptap.x.core.DnsResolver
import com.taptap.x.core.TunnelState
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException

/**
 * Shared transport ladder for VMess/VLESS/Trojan (M2): TCP → TLS → WS.
 *
 * Order matters and matches v2rayNG: plain TCP first, TLS wraps the TCP
 * socket when item.tls is set, then the WebSocket handshake runs over
 * whatever stream is underneath (plain TCP or TLS).
 *
 * The returned socket keeps SO_TIMEOUT = [HANDSHAKE_TIMEOUT_MS] during
 * dial so a dead peer fails fast; clients reset it to 0 (blocking) once
 * the protocol handshake has succeeded. The socket is owned by the
 * returned [OpenStream] — closing the socket closes everything under it.
 */
object Transport {

    const val CONNECT_TIMEOUT_MS = 10_000
    const val HANDSHAKE_TIMEOUT_MS = 10_000

    /**
     * Hook set by [com.taptap.x.service.TaptapVpnService] so dial
     * sockets bypass the TUN (VpnService.protect). Null = no
     * protection (unit tests, direct use). Returning false aborts
     * the dial — a dial that cannot bypass the VPN would loop into
     * the tunnel forever — but ONLY while [TunnelState.up]: before
     * establish() there is no VPN yet and protect() returns false,
     * so a pre-TUN dial goes direct instead of failing instantly
     * (v1.0.7: every v1.0.6 probe died here with "protect() gagal").
     * v1.0.9: a refused protect is ALSO non-fatal while
     * [TunnelState.appBypass] — the app's own package is disallowed
     * from the VPN, so the socket bypasses at the routing level
     * anyway (v2rayNG pattern; on this phone protect() returns false
     * once the TUN is up, and failing here starved the forwarder).
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    /**
     * Per-thread dial watchdog (v1.0.6, fix A). The dialling thread
     * (probe / forwarder dial) installs one before `client.dial()`
     * and stops it in a `finally` after. Transport registers the
     * live socket and the current stage with it, so a stage that
     * blocks past the watchdog is killed by closing the socket.
     * Null = no watchdog (plain unit-test dials).
     */
    private val threadWatchdog = ThreadLocal<DialWatchdog?>()

    fun setThreadWatchdog(watchdog: DialWatchdog?) {
        threadWatchdog.set(watchdog)
    }

    /** Record the stage the current thread's dial is in ("TCP", "TLS", ...). */
    fun noteStage(stage: String) {
        threadWatchdog.get()?.stage = stage
    }

    /** The protocol handshake succeeded: the watchdog must not touch this socket again. */
    fun clearWatchdogSocket() {
        threadWatchdog.get()?.clearSocket()
    }

    /**
     * The watchdog-tagged failure for the current thread's dial, or
     * null when the watchdog did not fire. Callers prefer this over
     * the raw exception — it says WHERE the dial was stuck.
     */
    fun watchdogFailure(): SocketTimeoutException? {
        val wd = threadWatchdog.get()
        return if (wd != null && wd.fired) {
            SocketTimeoutException("${wd.stage} gagal (watchdog ${wd.timeoutMs / 1000} dtk)")
        } else {
            null
        }
    }

    /** Prefer the watchdog-tagged failure over [e] when the watchdog fired. */
    fun preferWatchdogFailure(e: Exception): Exception = watchdogFailure() ?: e

    class OpenStream(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream,
    ) {
        fun close() = runCatching { socket.close() }
    }

    /**
     * Open the transport ladder (TCP → TLS → WS). Every stage tags its
     * failure ("DNS gagal: ...", "TCP gagal: ...", "TLS gagal: ...",
     * "WS gagal: ...") so the phone status shows WHERE the dial died
     * instead of a bare "timeout" — v1.0.4 only ever showed that.
     * The exception types are preserved on purpose: [SocketTimeoutException]
     * stays a timeout and [SSLException] stays a TLS failure, so
     * `TunForwarder.dialFailureReason` keeps mapping them the same way.
     */
    fun open(item: ProfileItem): OpenStream {
        require(item.address.isNotBlank()) { "Address proxy kosong" }
        require(item.port in 1..65535) { "Port proxy di luar 1..65535: ${item.port}" }
        val wd = threadWatchdog.get()
        val plain = Socket()
        try {
            // Arm the watchdog on the plain socket FIRST: a connect
            // that blocks past the watchdog is killed the same way
            // as a stuck read (see DialWatchdog).
            wd?.arm(plain)
            val protect = protectSocket
            if (protect != null && TunnelState.up && !protect(plain)) {
                if (TunnelState.appBypass) {
                    // v1.0.9: protect() refused, but our package is
                    // disallowed from the VPN, so this socket bypasses
                    // the TUN at the routing level anyway (v2rayNG
                    // pattern — its Pemicu dial "bypasses even if
                    // protect() returns false"). Continue the dial
                    // instead of failing it: on this phone protect()
                    // returns false once the TUN is up, and failing
                    // here meant the forwarder never dialled at all
                    // ("Vpn naik internet ga jalan", 2026-11-20
                    // 04:21). Without the disallow the refusal stays
                    // fatal — an unprotected dial would loop into
                    // the tunnel forever.
                    DialLog.log(
                        "PROTECT",
                        "protect() gagal — dial ${item.address} lanjut via disallow aplikasi",
                    )
                } else {
                    throw IllegalStateException("protect() gagal — dial tidak bisa bypass VPN")
                }
            }
            if (protect != null && !TunnelState.up) {
                // Probe-first dial, TUN belum naik: tidak ada VPN
                // yang perlu di-bypass, dial langsung (v1.0.7).
                DialLog.log("PROTECT", "TUN belum naik — dial ${item.address} langsung tanpa protect")
            }
            // Tahap DNS: resolve langsung (UDP ke 8.8.8.8, bypass TUN),
            // fallback ke resolver sistem bila gagal (relay DNS mungkin
            // jalan). JANGAN resolve lewat InetSocketAddress(host, port):
            // konstruktor itu memanggil resolver sistem TANPA timeout —
            // saat VPN naik lookup-nya masuk ke TUN dan menggantung
            // sampai resolver menyerah (gejala v1.0.4: status macet di
            // "Connecting..." selamanya). Di sini address sudah IP
            // hasil resolve, jadi connect() tidak lookup lagi.
            noteStage("DNS")
            val target = DnsResolver.resolveWithSystemFallback(item.address, item.port)
            DialLog.log("DNS", "${item.address} -> $target")
            noteStage("TCP")
            try {
                plain.connect(InetSocketAddress(target, item.port), CONNECT_TIMEOUT_MS)
            } catch (e: SocketTimeoutException) {
                throw SocketTimeoutException("TCP gagal: ${e.message}")
            } catch (e: ConnectException) {
                throw ConnectException("TCP gagal: ${e.message}")
            } catch (e: IOException) {
                throw IOException("TCP gagal: ${e.message}", e)
            }
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
            DialLog.log("TCP", "${item.address}:${item.port} ok")
        } catch (e: Exception) {
            runCatching { plain.close() }
            val failure = preferWatchdogFailure(e)
            DialLog.failure("DIAL", failure)
            throw failure
        }
        var socket: Socket = plain
        var input: InputStream = plain.getInputStream()
        var output: OutputStream = plain.getOutputStream()
        val network = item.network.ifBlank { "tcp" }.lowercase()
        if (network != "tcp" && network != "ws") {
            runCatching { socket.close() }
            throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws)")
        }
        try {
            if (item.tls) {
                // Tahap TLS. SNI tetap domain asli (item.sni atau
                // item.address): TlsUtil.wrap menerima item apa adanya
                // — createSocket(plain, host, ...) tidak me-resolve
                // host karena socket sudah terkoneksi; SNI di-set
                // eksplisit dari item, bukan dari IP hasil resolve.
                noteStage("TLS")
                try {
                    socket = TlsUtil.wrap(plain, item)
                } catch (e: SSLException) {
                    throw SSLException("TLS gagal: ${e.message}")
                } catch (e: Exception) {
                    throw IOException("TLS gagal: ${e.message}", e)
                }
                // Re-arm the watchdog on the TLS socket: closing the
                // plain socket would not unblock the TLS read.
                wd?.arm(socket)
                input = socket.getInputStream()
                output = socket.getOutputStream()
                DialLog.log("TLS", "${item.address} ok")
            }
            if (network == "ws") {
                // Tahap WS.
                noteStage("WS")
                try {
                    val ws = WsTransport.connect(input, output, wsHost(item), wsPath(item))
                    input = ws.input
                    output = ws.output
                } catch (e: Exception) {
                    throw IOException("WS gagal: ${e.message}", e)
                }
                DialLog.log("WS", "${wsHost(item)}${wsPath(item)} ok")
            }
        } catch (e: Exception) {
            runCatching { socket.close() }
            val failure = preferWatchdogFailure(e)
            DialLog.failure("DIAL", failure)
            throw failure
        }
        // The transport ladder is up; the protocol handshake that
        // follows runs under the same watchdog, and the protocol
        // client clears the socket (clearWatchdogSocket) once its
        // handshake has succeeded — so the timer can never kill a
        // live relay socket.
        return OpenStream(socket, input, output)
    }

    /** WS Host header: item.host, else the proxy address (+ :port if unusual). */
    fun wsHost(item: ProfileItem): String {
        val host = item.host.ifBlank { item.address }
        return if (item.port == 80 || item.port == 443) host else "$host:${item.port}"
    }

    /** WS request path, default "/". */
    fun wsPath(item: ProfileItem): String {
        val path = item.path.ifBlank { "/" }
        return if (path.startsWith("/")) path else "/$path"
    }
}
