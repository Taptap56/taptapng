package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.TunnelState
import com.taptap.ng.data.ProfileItem
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
 * v1.0.2 (XVEON order): the DialLog lines follow the XVEON Tunnel Pro
 * connect log, in the same order — "Connecting to <Proto> outbound
 * <host>:<port>", "Connecting TCP socket to <host>:<port>" (the DNS
 * resolve happens INSIDE this step — there is no separate DNS line
 * before TCP; the 120 s DnsResolver cache is unchanged), "TLS
 * handshake -> SNI: <sni>", "TLS established: TLSv1.3", "WebSocket
 * (WS) handshake -> Host: <host>, Path: <path>", "Server response:
 * HTTP/1.1 101 Switching Protocols", then the protocol client's
 * "Verifying ..." / "handshake & transport ready!" lines. The DNS
 * set + VPN CONNECTED lines are logged by the service after the
 * probe (see TaptapVpnService). This only aligns the VISIBLE order:
 * the 2026-11-21 08:08 phone evidence (TaptapNG connected iflix
 * 390 ms right after XVEON connected it) shows the decider is the
 * operator window / timing, not the log order — no connectivity
 * improvement is claimed for this change.
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
     * Proxy socket buffers (v1.0.19). Phone evidence (v1.0.18 log,
     * Speedtest 16:01): the relay spent 93-95% of its time WAITING
     * for data (tls+net=15170ms of 16,0 s, 0,50 MB/s per connection)
     * while every app-side stage was tiny — throughput per
     * connection ≈ TCP window / RTT, and the socket was never tuned
     * (plain Socket() defaults). xray-core sets large buffers and
     * reaches 133 Mbps over the same proxy/path, so the window is
     * the prime suspect — the phone test decides.
     *
     * Linux doubles SO_RCVBUF/SO_SNDBUF on read-back and clamps
     * them to net.core.rmem_max/wmem_max, so the effective values
     * can be smaller than requested (the SOCKET log line after
     * connect shows what the kernel actually granted).
     */
    const val SOCKET_RECV_BUFFER_SIZE = 1024 * 1024
    const val SOCKET_SEND_BUFFER_SIZE = 256 * 1024

    /**
     * Raise the proxy socket buffers BEFORE connect() so the kernel
     * uses them for the initial TCP window. A refused setting must
     * never kill the dial — it only falls back to the defaults.
     * The sizes are parameters (defaulting to the production
     * values) so tests can use values below the kernel's
     * rmem_max/wmem_max clamp and assert on them.
     */
    internal fun tuneSocketBuffers(
        socket: Socket,
        recvSize: Int = SOCKET_RECV_BUFFER_SIZE,
        sendSize: Int = SOCKET_SEND_BUFFER_SIZE,
    ) {
        runCatching {
            socket.receiveBufferSize = recvSize
            socket.sendBufferSize = sendSize
            socket.tcpNoDelay = true
        }.onFailure {
            DialLog.log(
                "SOCKET",
                "setel buffer gagal (${it.javaClass.simpleName}) — lanjut default",
            )
        }
    }

    /**
     * Hook set by [com.taptap.ng.service.TaptapVpnService] so dial
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

    /** Arm the watchdog with a non-socket resource (M3: a DNSTT stream). */
    fun armWatchdogCloseable(c: java.io.Closeable?) {
        threadWatchdog.get()?.armCloseable(c)
    }

    /** The dial succeeded: the watchdog must not touch this stream again. */
    fun clearWatchdogCloseable() {
        threadWatchdog.get()?.clearCloseable()
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
    fun open(
        item: ProfileItem,
        stats: SpeedStats? = null,
        /**
         * v1.0.30: TLS protocol names to offer (SSH `sshSniVersion`
         * forcing). Null = negotiate (the default for every other
         * protocol).
         */
        tlsProtocols: Array<String>? = null,
    ): OpenStream {
        require(item.address.isNotBlank()) { "Address proxy kosong" }
        require(item.port in 1..65535) { "Port proxy di luar 1..65535: ${item.port}" }
        val wd = threadWatchdog.get()
        // v1.0.2 (XVEON order): every dial opens with the outbound
        // line — "Connecting to VMess outbound front.wetv.vip:443..."
        // — the same first dial line XVEON logs.
        DialLog.log(
            "DIAL",
            "Connecting to ${item.typeLabel()} outbound ${item.address}:${item.port}...",
        )
        val plain = Socket()
        try {
            // Arm the watchdog on the plain socket FIRST: a connect
            // that blocks past the watchdog is killed the same way
            // as a stuck read (see DialWatchdog).
            wd?.arm(plain)
            // v1.0.19: raise the buffers BEFORE connect() so the
            // kernel uses them for the initial TCP window.
            tuneSocketBuffers(plain)
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
            // Tahap TCP (v1.0.2, XVEON order): "Connecting TCP socket
            // to <host>:<port>" — the resolve happens INSIDE this
            // step, exactly like XVEON (which never logs a separate
            // DNS line before TCP). The resolve itself still tags
            // its failures "DNS gagal" (see DnsResolver) and the
            // watchdog stage is "DNS" while it runs; only the
            // SUCCESS line "DNS <host> -> <ip>" is gone. JANGAN
            // resolve lewat InetSocketAddress(host, port):
            // konstruktor itu memanggil resolver sistem TANPA timeout —
            // saat VPN naik lookup-nya masuk ke TUN dan menggantung
            // sampai resolver menyerah (gejala v1.0.4: status macet di
            // "Connecting..." selamanya). Di sini address sudah IP
            // hasil resolve, jadi connect() tidak lookup lagi.
            noteStage("TCP")
            DialLog.log("TCP", "Connecting TCP socket to ${item.address}:${item.port}")
            noteStage("DNS")
            val target = DnsResolver.resolveWithSystemFallback(item.address, item.port)
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
            // v1.0.19: log the EFFECTIVE values the kernel granted
            // (Linux doubles and clamps to rmem_max/wmem_max — the
            // phone log shows whether the 1 MB request survived).
            runCatching {
                DialLog.log(
                    "SOCKET",
                    "rcv=${plain.receiveBufferSize} snd=${plain.sendBufferSize}",
                )
            }
            // No "TCP <host>:<port> ok" line (v1.0.2): XVEON has
            // none — the next stage's line proves TCP succeeded.
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
                // v1.0.23 (M4): entry Onering TIDAK lewat SSLSocket —
                // platform TLS tidak bisa membawa ekstensi kustom
                // 0xff00, dan patch byte ClientHello merusak transcript
                // hash — jadi Onering naik Bouncy Castle (OneringTls),
                // yang membangun ClientHello sendiri dengan 0xff00
                // paling depan. Socket di OpenStream tetap `plain`
                // (sudah di-arm watchdog): protokol BC membaca dari
                // stream-nya, jadi menutup plain tetap membangunkan
                // read yang macet.
                // v1.0.2 (XVEON order): the handshake line names the
                // SNI BEFORE the handshake runs; the "TLS established:
                // <version>" line is logged by the TLS implementation
                // itself (TlsUtil / OneringTls) right after the
                // handshake — the old "TLS <host> ok" line is gone.
                noteStage("TLS")
                val sni = item.sni.ifBlank { item.address }
                if (AddrCodec.isIpLiteral(sni)) {
                    DialLog.log("TLS", "TLS handshake")
                } else {
                    DialLog.log("TLS", "TLS handshake -> SNI: $sni")
                }
                try {
                    if (OneringTls.isOnering(item)) {
                        val (tlsIn, tlsOut) = OneringTls.wrap(input, output, item)
                        input = tlsIn
                        output = tlsOut
                    } else {
                        socket = TlsUtil.wrap(plain, item, tlsProtocols)
                        // Re-arm the watchdog on the TLS socket: closing the
                        // plain socket would not unblock the TLS read.
                        wd?.arm(socket)
                        input = socket.getInputStream()
                        output = socket.getOutputStream()
                    }
                } catch (e: SSLException) {
                    throw SSLException("TLS gagal: ${e.message}")
                } catch (e: Exception) {
                    throw IOException("TLS gagal: ${e.message}", e)
                }
            }
            // v1.0.16: time every read from the transport stream
            // (TLS unwrap + socket wait — inseparable on the
            // SSLSocket path, so one honest "tls+net" bucket) BEFORE
            // the WS layer reads from it. No WS: the body stream
            // reads from this wrapper directly. stats == null: no
            // wrapper, no overhead — byte-identical to v1.0.15.
            val timedIn = if (stats != null) TimedInputStream(input, stats) else input
            if (network == "ws") {
                // Tahap WS (v1.0.2, XVEON order): the handshake line
                // names Host + Path BEFORE the request goes out; the
                // "Server response: HTTP/1.1 101 ..." line is logged
                // by WsTransport.connect itself once the 101 arrives
                // — the old "WS <host><path> ok" line is gone.
                noteStage("WS")
                try {
                    DialLog.log(
                        "WS",
                        "WebSocket (WS) handshake -> Host: ${wsHost(item)}, Path: ${wsPath(item)}",
                    )
                    val ws = WsTransport.connect(timedIn, output, wsHost(item), wsPath(item), stats)
                    input = ws.input
                    output = ws.output
                } catch (e: Exception) {
                    throw IOException("WS gagal: ${e.message}", e)
                }
            } else {
                input = timedIn
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
