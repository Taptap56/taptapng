package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.TunnelState
import com.taptap.ng.data.ConfigType
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
 * Shared transport ladder for VMess/VLESS/Trojan (M2): TCP → TLS → WS
 * (or HTTPUpgrade, v1.0.13 — same upgrade request, raw stream after
 * the 101, no WS framing).
 *
 * Order matters and matches v2rayNG: plain TCP first, TLS wraps the TCP
 * socket when item.tls is set, then the WebSocket handshake runs over
 * whatever stream is underneath (plain TCP or TLS).
 *
 * v1.0.2 (XVEON order): the DialLog lines follow the XVEON Tunnel Pro
 * connect log, in the same order — "Connecting to Xray outbound
 * <host>:<port>", "Connecting TCP socket to <host>:<port>" (the DNS
 * resolve happens INSIDE this step — there is no separate DNS line
 * before TCP; the 120 s DnsResolver cache is unchanged), "TLS
 * handshake -> SNI: <sni>", "TLS established: TLSv1.3", "WebSocket
 * (WS) handshake -> Host: <host>, Path: <path>", "Server response:
 * HTTP/1.1 101 Switching Protocols", then the protocol client's
 * "Verifying ..." / "handshake & transport ready!" lines. The DNS
 * set + VPN CONNECTED lines are logged by the service after the
 * probe (see TaptapVpnService). v1.0.3: no "[STAGE]" tag prefix on
 * any line (see DialLog), no "PROTECT TUN belum naik" line and no
 * "SOCKET rcv=... snd=..." line — XVEON logs neither; the protect
 * behavior and the buffer tuning themselves are unchanged. This
 * only aligns the VISIBLE order: the 2026-11-21 08:08 phone
 * evidence (TaptapNG connected iflix 390 ms right after XVEON
 * connected it) shows the decider is the operator window / timing,
 * not the log order — no connectivity improvement is claimed for
 * this change.
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
     * can be smaller than requested (v1.0.3 removed the SOCKET
     * log line that used to show them — XVEON logs no such line;
     * TransportSocketBufferTest asserts the values on the socket
     * itself instead).
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
            // v1.0.4 (review Claude): XVEON menyalakan keepAlive
            // pada socket dial-nya; TaptapNG tidak. keepAlive menjaga
            // koneksi panjang (relay) tetap hidup di tengah NAT yang
            // agresif menutup socket idle.
            socket.keepAlive = true
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
     * v1.0.6 (M6): same hook for UDP sockets (Shadowsocks UDP
     * relay + any future UDP dial). Set by TaptapVpnService to
     * VpnService.protect(DatagramSocket) alongside
     * [protectSocket]; null = no protection (unit tests). A
     * refused protect is fatal only while [TunnelState.up] and
     * without [TunnelState.appBypass] — the same rule as TCP
     * (see [protectSocket]).
     */
    @Volatile
    var protectUdpSocket: ((java.net.DatagramSocket) -> Boolean)? = null

    /**
     * v1.0.5 (Fragment): provides the live Fragment settings for
     * the next dial, or null when fragmenting is off. Set by
     * [com.taptap.ng.TaptapNGApp] from SettingsStore (read fresh
     * on every dial, so a settings change applies without a
     * restart); null = the v1.0.4 TLS path, byte-identical.
     * Tests set this directly.
     */
    @Volatile
    var fragmentConfigProvider: (() -> FragmentConfig?)? = null

    /** The fragment config for this dial, or null when OFF. */
    internal fun resolveFragmentConfig(): FragmentConfig? = fragmentConfigProvider?.invoke()

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

    /**
     * v1.0.10 (XVEON proxy): the protocols the HTTP CONNECT proxy
     * + Xray payload apply to. SSH has its own payload +
     * remote-proxy chain (SshPayload / SshProxyClient) and
     * Shadowsocks is out of scope — both still call
     * [Transport.open], so the gate lives here, not in the
     * callers. SlowDNS entries reach this ladder too
     * (SlowDnsTransport delegates when dnsttEnabled is off); a
     * SlowDNS entry with proxy on is NOT proxied — its DNSTT
     * branch bypasses this ladder entirely (see README-v1.0.10).
     */
    internal val PROXY_TYPES = setOf(ConfigType.VMESS, ConfigType.VLESS, ConfigType.TROJAN)

    internal fun isProxyCapable(item: ProfileItem): Boolean = item.configType in PROXY_TYPES

    /**
     * The [XrayPayload.Ctx] for this dial, or null when the
     * payload chip is off. One Sec-WebSocket-Key per dial, shared
     * by the proxy payload and the WS handshake. `[ip]` resolves
     * the server best-effort (cached, operator-first — the same
     * announce shape as the v1.0.4 main dial); a failed lookup
     * falls back to the hostname instead of killing the dial.
     * [proxyHost] is the proxy host used this dial (after
     * [rotate] expansion) — it fills the `[proxy_host]`
     * placeholder (v1.0.11).
     */
    internal fun payloadCtx(item: ProfileItem, proxyHost: String? = null): XrayPayload.Ctx? {
        if (!item.xrayUsePayload || !isProxyCapable(item)) return null
        val ip = runCatching {
            DnsResolver.resolveWithSystemFallback(item.address, item.port).hostAddress
        }.getOrNull() ?: item.address
        return XrayPayload.Ctx(
            wsHost = wsHost(item),
            path = wsPath(item),
            sni = item.sni.ifBlank { item.address },
            host = item.address,
            ip = ip,
            port = item.port,
            wsKey = XrayPayload.newWsKey(),
            proxyHost = proxyHost ?: "",
        )
    }

    /**
     * v1.0.4: apakah kegagalan TLS ini berarti "IP ini menggantung
     * di TLS" sehingga dial berikutnya harus merotasi ke alamat
     * berikutnya di cache? Ya hanya bila benar-benar timeout — read
     * timed out, atau watchdog meledak saat dial stuck di TLS
     * (watchdog menutup socket, jadi handshake melempar
     * SocketException, bukan timeout). Kegagalan TLS lain
     * (sertifikat, protokol) bukan soal IP dan tidak merotasi.
     */
    internal fun shouldRotateAfterTlsFailure(e: Exception): Boolean =
        e is SocketTimeoutException || watchdogFailure() != null

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
        // v1.0.10 (XVEON proxy): the TCP target is the proxy, not
        // the server — the server is named only in the CONNECT
        // request that follows. A proxy chip with an empty host is
        // a config error: fail fast with a clear stage instead of
        // silently dialling direct (the editor already refuses to
        // save it, but an imported entry can still carry it).
        val useProxy = item.proxyEnabled && isProxyCapable(item)
        if (useProxy && item.proxyHost.isBlank()) {
            throw IllegalArgumentException("Proxy gagal: host proxy kosong")
        }
        val proxyTarget = if (useProxy) {
            XrayPayload.parseProxyTarget(item.proxyHost, item.proxyPort)
        } else {
            null
        }
        // One payload template context per dial (null = chip off);
        // the WS handshake reuses it with the handshake's own key.
        // v1.0.11: the proxy host (after [rotate]) fills the
        // [proxy_host] placeholder in the template.
        val payloadCtx = payloadCtx(item, proxyTarget?.first)
        // v1.0.11: "Payload saja" — like the SSH payload chain:
        // payload, then straight to TLS, no CONNECT.
        val usePayloadOnly = useProxy && item.proxyMode == "payload_only"
        // v1.0.11: the TCP target (proxy, or the server when no
        // proxy) lives at open() scope — the TCP stage AND the
        // proxy stage below both log it. (CI 44901027233: the
        // proxy stage could not see the TCP try block's locals.)
        val dialHost = proxyTarget?.first ?: item.address
        val dialPort = proxyTarget?.second ?: item.port
        val wd = threadWatchdog.get()
        // v1.0.3 (XVEON parity): "Connecting to Xray outbound
        // front.wetv.vip:443..." — no protocol name in this line
        // (the protocol is in the "Initializing Xray Core (...)"
        // line the service logs before the dial).
        DialLog.log(
            "DIAL",
            "Connecting to Xray outbound ${item.address}:${item.port}...",
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
            // Probe-first dial, TUN belum naik: tidak ada VPN
            // yang perlu di-bypass, dial langsung (v1.0.7).
            // v1.0.3 (XVEON parity): no log line for this — XVEON
            // logs no PROTECT line; the direct dial itself is
            // unchanged, so the whole branch (which only logged)
            // is gone.
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
            // v1.0.10 (XVEON proxy): the TCP target is the proxy —
            // its host resolves operator-first, exactly like the
            // server resolve in v1.0.4 (the same announce that opens
            // the operator window). dialHost/dialPort are defined at
            // open() scope (above), not here.
            if (useProxy) {
                DialLog.log("PROXY", "Proxy $dialHost:$dialPort -> ${item.address}:${item.port}")
            }
            noteStage("TCP")
            DialLog.log("TCP", "Connecting TCP socket to $dialHost:$dialPort")
            noteStage("DNS")
            val target = DnsResolver.resolveWithSystemFallback(dialHost, dialPort)
            noteStage("TCP")
            try {
                plain.connect(InetSocketAddress(target, dialPort), CONNECT_TIMEOUT_MS)
            } catch (e: SocketTimeoutException) {
                throw SocketTimeoutException("TCP gagal: ${e.message}")
            } catch (e: ConnectException) {
                throw ConnectException("TCP gagal: ${e.message}")
            } catch (e: IOException) {
                throw IOException("TCP gagal: ${e.message}", e)
            }
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
            // v1.0.3 (XVEON parity): the effective buffer values
            // are NO LONGER logged ("SOCKET rcv=... snd=..." is
            // gone — XVEON logs no such line). The tuning itself
            // is unchanged; the values are still asserted by
            // TransportSocketBufferTest on the socket itself.
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
        if (network != "tcp" && network != "ws" && network != "httpupgrade") {
            runCatching { socket.close() }
            throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws/httpupgrade)")
        }
        try {
            if (useProxy) {
                noteStage("Proxy")
                if (usePayloadOnly) {
                    // v1.0.11 ("Payload saja", seperti SSH): payload
                    // dulu, lalu LANGSUNG TLS — tanpa CONNECT. The
                    // [split] timing mirrors SshPayload (first
                    // segment, one response, the rest after 101/2xx).
                    // Payload chip OFF: TCP ke bug:port lalu langsung
                    // TLS (tanpa payload, tanpa CONNECT).
                    DialLog.log(
                        "PROXY",
                        "Payload saja: $dialHost:$dialPort -> ${item.address}:${item.port} (tanpa CONNECT)",
                    )
                    if (payloadCtx != null) {
                        val expanded = XrayPayload.expand(XrayPayload.templateFor(item), payloadCtx)
                        PayloadOnlyProxy.sendPayload(input, output, expanded)
                    }
                } else {
                    // v1.0.10 (XVEON proxy): payload first, then CONNECT,
                    // then TLS wraps the same socket. The payload is
                    // fire-and-forget (no response read — XVEON's
                    // "Sending proxy custom payload..." writes and moves
                    // on); CONNECT must answer 200 or the dial dies here
                    // with a tagged stage ("Proxy CONNECT ditolak: ...").
                    if (payloadCtx != null) {
                        DialLog.log("PROXY", "Sending proxy custom payload...")
                        val expanded = XrayPayload.expand(XrayPayload.templateFor(item), payloadCtx)
                        XrayPayload.writeSegments(output, expanded)
                    }
                    HttpConnectProxy.doConnect(input, output, item.address, item.port)
                }
            }
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
                    // v1.0.5: fragment config is resolved once per
                    // dial (fresh read — see fragmentConfigProvider).
                    val fragConfig = resolveFragmentConfig()
                    if (OneringTls.isOnering(item)) {
                        val (tlsIn, tlsOut) = OneringTls.wrap(input, output, item, fragmentConfig = fragConfig)
                        input = tlsIn
                        output = tlsOut
                    } else {
                        socket = TlsUtil.wrap(plain, item, tlsProtocols, fragmentConfig = fragConfig)
                        // Re-arm the watchdog on the TLS socket: closing the
                        // plain socket would not unblock the TLS read.
                        wd?.arm(socket)
                        input = socket.getInputStream()
                        output = socket.getOutputStream()
                    }
                } catch (e: SSLException) {
                    // v1.0.4: rotasi alamat setelah TLS timeout (lihat
                    // shouldRotateAfterTlsFailure).
                    if (shouldRotateAfterTlsFailure(e)) {
                        DnsResolver.rotateAfterTlsFailure(item.address)
                    }
                    throw SSLException("TLS gagal: ${e.message}")
                } catch (e: Exception) {
                    // v1.0.4: TLS timeout di satu IP — dial berikutnya
                    // memakai alamat berikutnya di cache, bukan IP
                    // yang baru saja menggantung (log 09:35: dial
                    // utama memakai IP yang sama persis dengan yang
                    // baru gagal di prime).
                    if (shouldRotateAfterTlsFailure(e)) {
                        DnsResolver.rotateAfterTlsFailure(item.address)
                    }
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
                    // v1.0.10 (XVEON payload): the handshake request
                    // is the entry's expanded payload template
                    // (default = the standard WS upgrade) with this
                    // dial's key — WsTransport injects the
                    // Sec-WebSocket-Key headers when the template
                    // asks for an upgrade but carries no key, so the
                    // Accept check below still works.
                    // v1.0.11: NOT in "Payload saja" mode — there the
                    // template is the SSH-style proxy payload (GET
                    // bug + PATCH + [split]), not a WS handshake,
                    // so the handshake after TLS is the standard one.
                    val ws = if (payloadCtx != null && !usePayloadOnly) {
                        WsTransport.connect(
                            timedIn, output, wsHost(item), wsPath(item), stats,
                            wsKey = payloadCtx.wsKey,
                            customHandshake = { key ->
                                XrayPayload.expand(
                                    XrayPayload.templateFor(item),
                                    payloadCtx.copy(wsKey = key),
                                )
                            },
                        )
                    } else {
                        WsTransport.connect(timedIn, output, wsHost(item), wsPath(item), stats)
                    }
                    input = ws.input
                    output = ws.output
                } catch (e: Exception) {
                    throw IOException("WS gagal: ${e.message}", e)
                }
            } else if (network == "httpupgrade") {
                // Tahap HTTPUpgrade (v1.0.13, Xray HTTPUpgrade): the
                // request is the standard WS-style upgrade (same
                // bytes as WsTransport), but after the 101 the stream
                // stays RAW — no WS framing — and the protocol runs
                // directly on it. The payload template is NOT used
                // as the handshake here (unlike WS): it is either
                // the WS upgrade template or the SSH-style proxy
                // payload, neither of which is an httpupgrade
                // request — the proxy-layer payload (sent to the
                // proxy at the TCP stage above) still applies.
                noteStage("HTTPUpgrade")
                try {
                    DialLog.log(
                        "HTTPUpgrade",
                        "HTTPUpgrade handshake -> Host: ${wsHost(item)}, Path: ${wsPath(item)}",
                    )
                    HttpUpgradeTransport.connect(timedIn, output, wsHost(item), wsPath(item))
                    input = timedIn
                    // output stays the raw output (no framing).
                } catch (e: Exception) {
                    throw IOException("HTTPUpgrade gagal: ${e.message}", e)
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
