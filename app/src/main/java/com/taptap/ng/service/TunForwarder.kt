package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsExchange
import com.taptap.ng.core.DnsRelayPolicy
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.DnsRoute
import com.taptap.ng.core.FakeDns
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.RouteOnlyGate
import com.taptap.ng.core.Sniffer
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.ProxyUdpSession
import com.taptap.ng.core.proto.SocketProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.core.proto.Transport
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * TUN packet forwarder (M2). Reads IPv4 packets from the TUN
 * interface and:
 * - TCP: a minimal TCP state machine (SYN → dial via [ProxyClient] →
 *   SYN-ACK → relay bytes both ways → FIN/RST). One relay thread per
 *   session. No retransmission (the TUN is a local reliable link);
 *   retransmitted app bytes are de-duplicated by sequence number.
 * - UDP port 53 (DNS): forwarded to [dnsServer] over a protected
 *   DatagramSocket (bypasses the VPN), response wrapped back;
 *   on a primary timeout the fallback [dnsFallbackServer] is tried.
 *   Other UDP is forwarded through the proxy ([ProxyClient.dialUdp],
 *   one session per 4-tuple).
 * - ICMP echo request: answered locally.
 * - IPv6 (v1.0.6, M6): same state machines with 128-bit session
 *   keys — TCP, UDP (incl. DNS/53 replies as UDPv6) and ICMPv6 echo.
 *
 * The proxy dial itself must bypass the VPN: the service sets
 * `Transport.protectSocket` before creating the client, and the DNS
 * socket is protected here via [protectUdp].
 *
 * v1.0.10: the forwarder LOGS its own life — v2rayNG's log flows
 * with every connection the core handles, while this forwarder was
 * silent except for dial attempts (and the v1.0.9 phone log proved
 * the silence hides the real question: did ANY packet reach the
 * TUN at all?). [start]/[stop] log, the reader counts every packet
 * and logs the first 20 in detail, and the DNS relay logs its
 * queries, answers and failures instead of dropping them silently.
 */
class TunForwarder(
    private val tunIn: InputStream,
    private val tunOut: OutputStream,
    private val proxy: ProxyClient,
    private val dnsServer: String,
    private val protectUdp: (DatagramSocket) -> Boolean,
    private val onStatus: (String) -> Unit,
    /** DNS reply wait; shortened by tests so a dead relay fails fast. */
    private val dnsTimeoutMs: Int = 5000,
    /** MTU from Settings (v2rayNG default 1500) — the SYN-ACK MSS
     * is derived from it (v1.0.13, fix A6). */
    private val tunMtu: Int = 1500,
    /**
     * SPEED window (v1.0.16): while a session transfers, a SPEED
     * line is logged every [speedWindowMs] ms. Tests shorten it so
     * a window line appears without a 5 s transfer.
     */
    private val speedWindowMs: Long = 5000,
    /** DNS fallback (v1.0.4): tried when the primary times out. */
    private val dnsFallbackServer: String = "1.0.0.1",
    /** Upstream DNS port (53). Tests point it at local servers. */
    private val dnsPort: Int = 53,
    /**
     * Kebijakan relay DNS (v1.0.5, kelompok C): dnsHosts, split
     * domestik/remote, DoH, local DNS, FakeDNS + transport yang
     * bisa di-inject tes. Default = perilaku relay v1.0.4 (UDP
     * primer → fallback). Bukan logika paket TCP — hanya DNS.
     */
    private val dnsPolicy: DnsRelayPolicy = DnsRelayPolicy.DEFAULT,
    /**
     * Sniffing (v1.0.5, kelompok F): parse SNI / HTTP Host dari
     * data pertama tiap sesi dan catat ke [knownHosts]. Default
     * true (sama dengan default setting sniffingEnabled).
     */
    private val sniffingEnabled: Boolean = true,
    /**
     * Route-only (v1.0.5, kelompok F): bila true, dial TCP hanya
     * untuk tujuan yang ada di [knownHosts] (lihat
     * [RouteOnlyGate] untuk semantik lengkap); sisanya di-RST.
     * Default false (perilaku v1.0.4).
     */
    private val routeOnlyEnabled: Boolean = false,
    /**
     * Tujuan yang dikenal: IP tujuan (int big-endian) → hostname
     * (dari jawaban DNS in-tunnel atau sniffing). Diisi forwarder
     * sendiri; tes boleh menyuntikkan isinya lewat parameter ini.
     */
    private val knownHosts: MutableMap<Int, String> = ConcurrentHashMap(),
    /**
     * v1.0.15: tujuan IPv6 yang dikenal — string IPv6 →
     * hostname (dari jawaban AAAA / sniffing). Dulu field privat
     * di badan kelas; kini parameter seperti [knownHosts] supaya
     * tes bisa menyuntikkan isinya dan gate IPv6 bisa diuji.
     * Kunci = [TcpPacket.IpAddr.toString] (bentuk Java).
     */
    private val knownHosts6: MutableMap<String, String> = ConcurrentHashMap(),
    /**
     * M7: routing per koneksi — null = perilaku lama (semua dial
     * lewat [proxy] yang tunggal). Bila diisi, tiap koneksi TCP
     * baru (dan tiap sesi UDP baru) diputuskan lewat resolver ini
     * (service memasang [com.taptap.ng.core.RouteEngine.resolve]
     * dengan grup + aturan + delay cache yang hidup); lihat
     * [dial] / [handleProxyUdp].
     */
    private val routeResolver: ((host: String?, ip: InetAddress, port: Int) -> RouteDecision)? = null,
    /**
     * M7: guid anggota grup -> [ProxyClient]-nya (cache per guid
     * di service; factory membuat client baru bila belum ada).
     * Null = keputusan Proxy selalu memakai [proxy]. Bila guid
     * tidak dikenal (terhapus sesudah aturan ditulis), dial
     * jatuh kembali ke [proxy] — fail-open ke entry terpilih.
     */
    private val clientProvider: ((guid: String) -> ProxyClient?)? = null,
    /**
     * M7: dial direct untuk keputusan [RouteDecision.Direct].
     * Null = [defaultDirectDial] (socket TCP ter-protect ke
     * target). Di-inject tes supaya jalur Direct bisa diuji tanpa
     * socket nyata.
     */
    private val directDial: ((host: String, port: Int, stats: SpeedStats?) -> ProxyStream)? = null,
) {

    private enum class State { DIALING, SYN_SENT, ESTABLISHED, CLOSED }

    /**
     * v1.0.6 (M6): kunci sesi memakai [TcpPacket.IpAddr] (4 byte
     * IPv4 atau 16 byte IPv6) — sesi IPv6 berkunci 128-bit.
     */
    private data class Key(val srcIp: TcpPacket.IpAddr, val srcPort: Int, val dstIp: TcpPacket.IpAddr, val dstPort: Int)

    /**
     * v1.0.6 (M6): satu sesi UDP lewat proxy — satu [ProxyUdpSession]
     * per 4-tuple, seperti sesi TCP. Balasan dibaca thread khusus
     * ([replyThread]) dan ditulis balik ke TUN sebagai paket UDP.
     * DNS (port 53) TIDAK lewat sini — tetap relay langsung
     * (lihat [handleUdp]).
     */
    private data class UdpKey(val srcIp: TcpPacket.IpAddr, val srcPort: Int, val dstIp: TcpPacket.IpAddr, val dstPort: Int)

    private class UdpSession(val key: UdpKey, val udp: com.taptap.ng.core.proto.ProxyUdpSession) {
        @Volatile var lastActivityMs: Long = System.currentTimeMillis()
        val closed = AtomicBoolean(false)
        @Volatile var replyThread: Thread? = null
    }

    private class TcpSession(val key: Key, val isn: Long) {
        @Volatile var state: State = State.DIALING
        @Volatile var clientSeq: Long = 0 // next byte expected from the app
        @Volatile var serverSeq: Long = isn // next byte we will send
        @Volatile var stream: ProxyStream? = null
        val closed = AtomicBoolean(false)
        /**
         * App data waiting to be written to the proxy (v1.0.13,
         * fix A1): XVEON queues payloads per connection (g7.IO)
         * and drains them on a dedicated writer thread (Ll4); the
         * old code wrote synchronously on the single TUN reader
         * thread, so one slow write stalled packet processing for
         * every connection, and data arriving while DIALING was
         * dropped. Bounded at 48 chunks (XVEON), drop-oldest.
         */
        val outQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(MAX_QUEUE_CHUNKS)
        /**
         * Out-of-order segments, keyed by seq (v1.0.13, fix A2):
         * XVEON buffers up to 32 and replays them when the gap
         * fills; the old code dropped them and relied on a
         * retransmit, which slowed the first page load.
         */
        val outOfOrder = java.util.TreeMap<Long, ByteArray>()
        /** Last packet/dial activity, for session eviction (A4). */
        @Volatile var lastActivityMs: Long = System.currentTimeMillis()
        /** The writer thread was started (single-shot). */
        val writerStarted = AtomicBoolean(false)
        /**
         * What the app's SYN offered (v1.0.10): the peer MSS caps
         * our segments, and SACK / window-scale offers are echoed
         * in the SYN-ACK like xray-core's tun stack does.
         */
        @Volatile var peerMss: Int = TcpPacket.TCP_MSS
        @Volatile var wsOffered: Boolean = false
        @Volatile var sackOffered: Boolean = false
        /** v1.0.5 (kelompok F): sniffing — host sudah ketemu? */
        @Volatile var sniffed: Boolean = false
        /** v1.0.5: berapa chunk data sudah dicoba di-sniff (max 3). */
        @Volatile var sniffAttempts: Int = 0
        /**
         * v1.0.16: per-session speed stats (created in dial(), one
         * object per connection, shared by the transport ladder,
         * the body streams, the relay thread and the writer
         * thread). Null while DIALING (no stream yet).
         */
        @Volatile var speedStats: SpeedStats? = null
        /** v1.0.16: when the stats clock started (dial ok). */
        @Volatile var speedStartMs: Long = 0L
        /** v1.0.16: the TUTUP summary was logged (single-shot). */
        val speedLogged = AtomicBoolean(false)
    }

    private val sessions = ConcurrentHashMap<Key, TcpSession>()
    /**
     * v1.0.6 (M6): sesi UDP lewat proxy (kunci 4-tuple IPv4).
     * Terpisah dari [sessions] (TCP) — eviksi + lifecycle sendiri.
     */
    private val udpSessions = ConcurrentHashMap<UdpKey, UdpSession>()
    /** Thread penyapu sesi UDP idle (lihat [UDP_IDLE_MS]). */
    private var udpSweeperThread: Thread? = null
    /**
     * v1.0.18: the TUN write moved to a single writer thread
     * (TunWriter) — the old synchronized(writeLock) + blocking
     * write() per segment stalled every relay thread whenever one
     * write blocked on a full TUN queue (phone log 2026-11-20:
     * tun=6046ms of an 8 s Speedtest connection). All writePacket
     * calls now only enqueue; the writer owns the fd.
     */
    private val tunWriter = TunWriter(tunOut)
    private val random = SecureRandom()
    private val running = AtomicBoolean(false)
    private var readerThread: Thread? = null
    @Volatile private var firstDialReported = false
    // First dial failure is reported immediately; later ones at most
    // once per 10 s, so a closed window does not spam the status.
    @Volatile private var firstFailureReported = false
    @Volatile private var lastFailureReportMs = 0L
    /** Packets read from the TUN since start (v1.0.10). */
    private val packetsRead = java.util.concurrent.atomic.AtomicLong(0)
    /** How many packets got a detail line (cap: first 20). */
    private val loggedPackets = java.util.concurrent.atomic.AtomicInteger(0)
    /** DNS queries seen / detail-logged / failed (v1.0.10). */
    private val dnsQueries = java.util.concurrent.atomic.AtomicLong(0)
    private val dnsLogged = java.util.concurrent.atomic.AtomicInteger(0)
    private val dnsFailures = java.util.concurrent.atomic.AtomicLong(0)

    /**
     * Bounded DNS relay pool (v1.0.4, review Claude): one thread
     * per query with no cap let a DNS flood exhaust threads. 2
     * core / 16 max / 60 s keepalive / queue 128; a query that
     * cannot be queued is counted as a failure and logged instead
     * of spawning a thread. Shut down in [stop] (each VPN start
     * builds a new forwarder, so a leaked pool would accumulate).
     */
    internal val dnsExecutor: ThreadPoolExecutor = ThreadPoolExecutor(
        2, 16, 60L, TimeUnit.SECONDS,
        LinkedBlockingQueue(128),
        ThreadFactory { r -> Thread(r, "tun-dns").apply { isDaemon = true } },
    ).apply {
        setRejectedExecutionHandler { _, _ ->
            dnsFailures.incrementAndGet()
            DialLog.log("DNS", "antrean DNS penuh — query dibuang")
        }
    }

    companion object {
        /** Max concurrent TCP sessions (v1.0.13, fix A4): XVEON caps
         * at 96 and evicts the oldest by last activity — the old
         * map was unbounded, so a SYN flood grew it forever. */
        const val MAX_SESSIONS = 96

        /** Stable id for one connection (Clash API /connections, M7 W3). */
        fun connectionId(
            network: String,
            srcIp: TcpPacket.IpAddr,
            srcPort: Int,
            dstIp: TcpPacket.IpAddr,
            dstPort: Int,
        ): String = "$network:$srcIp:$srcPort>$dstIp:$dstPort"

        /**
         * v1.0.6 (M6): max sesi UDP lewat proxy (XVEON memakai
         * batas yang sama dengan TCP; UDP tanpa balasan tidak boleh
         * menumbuhkan map tanpa batas).
         */
        const val MAX_UDP_SESSIONS = 64

        /**
         * v1.0.6 (M6): sesi UDP yang tidak ada paketnya selama ini
         * ditutup penyapu (datagram tanpa balasan — mis. QUIC yang
         * pindah koneksi — tidak boleh menahan sesi selamanya).
         * 120 dtk: jauh di atas interval keepalive QUIC (~25 dtk)
         * tapi cukup pendek untuk tidak menumpuk.
         */
        const val UDP_IDLE_MS = 120_000L

        /** Interval penyapu sesi UDP idle. */
        const val UDP_SWEEP_MS = 30_000L

        /**
         * M7: timeout connect untuk dial direct ([defaultDirectDial]).
         * Sama seperti timeout TCP test (10 s di ServerTester).
         */
        const val DIRECT_DIAL_TIMEOUT_MS = 10_000

        /** Max queued app-data chunks per connection (XVEON: 48). */
        const val MAX_QUEUE_CHUNKS = 48

        /** Max buffered out-of-order segments per connection (XVEON: 32). */
        const val MAX_OUT_OF_ORDER = 32

        /** Max chunks the writer drains per flush (XVEON's Ll4: 8). */
        const val MAX_WRITER_DRAIN = 8

        /**
         * Session writer poll timeout (v1.0.25, battery): the
         * writer wakes at most 1×/s per idle session (was 10×/s
         * at 100 ms — the #1 idle battery drain in the 2026-11-21
         * audit: 10–20 idle sessions × 10 wakeups/s, 24 h while
         * the VPN is up). poll() returns at once when data
         * arrives, so this adds NO upload latency — the timeout
         * only bounds how fast a closed session is noticed (≤ 1 s).
         */
        const val WRITER_POLL_MS = 30_000L

        /**
         * v1.0.16 (battery): sentinel yang membangunkan writer sesi
         * saat sesi ditutup. Dengan ini writer idle cukup bangun
         * 1×/30 dtk (bukan 1×/dtk per sesi) tanpa menunda deteksi
         * penutupan — close/sendFin memasukkan sentinel ke antrean.
         */
        private val WRITER_WAKE = ByteArray(0)

        /**
         * Relay read buffer (v1.0.15): one read() from the proxy
         * stream pulls up to 32 KiB (several VMess chunks / many
         * TCP segments) instead of one peer-MSS read per segment —
         * the old loop did one stream read + one buildTcp + one
         * TUN write per 1360-byte segment. Segments are still
         * emitted one by one (a TUN write is one IP packet), but
         * the read calls and the buildTcp/copyOf per segment are
         * gone; a short tail segment at a chunk boundary is
         * correct (the app reassembles by sequence number).
         */
        const val RELAY_READ_SIZE = 32 * 1024

        /**
         * Absolute max MSS (v1.0.21): MTU 9000 − 40 (IP + TCP
         * headers). The TUN MTU default is 9000 (v1.0.21; sing-box
         * TUN uses 9000 too) and the Settings range already allows
         * 576..9000, so this is the largest MSS the forwarder can
         * ever offer or build.
         */
        const val MAX_SEGMENT_MSS = 8960

        /**
         * Max MSS for a TUN MTU (v1.0.21): MTU − 40, floor 1140
         * (as before), ceiling [MAX_SEGMENT_MSS]. The old ceiling
         * was 1460 — with a 1500 MTU that was the whole story, but
         * a 9000 MTU lets the app offer (and the relay build)
         * 8960-byte segments: one TUN write then carries ~6x the
         * bytes, so the writer's ~5000 writes/s ceiling (phone
         * log 2026-11-20, histogram v1.0.20: ~140 us per write of
         * kernel delivery cost) stops capping throughput at
         * ~55 Mbps.
         */
        fun maxMssForMtu(tunMtu: Int, isV6: Boolean = false): Int =
            (tunMtu - if (isV6) 60 else 40).coerceIn(1140, MAX_SEGMENT_MSS)

        /**
         * Max wire bytes of one relay TCP segment at the biggest
         * MSS (v1.0.21): IP + TCP headers + [MAX_SEGMENT_MSS].
         * The relay's reusable packet buffer is sized by this, not
         * by the old 1500-byte [TcpPacket.MAX_TCP_SEGMENT_BYTES].
         */
        const val MAX_PACKET_BYTES = 40 + MAX_SEGMENT_MSS

        /**
         * v1.0.6 (M6): same, for IPv6 — the IPv6 header is 40
         * bytes, so a max-MSS segment needs 60 + [MAX_SEGMENT_MSS].
         */
        const val MAX_PACKET_BYTES_V6 = 60 + MAX_SEGMENT_MSS

        /**
         * SYN-ACK MSS from the MTU (v1.0.15, ceiling raised
         * v1.0.21): [maxMssForMtu], capped at the peer's MSS.
         * XVEON used clamp(tunMtu − 140, 1140, 1360) — the extra
         * 100 bytes guarded the OUTER tunnel overhead, which does
         * not apply to the local TUN link (the IP packet is
         * 20 + 20 + MSS ≤ tunMtu either way).
         */
        fun synAckMss(tunMtu: Int, peerMss: Int, isV6: Boolean = false): Int =
            minOf(peerMss, maxMssForMtu(tunMtu, isV6))

        /**
         * Short human-readable reason for a dial failure, for the
         * status bar. Timeouts (the closed-window case) get a plain
         * "timeout" instead of a long exception message.
         * v1.0.5: when Transport/VmessClient tagged the stage in the
         * message ("TCP gagal: ..."), the tag is shown instead — it
         * says WHERE the dial died. A raw timeout without our tag
         * keeps the plain word.
         */
        private val STAGE_TAGS = listOf(
            "DNS gagal", "TCP gagal", "TLS gagal", "WS gagal", "VMess gagal",
            "VLESS gagal", "Trojan gagal", "SS gagal", "SSH gagal",
        )

        fun dialFailureReason(e: Exception): String = when (e) {
            is java.net.SocketTimeoutException -> {
                val msg = e.message?.take(40)?.ifBlank { null }
                if (msg != null && STAGE_TAGS.any { msg.startsWith(it) }) msg else "timeout"
            }
            is javax.net.ssl.SSLException -> "TLS gagal"
            is java.net.ConnectException -> "TCP gagal"
            else -> e.message?.take(40)?.ifBlank { null } ?: "gagal"
        }
    }

    /** Sessions currently tracked (tests). */
    fun sessionCount(): Int = sessions.size

    /** UDP sessions currently tracked (tests, v1.0.6). */
    fun udpSessionCount(): Int = udpSessions.size

    // ---- Clash API (M7, W3): live traffic + connection snapshot ----

    /**
     * Bytes of sessions that already closed (accumulated once per
     * session in [logSpeedSummary]); live sessions add their
     * current counters in [trafficTotals].
     */
    private val closedUpBytes = java.util.concurrent.atomic.AtomicLong(0)
    private val closedDownBytes = java.util.concurrent.atomic.AtomicLong(0)

    /**
     * Total bytes through the tunnel since start: closed sessions
     * + live sessions' current counters. (0, 0) when nothing has
     * flowed yet — the Clash API reports it as /traffic.
     */
    fun trafficTotals(): Pair<Long, Long> {
        var up = closedUpBytes.get()
        var down = closedDownBytes.get()
        for (s in sessions.values) {
            val snap = s.speedStats?.snapshot() ?: continue
            up += snap.upBytes
            down += snap.downBytes
        }
        return up to down
    }

    /** One live connection, in the shape the Clash API returns. */
    fun activeConnections(): List<ConnectionInfo> {
        val out = ArrayList<ConnectionInfo>()
        for (s in sessions.values) {
            if (s.closed.get()) continue
            val snap = s.speedStats?.snapshot()
            val host = hostFor(s.key.dstIp)
            out += ConnectionInfo(
                id = connectionId("tcp", s.key.srcIp, s.key.srcPort, s.key.dstIp, s.key.dstPort),
                network = "tcp",
                host = host,
                destinationIp = s.key.dstIp.toString(),
                destinationPort = s.key.dstPort,
                sourceIp = s.key.srcIp.toString(),
                sourcePort = s.key.srcPort,
                upload = snap?.upBytes ?: 0L,
                download = snap?.downBytes ?: 0L,
                startMs = s.speedStartMs.takeIf { it > 0 } ?: s.lastActivityMs,
            )
        }
        for (s in udpSessions.values) {
            if (s.closed.get()) continue
            out += ConnectionInfo(
                id = connectionId("udp", s.key.srcIp, s.key.srcPort, s.key.dstIp, s.key.dstPort),
                network = "udp",
                host = hostFor(s.key.dstIp),
                destinationIp = s.key.dstIp.toString(),
                destinationPort = s.key.dstPort,
                sourceIp = s.key.srcIp.toString(),
                sourcePort = s.key.srcPort,
                upload = 0L,
                download = 0L,
                startMs = s.lastActivityMs,
            )
        }
        return out
    }

    /** Close one live connection by [ConnectionInfo.id]; false when unknown. */
    fun closeConnection(id: String): Boolean {
        for (s in sessions.values) {
            if (connectionId("tcp", s.key.srcIp, s.key.srcPort, s.key.dstIp, s.key.dstPort) == id) {
                closeSession(s)
                return true
            }
        }
        for (s in udpSessions.values) {
            if (connectionId("udp", s.key.srcIp, s.key.srcPort, s.key.dstIp, s.key.dstPort) == id) {
                closeUdpSession(s)
                return true
            }
        }
        return false
    }

    private fun hostFor(dstIp: TcpPacket.IpAddr): String? =
        if (dstIp.isV4) knownHosts[dstIp.toInt()]
        else knownHosts6[dstIp.toString()]


    /** Known destinations (tests): dst IP int → hostname. */
    fun knownHostsSnapshot(): Map<Int, String> = knownHosts.toMap()

    /** Record a known destination (tests / DNS relay / sniffing). */
    fun recordKnownHost(dstIp: Int, host: String) {
        if (host.isNotBlank()) knownHosts[dstIp] = host.lowercase()
    }

    /**
     * v1.0.6 (M6): tujuan IPv6 yang dikenal — string IPv6 →
     * hostname (dari jawaban AAAA / sniffing). v1.0.15: map ini
     * kini JUGA gate route-only IPv6 (lihat [RouteOnlyGate]
     * .decideV6 + handleTcp), sejajar map IPv4.
     */
    /** Known IPv6 destinations (tests): IPv6 string → hostname. */
    fun knownHosts6Snapshot(): Map<String, String> = knownHosts6.toMap()

    /** Record a known IPv6 destination (tests / DNS relay / sniffing). */
    fun recordKnownHost6(dstIp: TcpPacket.IpAddr, host: String) {
        if (host.isNotBlank()) knownHosts6[dstIp.toString()] = host.lowercase()
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        DialLog.log("FORWARDER", "mulai — baca TUN")
        // v1.0.21: one line proving the MTU/MSS the TUN came up
        // with — the phone log must show whether the app actually
        // gets the big MTU (mtu=9000 mss=8960) or falls back.
        DialLog.log("TUN", "mtu=$tunMtu mss=${maxMssForMtu(tunMtu)}")
        tunWriter.start()
        udpSweeperThread = thread(name = "tun-udp-sweep", isDaemon = true) { udpSweepLoop() }
        readerThread = thread(name = "tun-reader", isDaemon = true) { readLoop() }
    }

    /**
     * v1.0.6 (M6): penyapu sesi UDP idle — tiap [UDP_SWEEP_MS],
     * tutup sesi yang tidak ada paketnya selama [UDP_IDLE_MS].
     * close() membangunkan thread balasan sesi itu (baca stream
     * gagal → null → thread keluar).
     */
    private fun udpSweepLoop() {
        while (running.get()) {
            try {
                Thread.sleep(UDP_SWEEP_MS)
            } catch (_: InterruptedException) {
                break
            }
            if (!running.get()) break
            val now = System.currentTimeMillis()
            udpSessions.values.toList()
                .filter { now - it.lastActivityMs > UDP_IDLE_MS }
                .forEach { closeUdpSession(it) }
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { tunIn.close() }
        // v1.0.18: stop the writer BEFORE closing the fd — it
        // drains the queue and exits; the join is bounded (2 s), so
        // a stuck fd cannot hang teardown. Then clear the queue so
        // a relay blocked in enqueue (queue full + writer gone) can
        // finish its put() and see the closed session instead of
        // hanging.
        tunWriter.stop()
        tunWriter.clear()
        sessions.values.toList().forEach { closeSession(it) }
        sessions.clear()
        udpSessions.values.toList().forEach { closeUdpSession(it) }
        udpSessions.clear()
        udpSweeperThread?.interrupt()
        udpSweeperThread = null
        runCatching { tunOut.close() }
        DialLog.log(
            "FORWARDER",
            "berhenti (paket dibaca: ${packetsRead.get()}, " +
                "DNS: ${dnsQueries.get()} query / ${dnsFailures.get()} gagal)",
        )
        // v1.0.4: stop the DNS pool — in-flight relay threads are
        // interrupted (their socket reads throw and are counted as
        // failures); a new forwarder builds a new pool on restart.
        dnsExecutor.shutdownNow()
    }

    private fun readLoop() {
        val buf = ByteArray(65535)
        // v1.0.11: the service sets the TUN fd blocking in
        // establishTunnel(), so read() waits for a packet. This
        // line proves the reader thread is alive and waiting —
        // the v1.0.10 phone log showed "FORWARDER mulai" and then
        // nothing until "baca TUN selesai (n=0)" 1 ms later, so
        // nobody could tell the thread had even entered its read.
        DialLog.log("FORWARDER", "loop baca TUN jalan — menunggu paket")
        while (running.get()) {
            val n = try {
                tunIn.read(buf)
            } catch (e: Exception) {
                // A read error while still running means the reader
                // died — log it instead of vanishing silently (a
                // close during stop() is expected and stays quiet).
                if (running.get()) DialLog.failure("FORWARDER baca TUN", e)
                break
            }
            if (n == 0) {
                // No data yet (EAGAIN on a non-blocking fd) — NOT
                // end-of-stream. Keep waiting. The sleep only
                // matters if the fd somehow stayed non-blocking;
                // with a blocking fd read() never returns 0.
                try {
                    Thread.sleep(10)
                } catch (_: InterruptedException) {
                    // Stop was requested; the while condition exits.
                }
                continue
            }
            if (n < 0) {
                // EOF: the TUN fd closed while the VPN is still
                // running — an error, not a clean finish.
                if (running.get()) {
                    DialLog.failure(
                        "FORWARDER baca TUN",
                        java.io.IOException("EOF (n=-1): fd TUN tertutup saat VPN jalan"),
                    )
                }
                break
            }
            packetsRead.incrementAndGet()
            try {
                handlePacket(buf, n)
            } catch (_: Exception) {
                // One bad packet must not kill the reader.
            }
        }
        // "selesai" is only for a real teardown (stop() cleared
        // running); an error exit above already logged itself.
        if (!running.get()) {
            DialLog.log("FORWARDER", "baca TUN selesai (paket: ${packetsRead.get()})")
        }
    }

    /** Detail line for one parsed packet (first 20 only). */
    private fun logPacket(proto: String, srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int) {
        if (loggedPackets.getAndIncrement() >= 20) return
        DialLog.log(
            "TUN",
            "$proto ${TcpPacket.ipToString(srcIp)}:$srcPort -> " +
                "${TcpPacket.ipToString(dstIp)}:$dstPort (#${packetsRead.get()})",
        )
    }

    /** Detail line for one parsed IPv6 packet (first 20 only, v1.0.6). */
    private fun logPacket6(proto: String, srcIp: TcpPacket.IpAddr, srcPort: Int, dstIp: TcpPacket.IpAddr, dstPort: Int) {
        if (loggedPackets.getAndIncrement() >= 20) return
        DialLog.log(
            "TUN",
            "$proto $srcIp:$srcPort -> $dstIp:$dstPort (#${packetsRead.get()})",
        )
    }

    private fun handlePacket(buf: ByteArray, len: Int) {
        if (len < 1) return
        when (buf[0].toInt() shr 4) {
            4 -> handlePacket4(buf, len)
            6 -> handlePacket6(buf, len)
            else -> Unit // Unknown version: drop.
        }
    }

    private fun handlePacket4(buf: ByteArray, len: Int) {
        // v1.0.15: the TCP branch parses the IP header in place
        // (no copy) and copies only the TCP data payload out —
        // parseIp + parseTcp copied the whole segment twice per
        // packet. UDP/ICMP keep parseIp (their payload is held
        // by a thread / rebuilt, so the copy is load-bearing).
        val ipH = TcpPacket.parseIpHeader(buf, len) ?: return
        when (ipH.protocol) {
            TcpPacket.PROTO_TCP -> {
                val tcp = TcpPacket.parseTcpSegment(buf, ipH.payloadOff, ipH.payloadLen) ?: return
                logPacket("TCP", ipH.src, tcp.srcPort, ipH.dst, tcp.dstPort)
                handleTcp(TcpPacket.IpAddr.v4(ipH.src), TcpPacket.IpAddr.v4(ipH.dst), tcp)
            }
            TcpPacket.PROTO_UDP -> {
                val ip = TcpPacket.parseIp(buf, len) ?: return
                val udp = TcpPacket.parseUdp(ip.payload) ?: return
                logPacket("UDP", ip.src, udp.srcPort, ip.dst, udp.dstPort)
                handleUdp(ip, udp)
            }
            TcpPacket.PROTO_ICMP -> {
                logPacket("ICMP", ipH.src, 0, ipH.dst, 0)
                val reply = TcpPacket.buildIcmpEchoReply(buf, len) ?: return
                writePacket(reply)
            }
            else -> Unit // Other IPv4 protocols are dropped.
        }
    }

    /**
     * v1.0.6 (M6): IPv6 packets — TCP / UDP / ICMPv6 echo, same
     * state machines as IPv4 but with 128-bit session keys and
     * IPv6 packet builders. Extension headers are dropped by
     * [TcpPacket.parseIpv6Header].
     */
    private fun handlePacket6(buf: ByteArray, len: Int) {
        val ipH = TcpPacket.parseIpv6Header(buf, len) ?: return
        val src = TcpPacket.IpAddr.v6(ipH.src)
        val dst = TcpPacket.IpAddr.v6(ipH.dst)
        when (ipH.protocol) {
            TcpPacket.PROTO_TCP -> {
                val tcp = TcpPacket.parseTcpSegment(buf, ipH.payloadOff, ipH.payloadLen) ?: return
                logPacket6("TCP6", src, tcp.srcPort, dst, tcp.dstPort)
                handleTcp(src, dst, tcp)
            }
            TcpPacket.PROTO_UDP -> {
                val payload = buf.copyOfRange(ipH.payloadOff, ipH.payloadOff + ipH.payloadLen)
                val udp = TcpPacket.parseUdp(payload) ?: return
                logPacket6("UDP6", src, udp.srcPort, dst, udp.dstPort)
                handleUdp6(src, dst, udp)
            }
            TcpPacket.PROTO_ICMPV6 -> {
                logPacket6("ICMPv6", src, 0, dst, 0)
                val reply = TcpPacket.buildIcmpv6EchoReply(buf, len) ?: return
                writePacket(reply)
            }
            else -> Unit // Other IPv6 protocols are dropped.
        }
    }

    // ---- TCP ----

    private fun handleTcp(srcIp: TcpPacket.IpAddr, dstIp: TcpPacket.IpAddr, tcp: TcpPacket.TcpSegment) {
        val key = Key(srcIp, tcp.srcPort, dstIp, tcp.dstPort)
        val session = sessions[key]
        if (tcp.flags and TcpPacket.FLAG_RST != 0) {
            if (session != null) closeSession(session)
            return
        }
        if (session == null) {
            if (tcp.flags and TcpPacket.FLAG_SYN != 0) {
                // v1.0.5 (kelompok F, route-only): tujuan yang tidak
                // dikenal tidak didial sama sekali — RST + log, lihat
                // RouteOnlyGate. Terjadi SEBELUM sesi dibuat, jadi
                // tidak ada dial proxy dan tidak ada sesi bocor.
                // v1.0.15: gate kini IPv4 DAN IPv6 — IPv6 memakai
                // map knownHosts6 berkunci string 128-bit
                // (decideV6); IPv4 tidak berubah.
                val routeOnlyRefused = if (dstIp.isV4) {
                    RouteOnlyGate.decide(routeOnlyEnabled, dstIp.toInt(), knownHosts) ==
                        RouteOnlyGate.Decision.REFUSE
                } else {
                    RouteOnlyGate.decideV6(routeOnlyEnabled, dstIp.toString(), knownHosts6) ==
                        RouteOnlyGate.Decision.REFUSE
                }
                if (routeOnlyRefused) {
                    DialLog.log(
                        "ROUTE-ONLY",
                        "tolak $dstIp:${tcp.dstPort} " +
                            "(tujuan tidak dikenal — tidak ada di DNS/sniffing)",
                    )
                    sendRst(srcIp, dstIp, tcp)
                    return
                }
                // v1.0.13, fix A4: cap TCP sessions at 96 (XVEON)
                // — evict the oldest by last activity so a SYN
                // flood cannot grow the map without bound.
                if (sessions.size >= MAX_SESSIONS) {
                    sessions.values.minByOrNull { it.lastActivityMs }
                        ?.let { closeSession(it) }
                }
                val isn = (random.nextInt().toLong() and 0xFFFFFFFFL)
                val s = TcpSession(key, isn)
                s.clientSeq = (tcp.seq + 1) and 0xFFFFFFFFL
                // v1.0.10: remember what the SYN offered, like
                // xray-core's tun stack (synchronize): the peer MSS
                // caps our segments, and SACK / window-scale offers
                // are echoed in the SYN-ACK.
                // v1.0.21: cap at the MTU-derived max, not the old
                // 1460 — on a 9000 MTU the app offers up to 8960
                // and the relay must be allowed to build segments
                // that big, or the bigger MTU changes nothing.
                val offered = TcpPacket.parseTcpOptions(tcp.options)
                offered.mss?.let { s.peerMss = minOf(maxMssForMtu(tunMtu, dstIp.isV6), it) }
                s.wsOffered = offered.windowScale != null
                s.sackOffered = offered.sackPermitted
                sessions[key] = s
                thread(name = "tun-dial-${tcp.dstPort}", isDaemon = true) { dial(s) }
            } else if (tcp.flags and TcpPacket.FLAG_ACK == 0) {
                // Stray non-ACK segment for an unknown connection: refuse.
                sendRst(srcIp, dstIp, tcp)
            }
            // Pure ACKs for unknown sessions are dropped silently.
            return
        }
        session.lastActivityMs = System.currentTimeMillis()
        when (session.state) {
            State.DIALING -> {
                // v1.0.13, fix A1: data that arrives while the proxy
                // dial is in flight is QUEUED, not dropped — the
                // writer drains it once the stream is set. (In
                // practice the app only sends after the SYN-ACK, so
                // this is a race guard, not the hot path.)
                if (tcp.payload.isNotEmpty()) handleData(session, tcp)
            }
            State.SYN_SENT -> {
                if (tcp.flags and TcpPacket.FLAG_SYN != 0) {
                    // SYN retransmit: resend SYN-ACK with the same ISN.
                    sendSynAck(session)
                } else if (tcp.flags and TcpPacket.FLAG_ACK != 0 &&
                    tcp.ack == session.serverSeq
                ) {
                    session.state = State.ESTABLISHED
                    if (tcp.payload.isNotEmpty()) handleData(session, tcp)
                }
            }
            State.ESTABLISHED -> handleData(session, tcp)
            State.CLOSED -> Unit
        }
    }

    private fun handleData(session: TcpSession, tcp: TcpPacket.TcpSegment) {
        val payload = tcp.payload
        // v1.0.5 (kelompok F, sniffing): inspeksi chunk data
        // pertama (max 3 percobaan — ClientHello bisa terpotong
        // antar segmen) dan catat hostname ke knownHosts, untuk
        // koneksi BERIKUTNYA ke IP yang sama (route-only) dan
        // untuk diagnosis. Tidak pernah mengubah byte-nya.
        if (payload.isNotEmpty() && sniffingEnabled && !session.sniffed &&
            session.sniffAttempts < 3
        ) {
            session.sniffAttempts++
            Sniffer.extract(payload)?.let { found ->
                session.sniffed = true
                // v1.0.6 (M6): IPv6 dicatat di map string-nya sendiri.
                if (session.key.dstIp.isV4) {
                    recordKnownHost(session.key.dstIp.toInt(), found.host)
                } else {
                    recordKnownHost6(session.key.dstIp, found.host)
                }
            }
        }
        var ackNeeded = false
        if (payload.isNotEmpty()) {
            when {
                tcp.seq == session.clientSeq -> {
                    // v1.0.13, fix A1: enqueue for the writer
                    // thread — never write to the proxy stream on
                    // the TUN reader thread. A slow write on one
                    // connection used to stall packet processing
                    // for every connection (sluggish start).
                    enqueueData(session, payload)
                    session.clientSeq = (session.clientSeq + payload.size) and 0xFFFFFFFFL
                    ackNeeded = true
                    replayOutOfOrder(session)
                }
                tcp.seq < session.clientSeq &&
                    tcp.seq + payload.size > session.clientSeq -> {
                    // Retransmit with a new tail: forward only the new bytes.
                    val skip = (session.clientSeq - tcp.seq).toInt()
                    val tail = payload.copyOfRange(skip, payload.size)
                    enqueueData(session, tail)
                    session.clientSeq = (session.clientSeq + tail.size) and 0xFFFFFFFFL
                    ackNeeded = true
                    replayOutOfOrder(session)
                }
                tcp.seq > session.clientSeq -> {
                    // v1.0.13, fix A2: out of order — BUFFER it
                    // (seq-keyed, max 32, drop oldest) instead of
                    // dropping and waiting for a retransmit.
                    // XVEON replays the buffered segments when the
                    // gap fills; dropping forced a retransmit and
                    // slowed the first page load.
                    if (session.outOfOrder.size >= MAX_OUT_OF_ORDER) {
                        session.outOfOrder.pollFirstEntry()
                    }
                    session.outOfOrder[tcp.seq] = payload
                    ackNeeded = true
                }
                else -> {
                    // Pure retransmit of bytes we already have: ACK only.
                    ackNeeded = true
                }
            }
        }
        if (tcp.flags and TcpPacket.FLAG_FIN != 0) {
            session.clientSeq = (session.clientSeq + 1) and 0xFFFFFFFFL
            if (session.state == State.DIALING) {
                // App aborted before the handshake: drop the
                // session silently (no SYN-ACK was ever sent).
                closeSession(session)
                return
            }
            // ACK the FIN, then close our side. In-flight server data
            // that the relay thread has not written yet may be lost —
            // acceptable for M2 (FIN normally follows a complete reply).
            sendAck(session)
            sendFin(session)
            return
        }
        if (ackNeeded) sendAck(session)
    }

    /** Offer one app-data chunk to the session's writer queue
     * (drop-oldest when full) and make sure the writer runs. */
    private fun enqueueData(session: TcpSession, data: ByteArray) {
        while (!session.outQueue.offer(data)) {
            session.outQueue.poll()
        }
        session.lastActivityMs = System.currentTimeMillis()
        startWriter(session)
    }

    /** Replay buffered out-of-order segments that now follow in
     * order, in seq order, until the next gap. */
    private fun replayOutOfOrder(session: TcpSession) {
        while (true) {
            val next = session.outOfOrder.remove(session.clientSeq) ?: return
            enqueueData(session, next)
            session.clientSeq = (session.clientSeq + next.size) and 0xFFFFFFFFL
        }
    }

    /** Start the session's writer thread (single-shot), once the
     * proxy stream is set. Data queued while DIALING waits here
     * until then. */
    private fun startWriter(session: TcpSession) {
        if (session.stream == null) return
        if (!session.writerStarted.compareAndSet(false, true)) return
        thread(name = "tun-writer-${session.key.dstPort}", isDaemon = true) {
            writerLoop(session)
        }
    }

    /**
     * Writer thread (v1.0.13, fix A1 — XVEON's Ll4): drains the
     * session's queue, up to 8 chunks per flush, so a slow write
     * on this connection never stalls the TUN reader or any other
     * connection. Stops when the session closes.
     */
    private fun writerLoop(session: TcpSession) {
        val stream = session.stream ?: return
        try {
            while (!session.closed.get()) {
                val first = try {
                    session.outQueue.poll(WRITER_POLL_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    return
                } ?: continue
                if (first === WRITER_WAKE) continue
                val batch = ArrayList<ByteArray>(MAX_WRITER_DRAIN)
                batch.add(first)
                while (batch.size < MAX_WRITER_DRAIN) {
                    val next = session.outQueue.poll() ?: break
                    if (next !== WRITER_WAKE) batch.add(next)
                }
                // v1.0.16: the write+flush below is timed (see
                // after the flush).
                val stats = session.speedStats
                val t0 = if (stats != null) System.nanoTime() else 0L
                var written = 0
                for (chunk in batch) {
                    stream.output.write(chunk)
                    written += chunk.size
                }
                stream.output.flush()
                // v1.0.16: time the upload write+flush (upW: VMess
                // seal + WS frame + TLS wrap + socket write,
                // combined) and count the app bytes written to the
                // proxy. The VMess seal part is timed separately
                // inside VmessBodyOutputStream (upVmess).
                if (stats != null) {
                    stats.upWriteNs.addAndGet(System.nanoTime() - t0)
                    stats.upBytes.addAndGet(written.toLong())
                }
                session.lastActivityMs = System.currentTimeMillis()
            }
        } catch (_: Exception) {
            // Write failed: close our side (the app gets a FIN).
            if (!session.closed.get()) sendFin(session)
        }
    }

    private fun dial(session: TcpSession) {
        val key = session.key
        val dst = "${key.dstIp}:${key.dstPort}"
        // v1.0.9: log EVERY attempt, not just failures. taptapng-6.txt
        // (2026-11-20 04:17) stopped at "PROBE ok" with no forwarder
        // lines at all, so nobody could tell whether a dial was even
        // attempted once the TUN was up — the next phone log must
        // show the attempt and its outcome, not only failures.
        DialLog.log("DIAL", dst)
        val stream: ProxyStream
        // v1.0.6, fix A: every dial runs under its own watchdog, so
        // a stage that blocks past 30 s is killed (socket closed)
        // and reported with the stage — the dial can never hang
        // forever while the status stays "Connecting...".
        val watchdog = DialWatchdog()
        Transport.setThreadWatchdog(watchdog)
        // v1.0.16: one SpeedStats per session — threaded through
        // the transport ladder (TLS/WS) and the body streams, so
        // the SPEED lines can split the download time by stage.
        // A proxy that ignores it (test fakes) still gets its
        // forwarder-side stages timed (relay read / build / TUN).
        val speed = SpeedStats()
        // M7: host untuk routing — FakeDNS reverse dulu (log sama
        // seperti sebelum M7), lalu map known-hosts (jawaban DNS +
        // sniffing), lalu null (koneksi IP-only tanpa domain).
        // Host dial = hostname itu bila dikenal, else IP literal.
        // IP fake tidak ada artinya di luar TUN ini, jadi yang
        // dikirim ke proxy selalu hostname aslinya (server proxy
        // yang me-resolve-nya); FakeDNS hanya IPv4 (pool
        // 198.18.0.0/15) — tujuan IPv6 tidak pernah fake.
        val fakeHost = if (key.dstIp.isV4) {
            dnsPolicy.fakeDns?.lookupHost(key.dstIp.toInt())?.also {
                DialLog.log("DNS", "fake $dst -> $it")
            }
        } else {
            null
        }
        val routedHost = fakeHost
            ?: if (key.dstIp.isV4) knownHosts[key.dstIp.toInt()]
            else knownHosts6[key.dstIp.toString()]
        val dialHost = routedHost ?: key.dstIp.toString()
        // M7: putuskan rute koneksi ini. Resolver null = perilaku
        // lama (dial selalu lewat [proxy] yang tunggal). REJECT
        // dijawab di sini, sebelum dial apa pun — tanpa sesi dan
        // tanpa stream; status tidak dilaporkan sebagai "Konek
        // gagal" (penolakan aturan bukan kegagalan dial).
        val decision = routeResolver?.invoke(
            routedHost,
            InetAddress.getByAddress(key.dstIp.bytes),
            key.dstPort,
        )
        if (decision == RouteDecision.Reject) {
            sessions.remove(key)
            DialLog.log(
                "ROUTE",
                "tolak $dst" + (routedHost?.let { " ($it)" } ?: ""),
            )
            val rst = buildTcpPacket(
                key.dstIp, key.srcIp, key.dstPort, key.srcPort,
                0, session.clientSeq,
                TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK, ByteArray(0),
            )
            writePacket(rst)
            return
        }
        if (decision != null) {
            DialLog.log("ROUTE", "$dst -> $decision")
        }
        try {
            watchdog.start()
            stream = when (decision) {
                null -> proxy.dial(dialHost, key.dstPort, stats = speed)
                RouteDecision.Direct -> directDial?.invoke(dialHost, key.dstPort, speed)
                    ?: defaultDirectDial(dialHost, key.dstPort)
                is RouteDecision.Proxy -> {
                    // Guid tidak dikenal (terhapus sesudah aturan
                    // ditulis) jatuh kembali ke [proxy] — fail-open
                    // ke entry terpilih, bukan putus koneksi.
                    val client = clientProvider?.invoke(decision.profileGuid) ?: proxy
                    client.dial(dialHost, key.dstPort, stats = speed)
                }
                RouteDecision.Reject -> error("unreachable: Reject ditangani di atas")
            }
        } catch (e: Exception) {
            sessions.remove(key)
            DialLog.failure("DIAL $dst", e)
            // v1.0.4: report the failure instead of silently RST-ing
            // every dial while the status stays "Connecting..." forever.
            reportDialFailure(e)
            // Refuse the connection: RST|ACK.
            val rst = buildTcpPacket(
                key.dstIp, key.srcIp, key.dstPort, key.srcPort,
                0, session.clientSeq,
                TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK, ByteArray(0),
            )
            writePacket(rst)
            return
        } finally {
            watchdog.stop()
            Transport.setThreadWatchdog(null)
        }
        if (session.closed.get() || session.state != State.DIALING) {
            runCatching { stream.close() }
            return
        }
        session.stream = stream
        session.state = State.SYN_SENT
        // v1.0.16: the stats clock starts at dial-ok (the transfer,
        // not the dial + handshake, is what the SPEED lines time).
        session.speedStats = speed
        session.speedStartMs = System.currentTimeMillis()
        sendSynAck(session)
        // v1.0.13, fix A1: start the writer now, so data queued
        // while DIALING drains at once.
        startWriter(session)
        DialLog.log("DIAL", "$dst ok")
        if (!firstDialReported) {
            firstDialReported = true
            onStatus("Connected")
        }
        thread(name = "tun-relay-${key.dstPort}", isDaemon = true) { relay(session) }
    }

    /**
     * M7: dial direct untuk keputusan [RouteDecision.Direct] — socket
     * TCP polos ter-protect ke target, tanpa proxy. Host di-resolve
     * lewat [DnsResolver.resolveWithSystemFallback] (operator-first,
     * bypass TUN) kecuali sudah berupa IP literal; socket
     * di-protect seperti dial proxy ([Transport.protectSocket] +
     * aturan appBypass — lihat [Transport.open]). TLS aplikasi
     * jalan di atas stream ini, jadi tidak ada urusan SNI di sini.
     */
    private fun defaultDirectDial(host: String, port: Int): ProxyStream {
        val target = DnsResolver.resolveWithSystemFallback(host, port)
        val socket = Socket()
        try {
            val protect = Transport.protectSocket
            if (protect != null && TunnelState.up && !protect(socket)) {
                if (!TunnelState.appBypass) {
                    throw IllegalStateException(
                        "protect() gagal — dial direct tidak bisa bypass VPN",
                    )
                }
                DialLog.log(
                    "PROTECT",
                    "protect() gagal — dial direct lanjut via disallow aplikasi",
                )
            }
            socket.connect(InetSocketAddress(target, port), DIRECT_DIAL_TIMEOUT_MS)
            socket.soTimeout = 0
            return SocketProxyStream(socket, socket.getInputStream(), socket.getOutputStream())
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
    }

    /** First failure at once, then at most once per 10 s (see fields). */
    private fun reportDialFailure(e: Exception) {
        val now = System.currentTimeMillis()
        if (firstFailureReported && now - lastFailureReportMs < 10_000) return
        firstFailureReported = true
        lastFailureReportMs = now
        onStatus("Konek gagal (${dialFailureReason(e)})")
    }

    private fun relay(session: TcpSession) {
        val stream = session.stream ?: return
        // v1.0.16: this thread's stage timings land in the session's
        // SpeedStats — the SPEED window lines below are the whole
        // point of this version (measure, don't guess).
        val stats = session.speedStats
        val dst = "${session.key.dstIp}:${session.key.dstPort}"
        // v1.0.15: one read() pulls up to RELAY_READ_SIZE (several
        // VMess chunks) instead of one peer-MSS read per segment,
        // and segments are built straight from the read buffer
        // into a reusable packet buffer — no copyOf, no
        // ByteBuffer.allocate, no packet array per segment. A
        // short tail segment at a chunk boundary is correct (the
        // app reassembles by sequence number). Segments never
        // exceed what the app's SYN offered (v1.0.10).
        val readBuf = ByteArray(RELAY_READ_SIZE)
        // v1.0.21: the packet buffer must fit the biggest segment
        // the MTU allows (IP + TCP + MAX_SEGMENT_MSS = 9000), not
        // just the old 1500-byte MAX_TCP_SEGMENT_BYTES — a
        // 8960-byte segment would overflow the old buffer
        // (buildTcpInto requires out.size >= total). One buffer
        // per relay thread (max 96 sessions × 9 KiB worst case).
        val pktBuf = ByteArray(
            if (session.key.dstIp.isV6) MAX_PACKET_BYTES_V6 else MAX_PACKET_BYTES,
        )
        // Segments never exceed what the app's SYN offered
        // (v1.0.10); coerce to >= 1 like the old code did — a
        // peer MSS of 0 would otherwise emit zero-length segments
        // forever (pos never advances). v1.0.21: cap at the
        // MTU-derived max, not the old 1460.
        val segMss = session.peerMss.coerceIn(1, maxMssForMtu(tunMtu, session.key.dstIp.isV6))
        var buffered = 0
        var pos = 0
        // SPEED window bookkeeping: the window starts at the first
        // read with data (the dial + handshake is not transfer),
        // and a line is logged every speedWindowMs of active
        // transfer. windowSnap is the zero baseline taken at relay
        // start (no bytes have flowed yet).
        var windowStartMs = 0L
        var windowSnap = stats?.snapshot()
        try {
            while (!session.closed.get()) {
                if (pos >= buffered) {
                    // Time the proxy read (rd): inside it the
                    // tls+net / ws / vmess stages are timed by the
                    // layers below — never double-counted here.
                    val t0 = if (stats != null) System.nanoTime() else 0L
                    val n = stream.input.read(readBuf)
                    if (stats != null) stats.relayReadNs.addAndGet(System.nanoTime() - t0)
                    if (n == -1) break
                    if (n <= 0) continue
                    buffered = n
                    pos = 0
                    stats?.downBytes?.addAndGet(n.toLong())
                    if (stats != null) {
                        val nowMs = System.currentTimeMillis()
                        if (windowStartMs == 0L) {
                            windowStartMs = nowMs
                        } else if (nowMs - windowStartMs >= speedWindowMs) {
                            val snap = stats.snapshot()
                            DialLog.log(
                                "SPEED",
                                SpeedStats.windowLine(
                                    windowSnap ?: snap, snap, dst, nowMs - windowStartMs,
                                ),
                            )
                            windowStartMs = nowMs
                            windowSnap = snap
                        }
                    }
                }
                val take = minOf(segMss, buffered - pos)
                val tb = if (stats != null) System.nanoTime() else 0L
                val pktLen = buildTcpPacketInto(
                    pktBuf,
                    session.key.dstIp, session.key.srcIp,
                    session.key.dstPort, session.key.srcPort,
                    session.serverSeq, session.clientSeq,
                    TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK,
                    readBuf, pos, take,
                )
                if (stats != null) stats.buildNs.addAndGet(System.nanoTime() - tb)
                val tw = if (stats != null) System.nanoTime() else 0L
                writePacket(pktBuf, pktLen)
                if (stats != null) {
                    stats.tunNs.addAndGet(System.nanoTime() - tw)
                    stats.tunWrites.incrementAndGet()
                }
                pos += take
                session.serverSeq = (session.serverSeq + take) and 0xFFFFFFFFL
            }
        } catch (_: Exception) {
            // Proxy stream broke: fall through to FIN.
        }
        sendFin(session)
    }

    /**
     * v1.0.6 (M6): bangun satu paket TCP ke TUN — IPv4
     * ([TcpPacket.buildTcp]) atau IPv6 ([TcpPacket.buildTcp6])
     * sesuai keluarga alamat sumber. Semua pengirim paket TCP
     * (SYN-ACK / ACK / FIN / RST) lewat sini.
     */
    private fun buildTcpPacket(
        srcIp: TcpPacket.IpAddr,
        dstIp: TcpPacket.IpAddr,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        mss: Int = 0,
        options: ByteArray = byteArrayOf(),
        window: Int = TcpPacket.TCP_WINDOW,
    ): ByteArray = if (srcIp.isV6) {
        TcpPacket.buildTcp6(
            srcIp.bytes, dstIp.bytes, srcPort, dstPort, seq, ack,
            flags, payload, mss, options, window,
        )
    } else {
        TcpPacket.buildTcp(
            srcIp.toInt(), dstIp.toInt(), srcPort, dstPort, seq, ack,
            flags, payload, mss, options, window,
        )
    }

    /** Sama seperti [buildTcpPacket], ke buffer yang dipakai ulang (jalur relay). */
    private fun buildTcpPacketInto(
        out: ByteArray,
        srcIp: TcpPacket.IpAddr,
        dstIp: TcpPacket.IpAddr,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        payloadOff: Int = 0,
        payloadLen: Int = -1,
    ): Int = if (srcIp.isV6) {
        TcpPacket.buildTcp6Into(
            out, srcIp.bytes, dstIp.bytes, srcPort, dstPort, seq, ack,
            flags, payload, payloadOff, payloadLen,
        )
    } else {
        TcpPacket.buildTcpInto(
            out, srcIp.toInt(), dstIp.toInt(), srcPort, dstPort, seq, ack,
            flags, payload, payloadOff, payloadLen,
        )
    }

    /** Bangun satu paket UDP ke TUN — IPv4 atau IPv6 (v1.0.6, M6). */
    private fun buildUdpPacket(
        srcIp: TcpPacket.IpAddr,
        dstIp: TcpPacket.IpAddr,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray = if (srcIp.isV6) {
        TcpPacket.buildUdp6(srcIp.bytes, dstIp.bytes, srcPort, dstPort, payload)
    } else {
        TcpPacket.buildUdp(srcIp.toInt(), dstIp.toInt(), srcPort, dstPort, payload)
    }

    private fun sendSynAck(session: TcpSession) {
        val key = session.key
        // v1.0.10: echo what the SYN offered, like xray-core's tun
        // stack (sendSyn) — SACK-permitted and window scale (shift
        // 5, window 256 KiB >> 5) only when the peer offered them;
        // otherwise the plain MSS-only SYN-ACK as before.
        // v1.0.15: the MSS we offer comes from the MTU setting —
        // clamp(tunMtu - 40, 1140, 1460), capped at the peer's
        // MSS — instead of XVEON's clamp(tunMtu - 140, 1140, 1360).
        val extra = ByteArrayOutputStream()
        if (session.sackOffered) extra.write(byteArrayOf(1, 1, 4, 2))
        if (session.wsOffered) {
            extra.write(byteArrayOf(1, 3, 3, TcpPacket.TCP_WINDOW_SHIFT.toByte()))
        }
        val window = if (session.wsOffered) TcpPacket.TCP_WINDOW_SCALED else TcpPacket.TCP_WINDOW
        val pkt = buildTcpPacket(
            key.dstIp, key.srcIp, key.dstPort, key.srcPort,
            session.isn, session.clientSeq,
            TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK,
            ByteArray(0),
            mss = synAckMss(tunMtu, session.peerMss, key.dstIp.isV6),
            options = extra.toByteArray(),
            window = window,
        )
        writePacket(pkt)
        session.serverSeq = (session.isn + 1) and 0xFFFFFFFFL
    }

    private fun sendAck(session: TcpSession) {
        val key = session.key
        val pkt = buildTcpPacket(
            key.dstIp, key.srcIp, key.dstPort, key.srcPort,
            session.serverSeq, session.clientSeq,
            TcpPacket.FLAG_ACK, ByteArray(0),
        )
        writePacket(pkt)
    }

    /** Send FIN|ACK and tear the session down (single-shot). */
    private fun sendFin(session: TcpSession) {
        if (!session.closed.compareAndSet(false, true)) return
        session.outQueue.offer(WRITER_WAKE)
        logSpeedSummary(session)
        val key = session.key
        val pkt = buildTcpPacket(
            key.dstIp, key.srcIp, key.dstPort, key.srcPort,
            session.serverSeq, session.clientSeq,
            TcpPacket.FLAG_FIN or TcpPacket.FLAG_ACK, ByteArray(0),
        )
        writePacket(pkt)
        session.serverSeq = (session.serverSeq + 1) and 0xFFFFFFFFL
        session.state = State.CLOSED
        sessions.remove(key)
        runCatching { session.stream?.close() }
    }

    private fun closeSession(session: TcpSession) {
        if (!session.closed.compareAndSet(false, true)) return
        session.outQueue.offer(WRITER_WAKE)
        logSpeedSummary(session)
        session.state = State.CLOSED
        sessions.remove(session.key)
        runCatching { session.stream?.close() }
    }

    /**
     * v1.0.16: log the session's SPEED TUTUP summary once — the
     * totals over the whole connection (download MB + effective
     * MB/s + per-stage totals + upload totals + counts). Only
     * sessions that moved bytes get a line; a dial that never
     * transferred stays quiet. Called from sendFin() and
     * closeSession(); the guard makes the first call win. The
     * numbers are best-effort at teardown: if the writer thread
     * tears the session down first (write failure), the relay may
     * still be draining — the summary then misses its last bytes.
     */
    private fun logSpeedSummary(session: TcpSession) {
        val stats = session.speedStats ?: return
        if (!session.speedLogged.compareAndSet(false, true)) return
        val snap = stats.snapshot()
        // M7 (W3): closed-session bytes feed the Clash /traffic
        // totals (live sessions add their counters in trafficTotals).
        closedUpBytes.addAndGet(snap.upBytes)
        closedDownBytes.addAndGet(snap.downBytes)
        if (snap.downBytes == 0L && snap.upBytes == 0L) return
        val wallMs = System.currentTimeMillis() - session.speedStartMs
        val dst = "${session.key.dstIp}:${session.key.dstPort}"
        DialLog.log("SPEED", SpeedStats.totalLine(snap, dst, wallMs))
    }

    private fun sendRst(srcIp: TcpPacket.IpAddr, dstIp: TcpPacket.IpAddr, tcp: TcpPacket.TcpSegment) {
        val pkt = buildTcpPacket(
            dstIp, srcIp, tcp.dstPort, tcp.srcPort,
            0, (tcp.seq + 1) and 0xFFFFFFFFL,
            TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK, ByteArray(0),
        )
        writePacket(pkt)
    }

    // ---- UDP ----

    /** UDP IPv4 (v1.0.6: delegasi ke [handleUdpCommon] dengan alamat IpAddr). */
    private fun handleUdp(ip: TcpPacket.IpPacket, udp: TcpPacket.UdpDatagram) {
        handleUdpCommon(
            TcpPacket.IpAddr.v4(ip.src), udp.srcPort,
            TcpPacket.IpAddr.v4(ip.dst), udp.dstPort, udp.payload,
        )
    }

    /** UDP IPv6 (v1.0.6, M6): sama seperti IPv4, balasannya paket UDPv6. */
    private fun handleUdp6(src: TcpPacket.IpAddr, dst: TcpPacket.IpAddr, udp: TcpPacket.UdpDatagram) {
        handleUdpCommon(src, udp.srcPort, dst, udp.dstPort, udp.payload)
    }

    /**
     * v1.0.6 (M6): UDP non-DNS diteruskan lewat proxy (sesi per
     * 4-tuple); DNS port 53 TETAP relay langsung ke upstream —
     * jangan dialihkan lewat proxy, supaya resolve aplikasi tidak
     * bergantung pada tunnel yang sama. Berlaku untuk IPv4 dan
     * IPv6 (balasan DNS IPv6 ditulis sebagai paket UDPv6).
     */
    private fun handleUdpCommon(
        srcIp: TcpPacket.IpAddr,
        srcPort: Int,
        dstIp: TcpPacket.IpAddr,
        dstPort: Int,
        payload: ByteArray,
    ) {
        if (dstPort != 53) {
            handleProxyUdp(srcIp, srcPort, dstIp, dstPort, payload)
            return
        }
        val query = payload
        // v1.0.10: the DNS relay was completely silent — a query
        // that died here left no trace at all, so a browser that
        // cannot resolve looks identical to "no packets reach the
        // TUN". Log the first few queries/answers in detail and
        // EVERY failure with its reason (v2rayNG's log shows each
        // connection the core handles; this is the same idea for
        // the relay). Detail lines are capped so a page load does
        // not flood the 500-line ring buffer.
        val dnsNo = dnsQueries.incrementAndGet()
        val detail = dnsLogged.get() < 5
        if (detail) {
            dnsLogged.incrementAndGet()
            DialLog.log(
                "DNS",
                "query $dstIp ${query.size}B dari $srcIp:$srcPort (#$dnsNo)",
            )
        }
        dnsExecutor.execute {
            try {
                // v1.0.5 (DNS C): jawab lewat kebijakan relay
                // (statis / FakeDNS / lokal / domestik / DoH / UDP).
                // null = query dibuang (kegagalan sudah dihitung +
                // dilog di bawah); bukan jawaban kosong.
                val respBytes = answerDnsQuery(query, dnsNo, detail) ?: return@execute
                // v1.0.5 (kelompok F): catat jawaban DNS ke
                // knownHosts — IP jawaban → hostname yang ditanya
                // — supaya route-only mengenali tujuan yang baru
                // saja di-resolve aplikasi. v1.0.6 (M6): jawaban
                // AAAA dicatat di knownHosts6. v1.0.15: jawaban
                // AAAA kini JUGA membuka gate route-only IPv6
                // (decideV6 di handleTcp).
                runCatching {
                    val qName = Sniffer.parseDnsQueryName(query)
                    if (qName != null) {
                        val qId = ((query[0].toInt() and 0xFF) shl 8) or
                            (query[1].toInt() and 0xFF)
                        for (addr in DnsResolver.parseAnswers(respBytes, qId)) {
                            Sniffer.ipv4ToInt(addr)?.let { ip ->
                                recordKnownHost(ip, qName)
                            } ?: run {
                                if (addr is java.net.Inet6Address) {
                                    recordKnownHost6(TcpPacket.IpAddr(addr.address), qName)
                                }
                            }
                        }
                    }
                }
                val pkt = buildUdpPacket(dstIp, srcIp, 53, srcPort, respBytes)
                writePacket(pkt)
                if (detail) {
                    // v1.0.4: dnsLogged hanya naik sekali per
                    // query (di baris query di atas) — sebelumnya
                    // naik dua kali, jadi batas "5 query pertama"
                    // sebenarnya ~2–3 query.
                    DialLog.log(
                        "DNS",
                        "jawab $dstIp ${respBytes.size}B ke $srcIp:$srcPort (#$dnsNo)",
                    )
                }
            } catch (e: Exception) {
                dnsFailures.incrementAndGet()
                DialLog.failure("DNS", e)
            }
        }
    }

    /**
     * M7: satu sesi UDP direct untuk target [RouteDecision.Direct] —
     * [DatagramSocket] ter-protect yang terhubung ke tujuan, jadi
     * balasan kembali lewat socket yang sama. Timeout receive hanya
     * mengulang (sesi hidup sampai penyapu idle atau [close]);
     * [close] menutup socket, yang membangunkan receive yang sedang
     * menunggu. Dibangun di thread pembaca TUN, seperti
     * [ProxyClient.dialUdp] yang digantikannya.
     */
    private class DirectUdpSession(host: String, port: Int) : ProxyUdpSession {
        private val socket: DatagramSocket
        private val closed = AtomicBoolean(false)

        init {
            val target = DnsResolver.resolveWithSystemFallback(host, port)
            val s = DatagramSocket()
            try {
                val protect = Transport.protectUdpSocket
                if (protect != null && TunnelState.up && !protect(s)) {
                    if (!TunnelState.appBypass) {
                        throw IllegalStateException(
                            "protect() gagal — UDP direct tidak bisa bypass VPN",
                        )
                    }
                }
                s.connect(InetSocketAddress(target, port))
            } catch (e: Exception) {
                runCatching { s.close() }
                throw e
            }
            socket = s
        }

        override fun send(datagram: ByteArray) {
            socket.send(DatagramPacket(datagram, datagram.size))
        }

        override fun receive(timeoutMs: Long): ByteArray? {
            while (!closed.get()) {
                try {
                    socket.soTimeout = timeoutMs.toInt().coerceAtLeast(1)
                    val buf = ByteArray(65535)
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    return pkt.data.copyOf(pkt.length)
                } catch (_: java.net.SocketTimeoutException) {
                    // Belum ada datagram: tunggu lagi sampai close().
                } catch (_: Exception) {
                    return null
                }
            }
            return null
        }

        override fun close() {
            if (closed.compareAndSet(false, true)) runCatching { socket.close() }
        }
    }

    /**
     * v1.0.6 (M6): UDP non-DNS lewat proxy. Satu sesi per 4-tuple
     * (dibuat saat datagram pertama, ditutup penyapu bila idle);
     * datagram dikirim apa adanya lewat [ProxyClient.dialUdp],
     * balasan ditulis balik ke TUN oleh thread balasan sesi itu.
     * Entry yang tidak mendukung UDP (SSH — dialUdp default
     * melempar UnsupportedOperationException) membuat datagram
     * dibuang + satu baris log, bukan crash reader.
     */
    private fun handleProxyUdp(
        srcIp: TcpPacket.IpAddr,
        srcPort: Int,
        dstIp: TcpPacket.IpAddr,
        dstPort: Int,
        payload: ByteArray,
    ) {
        val key = UdpKey(srcIp, srcPort, dstIp, dstPort)
        var session = udpSessions[key]
        if (session == null || session.closed.get()) {
            if (udpSessions.size >= MAX_UDP_SESSIONS) {
                udpSessions.values.minByOrNull { it.lastActivityMs }
                    ?.let { closeUdpSession(it) }
            }
            // M7: host untuk routing — sama seperti TCP (FakeDNS
            // reverse dulu, lalu known-hosts, lalu IP literal).
            val fakeHost = if (dstIp.isV4) {
                dnsPolicy.fakeDns?.lookupHost(dstIp.toInt())?.also {
                    DialLog.log("DNS", "fake $dstIp:$dstPort -> $it")
                }
            } else {
                null
            }
            val routedHost = fakeHost
                ?: if (dstIp.isV4) knownHosts[dstIp.toInt()]
                else knownHosts6[dstIp.toString()]
            val dialHost = routedHost ?: dstIp.toString()
            // M7: keputusan yang sama seperti TCP. REJECT membuang
            // datagram tanpa balasan (drop diam-diam untuk UDP);
            // Direct membuka socket ter-protect ke target.
            val decision = routeResolver?.invoke(
                routedHost,
                InetAddress.getByAddress(dstIp.bytes),
                dstPort,
            )
            if (decision == RouteDecision.Reject) {
                DialLog.log("ROUTE", "tolak UDP $dstIp:$dstPort")
                return
            }
            if (decision != null) {
                DialLog.log("ROUTE", "UDP $dstIp:$dstPort -> $decision")
            }
            val proxySession = try {
                when (decision) {
                    null -> proxy.dialUdp(dialHost, dstPort)
                    RouteDecision.Direct -> DirectUdpSession(dialHost, dstPort)
                    is RouteDecision.Proxy -> {
                        val client = clientProvider?.invoke(decision.profileGuid) ?: proxy
                        client.dialUdp(dialHost, dstPort)
                    }
                    RouteDecision.Reject -> error("unreachable: Reject ditangani di atas")
                }
            } catch (e: Exception) {
                DialLog.failure("UDP $dstIp:$dstPort", e)
                return
            }
            val created = UdpSession(key, proxySession)
            val raced = udpSessions.putIfAbsent(key, created)
            if (raced != null && !raced.closed.get()) {
                runCatching { proxySession.close() }
                session = raced
            } else {
                session = created
                DialLog.log("UDP", "sesi $dstIp:$dstPort")
                created.replyThread = thread(
                    name = "tun-udp-reply-$dstPort", isDaemon = true,
                ) { udpReplyLoop(created) }
            }
        }
        val s = session ?: return
        s.lastActivityMs = System.currentTimeMillis()
        try {
            s.udp.send(payload)
        } catch (e: Exception) {
            DialLog.failure("UDP $dstIp:$dstPort", e)
            closeUdpSession(s)
        }
    }

    /** Thread balasan satu sesi UDP: datagram dari proxy → paket TUN. */
    private fun udpReplyLoop(session: UdpSession) {
        val key = session.key
        try {
            while (!session.closed.get()) {
                val data = session.udp.receive(1000) ?: break
                session.lastActivityMs = System.currentTimeMillis()
                val pkt = buildUdpPacket(key.dstIp, key.srcIp, key.dstPort, key.srcPort, data)
                writePacket(pkt)
            }
        } catch (_: Exception) {
            // Sesi mati (proxy putus / TUN tutup): keluar, tutup sesi.
        } finally {
            closeUdpSession(session)
        }
    }

    private fun closeUdpSession(session: UdpSession) {
        if (!session.closed.compareAndSet(false, true)) return
        udpSessions.remove(session.key, session)
        runCatching { session.udp.close() }
    }

    /**
     * Jawab satu query DNS menurut [dnsPolicy] (v1.0.5, kelompok C).
     * Mengembalikan byte jawaban, atau null bila query dibuang
     * (kegagalan sudah dihitung + dilog pemanggil ini). Urutan rute
     * ada di [DnsRelayPolicy.route]; yang tidak bisa diparse (EDNS /
     * qtype aneh) atau yang jawaban lokalnya gagal diteruskan mentah
     * ke upstream UDP seperti v1.0.4.
     */
    private fun answerDnsQuery(query: ByteArray, dnsNo: Long, detail: Boolean): ByteArray? {
        val udpServers = listOf(dnsServer, dnsFallbackServer)
        val parsed = DnsResolver.parseQuery(query)
        if (parsed != null) {
            when (val route = dnsPolicy.route(parsed.name, parsed.qtype)) {
                is DnsRoute.Static -> {
                    // Keluarga tidak cocok (mis. AAAA untuk IPv4
                    // statis) -> buildResponse null -> upstream.
                    DnsResolver.buildResponse(query, listOf(route.address))
                        ?.let { return it }
                }
                DnsRoute.Fake -> {
                    val fake = dnsPolicy.fakeDns
                    if (fake != null) {
                        val ip = runCatching { fake.allocate(parsed.name) }.getOrNull()
                        if (ip != null) {
                            DnsResolver.buildResponse(
                                query, listOf(ip), FakeDns.DEFAULT_TTL_SECONDS,
                            )?.let { return it }
                        } else if (detail) {
                            DialLog.log(
                                "DNS",
                                "pool FakeDNS habis untuk query #$dnsNo — coba $dnsServer",
                            )
                        }
                    }
                }
                DnsRoute.Local -> {
                    DnsResolver.buildResponse(query, localResolve(parsed.name, parsed.qtype))
                        ?.let { return it }
                    if (detail) {
                        DialLog.log(
                            "DNS",
                            "lokal kosong untuk query #$dnsNo — coba $dnsServer",
                        )
                    }
                }
                DnsRoute.Domestic -> {
                    return forwardUdp(
                        query,
                        listOf(dnsPolicy.domesticDnsServer, dnsServer),
                        dnsNo,
                        detail,
                    )
                }
                DnsRoute.RemoteDoh -> {
                    val doh = dnsPolicy.dohClient
                    if (doh != null) {
                        val addrs = runCatching {
                            doh.query(parsed.name, parsed.qtype)
                        }.getOrNull()
                        DnsResolver.buildResponse(query, addrs ?: emptyList())
                            ?.let { return it }
                        if (detail) {
                            DialLog.log(
                                "DNS",
                                "DoH gagal/kosong untuk query #$dnsNo — coba $dnsServer",
                            )
                        }
                    }
                }
                DnsRoute.RemoteUdp -> Unit // lanjut ke UDP di bawah
            }
        }
        return forwardUdp(query, udpServers, dnsNo, detail)
    }

    /**
     * Resolve lokal (v1.0.5): [dnsPolicy.localResolve] bila
     * di-inject (tes), bila tidak hook operator [DnsResolver.operatorResolve]
     * (Network.getAllByName di jaringan fisik — lihat
     * [DnsResolver.networkResolveAll]). Kosong bila tidak ada yang
     * bisa dipakai — pemanggil fallback ke UDP upstream, bukan ke
     * resolver sistem mentah (yang akan masuk TUN dan berputar di
     * relay ini).
     */
    private fun localResolve(host: String, qtype: Int): List<InetAddress> {
        dnsPolicy.localResolve?.let {
            return runCatching { it(host, qtype) }.getOrElse { emptyList() }
        }
        val hook = DnsResolver.operatorResolve ?: return emptyList()
        return runCatching { hook(host, DnsResolver.DEFAULT_TIMEOUT_MS) }
            .getOrElse { emptyList() }
    }

    /**
     * Teruskan query mentah ke server UDP, satu per satu (v1.0.4):
     * primer dulu, lalu berikutnya saat timeout/gagal kirim. Baris
     * log dipertahankan verbatim (tes TunForwarderDnsTest mengunci
     * "timeout ... — coba ..." dan "timeout ... untuk query #N").
     * Mengembalikan byte jawaban, atau null bila semua server gagal
     * (sudah dihitung sebagai failure + dilog).
     */
    private fun forwardUdp(
        query: ByteArray,
        servers: List<String>,
        dnsNo: Long,
        detail: Boolean,
    ): ByteArray? {
        val distinct = servers.distinct()
        var bypassLogged = false
        for ((index, serverName) in distinct.withIndex()) {
            val last = index == distinct.lastIndex
            try {
                return udpExchange(query, serverName, dnsTimeoutMs) {
                    if (!bypassLogged) {
                        bypassLogged = true
                        if (detail) {
                            DialLog.log(
                                "PROTECT",
                                "protect() gagal — relay DNS lanjut via disallow aplikasi",
                            )
                        }
                    }
                }
            } catch (e: ProtectRefusedException) {
                // Bila protect GAGAL, query JANGAN dikirim: tanpa
                // protect query masuk lagi ke TUN, forwarder
                // melihatnya sebagai query baru, dan begitu
                // seterusnya — loop thread tak berujung. Sebelumnya
                // return value protectUdp diabaikan. Drop diam-diam;
                // aplikasi akan retry sendiri. v1.0.9: pengecualian
                // bila aplikasi di-disallow dari VPN
                // (TunnelState.appBypass) — query bypass di level
                // routing dan tidak bisa masuk TUN (pola v2rayNG;
                // di HP ini protect() mengembalikan false begitu
                // TUN naik, dan drop di sini mematikan DNS semua
                // aplikasi).
                dnsFailures.incrementAndGet()
                DialLog.log(
                    "DNS",
                    "GAGAL: protect() gagal tanpa disallow — query #$dnsNo dibuang",
                )
                return null
            } catch (e: java.net.SocketTimeoutException) {
                if (last) {
                    dnsFailures.incrementAndGet()
                    DialLog.failure(
                        "DNS",
                        java.io.IOException("timeout $serverName untuk query #$dnsNo"),
                    )
                    return null
                }
                if (detail) {
                    DialLog.log(
                        "DNS",
                        "timeout $serverName untuk query #$dnsNo — coba ${distinct[index + 1]}",
                    )
                }
            } catch (e: java.io.IOException) {
                // Gagal kirim / nama tak dikenal: server
                // ini tidak bisa dipakai, coba berikutnya.
                if (last) {
                    dnsFailures.incrementAndGet()
                    DialLog.failure(
                        "DNS",
                        java.io.IOException(
                            "gagal $serverName untuk query #$dnsNo: ${e.message}",
                        ),
                    )
                    return null
                }
                if (detail) {
                    DialLog.log(
                        "DNS",
                        "gagal $serverName untuk query #$dnsNo (${e.message}) — coba ${distinct[index + 1]}",
                    )
                }
            }
        }
        return null
    }

    /**
     * Satu pertukaran UDP ke satu server upstream. Bila
     * [DnsRelayPolicy.dnsExchange] di-inject (tes), pakai itu —
     * tanpa socket. Bila tidak, socket UDP ter-protect asli
     * (perilaku v1.0.4): protect yang ditolak tanpa disallow
     * melempar [ProtectRefusedException] (pemanggil membuang query);
     * protect yang ditolak DENGAN disallow lanjut — query bypass di
     * level routing (laporan sekali per query via [onProtectBypass]).
     */
    private fun udpExchange(
        query: ByteArray,
        server: String,
        timeoutMs: Int,
        onProtectBypass: () -> Unit,
    ): ByteArray {
        dnsPolicy.dnsExchange?.let {
            return it.exchange(query, server, dnsPort, timeoutMs)
        }
        val sock = DatagramSocket()
        try {
            val protected = protectUdp(sock)
            if (!protected && !TunnelState.appBypass) {
                throw ProtectRefusedException()
            }
            if (!protected) onProtectBypass()
            sock.soTimeout = timeoutMs
            sock.send(DatagramPacket(query, query.size, InetAddress.getByName(server), dnsPort))
            val buf = ByteArray(8192)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            return resp.data.copyOf(resp.length)
        } finally {
            sock.close()
        }
    }

    /** Protect ditolak dan aplikasi tidak di-disallow (lihat [udpExchange]). */
    private class ProtectRefusedException : java.io.IOException(
        "protect() gagal — query DNS tidak bisa bypass VPN",
    )

    private fun writePacket(pkt: ByteArray, len: Int = pkt.size) {
        // v1.0.18: no more synchronized(writeLock) + blocking
        // write() per segment on the caller thread (phone log:
        // tun=6046ms of an 8 s Speedtest connection). The single
        // writer thread (TunWriter) owns the fd; this only enqueues
        // (copying the bytes — the relay reuses pktBuf) and blocks
        // in put() when the queue is full (backpressure, no global
        // lock). The relay's `tun` stage now measures this enqueue.
        tunWriter.enqueue(pkt, len)
    }
}
