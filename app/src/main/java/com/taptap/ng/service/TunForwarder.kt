package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsExchange
import com.taptap.ng.core.DnsRelayPolicy
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.DnsRoute
import com.taptap.ng.core.FakeDns
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.core.proto.Transport
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
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
 *   Other UDP is dropped.
 * - ICMP echo request: answered locally.
 * - IPv6: dropped (M6).
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
) {

    private enum class State { DIALING, SYN_SENT, ESTABLISHED, CLOSED }

    private data class Key(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)

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
        const val WRITER_POLL_MS = 1000L

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
        fun maxMssForMtu(tunMtu: Int): Int =
            (tunMtu - 40).coerceIn(1140, MAX_SEGMENT_MSS)

        /**
         * Max wire bytes of one relay TCP segment at the biggest
         * MSS (v1.0.21): IP + TCP headers + [MAX_SEGMENT_MSS].
         * The relay's reusable packet buffer is sized by this, not
         * by the old 1500-byte [TcpPacket.MAX_TCP_SEGMENT_BYTES].
         */
        const val MAX_PACKET_BYTES = 40 + MAX_SEGMENT_MSS

        /**
         * SYN-ACK MSS from the MTU (v1.0.15, ceiling raised
         * v1.0.21): [maxMssForMtu], capped at the peer's MSS.
         * XVEON used clamp(tunMtu − 140, 1140, 1360) — the extra
         * 100 bytes guarded the OUTER tunnel overhead, which does
         * not apply to the local TUN link (the IP packet is
         * 20 + 20 + MSS ≤ tunMtu either way).
         */
        fun synAckMss(tunMtu: Int, peerMss: Int): Int =
            minOf(peerMss, maxMssForMtu(tunMtu))

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

    fun start() {
        if (!running.compareAndSet(false, true)) return
        DialLog.log("FORWARDER", "mulai — baca TUN")
        // v1.0.21: one line proving the MTU/MSS the TUN came up
        // with — the phone log must show whether the app actually
        // gets the big MTU (mtu=9000 mss=8960) or falls back.
        DialLog.log("TUN", "mtu=$tunMtu mss=${maxMssForMtu(tunMtu)}")
        tunWriter.start()
        readerThread = thread(name = "tun-reader", isDaemon = true) { readLoop() }
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

    private fun handlePacket(buf: ByteArray, len: Int) {
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
                handleTcp(ipH.src, ipH.dst, tcp)
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
            else -> Unit // IPv6 and the rest are dropped (M6).
        }
    }

    // ---- TCP ----

    private fun handleTcp(srcIp: Int, dstIp: Int, tcp: TcpPacket.TcpSegment) {
        val key = Key(srcIp, tcp.srcPort, dstIp, tcp.dstPort)
        val session = sessions[key]
        if (tcp.flags and TcpPacket.FLAG_RST != 0) {
            if (session != null) closeSession(session)
            return
        }
        if (session == null) {
            if (tcp.flags and TcpPacket.FLAG_SYN != 0) {
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
                offered.mss?.let { s.peerMss = minOf(maxMssForMtu(tunMtu), it) }
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
                val batch = ArrayList<ByteArray>(MAX_WRITER_DRAIN)
                batch.add(first)
                while (batch.size < MAX_WRITER_DRAIN) {
                    val next = session.outQueue.poll() ?: break
                    batch.add(next)
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
        val dst = "${TcpPacket.ipToString(key.dstIp)}:${key.dstPort}"
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
        try {
            watchdog.start()
            // v1.0.5 (DNS C, FakeDNS): tujuan IP fake dipetakan balik
            // ke hostname aslinya SEBELUM dial — server proxy yang
            // me-resolve hostname itu (ProxyClient tidak pernah
            // resolve lokal). Bukan IP fake yang dikirim: IP fake
            // tidak ada artinya di luar TUN ini. Satu baris ini saja
            // yang menyentuh jalur TCP; state machine / relay paket
            // tidak berubah.
            val dialHost = dnsPolicy.fakeDns?.lookupHost(key.dstIp)?.also {
                DialLog.log("DNS", "fake $dst -> $it")
            } ?: TcpPacket.ipToString(key.dstIp)
            stream = proxy.dial(
                dialHost,
                key.dstPort,
                stats = speed,
            )
        } catch (e: Exception) {
            sessions.remove(key)
            DialLog.failure("DIAL $dst", e)
            // v1.0.4: report the failure instead of silently RST-ing
            // every dial while the status stays "Connecting..." forever.
            reportDialFailure(e)
            // Refuse the connection: RST|ACK.
            val rst = TcpPacket.buildTcp(
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
        val dst = "${TcpPacket.ipToString(session.key.dstIp)}:${session.key.dstPort}"
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
        val pktBuf = ByteArray(MAX_PACKET_BYTES)
        // Segments never exceed what the app's SYN offered
        // (v1.0.10); coerce to >= 1 like the old code did — a
        // peer MSS of 0 would otherwise emit zero-length segments
        // forever (pos never advances). v1.0.21: cap at the
        // MTU-derived max, not the old 1460.
        val segMss = session.peerMss.coerceIn(1, maxMssForMtu(tunMtu))
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
                val pktLen = TcpPacket.buildTcpInto(
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
        val pkt = TcpPacket.buildTcp(
            key.dstIp, key.srcIp, key.dstPort, key.srcPort,
            session.isn, session.clientSeq,
            TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK,
            ByteArray(0),
            mss = synAckMss(tunMtu, session.peerMss),
            options = extra.toByteArray(),
            window = window,
        )
        writePacket(pkt)
        session.serverSeq = (session.isn + 1) and 0xFFFFFFFFL
    }

    private fun sendAck(session: TcpSession) {
        val key = session.key
        val pkt = TcpPacket.buildTcp(
            key.dstIp, key.srcIp, key.dstPort, key.srcPort,
            session.serverSeq, session.clientSeq,
            TcpPacket.FLAG_ACK, ByteArray(0),
        )
        writePacket(pkt)
    }

    /** Send FIN|ACK and tear the session down (single-shot). */
    private fun sendFin(session: TcpSession) {
        if (!session.closed.compareAndSet(false, true)) return
        logSpeedSummary(session)
        val key = session.key
        val pkt = TcpPacket.buildTcp(
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
        if (snap.downBytes == 0L && snap.upBytes == 0L) return
        val wallMs = System.currentTimeMillis() - session.speedStartMs
        val dst = "${TcpPacket.ipToString(session.key.dstIp)}:${session.key.dstPort}"
        DialLog.log("SPEED", SpeedStats.totalLine(snap, dst, wallMs))
    }

    private fun sendRst(srcIp: Int, dstIp: Int, tcp: TcpPacket.TcpSegment) {
        val pkt = TcpPacket.buildTcp(
            dstIp, srcIp, tcp.dstPort, tcp.srcPort,
            0, (tcp.seq + 1) and 0xFFFFFFFFL,
            TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK, ByteArray(0),
        )
        writePacket(pkt)
    }

    // ---- UDP (DNS only) ----

    private fun handleUdp(ip: TcpPacket.IpPacket, udp: TcpPacket.UdpDatagram) {
        if (udp.dstPort != 53) return
        val query = udp.payload
        val srcIp = ip.src
        val srcPort = udp.srcPort
        val dstIp = ip.dst
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
                "query ${TcpPacket.ipToString(dstIp)} ${query.size}B dari " +
                    "${TcpPacket.ipToString(srcIp)}:$srcPort (#$dnsNo)",
            )
        }
        dnsExecutor.execute {
            try {
                // v1.0.5 (DNS C): jawab lewat kebijakan relay
                // (statis / FakeDNS / lokal / domestik / DoH / UDP).
                // null = query dibuang (kegagalan sudah dihitung +
                // dilog di bawah); bukan jawaban kosong.
                val respBytes = answerDnsQuery(query, dnsNo, detail) ?: return@execute
                val pkt = TcpPacket.buildUdp(dstIp, srcIp, 53, srcPort, respBytes)
                writePacket(pkt)
                if (detail) {
                    // v1.0.4: dnsLogged hanya naik sekali per
                    // query (di baris query di atas) — sebelumnya
                    // naik dua kali, jadi batas "5 query pertama"
                    // sebenarnya ~2–3 query.
                    DialLog.log(
                        "DNS",
                        "jawab ${TcpPacket.ipToString(dstIp)} ${respBytes.size}B ke " +
                            "${TcpPacket.ipToString(srcIp)}:$srcPort (#$dnsNo)",
                    )
                }
            } catch (e: Exception) {
                dnsFailures.incrementAndGet()
                DialLog.failure("DNS", e)
            }
        }
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
