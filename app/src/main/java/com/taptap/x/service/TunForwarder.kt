package com.taptap.x.service

import com.taptap.x.core.DialLog
import com.taptap.x.core.TunnelState
import com.taptap.x.core.proto.DialWatchdog
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.core.proto.Transport
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
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
 *   DatagramSocket (bypasses the VPN), response wrapped back.
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
    }

    private val sessions = ConcurrentHashMap<Key, TcpSession>()
    private val writeLock = Any()
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
         * SYN-ACK MSS from the MTU (v1.0.13, fix A6): XVEON offers
         * clamp(tunMtu - 140, 1140, 1360), capped at the peer's
         * MSS — the old code echoed the peer MSS capped at 1460
         * and ignored the user's MTU setting entirely.
         */
        fun synAckMss(tunMtu: Int, peerMss: Int): Int =
            minOf(peerMss, (tunMtu - 140).coerceIn(1140, 1360))

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
        readerThread = thread(name = "tun-reader", isDaemon = true) { readLoop() }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { tunIn.close() }
        runCatching { tunOut.close() }
        sessions.values.toList().forEach { closeSession(it) }
        sessions.clear()
        DialLog.log(
            "FORWARDER",
            "berhenti (paket dibaca: ${packetsRead.get()}, " +
                "DNS: ${dnsQueries.get()} query / ${dnsFailures.get()} gagal)",
        )
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
        val ip = TcpPacket.parseIp(buf, len) ?: return
        when (ip.protocol) {
            TcpPacket.PROTO_TCP -> {
                val tcp = TcpPacket.parseTcp(ip.payload) ?: return
                logPacket("TCP", ip.src, tcp.srcPort, ip.dst, tcp.dstPort)
                handleTcp(ip, tcp)
            }
            TcpPacket.PROTO_UDP -> {
                val udp = TcpPacket.parseUdp(ip.payload) ?: return
                logPacket("UDP", ip.src, udp.srcPort, ip.dst, udp.dstPort)
                handleUdp(ip, udp)
            }
            TcpPacket.PROTO_ICMP -> {
                logPacket("ICMP", ip.src, 0, ip.dst, 0)
                val reply = TcpPacket.buildIcmpEchoReply(buf, len) ?: return
                writePacket(reply)
            }
            else -> Unit // IPv6 and the rest are dropped (M6).
        }
    }

    // ---- TCP ----

    private fun handleTcp(ip: TcpPacket.IpPacket, tcp: TcpPacket.TcpSegment) {
        val key = Key(ip.src, tcp.srcPort, ip.dst, tcp.dstPort)
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
                val offered = TcpPacket.parseTcpOptions(tcp.options)
                offered.mss?.let { s.peerMss = minOf(TcpPacket.TCP_MSS, it) }
                s.wsOffered = offered.windowScale != null
                s.sackOffered = offered.sackPermitted
                sessions[key] = s
                thread(name = "tun-dial-${tcp.dstPort}", isDaemon = true) { dial(s) }
            } else if (tcp.flags and TcpPacket.FLAG_ACK == 0) {
                // Stray non-ACK segment for an unknown connection: refuse.
                sendRst(ip, tcp)
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
                    session.outQueue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    return
                } ?: continue
                val batch = ArrayList<ByteArray>(MAX_WRITER_DRAIN)
                batch.add(first)
                while (batch.size < MAX_WRITER_DRAIN) {
                    val next = session.outQueue.poll() ?: break
                    batch.add(next)
                }
                for (chunk in batch) {
                    stream.output.write(chunk)
                }
                stream.output.flush()
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
        // v1.0.9: log EVERY attempt, not just failures. taptapx-6.txt
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
        try {
            watchdog.start()
            stream = proxy.dial(
                TcpPacket.ipToString(key.dstIp),
                key.dstPort,
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
        // Segments never exceed what the app's SYN offered (v1.0.10).
        val buf = ByteArray(session.peerMss.coerceIn(1, TcpPacket.TCP_MSS))
        try {
            while (!session.closed.get()) {
                val n = stream.input.read(buf)
                if (n == -1) break
                if (n > 0) {
                    val pkt = TcpPacket.buildTcp(
                        session.key.dstIp, session.key.srcIp,
                        session.key.dstPort, session.key.srcPort,
                        session.serverSeq, session.clientSeq,
                        TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK,
                        buf.copyOf(n),
                    )
                    writePacket(pkt)
                    session.serverSeq = (session.serverSeq + n) and 0xFFFFFFFFL
                }
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
        // v1.0.13, fix A6: the MSS we offer comes from the MTU
        // setting — clamp(tunMtu - 140, 1140, 1360), capped at the
        // peer's MSS (XVEON) — instead of the peer MSS alone.
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
        session.state = State.CLOSED
        sessions.remove(session.key)
        runCatching { session.stream?.close() }
    }

    private fun sendRst(ip: TcpPacket.IpPacket, tcp: TcpPacket.TcpSegment) {
        val pkt = TcpPacket.buildTcp(
            ip.dst, ip.src, tcp.dstPort, tcp.srcPort,
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
        thread(name = "tun-dns", isDaemon = true) {
            try {
                val sock = DatagramSocket()
                try {
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
                    val protected = protectUdp(sock)
                    if (!protected && !TunnelState.appBypass) {
                        dnsFailures.incrementAndGet()
                        DialLog.log(
                            "DNS",
                            "GAGAL: protect() gagal tanpa disallow — query #$dnsNo dibuang",
                        )
                        return@thread
                    }
                    if (!protected && detail) {
                        DialLog.log(
                            "PROTECT",
                            "protect() gagal — relay DNS lanjut via disallow aplikasi",
                        )
                    }
                    sock.soTimeout = dnsTimeoutMs
                    val server = InetAddress.getByName(dnsServer)
                    sock.send(DatagramPacket(query, query.size, server, 53))
                    val buf = ByteArray(8192)
                    val resp = DatagramPacket(buf, buf.size)
                    try {
                        sock.receive(resp)
                    } catch (e: java.net.SocketTimeoutException) {
                        dnsFailures.incrementAndGet()
                        DialLog.failure(
                            "DNS",
                            java.io.IOException("timeout $dnsServer untuk query #$dnsNo"),
                        )
                        return@thread
                    }
                    val respBytes = resp.data.copyOf(resp.length)
                    val pkt = TcpPacket.buildUdp(dstIp, srcIp, 53, srcPort, respBytes)
                    writePacket(pkt)
                    if (detail) {
                        dnsLogged.incrementAndGet()
                        DialLog.log(
                            "DNS",
                            "jawab ${TcpPacket.ipToString(dstIp)} ${respBytes.size}B ke " +
                                "${TcpPacket.ipToString(srcIp)}:$srcPort (#$dnsNo)",
                        )
                    }
                } finally {
                    sock.close()
                }
            } catch (e: Exception) {
                dnsFailures.incrementAndGet()
                DialLog.failure("DNS", e)
            }
        }
    }

    private fun writePacket(pkt: ByteArray) {
        synchronized(writeLock) {
            runCatching {
                tunOut.write(pkt)
                tunOut.flush()
            }
        }
    }
}
