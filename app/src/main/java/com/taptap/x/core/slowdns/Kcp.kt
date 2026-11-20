package com.taptap.x.core.slowdns

/**
 * KCP state machine — faithful Kotlin port of kcp.go from
 * github.com/metacubex/kcp-go (v0.0.0-20260105040817-550693377604).
 *
 * Pure state machine, no I/O inside: datagrams come in via [input],
 * go out via the [output] callback, and the caller drives timing via
 * [update]/[check]. No Android imports, JDK only.
 *
 * All uint32 wire/state values are held as Kotlin [Int] bit patterns:
 * Int arithmetic wraps exactly like Go uint32 arithmetic, and
 * [timediff] reinterprets the wrapped difference as signed, which is
 * exactly Go's `_itimediff` (`int32(later - earlier)`). The only
 * places that need unsigned magnitude are the 0xFFFFFFFF fastack
 * sentinel comparisons, which use masked Longs.
 *
 * Two deliberate adaptations to the Go original (both forced by the
 * Kotlin API shape, not by behaviour):
 * - Go's `Update()`/`Check()`/`flush()`/`Input()` read the clock from
 *   `currentMs()` (monotonic ms since process start). Here the clock
 *   is the `nowMs` argument of [update]/[check] (low 32 bits), kept
 *   in [now32] and reused by [input]/[flush], so tests can drive a
 *   virtual clock. Initialised from `System.currentTimeMillis()` so
 *   [input] works before the first [update].
 * - Go's `Input(data, pktType, ackNoDelay)` takes a packet type and an
 *   ack-no-delay flag; this port always treats packets as regular and
 *   ackNoDelay=false, matching [input]'s signature.
 * - Go's `Send` does not check the dead state; [send] returns -1 once
 *   [isDead], per this API's contract ("negative on error, e.g. state
 *   dead").
 *
 * Segment header (24 bytes, little-endian):
 * conv(4) | cmd(1) | frg(1) | wnd(2) | ts(4) | sn(4) | una(4) | len(4) | data
 */
class Kcp(conv: Int, private val output: (ByteArray) -> Unit) {

    companion object {
        const val CMD_PUSH = 81
        const val CMD_ACK = 82
        const val CMD_WASK = 83
        const val CMD_WINS = 84

        const val ASK_SEND = 1 // need to send CMD_WASK
        const val ASK_TELL = 2 // need to send CMD_WINS

        const val RTO_NDL = 30
        const val RTO_MIN = 100
        const val RTO_DEF = 200
        const val RTO_MAX = 60000
        const val WND_SND = 32
        const val WND_RCV = 32
        const val MTU_DEF = 1400
        const val ACK_FAST = 3
        const val INTERVAL = 100
        const val OVERHEAD = 24
        const val DEADLINK = 20
        const val THRESH_INIT = 2
        const val THRESH_MIN = 2
        const val PROBE_INIT = 500
        const val PROBE_LIMIT = 120000

        private const val FLUSH_ACKONLY = 1
        private const val FLUSH_FULL = 2
        private const val FASTACK_SENTINEL = -1 // 0xFFFFFFFF as Int bit pattern
    }

    // ---- wire/state (uint32 values held as Int bit patterns) ----
    private var conv: Int = conv
    private var mtu: Int = MTU_DEF
    private var mss: Int = MTU_DEF - OVERHEAD
    private var state: Int = 0 // 0xFFFFFFFF (-1) once dead

    private var sndUna: Int = 0
    private var sndNxt: Int = 0
    private var rcvNxt: Int = 0

    private var ssthresh: Int = THRESH_INIT
    private var rxRttvar: Int = 0
    private var rxSrtt: Int = 0
    private var rxRto: Int = RTO_DEF
    private var rxMinrto: Int = RTO_MIN

    private var sndWnd: Int = WND_SND
    private var rcvWnd: Int = WND_RCV
    private var rmtWnd: Int = WND_RCV
    private var cwnd: Int = 0 // Go NewKCP leaves this 0; flush() raises it to 1
    private var probe: Int = 0

    private var interval: Int = INTERVAL
    private var tsFlush: Int = INTERVAL
    private var nodelay: Int = 0
    private var updated: Int = 0
    private var tsProbe: Int = 0
    private var probeWait: Int = 0
    private var deadLink: Int = DEADLINK
    private var incr: Int = 0

    private var fastresend: Int = 0
    private var nocwnd: Int = 0
    private var stream: Int = 0

    private val sndQueue = ArrayDeque<Segment>()
    private val rcvQueue = ArrayDeque<Segment>()
    private val sndBuf = ArrayDeque<Segment>()
    // Min-heap by sn (wrapping order via timediff) + membership set,
    // mirroring Go's segmentHeap (heap + marks map).
    private val rcvBuf = java.util.PriorityQueue<Segment>(Comparator<Segment> { a, b -> timediff(a.sn, b.sn) })
    private val rcvBufMarks = HashSet<Int>()

    private val acklist = ArrayList<AckItem>()

    private var buffer: ByteArray = ByteArray(mtu)

    // Clock: low 32 bits of the last nowMs passed to update()/check().
    private var now32: Int = (System.currentTimeMillis() and 0xFFFFFFFFL).toInt()

    /** True once a segment's xmit count reached [deadLink] (state == 0xFFFFFFFF). */
    val isDead: Boolean get() = state == -1

    // ---- segment ----

    private class Segment(
        var conv: Int = 0,
        var cmd: Int = 0,
        var frg: Int = 0,
        var wnd: Int = 0,
        var ts: Int = 0,
        var sn: Int = 0,
        var una: Int = 0,
        var rto: Int = 0,
        var xmit: Int = 0,
        var resendts: Int = 0,
        var fastack: Int = 0,
        var acked: Int = 0,
        var data: ByteArray? = null,
    )

    private class AckItem(val sn: Int, val ts: Int)

    // ---- helpers (Go _itimediff / _imin_ / _imax_ / _ibound_) ----

    /** Go `_itimediff(later, earlier)`: (int32)(later - earlier). Int wraps identically. */
    private fun timediff(later: Int, earlier: Int): Int = later - earlier

    private fun ibound(lower: Int, middle: Int, upper: Int): Int =
        minOf(maxOf(lower, middle), upper)

    private fun put16(buf: ByteArray, off: Int, v: Int): Int {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
        return off + 2
    }

    private fun put32(buf: ByteArray, off: Int, v: Int): Int {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 3] = ((v ushr 24) and 0xFF).toByte()
        return off + 4
    }

    private fun get16(buf: ByteArray, off: Int): Int =
        (buf[off].toInt() and 0xFF) or ((buf[off + 1].toInt() and 0xFF) shl 8)

    private fun get32(buf: ByteArray, off: Int): Int =
        (buf[off].toInt() and 0xFF) or
            ((buf[off + 1].toInt() and 0xFF) shl 8) or
            ((buf[off + 2].toInt() and 0xFF) shl 16) or
            ((buf[off + 3].toInt() and 0xFF) shl 24)

    /** Encode one segment header at [off]; returns the offset past the header. */
    private fun encodeSeg(
        buf: ByteArray, off: Int,
        conv: Int, cmd: Int, frg: Int, wnd: Int,
        ts: Int, sn: Int, una: Int, len: Int,
    ): Int {
        var p = put32(buf, off, conv)
        buf[p++] = (cmd and 0xFF).toByte()
        buf[p++] = (frg and 0xFF).toByte()
        p = put16(buf, p, wnd)
        p = put32(buf, p, ts)
        p = put32(buf, p, sn)
        p = put32(buf, p, una)
        p = put32(buf, p, len)
        return p
    }

    // ---- configuration (Go NoDelay / SetMtu / WndSize / SetStreamMode) ----

    /**
     * Go `NoDelay(nodelay, interval, resend, nc)`:
     * nodelay != 0 -> rx_minrto = RTO_NDL (30), else RTO_MIN (100);
     * interval clamped to [10, 5000]; resend -> fastresend; nc -> nocwnd.
     */
    fun setNoDelay(nodelay: Int, interval: Int, resend: Int, nc: Int) {
        if (nodelay >= 0) {
            this.nodelay = nodelay
            rxMinrto = if (nodelay != 0) RTO_NDL else RTO_MIN
        }
        if (interval >= 0) {
            var iv = interval
            if (iv > 5000) iv = 5000 else if (iv < 10) iv = 10
            this.interval = iv
        }
        if (resend >= 0) fastresend = resend
        if (nc >= 0) nocwnd = nc
    }

    /** Go `SetMtu`: ignored unless mtu >= 50 (and >= OVERHEAD); mss = mtu - 24. */
    fun setMtu(mtu: Int) {
        if (mtu < 50 || mtu < OVERHEAD) return
        this.mtu = mtu
        mss = mtu - OVERHEAD
        buffer = ByteArray(mtu)
    }

    /** Go `WndSize`: each side applied only when > 0. */
    fun setWindowSize(sndWnd: Int, rcvWnd: Int) {
        if (sndWnd > 0) this.sndWnd = sndWnd
        if (rcvWnd > 0) this.rcvWnd = rcvWnd
    }

    /** Go `SetStreamMode`: stream mode appends to the last partial segment. */
    fun setStreamMode(stream: Boolean) {
        this.stream = if (stream) 1 else 0
    }

    // ---- PeekSize / Recv ----

    /** Go `PeekSize`: bytes of the next complete message, or -1 if none. */
    fun peekSize(): Int {
        val seg = rcvQueue.firstOrNull() ?: return -1
        if (seg.frg == 0) return seg.data?.size ?: 0
        if (rcvQueue.size < seg.frg + 1) return -1
        var length = 0
        for (s in rcvQueue) {
            length += s.data?.size ?: 0
            if (s.frg == 0) break
        }
        return length
    }

    /**
     * Go `Recv`: bytes copied, -1 when no readable data, -2 when
     * [buf] is smaller than [peekSize]. In stream mode each segment
     * has frg == 0, so one call returns one segment; small chunks
     * merge on the [send] side (append to the last partial segment).
     */
    fun recv(buf: ByteArray): Int {
        val peeksize = peekSize()
        if (peeksize < 0) return -1
        if (peeksize > buf.size) return -2

        var fastRecover = false
        if (rcvQueue.size >= rcvWnd) fastRecover = true

        // Merge fragments until frg == 0.
        var n = 0
        while (true) {
            val seg = rcvQueue.removeFirstOrNull() ?: break
            val d = seg.data ?: ByteArray(0)
            d.copyInto(buf, n)
            n += d.size
            if (seg.frg == 0) break
        }

        // Move available data from rcv_buf -> rcv_queue.
        while (true) {
            val seg = rcvBuf.peek() ?: break
            if (seg.sn == rcvNxt && rcvQueue.size < rcvWnd) {
                rcvBuf.poll()
                rcvBufMarks.remove(seg.sn)
                rcvQueue.addLast(seg)
                rcvNxt++
            } else {
                break
            }
        }

        // Fast recover: receive window freed up, tell the peer.
        if (rcvQueue.size < rcvWnd && fastRecover) probe = probe or ASK_TELL
        return n
    }

    // ---- Send ----

    /**
     * Go `Send`: 0 ok, -1 on empty input (or once [isDead]), -2 when
     * the message needs more than 255 fragments.
     */
    fun send(data: ByteArray): Int {
        if (isDead) return -1
        var rest = data
        if (rest.isEmpty()) return -1

        // Stream mode: append to the previous (last) partial segment if possible.
        if (stream != 0) {
            val last = sndQueue.lastOrNull()
            if (last != null) {
                val lastData = last.data ?: ByteArray(0)
                if (lastData.size < mss) {
                    val capacity = mss - lastData.size
                    val extend = minOf(rest.size, capacity)
                    val merged = ByteArray(lastData.size + extend)
                    lastData.copyInto(merged)
                    rest.copyInto(merged, lastData.size, 0, extend)
                    last.data = merged
                    rest = rest.copyOfRange(extend, rest.size)
                }
            }
            if (rest.isEmpty()) return 0
        }

        val count = if (rest.size <= mss) 1 else (rest.size + mss - 1) / mss
        if (count > 255) return -2

        var offset = 0
        for (i in 0 until count) {
            val size = minOf(rest.size - offset, mss)
            val seg = Segment(data = rest.copyOfRange(offset, offset + size))
            seg.frg = if (stream == 0) count - i - 1 else 0
            sndQueue.addLast(seg)
            offset += size
        }
        return 0
    }

    // ---- ACK / RTT / una parsing ----

    private fun updateAck(rtt: Int) {
        // https://tools.ietf.org/html/rfc6298
        if (rxSrtt == 0) {
            rxSrtt = rtt
            rxRttvar = rtt shr 1
        } else {
            var delta = rtt - rxSrtt
            rxSrtt += delta shr 3
            if (delta < 0) delta = -delta
            if (rtt < rxSrtt - rxRttvar) {
                rxRttvar += (delta - rxRttvar) shr 5
            } else {
                rxRttvar += (delta - rxRttvar) shr 2
            }
        }
        val rto = rxSrtt + maxOf(interval, rxRttvar shl 2)
        rxRto = ibound(rxMinrto, rto, RTO_MAX)
    }

    private fun shrinkBuf() {
        sndUna = sndBuf.firstOrNull()?.sn ?: sndNxt
    }

    private fun parseAck(sn: Int) {
        if (timediff(sn, sndUna) < 0 || timediff(sn, sndNxt) >= 0) return
        for (seg in sndBuf) {
            if (sn == seg.sn) {
                // Mark and free space, but leave the segment here until `una`
                // deletes it, so segments behind need no shifting.
                seg.acked = 1
                seg.data = null
                return
            }
            if (timediff(sn, seg.sn) < 0) return
        }
    }

    private fun parseFastack(sn: Int, ts: Int): Int {
        var shouldFastAck = 0
        if (timediff(sn, sndUna) < 0 || timediff(sn, sndNxt) >= 0) return 0
        for (seg in sndBuf) {
            if (timediff(sn, seg.sn) < 0) return shouldFastAck
            if (sn != seg.sn && timediff(seg.ts, ts) <= 0) {
                if (seg.fastack != FASTACK_SENTINEL) {
                    seg.fastack++
                    if ((seg.fastack.toLong() and 0xFFFFFFFFL) >= fastresend.toLong()) {
                        shouldFastAck = 1
                    }
                }
            }
        }
        return shouldFastAck
    }

    private fun parseUna(una: Int): Int {
        var count = 0
        for (seg in sndBuf) {
            if (timediff(una, seg.sn) > 0) {
                seg.data = null
                count++
            } else {
                break
            }
        }
        repeat(count) { sndBuf.removeFirst() }
        return count
    }

    private fun ackPush(sn: Int, ts: Int) {
        acklist.add(AckItem(sn, ts))
    }

    /** Returns true if the data has repeated (out of window / duplicate). */
    private fun parseData(newseg: Segment): Boolean {
        val sn = newseg.sn
        if (timediff(sn, rcvNxt + rcvWnd) >= 0 || timediff(sn, rcvNxt) < 0) {
            return true
        }
        val repeat = false
        if (!rcvBufMarks.contains(sn)) {
            // Replicate the content: the caller's datagram buffer is not retained.
            newseg.data = newseg.data?.copyOf()
            rcvBuf.add(newseg)
            rcvBufMarks.add(sn)
        }
        // Move available data from rcv_buf -> rcv_queue.
        while (true) {
            val seg = rcvBuf.peek() ?: break
            if (seg.sn == rcvNxt && rcvQueue.size < rcvWnd) {
                rcvBuf.poll()
                rcvBufMarks.remove(seg.sn)
                rcvQueue.addLast(seg)
                rcvNxt++
            } else {
                break
            }
        }
        return repeat
    }

    // ---- Input ----

    /**
     * Go `Input` (regular packets, ackNoDelay=false): feed one received
     * datagram. Returns 0 ok, -1 on conv mismatch (whole datagram
     * dropped) or a datagram shorter than the 24-byte header, -2 on a
     * truncated segment, -3 on an unknown command.
     */
    fun input(data: ByteArray): Int {
        val sndUnaBefore = sndUna
        if (data.size < OVERHEAD) return -1

        var latest = 0
        var updateRtt = false
        var flushSegments = 0

        var pos = 0
        while (true) {
            if (data.size - pos < OVERHEAD) break

            val conv = get32(data, pos); pos += 4
            if (conv != this.conv) return -1
            val cmd = data[pos++].toInt() and 0xFF
            val frg = data[pos++].toInt() and 0xFF
            val wnd = get16(data, pos); pos += 2
            val ts = get32(data, pos); pos += 4
            val sn = get32(data, pos); pos += 4
            val una = get32(data, pos); pos += 4
            // len is uint32: treat it unsigned, or a huge/truncated
            // length would go negative as an Int (Go returns -2).
            val lengthU = get32(data, pos).toLong() and 0xFFFFFFFFL; pos += 4

            if (lengthU > (data.size - pos)) return -2
            val length = lengthU.toInt()
            if (cmd != CMD_PUSH && cmd != CMD_ACK && cmd != CMD_WASK && cmd != CMD_WINS) {
                return -3
            }

            // Only trust window updates from regular packets.
            rmtWnd = wnd
            if (parseUna(una) > 0) flushSegments = flushSegments or 1
            shrinkBuf()

            when (cmd) {
                CMD_ACK -> {
                    parseAck(sn)
                    flushSegments = flushSegments or parseFastack(sn, ts)
                    updateRtt = true
                    latest = ts
                }
                CMD_PUSH -> {
                    var repeat = true
                    if (timediff(sn, rcvNxt + rcvWnd) < 0) {
                        ackPush(sn, ts)
                        if (timediff(sn, rcvNxt) >= 0) {
                            val seg = Segment(
                                conv = conv, cmd = cmd, frg = frg, wnd = wnd,
                                ts = ts, sn = sn, una = una,
                                data = data.copyOfRange(pos, pos + length),
                            )
                            repeat = parseData(seg)
                        }
                    }
                    @Suppress("UNUSED_VARIABLE")
                    val unusedRepeat = repeat // Go counts RepeatSegs in SNMP; no counter here.
                }
                CMD_WASK -> {
                    // Ready to send back CMD_WINS in flush().
                    probe = probe or ASK_TELL
                }
                CMD_WINS -> {
                    // Nothing to do.
                }
                else -> return -3
            }

            pos += length
        }

        // Update RTT with the latest ts.
        if (updateRtt) {
            if (timediff(now32, latest) >= 0) {
                updateAck(timediff(now32, latest))
            }
        }

        // Congestion-window update when a packet arrived.
        if (nocwnd == 0) {
            if (timediff(sndUna, sndUnaBefore) > 0) {
                if (cwnd < rmtWnd) {
                    if (cwnd < ssthresh) {
                        cwnd++
                        incr += mss
                    } else {
                        if (incr < mss) incr = mss
                        incr += (mss * mss) / incr + (mss / 16)
                        if ((cwnd + 1) * mss <= incr) {
                            cwnd = if (mss > 0) (incr + mss - 1) / mss else incr + mss - 1
                        }
                    }
                    if (cwnd > rmtWnd) {
                        cwnd = rmtWnd
                        incr = rmtWnd * mss
                    }
                }
            }
        }

        // Determine if we need to flush data segments or acks.
        if (flushSegments != 0) {
            flush(FLUSH_FULL)
        } else if (acklist.size >= mtu / OVERHEAD) {
            // Clocking: too many acks pending, send them out immediately.
            flush(FLUSH_ACKONLY)
        }
        return 0
    }

    private fun wndUnused(): Int {
        return if (rcvQueue.size < rcvWnd) (rcvWnd - rcvQueue.size) and 0xFFFF else 0
    }

    // ---- Flush ----

    /**
     * Go `flush`: emits pending ACKs, window probes (WASK/WINS with
     * exponential backoff probe_wait 500ms -> 120s), moves snd_queue
     * -> snd_buf up to cwnd, and (re)transmits snd_buf segments
     * (initial / fast / early / RTO). xmit >= dead_link marks the
     * state dead. Returns the ms until the next retransmit is due
     * (Go's nextUpdate; [update] ignores it, like Go's `Update`).
     */
    private fun flush(flushType: Int): Int {
        val wnd = wndUnused()
        val una = rcvNxt
        // Go reuses one `seg` header for ACK/WASK/WINS; sn/ts carry over
        // from the last ACK emitted (0 when no ACK was emitted).
        var hdrSn = 0
        var hdrTs = 0

        val buf = buffer
        var ptr = 0

        fun makeSpace(space: Int) {
            if (ptr + space > mtu) {
                if (ptr > 0) output(buf.copyOfRange(0, ptr))
                ptr = 0
            }
        }

        try {
            // Flush acknowledgements.
            if (flushType == FLUSH_ACKONLY || flushType == FLUSH_FULL) {
                for ((i, ack) in acklist.withIndex()) {
                    makeSpace(OVERHEAD)
                    // Filter jitters caused by bufferbloat: skip stale acks
                    // except the last one.
                    if (timediff(ack.sn, rcvNxt) >= 0 || acklist.size - 1 == i) {
                        hdrSn = ack.sn
                        hdrTs = ack.ts
                        ptr = encodeSeg(buf, ptr, conv, CMD_ACK, 0, wnd, ack.ts, ack.sn, una, 0)
                    }
                }
                acklist.clear()
            }

            // Probe window size (if remote window size equals zero).
            if (rmtWnd == 0) {
                if (probeWait == 0) {
                    probeWait = PROBE_INIT
                    tsProbe = now32 + probeWait
                } else if (timediff(now32, tsProbe) >= 0) {
                    if (probeWait < PROBE_INIT) probeWait = PROBE_INIT
                    probeWait += probeWait / 2
                    if (probeWait > PROBE_LIMIT) probeWait = PROBE_LIMIT
                    tsProbe = now32 + probeWait
                    probe = probe or ASK_SEND
                }
            } else {
                tsProbe = 0
                probeWait = 0
            }

            // Flush window probing commands.
            if ((probe and ASK_SEND) != 0) {
                makeSpace(OVERHEAD)
                ptr = encodeSeg(buf, ptr, conv, CMD_WASK, 0, wnd, hdrTs, hdrSn, una, 0)
            }
            if ((probe and ASK_TELL) != 0) {
                makeSpace(OVERHEAD)
                ptr = encodeSeg(buf, ptr, conv, CMD_WINS, 0, wnd, hdrTs, hdrSn, una, 0)
            }
            probe = 0

            // Calculate window size.
            var cwndLocal = minOf(sndWnd, rmtWnd)
            if (nocwnd == 0) cwndLocal = minOf(cwnd, cwndLocal)

            // Sliding window, controlled by snd_nxt && snd_una + cwnd.
            var newSegsCount = 0
            while (true) {
                if (timediff(sndNxt, sndUna + cwndLocal) >= 0) break
                val newseg = sndQueue.removeFirstOrNull() ?: break
                newseg.conv = conv
                newseg.cmd = CMD_PUSH
                newseg.sn = sndNxt
                sndBuf.addLast(newseg)
                sndNxt++
                newSegsCount++
            }

            // Calculate resent.
            val resentU: Long = if (fastresend <= 0) 0xFFFFFFFFL else fastresend.toLong()

            // Flush segments.
            var nextUpdate = interval
            var change = 0L
            var lostSegs = 0L
            var fastRetransSegs = 0L
            var earlyRetransSegs = 0L
            if (flushType == FLUSH_FULL) {
                val current = now32
                for (segment in sndBuf) {
                    if (segment.acked == 1) continue
                    var needsend = false
                    val fastackU = segment.fastack.toLong() and 0xFFFFFFFFL
                    if (segment.xmit == 0) {
                        // Initial transmit.
                        needsend = true
                        segment.rto = rxRto
                        segment.resendts = current + segment.rto
                    } else if (fastackU >= resentU && segment.fastack != FASTACK_SENTINEL) {
                        // Fast retransmit.
                        needsend = true
                        segment.fastack = FASTACK_SENTINEL // must wait until RTO to reset
                        segment.rto = rxRto
                        segment.resendts = current + segment.rto
                        change++
                        fastRetransSegs++
                    } else if (segment.fastack > 0 && segment.fastack != FASTACK_SENTINEL &&
                        newSegsCount == 0
                    ) {
                        // Early retransmit.
                        needsend = true
                        segment.fastack = FASTACK_SENTINEL
                        segment.rto = rxRto
                        segment.resendts = current + segment.rto
                        change++
                        earlyRetransSegs++
                    } else if (timediff(current, segment.resendts) >= 0) {
                        // RTO.
                        needsend = true
                        segment.rto += if (nodelay == 0) rxRto else rxRto / 2
                        segment.fastack = 0
                        segment.resendts = current + segment.rto
                        lostSegs++
                    }

                    if (needsend) {
                        segment.xmit++
                        segment.ts = current
                        segment.wnd = wnd
                        segment.una = una

                        val segData = segment.data ?: ByteArray(0)
                        val need = OVERHEAD + segData.size
                        makeSpace(need)
                        ptr = encodeSeg(
                            buf, ptr, segment.conv, segment.cmd, segment.frg,
                            segment.wnd, segment.ts, segment.sn, segment.una, segData.size,
                        )
                        segData.copyInto(buf, ptr)
                        ptr += segData.size

                        if (segment.xmit >= deadLink) state = -1
                    }

                    // Get the nearest rto.
                    val rtoDiff = timediff(segment.resendts, current)
                    if (rtoDiff > 0 && rtoDiff < nextUpdate) nextUpdate = rtoDiff
                }
            }

            // Congestion-window update (Go RFC 6937 rate halving + RFC 5681).
            if (nocwnd == 0) {
                if (change > 0) {
                    val inflight = sndNxt - sndUna
                    ssthresh = inflight / 2
                    if (ssthresh < THRESH_MIN) ssthresh = THRESH_MIN
                    cwnd = ssthresh + resentU.toInt()
                    incr = cwnd * mss
                }
                if (lostSegs > 0) {
                    ssthresh = cwndLocal / 2
                    if (ssthresh < THRESH_MIN) ssthresh = THRESH_MIN
                    cwnd = 1
                    incr = mss
                }
                if (cwnd < 1) {
                    cwnd = 1
                    incr = mss
                }
            }
            @Suppress("UNUSED_VARIABLE")
            val unusedRetrans = fastRetransSegs + earlyRetransSegs + lostSegs // Go counts these in SNMP.
            return nextUpdate
        } finally {
            if (ptr > 0) output(buf.copyOfRange(0, ptr))
        }
    }

    // ---- Update / Check ----

    /**
     * Go `Update` (deprecated upstream, kept as the driver): call
     * repeatedly; [nowMs] is wall-clock ms — pass
     * `System.currentTimeMillis() and 0xFFFFFFFFL`. Flushes when the
     * interval has elapsed since the last flush.
     */
    fun update(nowMs: Long) {
        now32 = (nowMs and 0xFFFFFFFFL).toInt()
        val current = now32
        if (updated == 0) {
            updated = 1
            tsFlush = current
        }
        var slap = timediff(current, tsFlush)
        if (slap >= 10000 || slap < -10000) {
            tsFlush = current
            slap = 0
        }
        if (slap >= 0) {
            tsFlush += interval
            if (timediff(current, tsFlush) >= 0) tsFlush = current + interval
            flush(FLUSH_FULL)
        }
    }

    /**
     * Go `Check`, as a duration: ms until [update] should next be
     * called (Go returns an absolute timestamp; this returns the
     * difference from [nowMs]). 0 when an update is due now, or when
     * [update] has never been called.
     */
    fun check(nowMs: Long): Long {
        now32 = (nowMs and 0xFFFFFFFFL).toInt()
        val current = now32
        if (updated == 0) return 0L
        var tsFlushLocal = tsFlush
        if (timediff(current, tsFlushLocal) >= 10000 ||
            timediff(current, tsFlushLocal) < -10000
        ) {
            tsFlushLocal = current
        }
        if (timediff(current, tsFlushLocal) >= 0) return 0L

        val tmFlush = timediff(tsFlushLocal, current)
        var tmPacket = 0x7FFFFFFF
        for (seg in sndBuf) {
            val diff = timediff(seg.resendts, current)
            if (diff <= 0) return 0L
            if (diff < tmPacket) tmPacket = diff
        }
        var minimal = tmPacket
        if (tmPacket >= tmFlush) minimal = tmFlush
        if (minimal >= interval) minimal = interval
        return minimal.toLong()
    }
}
