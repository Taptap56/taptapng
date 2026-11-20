package com.taptap.x.service

import com.taptap.x.core.DialLog
import java.io.OutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Dedicated TUN writer thread (v1.0.18).
 *
 * Phone evidence (log taptapx-0d94e353.txt, Speedtest 2026-11-20
 * 15:27, 16,1 Mbps): every Speedtest connection spent ~6 s of 8 s
 * inside the TUN write (tun=6046ms, 1622 writes for 2,06 MB —
 * ~3,7 ms per write), 70-75% of the relay thread's time, while WS
 * parse (~20 ms), VMess decrypt (~100 ms) and segment build
 * (~30 ms) were negligible. The old writePacket() made every relay
 * thread (one per TCP connection) queue behind ONE
 * synchronized(writeLock) and then do ONE blocking write() syscall
 * per ~1460 B segment on a blocking fd — the moment the kernel's
 * TUN queue filled, one write blocked WHILE HOLDING the lock, and
 * every other connection stalled behind it.
 *
 * This class fixes the shape, not the fd: all TUN writes — data
 * segments, SYN-ACK, RST, DNS replies — go through one bounded FIFO
 * queue drained by ONE writer thread. Relay threads only enqueue
 * (and block in put() when the queue is full: backpressure, with no
 * global lock held). Per-connection order is preserved: one
 * connection's segments are enqueued in order by its own relay
 * thread, and a single writer draining FIFO cannot reorder them.
 *
 * The trap NOT to fall into: batching several IP packets into one
 * write() — the TUN fd takes EXACTLY ONE IP packet per write(), so
 * coalescing would corrupt packets. The win here is the single
 * writer + queue, not fewer write() calls.
 *
 * Instrumentation: the per-connection `tun` stage now measures the
 * ENQUEUE time (it should be microseconds — proof the relay is no
 * longer stuck), and this thread logs one TUNWRITER aggregate line
 * per stats window while transferring: packets written, max queue
 * depth, total time inside out.write(), and total time enqueue
 * callers spent blocked in put() (backpressure). If the fd write is
 * still the bottleneck, tulisMs stays large; if the writer cannot
 * keep up with the relays, blokirMs grows and the queue stays full.
 */
class TunWriter(
    private val out: OutputStream,
    private val capacity: Int = DEFAULT_CAPACITY,
    private val statsIntervalMs: Long = DEFAULT_STATS_INTERVAL_MS,
) {

    /** Sentinel: end of queue (a TUN packet is never empty). */
    private val poison = ByteArray(0)

    private val queue = ArrayBlockingQueue<ByteArray>(capacity)
    private val running = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private var writerThread: Thread? = null

    /** Total wall time all enqueue callers spent inside put(). */
    private val enqueueBlockedNs = AtomicLong(0)

    /** Max queue depth seen since the current window started. */
    private val windowMaxDepth = AtomicInteger(0)

    // Window aggregates (writer thread only).
    private var windowStartMs = 0L
    private var windowWrites = 0
    private var windowWriteNs = 0L
    private var windowBlockedBaseNs = 0L

    companion object {
        /** Bounded queue: 1024 packets ≈ 1,5 MB worst case. Full =
         * the writer is behind and the relays must wait (put()
         * blocks) — that is backpressure, not a bug. */
        const val DEFAULT_CAPACITY = 1024

        /** TUNWRITER aggregate line every 5 s while transferring. */
        const val DEFAULT_STATS_INTERVAL_MS = 5000L

        /** stop() waits at most this long for the writer to drain. */
        const val STOP_JOIN_TIMEOUT_MS = 2000L

        /**
         * One TUNWRITER window line (content after the DialLog
         * "TUNWRITER" tag): packets written in the window, max
         * queue depth, total time inside out.write(), total time
         * enqueue callers spent blocked in put().
         */
        fun writerLine(writes: Int, maxDepth: Int, writeMs: Long, blockedMs: Long): String =
            "tulis=$writes antriMax=$maxDepth tulisMs=${writeMs}ms blokirMs=${blockedMs}ms"
    }

    fun start() {
        if (!started.compareAndSet(false, true)) return
        running.set(true)
        writerThread = thread(name = "tun-writer", isDaemon = true) { writerLoop() }
    }

    /**
     * Enqueue one IP packet for the writer thread. COPIES the bytes:
     * the relay reuses its packet buffer (pktBuf) across segments, so
     * the queued reference must not alias it. Blocks (put) when the
     * queue is full — backpressure without holding any lock; the
     * proxy side then slows down through its own TCP window instead
     * of the relay thread spinning. The put() wall time is counted
     * into the TUNWRITER blokirMs (microseconds while the queue has
     * room, milliseconds when it is full and the writer is behind).
     */
    fun enqueue(pkt: ByteArray, len: Int = pkt.size) {
        val copy = pkt.copyOf(len)
        val t0 = System.nanoTime()
        try {
            queue.put(copy)
        } finally {
            enqueueBlockedNs.addAndGet(System.nanoTime() - t0)
        }
        windowMaxDepth.updateAndGet { maxOf(it, queue.size) }
    }

    /** Stop-path only: drop queued packets so a relay blocked in
     * put() can finish its enqueue and see the closed session
     * instead of hanging (the VPN is tearing down anyway). */
    fun clear() {
        queue.clear()
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        // Poison pill: the writer drains the queue, then exits.
        // Offer with a timeout — if the queue is full the writer is
        // draining it, so space appears; give up after ~2 s and let
        // the fd close error the writer out instead.
        val deadline = System.currentTimeMillis() + STOP_JOIN_TIMEOUT_MS
        var offered = false
        try {
            while (System.currentTimeMillis() < deadline && writerThread?.isAlive == true) {
                if (queue.offer(poison, 100, TimeUnit.MILLISECONDS)) {
                    offered = true
                    break
                }
            }
        } catch (_: InterruptedException) {
            // Stop was interrupted: fall through to the interrupt
            // below; the writer is a daemon thread either way.
        }
        if (offered) {
            runCatching { writerThread?.join(STOP_JOIN_TIMEOUT_MS) }
        }
        if (writerThread?.isAlive == true) {
            // Unblock take() (a write() blocked on the fd is ended
            // by the fd close that follows stop()).
            writerThread?.interrupt()
        }
    }

    private fun writerLoop() {
        try {
            while (true) {
                val pkt = try {
                    queue.take()
                } catch (_: InterruptedException) {
                    return
                }
                if (pkt === poison) break
                val t0 = System.nanoTime()
                try {
                    // ONE packet per write() — the TUN fd takes
                    // exactly one IP packet per call; never coalesce
                    // (and no flush(): the raw FileOutputStream's
                    // flush is a no-op, the old one was too).
                    out.write(pkt)
                } catch (e: Exception) {
                    // The fd broke (or stop() closed it): if we are
                    // stopping this is the expected exit; otherwise
                    // log once and exit — without a working fd there
                    // is nothing left to write to.
                    if (running.get()) DialLog.failure("TUNWRITER", e)
                    return
                }
                val writeNs = System.nanoTime() - t0
                windowWrites++
                windowWriteNs += writeNs
                val now = System.currentTimeMillis()
                if (windowStartMs == 0L) {
                    windowStartMs = now
                    windowBlockedBaseNs = enqueueBlockedNs.get()
                } else if (now - windowStartMs >= statsIntervalMs) {
                    emitWindow()
                    windowStartMs = now
                    windowBlockedBaseNs = enqueueBlockedNs.get()
                }
            }
        } finally {
            // Final partial window, so a transfer shorter than one
            // window still shows what the writer cost (it would
            // otherwise leave no TUNWRITER line at all).
            if (windowWrites > 0) emitWindow()
        }
    }

    private fun emitWindow() {
        val blockedMs = (enqueueBlockedNs.get() - windowBlockedBaseNs) / 1_000_000
        val maxDepth = windowMaxDepth.getAndSet(0)
        DialLog.log(
            "TUNWRITER",
            writerLine(windowWrites, maxDepth, windowWriteNs / 1_000_000, blockedMs),
        )
        windowWrites = 0
        windowWriteNs = 0
    }
}
