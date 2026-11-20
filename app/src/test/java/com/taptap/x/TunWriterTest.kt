package com.taptap.x

import com.taptap.x.core.DialLog
import com.taptap.x.service.TunWriter
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.18: the TUN write moved to a single writer thread + bounded
 * FIFO queue. These tests fail on v1.0.17 code (no TunWriter at
 * all) and pass on the fix. They assert the properties the phone
 * bottleneck depends on:
 * - FIFO order (per-connection order cannot be reordered by the
 *   single writer),
 * - concurrent enqueues arrive exactly once, in per-thread order,
 * - enqueue BLOCKS when the queue is full (backpressure — the
 *   relay must stall, not drop segments),
 * - enqueue does NOT block while the writer is busy but the queue
 *   has room (the v1.0.17 bug was every relay stalling behind one
 *   lock + one blocking write),
 * - enqueue copies the buffer (the relay reuses pktBuf),
 * - the TUNWRITER aggregate line appears with all four fields,
 * - stop() drains the queue, then exits.
 */
class TunWriterTest {

    /** OutputStream whose write() blocks until [release] is called. */
    private class BlockingOutputStream : OutputStream() {
        private val delegate = ByteArrayOutputStream()
        private val releaseLatch = CountDownLatch(1)

        fun release() = releaseLatch.countDown()

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            releaseLatch.await()
            synchronized(delegate) { delegate.write(b, off, len) }
        }

        fun bytes(): ByteArray = synchronized(delegate) { delegate.toByteArray() }
    }

    private fun waitFor(
        timeoutMs: Long = 5_000,
        what: String,
        condition: () -> Boolean,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    @Test
    fun `writer delivers packets in FIFO order`() {
        val out = ByteArrayOutputStream()
        val writer = TunWriter(out, capacity = 16, statsIntervalMs = 5000)
        writer.start()
        writer.enqueue(byteArrayOf(1, 1, 1))
        writer.enqueue(byteArrayOf(2, 2, 2, 2))
        writer.enqueue(byteArrayOf(3, 3))
        assertTrue(waitFor(what = "all packets written") {
            synchronized(out) { out.size() } == 9
        })
        writer.stop()
        assertArrayEquals(
            byteArrayOf(1, 1, 1, 2, 2, 2, 2, 3, 3),
            out.toByteArray(),
        )
    }

    @Test
    fun `concurrent enqueues arrive exactly once in per-thread order`() {
        val out = ByteArrayOutputStream()
        val writer = TunWriter(out, capacity = 1024, statsIntervalMs = 5000)
        writer.start()
        val threads = 8
        val perThread = 50
        val pktSize = 8
        val jobs = (0 until threads).map { t ->
            thread(name = "test-enq-$t", isDaemon = true) {
                repeat(perThread) { s ->
                    val pkt = ByteArray(pktSize)
                    pkt[0] = t.toByte()
                    pkt[1] = (s ushr 8).toByte()
                    pkt[2] = s.toByte()
                    writer.enqueue(pkt)
                }
            }
        }
        jobs.forEach { it.join(10_000) }
        assertTrue(waitFor(what = "all packets written") {
            synchronized(out) { out.size() } == threads * perThread * pktSize
        })
        writer.stop()
        val bytes = out.toByteArray()
        val seen = mutableSetOf<Pair<Int, Int>>()
        val lastSeq = IntArray(threads) { -1 }
        var i = 0
        while (i < bytes.size) {
            val t = bytes[i].toInt()
            val s = ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                (bytes[i + 2].toInt() and 0xFF)
            assertTrue(seen.add(t to s), "packet $t/$s written twice")
            assertTrue(s > lastSeq[t], "thread $t out of order: $s after ${lastSeq[t]}")
            lastSeq[t] = s
            i += pktSize
        }
        assertEquals(threads * perThread, seen.size)
    }

    @Test
    fun `enqueue blocks when the queue is full`() {
        val out = BlockingOutputStream()
        val writer = TunWriter(out, capacity = 2, statsIntervalMs = 5000)
        writer.start()
        // The writer takes pkt1 at once and blocks in write();
        // pkt2 and pkt3 fill the 2-slot queue; pkt4 must block.
        writer.enqueue(byteArrayOf(1))
        Thread.sleep(200) // let the writer pick pkt1 up and block in write()
        writer.enqueue(byteArrayOf(2))
        writer.enqueue(byteArrayOf(3))
        val done = AtomicBoolean(false)
        val t = thread(name = "test-blocked-enq", isDaemon = true) {
            writer.enqueue(byteArrayOf(4))
            done.set(true)
        }
        Thread.sleep(300)
        assertEquals(false, done.get(), "enqueue must block while the queue is full")
        out.release()
        assertTrue(waitFor(what = "blocked enqueue returns") { done.get() })
        t.join(5000)
        writer.stop()
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), out.bytes())
    }

    @Test
    fun `enqueue returns quickly while the writer is busy but the queue has room`() {
        // The v1.0.17 shape: every relay stalled behind one lock +
        // one blocking write, even when the work ahead of it was
        // another connection's. With the queue, an enqueue with
        // room ahead of it must return at once.
        val out = BlockingOutputStream()
        val writer = TunWriter(out, capacity = 16, statsIntervalMs = 5000)
        writer.start()
        writer.enqueue(byteArrayOf(1))
        Thread.sleep(200) // writer picked pkt1 up, blocked in write()
        val t0 = System.currentTimeMillis()
        writer.enqueue(byteArrayOf(2))
        val tookMs = System.currentTimeMillis() - t0
        assertTrue(tookMs < 1000, "enqueue blocked ${tookMs}ms while the queue had room")
        out.release()
        writer.stop()
        assertArrayEquals(byteArrayOf(1, 2), out.bytes())
    }

    @Test
    fun `enqueue copies the buffer so caller reuse cannot corrupt it`() {
        val out = ByteArrayOutputStream()
        val writer = TunWriter(out, capacity = 16, statsIntervalMs = 5000)
        // Do NOT start the writer yet: the packet must still be in
        // the queue when the source buffer is mutated.
        val src = byteArrayOf(9, 8, 7, 6)
        writer.enqueue(src)
        src.fill(0) // the relay reuses pktBuf across segments
        writer.start()
        assertTrue(waitFor(what = "packet written") {
            synchronized(out) { out.size() } == 4
        })
        writer.stop()
        assertArrayEquals(byteArrayOf(9, 8, 7, 6), out.toByteArray())
    }

    @Test
    fun `tunwriter aggregate line appears while transferring`() {
        val before = DialLog.lines().size
        val out = ByteArrayOutputStream()
        val writer = TunWriter(out, capacity = 64, statsIntervalMs = 100)
        writer.start()
        // One packet every 30 ms for ~420 ms: writes cross several
        // 100 ms windows, so the periodic line must fire.
        repeat(14) {
            writer.enqueue(ByteArray(100) { it.toByte() })
            Thread.sleep(30)
        }
        assertTrue(waitFor(what = "TUNWRITER line", timeoutMs = 5000) {
            DialLog.lines().drop(before).any { it.contains("TUNWRITER") }
        })
        writer.stop()
        val line = DialLog.lines().drop(before).first { it.contains("TUNWRITER") }
        assertTrue(line.contains("tulis="), line)
        assertTrue(line.contains("antriMax="), line)
        assertTrue(line.contains("tulisMs="), line)
        assertTrue(line.contains("blokirMs="), line)
    }

    @Test
    fun `stop drains the queue then exits`() {
        val out = ByteArrayOutputStream()
        val writer = TunWriter(out, capacity = 16, statsIntervalMs = 5000)
        writer.start()
        repeat(10) { writer.enqueue(byteArrayOf(it.toByte())) }
        val t0 = System.currentTimeMillis()
        writer.stop()
        val tookMs = System.currentTimeMillis() - t0
        assertTrue(tookMs < 5000, "stop took ${tookMs}ms")
        assertEquals(10, synchronized(out) { out.size() })
        assertArrayEquals(ByteArray(10) { it.toByte() }, out.toByteArray())
    }

    @Test
    fun `writer line formats all four fields`() {
        assertEquals(
            "tulis=1234 antriMax=57 tulisMs=812ms blokirMs=0ms",
            TunWriter.writerLine(1234, 57, 812, 0),
        )
    }
}
