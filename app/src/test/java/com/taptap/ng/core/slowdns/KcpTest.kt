package com.taptap.ng.core.slowdns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * KCP loopback tests — no UDP (blocked in this VM). Two [Kcp]
 * instances are wired directly through in-memory queues, driven by a
 * virtual clock (5 ms ticks), exactly like kcp-go's lossy-conn tests
 * but without sockets or real sleeps, so the whole class runs in
 * well under a second of wall time.
 *
 * Both peers use the upstream test parameters: NoDelay(1, 10, 2, 1)
 * (nodelay, 10 ms interval, fast resend 2, congestion control off)
 * and stream mode, unless a test says otherwise.
 */
@Timeout(value = 10, unit = TimeUnit.SECONDS)
class KcpTest {

    private companion object {
        const val CONV = 0x11223344
        const val TICK_MS = 5L
    }

    /** Two Kcp peers wired through queues, driven by a virtual clock. */
    private class Link(
        private val lossRate: Double = 0.0,
        seed: Long = 42L,
        nodelay: Boolean = true,
    ) {
        private val random = Random(seed)
        private val aToB = ArrayDeque<ByteArray>()
        private val bToA = ArrayDeque<ByteArray>()
        private var dropped = 0

        val a = Kcp(CONV) { aToB.addLast(it) }
        val b = Kcp(CONV) { bToA.addLast(it) }

        /** Virtual clock, ms. Starts at an arbitrary non-zero value. */
        var now: Long = 1_000_000L

        init {
            if (nodelay) {
                a.setNoDelay(1, 10, 2, 1)
                b.setNoDelay(1, 10, 2, 1)
            }
            a.setStreamMode(true)
            b.setStreamMode(true)
        }

        fun droppedCount(): Int = dropped

        /** Deliver one side's queue to the peer, dropping [lossRate] of datagrams. */
        private fun deliver(from: ArrayDeque<ByteArray>, peer: Kcp) {
            while (from.isNotEmpty()) {
                val datagram = from.removeFirst()
                if (lossRate > 0.0 && random.nextDouble() < lossRate) {
                    dropped++
                    continue
                }
                peer.input(datagram)
            }
        }

        /** One tick: advance the clock, deliver queued datagrams, update both peers. */
        fun tick(dtMs: Long = TICK_MS) {
            now += dtMs
            deliver(aToB, b)
            deliver(bToA, a)
            a.update(now)
            b.update(now)
        }

        /** Tick until [cond] holds or [timeoutMs] of virtual time passes. Returns success. */
        fun runUntil(timeoutMs: Long, cond: () -> Boolean): Boolean {
            val deadline = now + timeoutMs
            while (now < deadline) {
                if (cond()) return true
                tick()
            }
            return cond()
        }
    }

    /** Drain everything currently receivable into [out]; returns bytes collected. */
    private fun drain(kcp: Kcp, out: ByteArray, already: Int): Int {
        var n = already
        val buf = ByteArray(4096)
        while (n < out.size) {
            val got = kcp.recv(buf)
            if (got <= 0) break
            buf.copyInto(out, n, 0, got)
            n += got
        }
        return n
    }

    @Test
    fun roundTripSmallMessage() {
        val link = Link()
        val hello = "hello kcp".toByteArray()
        assertEquals(0, link.a.send(hello))

        val out = ByteArray(hello.size)
        val ok = link.runUntil(5_000) {
            drain(link.b, out, 0) == hello.size
        }
        assertTrue(ok, "small message never arrived")
        assertArrayEquals(hello, out)
    }

    @Test
    fun roundTripTenKilobytes() {
        val link = Link()
        val data = ByteArray(10 * 1024) { (it * 31 % 251).toByte() }
        assertEquals(0, link.a.send(data))

        val out = ByteArray(data.size)
        var received = 0
        val ok = link.runUntil(10_000) {
            received = drain(link.b, out, received)
            received == data.size
        }
        assertTrue(ok, "10 KB message incomplete: got $received of ${data.size}")
        assertArrayEquals(data, out)
    }

    @Test
    fun messageModeReassemblesFragments() {
        // Same link but message mode (frg counts, PeekSize sums fragments).
        val link = Link(nodelay = true)
        link.a.setStreamMode(false)
        link.b.setStreamMode(false)
        val data = ByteArray(3000) { (it % 253).toByte() }
        assertEquals(0, link.a.send(data))

        val ok = link.runUntil(5_000) { link.b.peekSize() == data.size }
        assertTrue(ok, "peekSize never reached ${data.size}, got ${link.b.peekSize()}")
        val buf = ByteArray(data.size)
        assertEquals(data.size, link.b.recv(buf))
        assertArrayEquals(data, buf)
        assertEquals(-1, link.b.recv(buf), "nothing left to read")
    }

    @Test
    fun lossyLinkStillDeliversInOrder() {
        val link = Link(lossRate = 0.2, seed = 1234L)
        val data = ByteArray(10 * 1024) { (it * 17 % 251).toByte() }
        assertEquals(0, link.a.send(data))

        val out = ByteArray(data.size)
        var received = 0
        val ok = link.runUntil(30_000) {
            received = drain(link.b, out, received)
            received == data.size
        }
        assertTrue(ok, "lossy transfer incomplete: got $received of ${data.size}")
        assertTrue(link.droppedCount() > 0, "loss pump should have dropped datagrams")
        assertArrayEquals(data, out)
    }

    @Test
    fun convMismatchDropsDatagram() {
        val link = Link()
        val hello = "hello kcp".toByteArray()
        assertEquals(0, link.a.send(hello))
        link.a.update(link.now)
        // Send the same datagram from a peer with a different conv.
        var alienDatagram: ByteArray? = null
        val alienSender = Kcp(-0x66666667) { alienDatagram = it }
        alienSender.setNoDelay(1, 10, 2, 1)
        alienSender.setStreamMode(true)
        assertEquals(0, alienSender.send(hello))
        alienSender.update(link.now)
        val datagram = alienDatagram ?: error("alien produced no datagram")

        assertEquals(-1, link.b.input(datagram), "wrong conv must return -1")
        assertEquals(-1, link.b.peekSize(), "wrong-conv datagram must deliver nothing")
        assertEquals(-1, link.b.input(ByteArray(0)), "short datagram must return -1")
    }

    @Test
    fun streamModeMergesSmallChunks() {
        val link = Link()
        assertEquals(0, link.a.send("foo".toByteArray()))
        assertEquals(0, link.a.send("bar".toByteArray()))
        assertEquals(0, link.a.send("baz".toByteArray()))

        val buf = ByteArray(64)
        val ok = link.runUntil(5_000) { link.b.peekSize() == 9 }
        assertTrue(ok, "merged chunks never arrived, peekSize=${link.b.peekSize()}")
        assertEquals(9, link.b.recv(buf))
        assertArrayEquals("foobarbaz".toByteArray(), buf.copyOfRange(0, 9))
        assertEquals(-1, link.b.recv(buf), "nothing left to read")
    }

    @Test
    fun updateCheckWithNoDataProducesNoOutput() {
        val emitted = ArrayDeque<ByteArray>()
        val kcp = Kcp(CONV) { emitted.addLast(it) }
        val now = 2_000_000L
        assertEquals(0L, kcp.check(now), "check before any update is due now")
        kcp.update(now)
        assertTrue(emitted.isEmpty(), "idle update must emit nothing")
        val wait = kcp.check(now)
        assertTrue(wait in 1..100, "check after update must be a small interval, got $wait")
        // Advancing past the interval flushes, still with nothing to send.
        kcp.update(now + 200)
        assertTrue(emitted.isEmpty(), "idle update after interval must emit nothing")
        assertFalse(kcp.isDead, "idle kcp must not be dead")
    }

    @Test
    fun setNoDelaySemantics() {
        // (0,0,0,1): nodelay=0 -> rx_minrto 100, interval 0 clamped to 10,
        // resend=0 -> no fast resend, nc=1 -> congestion control off.
        // Observable: with nocwnd=1 the first flush sends immediately
        // (cwnd gate disabled), even though Go leaves cwnd=0 at creation.
        val emitted = ArrayDeque<ByteArray>()
        val kcp2 = Kcp(CONV) { emitted.addLast(it) }
        kcp2.setNoDelay(0, 0, 0, 1)
        kcp2.setStreamMode(true)
        assertEquals(0, kcp2.send("x".toByteArray()))
        kcp2.update(3_000_000L)
        assertEquals(1, emitted.size, "nocwnd=1 must send on the first flush")
        // Interval clamp: check() after update must be <= 100 and reflect
        // the 10 ms interval (never 0 and never the unclamped value).
        val wait = kcp2.check(3_000_000L)
        assertTrue(wait in 1..10, "interval 0 must clamp to 10 ms, got $wait")
    }

    @Test
    fun deadAfterTotalLoss() {
        // 100% loss: drop everything the sender emits; drive a virtual
        // clock so the ~40 s of simulated RTO backoff costs no wall time.
        val emitted = ArrayDeque<ByteArray>()
        val sender = Kcp(CONV) { emitted.addLast(it) }
        sender.setNoDelay(1, 10, 2, 1)
        sender.setStreamMode(true)
        assertEquals(0, sender.send("hello kcp".toByteArray()))

        var now = 4_000_000L
        var ticks = 0
        while (!sender.isDead && ticks < 20_000) {
            now += TICK_MS
            emitted.clear() // 100% loss: nothing ever reaches the peer
            sender.update(now)
            ticks++
        }
        assertTrue(sender.isDead, "sender must go dead under 100% loss")
        assertTrue(ticks < 20_000, "dead must arrive within the tick budget")
        assertEquals(-1, sender.send("more".toByteArray()), "send on a dead kcp fails")
    }

    @Test
    fun sendRejectsEmptyAndOversize() {
        val kcp = Kcp(CONV) { }
        assertEquals(-1, kcp.send(ByteArray(0)), "empty send must fail")
        // 256 fragments needed (256 * 1376 + 1 bytes) -> -2.
        assertEquals(-2, kcp.send(ByteArray(256 * 1376 + 1)), "oversize send must fail")
        assertEquals(-1, kcp.recv(ByteArray(16)), "recv with no data must return -1")
        assertEquals(-1, kcp.peekSize(), "peekSize with no data must return -1")
    }
}
