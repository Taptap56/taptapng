package com.taptap.x

import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.service.TcpPacket
import com.taptap.x.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression tests for the v1.0.13 responsiveness fixes (XVEON
 * imitation items 1, 2, 4, 6): the old forwarder wrote to the proxy
 * stream synchronously on the single TUN reader thread (one slow
 * write stalled every connection), dropped data arriving while
 * DIALING, dropped out-of-order segments (retransmit), kept an
 * unbounded session map, and ignored the MTU setting for the
 * SYN-ACK MSS. The user reported the start as "kurang responsif"
 * (2026-11-20 08:58:59) — the first page load was sluggish.
 */
class TunForwarderResponsivenessTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)

    /** Proxy stream that records everything written to it. The
     * input is a CONNECTED pipe whose write end is never written
     * to, so read() blocks forever like a real socket waiting for
     * server data — an unconnected PipedInputStream throws
     * immediately ("Pipe not connected"), which made the relay
     * FIN the session microseconds after dial and broke every
     * test that feeds data after "Connected". The write end is
     * held in a field so the pipe stays connected. */
    private class RecordingStream : ProxyStream {
        val written = ByteArrayOutputStream()
        @Suppress("unused")
        private val pipeOut = PipedOutputStream()
        override val input: InputStream = PipedInputStream(pipeOut)
        override val output: OutputStream = written
        override fun close() {
            runCatching { input.close() }
        }
    }

    /** Proxy that always succeeds; the stream's input blocks forever. */
    private class OkProxy : ProxyClient {
        val last = RecordingStream()
        override fun dial(targetHost: String, targetPort: Int, probeBody: ByteArray?): ProxyStream =
            last

        override fun close() = Unit
    }

    /** Proxy whose dial blocks on [latch] until released. */
    private class SlowProxy(private val latch: CountDownLatch) : ProxyClient {
        val stream = RecordingStream()
        override fun dial(targetHost: String, targetPort: Int, probeBody: ByteArray?): ProxyStream {
            latch.await(10, TimeUnit.SECONDS)
            return stream
        }

        override fun close() = Unit
    }

    /** A forwarder wired to a pipe pair; tunOut is drained into [drained]. */
    private class Harness(
        proxy: ProxyClient,
        tunMtu: Int = 1500,
    ) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val statuses = mutableListOf<String>()
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, proxy, "192.0.2.1",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
            tunMtu = tunMtu,
        )

        init {
            thread(name = "test-drainer", isDaemon = true) {
                val buf = ByteArray(8192)
                try {
                    while (true) {
                        val n = tunOutRead.read(buf)
                        if (n <= 0) break
                        synchronized(drained) { drained.write(buf, 0, n) }
                    }
                } catch (_: Exception) {
                    // Pipe closed by stop().
                }
            }
        }

        fun feed(pkt: ByteArray) {
            tunInWrite.write(pkt)
            tunInWrite.flush()
        }

        fun stop() {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }

        fun drainedBytes(): ByteArray = synchronized(drained) { drained.toByteArray() }
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

    private fun syn(srcPort: Int = 12345, seq: Long = 1000L): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, 443,
            seq, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = TcpPacket.TCP_MSS,
        )

    private fun dataPkt(
        srcPort: Int = 12345,
        seq: Long,
        ack: Long,
        payload: ByteArray,
    ): ByteArray = TcpPacket.buildTcp(
        clientIp, serverIp, srcPort, 443,
        seq, ack, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
    )

    private fun ackPkt(srcPort: Int = 12345, seq: Long, ack: Long): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, 443,
            seq, ack, TcpPacket.FLAG_ACK, ByteArray(0),
        )

    /** The ISN the forwarder offered in the SYN-ACK (first drained packet). */
    private fun synAckIsn(h: Harness): Long {
        val bytes = h.drainedBytes()
        val ip = TcpPacket.parseIp(bytes, bytes.size) ?: error("no SYN-ACK in drained bytes")
        val tcp = TcpPacket.parseTcp(ip.payload) ?: error("no TCP in SYN-ACK")
        return tcp.seq
    }

    @Test
    fun `syn-ack mss comes from the mtu setting`() {
        // v1.0.15: clamp(tunMtu - 40, 1140, 1460), capped at the peer MSS.
        assertEquals(1460, TunForwarder.synAckMss(1500, 1460))
        assertEquals(1200, TunForwarder.synAckMss(1500, 1200))
        assertEquals(1460, TunForwarder.synAckMss(9000, 1460))
        assertEquals(1140, TunForwarder.synAckMss(576, 1460))
        assertEquals(1240, TunForwarder.synAckMss(1280, 1460))
    }

    @Test
    fun `data arriving while dialing is queued, not dropped`() {
        // v1.0.13, fix A1: the old code ignored data while DIALING
        // (handleTcp: Unit) and handleData returned early without a
        // stream — the app's first bytes were lost. Fails on
        // v1.0.12 code (the proxy never receives the payload).
        val latch = CountDownLatch(1)
        val proxy = SlowProxy(latch)
        val h = Harness(proxy)
        try {
            h.fwd.start()
            h.feed(syn())
            // Wait until the reader processed the SYN alone: the
            // pipe is a byte stream, so a data packet fed
            // immediately after the SYN can coalesce into the same
            // read() and be lost (the reader parses one packet per
            // read). The session existing proves the SYN was read.
            assertTrue(waitFor(what = "SYN processed") { h.fwd.sessionCount() == 1 })
            // The dial is blocked on the latch; the app's first
            // data arrives while DIALING and must be queued.
            val before = h.drainedBytes().size
            h.feed(dataPkt(seq = 1001L, ack = 0L, payload = "hello-dialing".toByteArray()))
            // Wait until the reader processed the data packet (it
            // ACKs it) before releasing the dial.
            assertTrue(waitFor(what = "data packet ACKed") { h.drainedBytes().size > before })
            latch.countDown()
            assertTrue(waitFor(what = "queued payload written to proxy") {
                proxy.stream.written.toString(Charsets.UTF_8.name())
                    .contains("hello-dialing")
            })
        } finally {
            latch.countDown()
            h.stop()
        }
    }

    @Test
    fun `out-of-order segments are buffered and replayed in order`() {
        // v1.0.13, fix A2: the old code dropped seq > clientSeq
        // and relied on a retransmit. Fails on v1.0.12 code (the
        // proxy only ever receives "hello").
        val proxy = OkProxy()
        val h = Harness(proxy)
        try {
            h.fwd.start()
            h.feed(syn())
            assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
            val isn = synAckIsn(h)
            val serverSeq = (isn + 1) and 0xFFFFFFFFL
            // Pure ACK completes the handshake (no packet is sent
            // back for it, so give the reader a moment).
            h.feed(ackPkt(seq = 1001L, ack = serverSeq))
            Thread.sleep(150)
            // Out-of-order first, then the missing in-order chunk.
            h.feed(dataPkt(seq = 1006L, ack = serverSeq, payload = "world".toByteArray()))
            Thread.sleep(150)
            h.feed(dataPkt(seq = 1001L, ack = serverSeq, payload = "hello".toByteArray()))
            assertTrue(waitFor(what = "helloworld at proxy", timeoutMs = 10_000) {
                proxy.last.written.toString(Charsets.UTF_8.name()) == "helloworld"
            }, "expected helloworld, got: ${proxy.last.written.toString(Charsets.UTF_8.name())}")
        } finally {
            h.stop()
        }
    }

    @Test
    fun `tcp sessions are capped at 96 with the oldest evicted`() {
        // v1.0.13, fix A4: the old sessions map was unbounded.
        // Fails on v1.0.12 code (count grows past 96).
        val h = Harness(OkProxy())
        try {
            h.fwd.start()
            for (i in 0 until 100) {
                h.feed(syn(srcPort = 20000 + i, seq = 1000L + i))
                // Feed one at a time: back-to-back writes can
                // coalesce in the pipe and the reader only parses
                // the first packet of each read.
                val want = minOf(i + 1, TunForwarder.MAX_SESSIONS)
                assertTrue(waitFor(what = "session $want", timeoutMs = 2_000) {
                    h.fwd.sessionCount() >= want
                })
            }
            assertEquals(TunForwarder.MAX_SESSIONS, h.fwd.sessionCount())
        } finally {
            h.stop()
        }
    }
}
