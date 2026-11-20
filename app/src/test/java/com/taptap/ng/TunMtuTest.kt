package com.taptap.ng

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.TcpPacket
import com.taptap.ng.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.21 — MTU 9000 / MSS 8960 experiment tests.
 *
 * The writer's ~5000 writes/s ceiling (phone log 2026-11-20,
 * histogram v1.0.20: ~140 us per write of kernel delivery cost)
 * caps throughput at ~55 Mbps with 1460-byte segments, because
 * the kernel charges per PACKET. A 9000 MTU lets the app offer
 * MSS 8960, so one TUN write carries ~6x the bytes. These tests
 * prove the mechanism end to end: the SYN-ACK advertises 8960,
 * the relay builds segments up to 8960 bytes (not the old 1460
 * cap), and an 8000-byte app segment is forwarded whole on the
 * upload path. They fail on v1.0.20 code (peerMss capped at
 * 1460, segments 1460, SYN-ACK MSS 1460).
 *
 * All in-memory (pipe pairs); no real network anywhere.
 */
class TunMtuTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)
    private val dstPort = 443

    /** Proxy stream whose input the test feeds (SpeedStatsTest's FeedStream). */
    private class FeedStream : ProxyStream {
        val written = ByteArrayOutputStream()
        val feedOut = PipedOutputStream()
        override val input: InputStream = PipedInputStream(feedOut, 1 shl 20)
        override val output: OutputStream = written
        override fun close() {
            runCatching { input.close() }
            runCatching { feedOut.close() }
        }
    }

    private class FeedProxy : ProxyClient {
        val stream = FeedStream()
        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream = stream

        override fun close() = Unit
    }

    /** A forwarder wired to a pipe pair; tunOut is drained into [drained]. */
    private class Harness(proxy: ProxyClient, tunMtu: Int = 9000) {
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
        timeoutMs: Long = 10_000,
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

    private fun syn(srcPort: Int = 12345, seq: Long = 1000L, mss: Int = 8960): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, dstPort,
            seq, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = mss,
        )

    private fun ackPkt(srcPort: Int = 12345, seq: Long, ack: Long): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, dstPort,
            seq, ack, TcpPacket.FLAG_ACK, ByteArray(0),
        )

    private fun dataPkt(
        srcPort: Int = 12345,
        seq: Long,
        ack: Long,
        payload: ByteArray,
    ): ByteArray = TcpPacket.buildTcp(
        clientIp, serverIp, srcPort, dstPort,
        seq, ack, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
    )

    /** Walk the drained byte stream, slicing one IP packet per total-length field. */
    private fun parseDrained(bytes: ByteArray): List<TcpPacket.TcpSegment> {
        val out = mutableListOf<TcpPacket.TcpSegment>()
        var off = 0
        while (off + 20 <= bytes.size) {
            val total = ((bytes[off + 2].toInt() and 0xFF) shl 8) or
                (bytes[off + 3].toInt() and 0xFF)
            if (total < 20 || off + total > bytes.size) break
            val ip = TcpPacket.parseIp(bytes.copyOfRange(off, off + total), total) ?: break
            val tcp = TcpPacket.parseTcp(ip.payload) ?: break
            out.add(tcp)
            off += total
        }
        return out
    }

    /** Establish a session against a 9000-MTU forwarder; returns the SYN-ACK ISN. */
    private fun establish(h: Harness): Long {
        h.fwd.start()
        assertTrue(
            waitFor(what = "TUN mtu/mss log line") {
                DialLog.lines().any { it.contains("TUN mtu=9000 mss=8960") }
            },
        )
        h.feed(syn(mss = 8960))
        assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
        assertTrue(waitFor(what = "SYN-ACK drained") { h.drainedBytes().isNotEmpty() })
        val synAck = parseDrained(h.drainedBytes()).firstOrNull()
            ?: error("no SYN-ACK in drained bytes")
        assertEquals(
            8960,
            TcpPacket.parseTcpOptions(synAck.options).mss,
            "SYN-ACK must advertise MSS 8960 on a 9000 MTU",
        )
        val serverSeq = (synAck.seq + 1) and 0xFFFFFFFFL
        h.feed(ackPkt(seq = 1001L, ack = serverSeq))
        Thread.sleep(200) // let the reader process the ACK alone (one packet per read)
        return serverSeq
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    fun `mtu 9000 syn gets mss 8960 syn-ack and bigger relay segments`() {
        // v1.0.21: 20000 proxy bytes at MSS 8960 must arrive as
        // segments up to 8960 bytes — not fourteen 1460-byte
        // segments. The exact count depends on how the relay's
        // 32 KiB reads chunk the feed, so assert the properties
        // that prove the mechanism: max payload > 1460, every
        // payload <= 8960, total == fed, bytes reassemble exactly.
        val proxy = FeedProxy()
        val h = Harness(proxy, tunMtu = 9000)
        try {
            establish(h)
            val data = ByteArray(20_000) { (it * 31 and 0xFF).toByte() }
            proxy.stream.feedOut.write(data)
            proxy.stream.feedOut.flush()
            assertTrue(
                waitFor(what = "20 KB relayed to the TUN") {
                    parseDrained(h.drainedBytes()).sumOf { it.payload.size } >= data.size
                },
            )
            val segments = parseDrained(h.drainedBytes())
                .filter { it.payload.isNotEmpty() }
            assertTrue(
                segments.maxOf { it.payload.size } > 1460,
                "no segment bigger than 1460: ${segments.map { it.payload.size }}",
            )
            assertTrue(segments.all { it.payload.size <= 8960 })
            assertTrue(
                segments.size < 14,
                "still emitting 1460-byte segments: ${segments.size} segments",
            )
            val reassembled = segments.flatMap { it.payload.asList() }.toByteArray()
            assertArrayEquals(data, reassembled)
        } finally {
            h.stop()
        }
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    fun `app sending an 8000 byte segment is forwarded whole`() {
        // v1.0.21: the SYN-ACK advertises MSS 8960, so the app may
        // send 8960-byte segments. The TUN read buffer (64 KiB)
        // must accept them and the writer must forward the whole
        // payload to the proxy — not truncate at 1460. Fails on
        // any path that still assumes a 1500-byte packet.
        val proxy = FeedProxy()
        val h = Harness(proxy, tunMtu = 9000)
        try {
            val serverSeq = establish(h)
            val payload = ByteArray(8000) { (it * 17 and 0xFF).toByte() }
            h.feed(dataPkt(seq = 1001L, ack = serverSeq, payload = payload))
            assertTrue(
                waitFor(what = "8000 bytes written to proxy") {
                    proxy.stream.written.size() >= payload.size
                },
            )
            assertArrayEquals(payload, proxy.stream.written.toByteArray())
        } finally {
            h.stop()
        }
    }

    @Test
    fun `mtu 1500 still caps segments at 1460`() {
        // Guardrail: the old behaviour must not change for a 1500
        // MTU (a user who sets MTU back to 1500 in Settings gets
        // exactly the v1.0.20 behaviour).
        assertEquals(1460, TunForwarder.maxMssForMtu(1500))
        assertEquals(1460, TunForwarder.synAckMss(1500, 8960))
    }
}
