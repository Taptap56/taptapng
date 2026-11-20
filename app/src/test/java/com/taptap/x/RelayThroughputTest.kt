package com.taptap.x

import com.taptap.x.core.proto.Crypto
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.core.proto.SpeedStats
import com.taptap.x.core.proto.VmessBodyInputStream
import com.taptap.x.core.proto.VmessBodyOutputStream
import com.taptap.x.core.proto.VmessSecurity
import com.taptap.x.core.proto.VmessSession
import com.taptap.x.service.TcpPacket
import com.taptap.x.service.TunForwarder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * Throughput regression tests for the v1.0.15 relay-speed work
 * (Speedtest 2026-11-20 09:49–09:59, back-to-back, entry sama:
 * v2rayNG 133 Mbps, XVEON ~32 Mbps, TaptapX ~30,9 Mbps — dua app
 * tanpa core mentok di ~30 Mbps).
 *
 * Both tests are fully in-memory — NO sockets at all (JVM loopback
 * is intercepted in this VM; the VMess tests that need a socket use
 * ::1, but these need none): the relay test drives a TunForwarder
 * through PipedInput/OutputStreams with a fake proxy stream, and
 * the codec test round-trips bytes through VmessBodyOutputStream /
 * VmessBodyInputStream over ByteArray streams.
 *
 * Each test PRINTS its measured MB/s (grep "THROUGHPUT" in the CI
 * log) — the printed number is the before/after signal. The
 * asserted floors are deliberately conservative for shared CI
 * runners (they catch a gross regression, not a micro-regression);
 * the real in-memory number should be far above them.
 */
class RelayThroughputTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)

    /** Proxy stream the test feeds: the relay reads server data from
     * [feedOut] (a pipe the test writes into); what the forwarder
     * writes to the proxy lands in [written] (unused here). */
    private class FeedStream : ProxyStream {
        val feedOut = PipedOutputStream()
        override val input: InputStream = PipedInputStream(feedOut, 1 shl 20)
        val written = ByteArrayOutputStream()
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
            stats: SpeedStats? = null,
        ): ProxyStream =
            stream

        override fun close() = Unit
    }

    /** A forwarder wired to pipe pairs. The drainer frames the
     * outgoing IP packets (the pipe is a byte stream — a read can
     * split a packet) and counts TCP payload bytes exactly, so the
     * test's completion condition is "all payload arrived", not
     * "enough raw bytes" (headers would skew the timing). */
    private class Harness(proxy: ProxyClient, tunMtu: Int = 1500) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val payloadBytes = AtomicLong(0)
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
                val pending = ByteArrayOutputStream()
                try {
                    while (true) {
                        val n = tunOutRead.read(buf)
                        if (n <= 0) break
                        synchronized(drained) { drained.write(buf, 0, n) }
                        pending.write(buf, 0, n)
                        // Extract complete IP packets from the stream.
                        while (true) {
                            val bytes = pending.toByteArray()
                            if (bytes.size < 20) break
                            val total = ((bytes[2].toInt() and 0xFF) shl 8) or
                                (bytes[3].toInt() and 0xFF)
                            if (total <= 0 || bytes.size < total) break
                            val pkt = bytes.copyOfRange(0, total)
                            pending.reset()
                            if (bytes.size > total) pending.write(bytes, total, bytes.size - total)
                            val ip = TcpPacket.parseIp(pkt, pkt.size)
                            if (ip?.protocol == TcpPacket.PROTO_TCP) {
                                val tcp = TcpPacket.parseTcp(ip.payload)
                                if (tcp != null) payloadBytes.addAndGet(tcp.payload.size.toLong())
                            }
                        }
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
            Thread.sleep(5)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    private fun syn(srcPort: Int = 12345, seq: Long = 1000L): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, 443,
            seq, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = TcpPacket.TCP_MSS,
        )

    private fun ackPkt(srcPort: Int = 12345, seq: Long, ack: Long): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, 443,
            seq, ack, TcpPacket.FLAG_ACK, ByteArray(0),
        )

    /** The ISN the forwarder offered in the SYN-ACK (first drained packet). */
    private fun synAckIsn(h: Harness): Long {
        assertTrue(waitFor(what = "SYN-ACK drained") { h.drainedBytes().isNotEmpty() })
        val bytes = h.drainedBytes()
        val ip = TcpPacket.parseIp(bytes, bytes.size) ?: error("no SYN-ACK in drained bytes")
        val tcp = TcpPacket.parseTcp(ip.payload) ?: error("no TCP in SYN-ACK")
        return tcp.seq
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `relay download throughput through the forwarder`() {
        // The Speedtest download direction: server data arrives on
        // the proxy stream and the relay turns it into TCP segments
        // on the TUN. 4 MB is enough to swamp per-call overhead and
        // small enough to finish in seconds even on shared CI.
        val total = 4 * 1024 * 1024
        val proxy = FeedProxy()
        val h = Harness(proxy)
        val feederDone = CountDownLatch(1)
        try {
            h.fwd.start()
            h.feed(syn())
            assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
            val isn = synAckIsn(h)
            val serverSeq = (isn + 1) and 0xFFFFFFFFL
            h.feed(ackPkt(seq = 1001L, ack = serverSeq))
            Thread.sleep(100) // let the relay thread start blocking on the feed pipe
            val payload = ByteArray(16 * 1024) { (it and 0xFF).toByte() }
            val startNs = System.nanoTime()
            thread(name = "test-feeder", isDaemon = true) {
                try {
                    var left = total
                    while (left > 0) {
                        val take = minOf(payload.size, left)
                        proxy.stream.feedOut.write(payload, 0, take)
                        left -= take
                    }
                    proxy.stream.feedOut.flush()
                } catch (_: Exception) {
                    // Forwarder stopped / pipe closed.
                } finally {
                    feederDone.countDown()
                }
            }
            assertTrue(
                waitFor(timeoutMs = 100_000, what = "relay drains $total payload bytes") {
                    h.payloadBytes.get() >= total
                },
                "relay only drained ${h.payloadBytes.get()} of $total payload bytes",
            )
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000.0
            val mbps = total / 1024.0 / 1024.0 / (elapsedMs / 1000.0)
            println(
                "THROUGHPUT relay-download: $total bytes in " +
                    "${"%.1f".format(elapsedMs)} ms = ${"%.2f".format(mbps)} MB/s",
            )
            // Conservative floor for shared CI (the real number
            // should be an order of magnitude above it); the
            // printed MB/s is the before/after signal.
            assertTrue(mbps >= 1.0, "relay download throughput too low: $mbps MB/s")
        } finally {
            runCatching { proxy.stream.feedOut.close() }
            feederDone.await(5, TimeUnit.SECONDS)
            h.stop()
        }
    }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `vmess chunk codec round-trip throughput`() {
        // The upload-path chunking cost: the writer's bytes go
        // through VmessBodyOutputStream (seal per chunk) and back
        // through VmessBodyInputStream (open per chunk). Written in
        // 1460-byte pieces like the forwarder's writer does, so the
        // pending-buffer cost is exercised realistically. The reader
        // opens with the same key/IV pair the writer sealed with.
        val total = 4 * 1024 * 1024
        val session = VmessSession(
            requestBytes = ByteArray(0),
            bodyKey = Crypto.randomBytes(16),
            bodyIV = Crypto.randomBytes(16),
            responseBodyKey = Crypto.randomBytes(16),
            responseBodyIV = Crypto.randomBytes(16),
            responseV = 0,
            security = VmessSecurity.AES_128_GCM,
        )
        val plain = ByteArray(total) { (it * 31 and 0xFF).toByte() }
        val raw = ByteArrayOutputStream()
        val out = VmessBodyOutputStream(raw, session)
        val writeStart = System.nanoTime()
        var pos = 0
        while (pos < total) {
            val take = minOf(1460, total - pos)
            out.write(plain, pos, take)
            pos += take
        }
        out.flush()
        out.close()
        val writeMs = (System.nanoTime() - writeStart) / 1_000_000.0
        val writeMbps = total / 1024.0 / 1024.0 / (writeMs / 1000.0)
        println(
            "THROUGHPUT vmess-chunk-write: $total bytes in " +
                "${"%.1f".format(writeMs)} ms = ${"%.2f".format(writeMbps)} MB/s",
        )
        assertTrue(writeMbps >= 1.0, "vmess chunk write too slow: $writeMbps MB/s")
        val back = ByteArray(total)
        val readStart = System.nanoTime()
        val input = VmessBodyInputStream(
            ByteArrayInputStream(raw.toByteArray()), session,
            key = session.bodyKey, iv = session.bodyIV,
        )
        var filled = 0
        while (filled < total) {
            val r = input.read(back, filled, minOf(1460, total - filled))
            if (r == -1) break
            filled += r
        }
        val readMs = (System.nanoTime() - readStart) / 1_000_000.0
        val readMbps = total / 1024.0 / 1024.0 / (readMs / 1000.0)
        println(
            "THROUGHPUT vmess-chunk-read: $total bytes in " +
                "${"%.1f".format(readMs)} ms = ${"%.2f".format(readMbps)} MB/s",
        )
        assertEquals(total, filled, "round-trip lost bytes")
        assertArrayEquals(plain, back)
        assertTrue(readMbps >= 1.0, "vmess chunk read too slow: $readMbps MB/s")
    }
}
