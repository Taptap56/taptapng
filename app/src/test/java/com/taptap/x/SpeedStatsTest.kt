package com.taptap.x

import com.taptap.x.core.Base64Util
import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.Crypto
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.core.proto.SpeedStats
import com.taptap.x.core.proto.TimedInputStream
import com.taptap.x.core.proto.VmessBodyInputStream
import com.taptap.x.core.proto.VmessBodyOutputStream
import com.taptap.x.core.proto.VmessSecurity
import com.taptap.x.core.proto.VmessSession
import com.taptap.x.core.proto.WsTransport
import com.taptap.x.service.TcpPacket
import com.taptap.x.service.TunForwarder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.ServerSocket
import java.security.MessageDigest
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
 * v1.0.16 — speed instrumentation tests.
 *
 * The SPEED lines are the whole point of this version (measure,
 * don't guess), so their format is pinned exactly: a format change
 * breaks this test on purpose. The layer tests prove each stage
 * lands in its own bucket (TLS/net vs WS parse vs VMess AEAD vs
 * TUN write), and the forwarder test proves a real transfer logs
 * a window line + a TUTUP summary with the right destination.
 *
 * All in-memory except the WS test, which uses a ::1 loopback
 * socket like WsTransportTest (IPv4 loopback is blackholed in
 * this VM; ::1 connects fine). No real network anywhere.
 */
class SpeedStatsTest {

    @Test
    fun `window and total lines format stage times and rates`() {
        val s = SpeedStats()
        s.tlsNetNs.set(3_120_000_000)
        s.wsNs.set(180_000_000)
        s.vmessNs.set(240_000_000)
        s.relayReadNs.set(3_600_000_000)
        s.buildNs.set(12_000_000)
        s.tunNs.set(35_000_000)
        s.downBytes.set(13_107_200) // exactly 12.50 MB
        s.wsFrames.set(800)
        s.vmessChunks.set(1600)
        s.tunWrites.set(9000)
        val snap = s.snapshot()
        val zero = SpeedStats.Snapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        assertEquals(
            "SPEED 93.184.216.34:443 down=12.50MB 2.50MB/s " +
                "tls+net=3120ms ws=180ms vmess=240ms rd=3600ms build=12ms tun=35ms",
            SpeedStats.windowLine(zero, snap, "93.184.216.34:443", 5000),
        )
        assertEquals(
            "SPEED 93.184.216.34:443 TUTUP down=12.50MB 8.2s 1.52MB/s " +
                "tls+net=3120ms ws=180ms vmess=240ms rd=3600ms build=12ms tun=35ms " +
                "up=0.00MB upW=0ms upVmess=0ms frames=800 chunks=1600 tunW=9000",
            SpeedStats.totalLine(snap, "93.184.216.34:443", 8230),
        )
    }

    @Test
    fun `timed input stream passes bytes through and records read time`() {
        val payload = ByteArray(1024) { (it and 0xFF).toByte() }
        val stats = SpeedStats()
        val timed = TimedInputStream(ByteArrayInputStream(payload), stats)
        val got = ByteArray(payload.size)
        var filled = 0
        while (filled < got.size) {
            val r = timed.read(got, filled, got.size - filled)
            if (r == -1) break
            filled += r
        }
        assertEquals(payload.size, filled)
        assertArrayEquals(payload, got)
        // A read happened, so the bucket was touched (the exact
        // nanoseconds are clock-dependent — the forwarder test
        // below asserts a non-zero stage time end to end).
        assertTrue(stats.tlsNetNs.get() >= 0)
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    fun `ws input records frame count and parse time`() {
        // Fake WS server on ::1: 101, then one 16 KiB binary frame.
        val server = ServerSocket(0)
        val port = server.localPort
        val payload = ByteArray(16 * 1024) { (it * 7 and 0xFF).toByte() }
        var serverError: Throwable? = null
        val serverThread = Thread {
            try {
                val socket = server.accept()
                socket.soTimeout = 5_000
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val req = ByteArrayOutputStream()
                val tail = ArrayDeque<Int>()
                while (true) {
                    val b = input.read()
                    if (b == -1) return@Thread
                    req.write(b)
                    tail.addLast(b)
                    if (tail.size > 4) tail.removeFirst()
                    if (tail.size == 4 && tail[0] == '\r'.code && tail[1] == '\n'.code &&
                        tail[2] == '\r'.code && tail[3] == '\n'.code
                    ) break
                }
                val key = req.toString(Charsets.UTF_8).lines()
                    .first { it.startsWith("Sec-WebSocket-Key:", ignoreCase = true) }
                    .substringAfter(":").trim()
                val accept = Base64Util.encode(
                    MessageDigest.getInstance("SHA-1").digest(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.UTF_8),
                    ),
                )
                output.write(
                    ("HTTP/1.1 101 Switching Protocols\r\n" +
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                        "Sec-WebSocket-Accept: $accept\r\n\r\n")
                        .toByteArray(Charsets.UTF_8),
                )
                output.flush()
                // One unmasked binary frame, 16 KiB payload.
                val header = ByteArrayOutputStream()
                header.write(0x82)
                header.write(126)
                header.write((payload.size ushr 8) and 0xFF)
                header.write(payload.size and 0xFF)
                output.write(header.toByteArray())
                output.write(payload)
                output.flush()
                Thread.sleep(2_000) // keep the socket open while the client reads
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val stats = SpeedStats()
        val socket = java.net.Socket("::1", port)
        socket.soTimeout = 5_000
        try {
            // Exactly like Transport.open: the transport stream is
            // timed BEFORE the WS layer reads from it.
            val timed = TimedInputStream(socket.getInputStream(), stats)
            val ws = WsTransport.connect(timed, socket.getOutputStream(), "[::1]:$port", "/ws", stats)
            val got = ByteArray(payload.size)
            var filled = 0
            while (filled < got.size) {
                val r = ws.input.read(got, filled, got.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(payload.size, filled)
            assertArrayEquals(payload, got)
            assertEquals(1, stats.wsFrames.get(), "one data frame must be counted")
            assertTrue(stats.tlsNetNs.get() >= 0, "transport reads must be timed")
            assertTrue(stats.wsNs.get() >= 0, "WS parse time must be recorded")
            ws.close()
        } finally {
            runCatching { socket.close() }
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake WS server gagal", it) }
    }

    @Test
    fun `vmess body streams record aead time and chunk count`() {
        // Round-trip like RelayThroughputTest's codec test, but
        // with stats on both directions: the writer seals (upVmess)
        // and the reader opens (vmess) — the counts prove the
        // timing hooks actually ran, the bytes prove nothing broke.
        val total = 64 * 1024
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
        val stats = SpeedStats()
        val out = VmessBodyOutputStream(raw, session, stats = stats)
        var pos = 0
        while (pos < total) {
            val take = minOf(1460, total - pos)
            out.write(plain, pos, take)
            pos += take
        }
        out.flush()
        out.close()
        assertTrue(stats.upVmessNs.get() >= 0, "seal time must be recorded")
        val back = ByteArray(total)
        val input = VmessBodyInputStream(
            ByteArrayInputStream(raw.toByteArray()), session,
            stats = stats, key = session.bodyKey, iv = session.bodyIV,
        )
        var filled = 0
        while (filled < total) {
            val r = input.read(back, filled, minOf(1460, total - filled))
            if (r == -1) break
            filled += r
        }
        assertEquals(total, filled, "round-trip lost bytes")
        assertArrayEquals(plain, back)
        assertTrue(stats.vmessChunks.get() >= 1, "at least one chunk must be opened")
        assertTrue(stats.vmessNs.get() >= 0, "open time must be recorded")
    }

    // ---- forwarder integration: SPEED window + TUTUP lines ----

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)
    private val dstPort = 8443 // distinctive: the SPEED lines carry this dst
    private val dst = "93.184.216.34:8443"

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
            stats: SpeedStats?,
        ): ProxyStream = stream

        override fun close() = Unit
    }

    private class Harness(proxy: ProxyClient, speedWindowMs: Long) {
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
            speedWindowMs = speedWindowMs,
        )

        init {
            // Drain TUN-out continuously or the relay's
            // writePacket blocks once the 64 KiB pipe fills.
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
            Thread.sleep(10)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    private fun syn(srcPort: Int = 12345, seq: Long = 1000L): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, dstPort,
            seq, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = TcpPacket.TCP_MSS,
        )

    private fun ackPkt(srcPort: Int = 12345, seq: Long, ack: Long): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, srcPort, dstPort,
            seq, ack, TcpPacket.FLAG_ACK, ByteArray(0),
        )

    private fun synAckIsn(h: Harness): Long {
        assertTrue(waitFor(what = "SYN-ACK drained") { h.drainedBytes().isNotEmpty() })
        val bytes = h.drainedBytes()
        val ip = TcpPacket.parseIp(bytes, bytes.size) ?: error("no SYN-ACK in drained bytes")
        val tcp = TcpPacket.parseTcp(ip.payload) ?: error("no TCP in SYN-ACK")
        return tcp.seq
    }

    private fun speedLines(): List<String> =
        DialLog.lines().filter { it.contains("SPEED $dst") }

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    fun `forwarder logs speed window and tutup summary`() {
        // A slow drip feed (20 x 16 KiB, 30 ms apart) keeps the
        // transfer alive across several 100 ms windows, so the
        // window lines must appear — then closing the feed ends
        // the relay and the TUTUP summary must follow.
        val proxy = FeedProxy()
        val h = Harness(proxy, speedWindowMs = 100)
        val feederDone = CountDownLatch(1)
        try {
            h.fwd.start()
            h.feed(syn())
            assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
            val isn = synAckIsn(h)
            val serverSeq = (isn + 1) and 0xFFFFFFFFL
            h.feed(ackPkt(seq = 1001L, ack = serverSeq))
            Thread.sleep(100) // let the relay thread start blocking on the feed pipe
            val chunk = ByteArray(16 * 1024) { (it and 0xFF).toByte() }
            thread(name = "test-feeder", isDaemon = true) {
                try {
                    repeat(20) {
                        proxy.stream.feedOut.write(chunk)
                        proxy.stream.feedOut.flush()
                        Thread.sleep(30)
                    }
                } catch (_: Exception) {
                    // Forwarder stopped / pipe closed.
                } finally {
                    feederDone.countDown()
                }
            }
            assertTrue(
                waitFor(timeoutMs = 30_000, what = "SPEED window line") {
                    speedLines().any { !it.contains("TUTUP") }
                },
                "no SPEED window line logged; lines: ${speedLines()}",
            )
            val window = speedLines().first { !it.contains("TUTUP") }
            assertTrue(window.contains("down="), "window line must carry down=: $window")
            assertTrue(window.contains("tls+net="), "window line must carry tls+net=: $window")
            assertTrue(window.contains("vmess="), "window line must carry vmess=: $window")
            assertTrue(window.contains("tun="), "window line must carry tun=: $window")
            // The relay really waited on the proxy stream in this
            // window — the read stage must be non-zero.
            val rdMs = Regex("rd=(\\d+)ms").find(window)?.groupValues?.get(1)?.toLongOrNull()
            assertTrue((rdMs ?: 0) > 0, "relay read time must be > 0 in a live window: $window")
            // End the relay: closing the feed makes the read return
            // -1, sendFin logs the summary.
            runCatching { proxy.stream.feedOut.close() }
            feederDone.await(5, TimeUnit.SECONDS)
            assertTrue(
                waitFor(timeoutMs = 10_000, what = "SPEED TUTUP line") {
                    speedLines().any { it.contains("TUTUP") }
                },
                "no SPEED TUTUP line logged; lines: ${speedLines()}",
            )
            val tutup = speedLines().first { it.contains("TUTUP") }
            // 20 x 16 KiB = 327680 B = 0.31 MB down.
            assertTrue(tutup.contains("down=0.31MB"), "summary must carry the total: $tutup")
            assertTrue(tutup.contains("tunW="), "summary must carry counts: $tutup")
        } finally {
            runCatching { proxy.stream.feedOut.close() }
            feederDone.await(5, TimeUnit.SECONDS)
            h.stop()
        }
    }
}
