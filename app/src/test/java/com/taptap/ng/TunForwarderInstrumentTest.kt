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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.10: the forwarder was silent — the v1.0.9 phone log had
 * ZERO forwarder lines, so nobody could tell whether app traffic
 * ever reached the TUN, whether the reader died, or whether the
 * DNS relay ate the queries. These tests fail on v1.0.9 code
 * (no FORWARDER/TUN/DNS lines, no option echo, plain MSS-only
 * SYN-ACK) and pass on the fix.
 */
class TunForwarderInstrumentTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)

    /** Proxy stream whose input blocks forever (no server data). */
    private class BlockingStream : ProxyStream {
        override val input: InputStream = PipedInputStream()
        override val output: OutputStream = ByteArrayOutputStream()
        override fun close() {
            runCatching { input.close() }
        }
    }

    private class OkProxy : ProxyClient {
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream =
            BlockingStream()

        override fun close() = Unit
    }

    private class FailingProxy : ProxyClient {
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream =
            throw java.io.IOException("dial gagal")

        override fun close() = Unit
    }

    /** A forwarder wired to a pipe pair; tunOut is drained into [drained]. */
    private class Harness(
        proxy: ProxyClient,
        dnsServer: String = "192.0.2.1", // TEST-NET-1: blackholes DNS
        dnsTimeoutMs: Int = 200,
    ) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val statuses = mutableListOf<String>()
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, proxy, dnsServer,
            protectUdp = { true },
            onStatus = { statuses.add(it) },
            dnsTimeoutMs = dnsTimeoutMs,
            // v1.0.4: fallback ikut blackhole — default 1.0.0.1
            // adalah server DNS beneran dan menjawab example.com
            // di CI, jadi jalur GAGAL tidak pernah tercapai di tes
            // ini (regr. CI 44860422297: baris DNS GAGAL tak muncul).
            dnsFallbackServer = dnsServer,
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

    private fun syn(options: ByteArray = byteArrayOf(), mss: Int = 1460): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = mss, options = options,
        )

    private fun udpDnsQuery(): ByteArray {
        // Minimal DNS query (id 0x1234, 1 question, RD set).
        val q = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
        )
        return TcpPacket.buildUdp(clientIp, serverIp, 53000, 53, q)
    }

    private fun icmpEchoRequest(): ByteArray {
        val total = 20 + 8 + 4
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x45.toByte())
        buf.put(0)
        buf.putShort(total.toShort())
        buf.putShort(1)
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(TcpPacket.PROTO_ICMP.toByte())
        buf.putShort(0)
        buf.putInt(clientIp)
        buf.putInt(serverIp)
        buf.put(8.toByte()) // echo request
        buf.put(0.toByte())
        buf.putShort(0)
        buf.putShort(1) // id
        buf.putShort(1) // seq
        buf.put(byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()))
        val out = buf.array()
        val ipSum = TcpPacket.checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
        val icmpSum = TcpPacket.checksum(out, 20, out.size - 20)
        out[22] = (icmpSum ushr 8).toByte()
        out[23] = (icmpSum and 0xFF).toByte()
        return out
    }

    @Test
    fun `start logs mulai and each packet is counted and logged`() {
        val before = DialLog.lines().size
        val h = Harness(OkProxy())
        h.fwd.start()
        assertTrue(waitFor(what = "FORWARDER mulai") {
            DialLog.lines().drop(before).any { it.contains("mulai — baca TUN") }
        })
        // Feed one packet at a time and wait for its line: a
        // PipedInputStream read() can coalesce packets written
        // back-to-back into one read, and handlePacket only parses
        // the first packet of each read.
        h.feed(syn())
        assertTrue(waitFor(what = "TUN TCP line") {
            DialLog.lines().drop(before).any { it.contains("TCP 10.10.14.2:12345 -> 93.184.216.34:443") }
        })
        h.feed(udpDnsQuery())
        assertTrue(waitFor(what = "TUN UDP line") {
            DialLog.lines().drop(before).any { it.contains("UDP 10.10.14.2:53000 -> 93.184.216.34:53") }
        })
        h.feed(icmpEchoRequest())
        assertTrue(waitFor(what = "TUN ICMP line") {
            DialLog.lines().drop(before).any { it.contains("ICMP 10.10.14.2:0 -> 93.184.216.34:0") }
        })
        val lines = DialLog.lines().drop(before).joinToString("\n")
        assertTrue(lines.contains("TCP 10.10.14.2:12345 -> 93.184.216.34:443 (#1)"))
        assertTrue(lines.contains("UDP 10.10.14.2:53000 -> 93.184.216.34:53 (#2)"))
        assertTrue(lines.contains("ICMP 10.10.14.2:0 -> 93.184.216.34:0 (#3)"))
        assertTrue(lines.contains("query 93.184.216.34"))
        h.stop()
        assertTrue(waitFor(what = "FORWARDER berhenti") {
            DialLog.lines().drop(before).any { it.contains("berhenti (paket dibaca:") }
        })
        val stopLine = DialLog.lines().drop(before).first { it.contains("berhenti (paket dibaca:") }
        assertTrue(stopLine.contains("paket dibaca: 3"))
    }

    @Test
    fun `syn with window scale and sack gets echo in syn-ack`() {
        val h = Harness(OkProxy())
        h.fwd.start()
        // SYN offers MSS 1460 + SACK-permitted + window scale 7.
        h.feed(syn(options = byteArrayOf(1, 1, 4, 2, 1, 3, 3, 7)))
        assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
        // v1.0.21: wait for the SYN-ACK to reach the drainer BEFORE
        // stopping — the writer thread is async, and stop() closes
        // the pipe while the drainer may not have consumed the
        // bytes yet (flaky `bytes.size >= 32` on a loaded runner).
        assertTrue(waitFor(what = "SYN-ACK drained") { h.drainedBytes().isNotEmpty() })
        h.stop()
        val bytes = h.drainedBytes()
        assertTrue(bytes.size >= 32)
        val ip = TcpPacket.parseIp(bytes, bytes.size)
        assertNotNull(ip)
        val tcp = TcpPacket.parseTcp(ip!!.payload)
        assertNotNull(tcp)
        tcp!!
        // SYN-ACK: MSS 4 + SACK 4 + WS 4 = 12 option bytes.
        assertEquals(12, tcp.options.size)
        val opts = TcpPacket.parseTcpOptions(tcp.options)
        // v1.0.15: the offered MSS comes from the MTU —
        // clamp(1500 - 40, 1140, 1460) = 1460, capped at the
        // peer's 1460 — not XVEON's 1360 (the extra 100 bytes
        // guarded outer-tunnel overhead that does not apply to
        // the local TUN link).
        assertEquals(1460, opts.mss)
        assertEquals(5, opts.windowScale) // xray-core shift
        assertTrue(opts.sackPermitted)
        assertEquals(TcpPacket.TCP_WINDOW_SCALED, tcp.window)
        assertEquals(TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK, tcp.flags)
    }

    @Test
    fun `syn without options gets mss-only syn-ack`() {
        val h = Harness(OkProxy())
        h.fwd.start()
        h.feed(syn())
        assertTrue(waitFor(what = "Connected") { h.statuses.contains("Connected") })
        // v1.0.21: same drain race as the WS/SACK test above — wait
        // for the SYN-ACK to reach the drainer before stopping.
        assertTrue(waitFor(what = "SYN-ACK drained") { h.drainedBytes().isNotEmpty() })
        h.stop()
        val bytes = h.drainedBytes()
        assertTrue(bytes.size >= 24)
        val ip = TcpPacket.parseIp(bytes, bytes.size)
        assertNotNull(ip)
        val tcp = TcpPacket.parseTcp(ip!!.payload)
        assertNotNull(tcp)
        tcp!!
        assertEquals(4, tcp.options.size) // MSS only
        val opts = TcpPacket.parseTcpOptions(tcp.options)
        // v1.0.15: MSS from the MTU (1460), not XVEON's 1360.
        assertEquals(1460, opts.mss)
        assertEquals(null, opts.windowScale)
        assertEquals(false, opts.sackPermitted)
        assertEquals(TcpPacket.TCP_WINDOW, tcp.window)
    }

    @Test
    fun `dial start line is written before proxy dial runs`() {
        // v1.0.9 fix C: the DIAL line must exist even when the
        // proxy dial throws immediately — the v1.0.9 phone log had
        // no forwarder DIAL lines at all, so a failure before the
        // line was written is indistinguishable from "no traffic".
        val before = DialLog.lines().size
        val h = Harness(FailingProxy())
        h.fwd.start()
        h.feed(syn())
        assertTrue(waitFor(what = "DIAL start line") {
            DialLog.lines().drop(before).any { it.contains("93.184.216.34:443") }
        })
        assertTrue(waitFor(what = "DIAL GAGAL line") {
            DialLog.lines().drop(before).any { it.contains("DIAL 93.184.216.34:443 GAGAL") }
        })
        h.stop()
    }

    @Test
    fun `dns query receipt and failure are logged`() {
        // The DNS relay used to drop failed queries silently; the
        // browser then cannot resolve, so no TCP SYN is ever
        // generated and the forwarder looks dead. Receipt must be
        // logged at once; the failure (blackhole server) within
        // the test's 5 s window.
        val before = DialLog.lines().size
        val h = Harness(OkProxy(), dnsTimeoutMs = 200)
        h.fwd.start()
        h.feed(udpDnsQuery())
        assertTrue(waitFor(what = "DNS query line") {
            DialLog.lines().drop(before).any { it.contains("query 93.184.216.34") }
        })
        assertTrue(waitFor(what = "DNS GAGAL line", timeoutMs = 10_000) {
            DialLog.lines().drop(before).any { it.contains("DNS") && it.contains("GAGAL") }
        })
        h.stop()
    }
}
