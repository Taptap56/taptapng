package com.taptap.ng

import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.ProxyUdpSession
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.TcpPacket
import com.taptap.ng.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): paket IPv6 di TUN — TCP (SYN → SYN-ACK → data dua
 * arah), UDP non-DNS lewat proxy, ICMPv6 echo, dan balasan DNS
 * AAAA sebagai paket UDPv6.
 */
@Timeout(30)
class TunForwarderIpv6Test {

    private val client = TcpPacket.IpAddr.parse("fd00:1:2:3::2")
    private val server = TcpPacket.IpAddr.parse("2001:db8::1")

    private class EchoStream(
        val feedOut: PipedOutputStream,
        val feedIn: PipedInputStream,
        val sink: ByteArrayOutputStream,
    ) : ProxyStream {
        override val input: InputStream = feedIn
        override val output: OutputStream = sink
        override fun close() {
            runCatching { feedOut.close() }
            runCatching { feedIn.close() }
        }
    }

    private class EchoUdpSession : ProxyUdpSession {
        val sent = LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)
        override fun send(datagram: ByteArray) {
            sent.add(datagram)
        }

        override fun receive(timeoutMs: Long): ByteArray? {
            while (!closed.get()) {
                sent.poll(100, TimeUnit.MILLISECONDS)?.let { return it }
            }
            return null
        }

        override fun close() {
            closed.set(true)
        }
    }

    private class FakeProxy : ProxyClient {
        val dialed = mutableListOf<Pair<String, Int>>()
        val udpDialed = mutableListOf<Pair<String, Int>>()
        var lastStream: EchoStream? = null
        var lastUdp: EchoUdpSession? = null

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            dialed += targetHost to targetPort
            val feedOut = PipedOutputStream()
            val feedIn = PipedInputStream(feedOut, 16384)
            return EchoStream(feedOut, feedIn, ByteArrayOutputStream()).also { lastStream = it }
        }

        override fun dialUdp(targetHost: String, targetPort: Int, stats: SpeedStats?): ProxyUdpSession {
            udpDialed += targetHost to targetPort
            return EchoUdpSession().also { lastUdp = it }
        }

        override fun close() = Unit
    }

    private class Harness(
        proxy: ProxyClient,
        dnsServer: String = "192.0.2.1",
        dnsPort: Int = 53,
    ) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, proxy, dnsServer,
            protectUdp = { true },
            onStatus = {},
            dnsTimeoutMs = 2000,
            dnsFallbackServer = dnsServer,
            dnsPort = dnsPort,
        )

        init {
            thread(name = "test-drainer-v6", isDaemon = true) {
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

        fun start() = fwd.start()

        fun feed(pkt: ByteArray) {
            tunInWrite.write(pkt)
            tunInWrite.flush()
        }

        fun stop() {
            runCatching { fwd.stop() }
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }

        fun drainedBytes(): ByteArray = synchronized(drained) { drained.toByteArray() }
    }

    private fun waitFor(timeoutMs: Long = 5000, what: String, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    /** Ambil SEMUA paket IPv6 utuh dari drained (framing payload-length). */
    private fun drainedIpv6Packets(h: Harness): List<ByteArray> {
        val bytes = h.drainedBytes()
        val out = mutableListOf<ByteArray>()
        var off = 0
        while (off + 40 <= bytes.size) {
            if (bytes[off].toInt() shr 4 != 6) break
            val payloadLen = ((bytes[off + 4].toInt() and 0xFF) shl 8) or
                (bytes[off + 5].toInt() and 0xFF)
            val total = 40 + payloadLen
            if (off + total > bytes.size) break
            out.add(bytes.copyOfRange(off, off + total))
            off += total
        }
        return out
    }

    private fun syn(srcPort: Int = 12345, seq: Long = 1000L): ByteArray =
        TcpPacket.buildTcp6(
            client.bytes, server.bytes, srcPort, 443,
            seq, 0L, TcpPacket.FLAG_SYN, ByteArray(0), mss = 1460,
        )

    @Test
    fun `SYN IPv6 dibalas SYN-ACK IPv6 lalu data dua arah jalan`() {
        val proxy = FakeProxy()
        val h = Harness(proxy)
        h.start()
        try {
            h.feed(syn())
            assertTrue(
                waitFor(what = "SYN-ACK v6") { drainedIpv6Packets(h).isNotEmpty() },
                "tidak ada SYN-ACK IPv6",
            )
            val synAck = drainedIpv6Packets(h).first()
            val ipH = TcpPacket.parseIpv6Header(synAck, synAck.size)!!
            assertArrayEquals(server.bytes, ipH.src)
            assertArrayEquals(client.bytes, ipH.dst)
            val tcp = TcpPacket.parseTcpSegment(synAck, ipH.payloadOff, ipH.payloadLen)!!
            assertEquals(TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK, tcp.flags)
            assertEquals(1001L, tcp.ack)
            val isn = tcp.seq
            // Dial memakai alamat IPv6 literal sebagai host
            // (bentuk panjang Java — bandingkan byte-nya).
            assertEquals(1, proxy.dialed.size)
            assertArrayEquals(
                server.bytes,
                java.net.InetAddress.getByName(proxy.dialed[0].first).address,
            )
            assertEquals(443, proxy.dialed[0].second)
            // ACK + data dari aplikasi.
            val data = "hello-v6".toByteArray()
            h.feed(
                TcpPacket.buildTcp6(
                    client.bytes, server.bytes, 12345, 443,
                    1001L, isn + 1, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, data,
                ),
            )
            assertTrue(
                waitFor(what = "data sampai proxy") {
                    proxy.lastStream?.sink?.size() == data.size
                },
                "data aplikasi tidak sampai ke proxy",
            )
            assertArrayEquals(data, proxy.lastStream!!.sink.toByteArray())
            // Balasan dari server → paket data ke TUN.
            val stream = proxy.lastStream!!
            stream.feedOut.write("world-v6".toByteArray())
            stream.feedOut.flush()
            assertTrue(
                waitFor(what = "balasan data v6") { drainedIpv6Packets(h).size >= 2 },
                "tidak ada paket balasan IPv6",
            )
            val reply = drainedIpv6Packets(h)[1]
            val replyH = TcpPacket.parseIpv6Header(reply, reply.size)!!
            val replyTcp = TcpPacket.parseTcpSegment(reply, replyH.payloadOff, replyH.payloadLen)!!
            assertArrayEquals("world-v6".toByteArray(), replyTcp.payload)
        } finally {
            h.stop()
        }
    }

    @Test
    fun `UDP IPv6 non-DNS di-echo lewat proxy`() {
        val proxy = FakeProxy()
        val h = Harness(proxy)
        h.start()
        try {
            val payload = "quic-v6".toByteArray()
            h.feed(TcpPacket.buildUdp6(client.bytes, server.bytes, 5000, 443, payload))
            assertTrue(
                waitFor(what = "balasan UDPv6") { drainedIpv6Packets(h).isNotEmpty() },
                "tidak ada balasan UDP IPv6",
            )
            val reply = drainedIpv6Packets(h).first()
            val ipH = TcpPacket.parseIpv6Header(reply, reply.size)!!
            assertArrayEquals(server.bytes, ipH.src)
            assertArrayEquals(client.bytes, ipH.dst)
            val udp = TcpPacket.parseUdp(reply.copyOfRange(40, reply.size))!!
            assertEquals(443, udp.srcPort)
            assertEquals(5000, udp.dstPort)
            assertArrayEquals(payload, udp.payload)
            assertEquals(1, proxy.udpDialed.size)
            assertArrayEquals(
                server.bytes,
                java.net.InetAddress.getByName(proxy.udpDialed[0].first).address,
            )
            assertEquals(443, proxy.udpDialed[0].second)
        } finally {
            h.stop()
        }
    }

    @Test
    fun `ICMPv6 echo dibalas lokal`() {
        val proxy = FakeProxy()
        val h = Harness(proxy)
        h.start()
        try {
            // Echo request type 128, id/seq + payload "ping".
            val icmp = ByteArray(12)
            icmp[0] = 128.toByte()
            icmp[4] = 0x12; icmp[5] = 0x34
            icmp[6] = 0; icmp[7] = 1
            "ping".toByteArray().copyInto(icmp, 8)
            val pkt = ByteArray(40 + icmp.size)
            val buf = java.nio.ByteBuffer.wrap(pkt).order(java.nio.ByteOrder.BIG_ENDIAN)
            buf.put(0x60.toByte()); buf.put(0); buf.put(0); buf.put(0)
            buf.putShort(icmp.size.toShort())
            buf.put(TcpPacket.PROTO_ICMPV6.toByte()); buf.put(64.toByte())
            buf.put(client.bytes); buf.put(server.bytes)
            icmp.copyInto(pkt, 40)
            val sum = TcpPacket.checksum6(
                pkt, 40, icmp.size, client.bytes, server.bytes, TcpPacket.PROTO_ICMPV6,
            )
            pkt[42] = (sum ushr 8).toByte()
            pkt[43] = (sum and 0xFF).toByte()
            h.feed(pkt)
            assertTrue(
                waitFor(what = "balasan ICMPv6") { drainedIpv6Packets(h).isNotEmpty() },
                "tidak ada balasan ICMPv6",
            )
            val reply = drainedIpv6Packets(h).first()
            assertEquals(129, reply[40].toInt() and 0xFF)
            assertArrayEquals(server.bytes, reply.copyOfRange(8, 24))
            assertArrayEquals(client.bytes, reply.copyOfRange(24, 40))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `query DNS AAAA lewat IPv6 dijawab sebagai paket UDPv6 dan dicatat knownHosts6`() {
        // Server DNS palsu di loopback IPv4 (port dinamis).
        val dnsSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val dnsPort = dnsSocket.localPort
        val dnsThread = thread(name = "dns-v6-stub", isDaemon = true) {
            try {
                val buf = ByteArray(8192)
                val packet = DatagramPacket(buf, buf.size)
                dnsSocket.receive(packet)
                val query = packet.data.copyOf(packet.length)
                val resp = buildDnsAaaaResponse(query)
                dnsSocket.send(DatagramPacket(resp, resp.size, packet.address, packet.port))
            } catch (_: Exception) {
                // Socket ditutup di finally tes.
            }
        }
        val proxy = FakeProxy()
        val h = Harness(proxy, dnsServer = "127.0.0.1", dnsPort = dnsPort)
        h.start()
        try {
            val query = buildDnsQuery("example.com", 28) // AAAA
            h.feed(TcpPacket.buildUdp6(client.bytes, server.bytes, 5000, 53, query))
            assertTrue(
                waitFor(what = "jawaban DNS v6") { drainedIpv6Packets(h).isNotEmpty() },
                "tidak ada jawaban DNS IPv6",
            )
            val reply = drainedIpv6Packets(h).first()
            val ipH = TcpPacket.parseIpv6Header(reply, reply.size)!!
            assertEquals(TcpPacket.PROTO_UDP, ipH.protocol)
            val udp = TcpPacket.parseUdp(reply.copyOfRange(40, reply.size))!!
            assertEquals(53, udp.srcPort)
            assertEquals(5000, udp.dstPort)
            assertEquals(0x1234, ((udp.payload[0].toInt() and 0xFF) shl 8) or (udp.payload[1].toInt() and 0xFF))
            // Kunci knownHosts6 adalah bentuk panjang Java
            // (InetAddress.hostAddress) — bandingkan lewat itu.
            val v6Key = java.net.InetAddress.getByName("2001:db8::1").hostAddress
            assertTrue(
                waitFor(what = "knownHosts6") {
                    h.fwd.knownHosts6Snapshot().containsKey(v6Key)
                },
                "jawaban AAAA tidak tercatat di knownHosts6: ${h.fwd.knownHosts6Snapshot()}",
            )
            assertEquals("example.com", h.fwd.knownHosts6Snapshot()[v6Key])
        } finally {
            h.stop()
            runCatching { dnsSocket.close() }
            dnsThread.join(2000)
        }
    }

    /** Query DNS minimal: ID 0x1234, QDCOUNT 1, QNAME + QTYPE + QCLASS IN. */
    private fun buildDnsQuery(name: String, qtype: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        for (label in name.split(".")) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.UTF_8))
        }
        out.write(0)
        out.write((qtype shr 8) and 0xFF)
        out.write(qtype and 0xFF)
        out.write(0); out.write(1) // QCLASS IN
        return out.toByteArray()
    }

    /** Jawaban DNS: header query + 1 jawaban AAAA 2001:db8::1 (pointer nama 0xC00C). */
    private fun buildDnsAaaaResponse(query: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(query.copyOfRange(0, 2)) // ID
        out.write(byteArrayOf(0x81.toByte(), 0x80.toByte())) // QR + RA, RCODE 0
        out.write(byteArrayOf(0x00, 0x01)) // QDCOUNT 1
        out.write(byteArrayOf(0x00, 0x01)) // ANCOUNT 1
        out.write(byteArrayOf(0x00, 0x00, 0x00, 0x00)) // NSCOUNT + ARCOUNT 0
        out.write(query.copyOfRange(12, query.size)) // pertanyaan
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte())) // NAME pointer
        out.write(byteArrayOf(0x00, 0x1C)) // TYPE AAAA (28)
        out.write(byteArrayOf(0x00, 0x01)) // CLASS IN
        out.write(byteArrayOf(0x00, 0x00, 0x01, 0x2C)) // TTL 300
        out.write(byteArrayOf(0x00, 0x10)) // RDLENGTH 16
        out.write(java.net.InetAddress.getByName("2001:db8::1").address)
        return out.toByteArray()
    }
}
