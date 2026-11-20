package com.taptap.x

import com.taptap.x.service.TcpPacket
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TcpPacketTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 0, 0, 2)
    private val serverIp = TcpPacket.ipFromBytes(1, 2, 3, 4)

    @Test
    fun `tcp build parse round trip`() {
        val payload = "hello-tun".toByteArray(Charsets.UTF_8)
        val pkt = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 5000L,
            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
        )
        val ip = TcpPacket.parseIp(pkt, pkt.size)
        assertNotNull(ip)
        ip!!
        assertEquals(clientIp, ip.src)
        assertEquals(serverIp, ip.dst)
        assertEquals(TcpPacket.PROTO_TCP, ip.protocol)
        val tcp = TcpPacket.parseTcp(ip.payload)
        assertNotNull(tcp)
        tcp!!
        assertEquals(12345, tcp.srcPort)
        assertEquals(443, tcp.dstPort)
        assertEquals(1000L, tcp.seq)
        assertEquals(5000L, tcp.ack)
        assertEquals(TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, tcp.flags)
        assertEquals("hello-tun", String(tcp.payload, Charsets.UTF_8))
    }

    @Test
    fun `tcp checksums verify to zero`() {
        val pkt = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 5000L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = TcpPacket.TCP_MSS,
        )
        // Recomputing the checksum over a header that already carries
        // its checksum must yield 0 (one's complement sum is 0xFFFF).
        assertEquals(0, TcpPacket.checksum(pkt, 0, 20))
        val tcpLen = pkt.size - 20
        assertEquals(0, TcpPacket.tcpChecksum(clientIp, serverIp, pkt, 20, tcpLen))
        // MSS option present: data offset is 6 (24-byte TCP header).
        val tcp = TcpPacket.parseTcp(pkt.copyOfRange(20, pkt.size))
        assertNotNull(tcp)
        assertEquals(0, tcp!!.payload.size)
        // The MSS value itself is at TCP offset 22.
        assertEquals(1460, ((pkt[42].toInt() and 0xFF) shl 8) or (pkt[43].toInt() and 0xFF))
    }

    @Test
    fun `udp build parse round trip`() {
        val payload = byteArrayOf(0x12, 0x34, 0x00, 0x00, 0x00, 0x01)
        val pkt = TcpPacket.buildUdp(clientIp, serverIp, 53000, 53, payload)
        assertEquals(0, TcpPacket.checksum(pkt, 0, 20))
        val ip = TcpPacket.parseIp(pkt, pkt.size)
        assertNotNull(ip)
        val udp = TcpPacket.parseUdp(ip!!.payload)
        assertNotNull(udp)
        assertEquals(53000, udp!!.srcPort)
        assertEquals(53, udp.dstPort)
        assertEquals(payload.toList(), udp.payload.toList())
    }

    @Test
    fun `icmp echo reply swaps addresses and answers`() {
        val request = buildEchoRequest()
        val reply = TcpPacket.buildIcmpEchoReply(request, request.size)
        assertNotNull(reply)
        reply!!
        val ip = TcpPacket.parseIp(reply, reply.size)
        assertNotNull(ip)
        assertEquals(serverIp, ip!!.src)
        assertEquals(clientIp, ip.dst)
        assertEquals(TcpPacket.PROTO_ICMP, ip.protocol)
        assertEquals(0, ip.payload[0].toInt() and 0xFF) // type 0 = echo reply
        assertEquals(0, TcpPacket.checksum(reply, 0, 20))
        assertEquals(0, TcpPacket.checksum(reply, 20, reply.size - 20))
        // Identifier / sequence / payload are echoed back unchanged.
        assertEquals(request.copyOfRange(24, 28).toList(), reply.copyOfRange(24, 28).toList())
        assertEquals(request.copyOfRange(28, 32).toList(), reply.copyOfRange(28, 32).toList())
    }

    @Test
    fun `udp checksum is real and verifies to zero`() {
        // v1.0.10: buildUdp used to write a 0 checksum ("optional").
        // xray-core's tun stack computes a real one (0 -> 0xffff),
        // and the DNS reply is the first packet the app ever
        // receives from us — it must be beyond doubt. Recomputing
        // the checksum over a packet that already carries it must
        // yield 0, and the field itself must not be 0.
        val payload = byteArrayOf(0x12, 0x34, 0x00, 0x00, 0x00, 0x01)
        val pkt = TcpPacket.buildUdp(clientIp, serverIp, 53000, 53, payload)
        val udpLen = pkt.size - 20
        assertEquals(0, TcpPacket.udpChecksum(clientIp, serverIp, pkt, 20, udpLen))
        val field = ((pkt[26].toInt() and 0xFF) shl 8) or (pkt[27].toInt() and 0xFF)
        assertTrue(field != 0, "UDP checksum field must not be 0, got $field")
    }

    @Test
    fun `tcp options parse and build round trip`() {
        // v1.0.10: a SYN offering MSS + SACK + window scale must
        // survive build -> parse, so the forwarder can echo the
        // offers in its SYN-ACK like xray-core's tun stack does.
        // Fails on v1.0.9 code (parseTcp drops the options).
        val options = byteArrayOf(1, 1, 4, 2, 1, 3, 3, 7) // SACK + WS 7
        val pkt = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = 1460, options = options,
        )
        assertEquals(0, TcpPacket.checksum(pkt, 0, 20))
        val tcpLen = pkt.size - 20
        assertEquals(0, TcpPacket.tcpChecksum(clientIp, serverIp, pkt, 20, tcpLen))
        val ip = TcpPacket.parseIp(pkt, pkt.size)
        assertNotNull(ip)
        val tcp = TcpPacket.parseTcp(ip!!.payload)
        assertNotNull(tcp)
        tcp!!
        // Data offset 8 (32-byte TCP header: 20 + MSS 4 + SACK 4 + WS 4).
        assertEquals(12, tcp.options.size)
        val parsed = TcpPacket.parseTcpOptions(tcp.options)
        assertEquals(1460, parsed.mss)
        assertEquals(7, parsed.windowScale)
        assertTrue(parsed.sackPermitted)
        assertEquals(0, tcp.payload.size)
    }

    @Test
    fun `parseTcp handles a realistic SYN with timestamps`() {
        // v1.0.10: a real app SYN (Linux/Android) carries MSS +
        // SACK + window scale + timestamps — a 44-byte header,
        // data-offset byte 0xB0 (negative as a signed Byte). On
        // v1.0.9 code parseTcp returned null for it, so the
        // forwarder silently dropped every real SYN and the v1.0.9
        // phone log had zero DIAL lines.
        val options = byteArrayOf(
            1, 1, 4, 2, // SACK-permitted
            1, 3, 3, 7, // window scale 7
            1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // timestamps
        )
        val pkt = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = 1460, options = options,
        )
        val ip = TcpPacket.parseIp(pkt, pkt.size)
        assertNotNull(ip)
        val tcp = TcpPacket.parseTcp(ip!!.payload)
        assertNotNull(tcp)
        tcp!!
        assertEquals(24, tcp.options.size)
        val parsed = TcpPacket.parseTcpOptions(tcp.options)
        assertEquals(1460, parsed.mss)
        assertEquals(7, parsed.windowScale)
        assertTrue(parsed.sackPermitted)
        assertEquals(TcpPacket.TCP_WINDOW, tcp.window)
        assertEquals(TcpPacket.FLAG_SYN, tcp.flags)
    }

    @Test
    fun `parseTcpOptions handles nop eol and unknown kinds`() {
        // EOL stops the scan; unknown kinds are skipped by length.
        val withEol = byteArrayOf(2, 4, 0x05, 0xB4.toByte(), 0, 3, 3, 7)
        val parsed = TcpPacket.parseTcpOptions(withEol)
        assertEquals(1460, parsed.mss)
        assertEquals(null, parsed.windowScale) // after EOL: unseen
        assertEquals(false, parsed.sackPermitted)
        // Unknown kind 9, length 4, then a WS option.
        val unknown = byteArrayOf(9, 4, 0xAA.toByte(), 0xBB.toByte(), 1, 3, 3, 5)
        val parsed2 = TcpPacket.parseTcpOptions(unknown)
        assertEquals(5, parsed2.windowScale)
        // Truncated option stops the scan without throwing.
        val truncated = byteArrayOf(3, 3)
        assertEquals(null, TcpPacket.parseTcpOptions(truncated).windowScale)
        assertEquals(null, TcpPacket.parseTcpOptions(byteArrayOf()).mss)
    }

    @Test
    fun `non ipv4 and truncated packets return null`() {
        assertNull(TcpPacket.parseIp(byteArrayOf(0x60, 0, 0, 0), 4))
        assertNull(TcpPacket.parseIp(ByteArray(10), 10))
        assertNull(TcpPacket.parseTcp(ByteArray(10)))
        assertNull(TcpPacket.parseUdp(ByteArray(4)))
    }

    @Test
    fun `ipToString formats dotted quads`() {
        assertEquals("10.0.0.2", TcpPacket.ipToString(clientIp))
        assertEquals("1.2.3.4", TcpPacket.ipToString(serverIp))
    }

    @Test
    fun `buildTcpInto matches buildTcp byte for byte`() {
        // v1.0.15: the relay builds into a reusable buffer — the
        // bytes must be identical to the allocating buildTcp,
        // including the checksums (ipId differs per call, so the
        // two packets are built from the same call sequence and
        // compared field by field, not by raw bytes).
        val payload = ByteArray(1460) { (it % 251).toByte() }
        val options = byteArrayOf(1, 1, 4, 2, 1, 3, 3, 5)
        val a = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443, 1000L, 5000L,
            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
            mss = 1460, options = options, window = 8192,
        )
        val buf = ByteArray(2048) // options (12B) + payload 1460B = 1512B
        val n = TcpPacket.buildTcpInto(
            buf,
            clientIp, serverIp, 12345, 443, 1000L, 5000L,
            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
            0, payload.size, mss = 1460, options = options, window = 8192,
        )
        assertEquals(a.size, n)
        // Same bytes except the IP id field (bytes 4-5), which is a
        // per-call counter.
        for (i in a.indices) {
            if (i == 4 || i == 5) continue
            assertEquals(a[i], buf[i], "byte $i differs")
        }
        assertEquals(0, TcpPacket.checksum(buf, 0, 20))
        assertEquals(0, TcpPacket.tcpChecksum(clientIp, serverIp, buf, 20, n - 20))
        // Slice form: build from the middle of a larger buffer.
        val big = ByteArray(4096) { (it % 251).toByte() }
        val off = 1000
        val n2 = TcpPacket.buildTcpInto(
            buf,
            clientIp, serverIp, 12345, 443, 2000L, 6000L,
            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, big, off, 1460,
        )
        assertEquals(20 + 20 + 1460, n2)
        val parsed = TcpPacket.parseTcpSegment(buf, 20, n2 - 20)
        assertNotNull(parsed)
        assertEquals(2000L, parsed!!.seq)
        assertTrue(big.copyOfRange(off, off + 1460).contentEquals(parsed.payload))
    }

    @Test
    fun `parseTcpSegment matches parseIp plus parseTcp`() {
        // v1.0.15: the single-copy hot path must agree with the
        // old two-copy path on every field, including a realistic
        // SYN with options (data offset 0xA0 — the v1.0.10
        // signed-byte case) and a data segment.
        val synOptions = byteArrayOf(
            2, 4, 0x05, 0xB4, // MSS 1460
            1, 3, 3, 7, // window scale 7
            1, 1, 4, 2, // SACK permitted
            1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, // timestamps
            1, 1, 1, // NOP padding
        )
        val syn = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443, 1000L, 0L,
            TcpPacket.FLAG_SYN, ByteArray(0),
            mss = 1460, options = synOptions,
        )
        val data = TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443, 1001L, 5000L,
            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK,
            "hello-segment".toByteArray(Charsets.UTF_8),
        )
        for (pkt in listOf(syn, data)) {
            val ip = TcpPacket.parseIp(pkt, pkt.size)!!
            val old = TcpPacket.parseTcp(ip.payload)!!
            val header = TcpPacket.parseIpHeader(pkt, pkt.size)!!
            assertEquals(ip.src, header.src)
            assertEquals(ip.dst, header.dst)
            assertEquals(ip.protocol, header.protocol)
            assertEquals(20, header.payloadOff)
            assertEquals(ip.payload.size, header.payloadLen)
            val fast = TcpPacket.parseTcpSegment(pkt, header.payloadOff, header.payloadLen)
            assertNotNull(fast)
            fast!!
            assertEquals(old.srcPort, fast.srcPort)
            assertEquals(old.dstPort, fast.dstPort)
            assertEquals(old.seq, fast.seq)
            assertEquals(old.ack, fast.ack)
            assertEquals(old.flags, fast.flags)
            assertEquals(old.window, fast.window)
            assertTrue(old.options.contentEquals(fast.options))
            assertTrue(old.payload.contentEquals(fast.payload))
        }
        assertNull(TcpPacket.parseTcpSegment(ByteArray(10), 0, 10))
        assertNull(TcpPacket.parseIpHeader(ByteArray(10), 10))
    }

    /** A well-formed ICMP echo request (client -> server), id 0x1234. */
    private fun buildEchoRequest(): ByteArray {
        val icmpPayload = "ping".toByteArray(Charsets.UTF_8)
        val icmpLen = 8 + icmpPayload.size
        val total = 20 + icmpLen
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
        buf.put(8.toByte()) // type: echo request
        buf.put(0.toByte()) // code
        buf.putShort(0) // checksum, filled below
        buf.putShort(0x1234)
        buf.putShort(1)
        buf.put(icmpPayload)
        val out = buf.array()
        val ipSum = TcpPacket.checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
        val icmpSum = TcpPacket.checksum(out, 20, icmpLen)
        out[22] = (icmpSum ushr 8).toByte()
        out[23] = (icmpSum and 0xFF).toByte()
        return out
    }
}
