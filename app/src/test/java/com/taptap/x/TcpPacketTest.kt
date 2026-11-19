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
