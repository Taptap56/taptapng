package com.taptap.ng

import com.taptap.ng.service.TcpPacket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.6 (M6): codec IPv6 — parse header, bangun TCP/UDP/ICMPv6,
 * checksum pseudo-header terverifikasi (jumlah atas paket utuh
 * termasuk field checksum harus 0).
 */
class TcpPacketIpv6Test {

    private val client = TcpPacket.IpAddr.parse("fd00:1:2:3::2")
    private val server = TcpPacket.IpAddr.parse("2001:db8::1")

    @Test
    fun `parse header IPv6 dari paket TCP6`() {
        val pkt = TcpPacket.buildTcp6(
            client.bytes, server.bytes, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0), mss = 1460,
        )
        val h = TcpPacket.parseIpv6Header(pkt, pkt.size)
        assertNotNull(h)
        assertArrayEquals(client.bytes, h!!.src)
        assertArrayEquals(server.bytes, h.dst)
        assertEquals(TcpPacket.PROTO_TCP, h.protocol)
        assertEquals(40, h.payloadOff)
        assertEquals(pkt.size - 40, h.payloadLen)
    }

    @Test
    fun `parse header IPv6 menolak paket IPv4`() {
        val pkt = TcpPacket.buildTcp(
            TcpPacket.ipFromBytes(10, 0, 0, 2), TcpPacket.ipFromBytes(8, 8, 8, 8),
            12345, 443, 1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
        )
        assertNull(TcpPacket.parseIpv6Header(pkt, pkt.size))
    }

    @Test
    fun `parse header IPv6 menolak extension header`() {
        val pkt = TcpPacket.buildTcp6(
            client.bytes, server.bytes, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
        )
        // Ubah Next Header jadi 0 (Hop-by-Hop) — harus ditolak.
        val bad = pkt.copyOf().also { it[6] = 0 }
        assertNull(TcpPacket.parseIpv6Header(bad, bad.size))
    }

    @Test
    fun `TCP6 round trip dan checksum valid`() {
        val payload = "hello-v6".toByteArray()
        val pkt = TcpPacket.buildTcp6(
            client.bytes, server.bytes, 12345, 443,
            1000L, 500L, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
        )
        val h = TcpPacket.parseIpv6Header(pkt, pkt.size)!!
        val tcp = TcpPacket.parseTcpSegment(pkt, h.payloadOff, h.payloadLen)!!
        assertEquals(12345, tcp.srcPort)
        assertEquals(443, tcp.dstPort)
        assertEquals(1000L, tcp.seq)
        assertEquals(500L, tcp.ack)
        assertArrayEquals(payload, tcp.payload)
        // Checksum atas segmen utuh (termasuk field checksum) = 0.
        assertEquals(
            0,
            TcpPacket.tcpChecksum6(client.bytes, server.bytes, pkt, 40, pkt.size - 40),
        )
    }

    @Test
    fun `UDP6 round trip dan checksum valid`() {
        val payload = "dns-v6".toByteArray()
        val pkt = TcpPacket.buildUdp6(client.bytes, server.bytes, 5000, 53, payload)
        val h = TcpPacket.parseIpv6Header(pkt, pkt.size)!!
        assertEquals(TcpPacket.PROTO_UDP, h.protocol)
        val udp = TcpPacket.parseUdp(pkt.copyOfRange(40, pkt.size))!!
        assertEquals(5000, udp.srcPort)
        assertEquals(53, udp.dstPort)
        assertArrayEquals(payload, udp.payload)
        assertEquals(
            0,
            TcpPacket.udpChecksum6(client.bytes, server.bytes, pkt, 40, pkt.size - 40),
        )
    }

    @Test
    fun `ICMPv6 echo request dibalas type 129 dengan alamat tukar`() {
        val request = buildIcmpv6EchoRequest()
        val reply = TcpPacket.buildIcmpv6EchoReply(request, request.size)
        assertNotNull(reply)
        val h = TcpPacket.parseIpv6Header(reply!!, reply.size)!!
        assertEquals(TcpPacket.PROTO_ICMPV6, h.protocol)
        assertArrayEquals(server.bytes, h.src)
        assertArrayEquals(client.bytes, h.dst)
        assertEquals(129, reply[40].toInt() and 0xFF)
        // Checksum balasan valid.
        assertEquals(
            0,
            TcpPacket.checksum6(
                reply, 40, reply.size - 40,
                reply.copyOfRange(8, 24), reply.copyOfRange(24, 40),
                TcpPacket.PROTO_ICMPV6,
            ),
        )
        // Bukan echo request → null.
        val notEcho = request.copyOf().also { it[40] = 0 }
        assertNull(TcpPacket.buildIcmpv6EchoReply(notEcho, notEcho.size))
    }

    /** Paket ICMPv6 echo request (type 128) client → server. */
    private fun buildIcmpv6EchoRequest(): ByteArray {
        val icmp = ByteArray(8 + 4)
        icmp[0] = 128.toByte() // type echo request
        icmp[1] = 0 // code
        // checksum diisi buildIcmpv6EchoReply? Tidak — request butuh
        // checksum sendiri; hitung di sini.
        icmp[4] = 0x12
        icmp[5] = 0x34 // identifier
        icmp[6] = 0
        icmp[7] = 1 // sequence
        icmp[8] = 'p'.code.toByte()
        icmp[9] = 'i'.code.toByte()
        icmp[10] = 'n'.code.toByte()
        icmp[11] = 'g'.code.toByte()
        val pkt = ByteArray(40 + icmp.size)
        val buf = ByteBuffer.wrap(pkt).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x60.toByte())
        buf.put(0); buf.put(0); buf.put(0)
        buf.putShort(icmp.size.toShort())
        buf.put(TcpPacket.PROTO_ICMPV6.toByte())
        buf.put(64.toByte())
        buf.put(client.bytes)
        buf.put(server.bytes)
        icmp.copyInto(pkt, 40)
        val sum = TcpPacket.checksum6(
            pkt, 40, icmp.size, client.bytes, server.bytes, TcpPacket.PROTO_ICMPV6,
        )
        pkt[42] = (sum ushr 8).toByte()
        pkt[43] = (sum and 0xFF).toByte()
        return pkt
    }

    @Test
    fun `IpAddr equality berdasarkan isi byte`() {
        val a = TcpPacket.IpAddr.parse("2001:db8::1")
        val b = TcpPacket.IpAddr.parse("2001:db8::1")
        val c = TcpPacket.IpAddr.parse("2001:db8::2")
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertFalse(a == c)
        assertFalse(a == TcpPacket.IpAddr.v4(TcpPacket.ipFromBytes(10, 0, 0, 1)))
        assertTrue(a.isV6)
        assertTrue(TcpPacket.IpAddr.v4(0).isV4)
    }
}
