package com.taptap.ng.proto

import com.taptap.ng.core.proto.TrojanUdpPacket
import com.taptap.ng.core.proto.UdpFraming
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * v1.0.6 (M6): framing datagram UDP — length-prefix (VMess/VLESS)
 * + paket UDP Trojan. Murni byte, tanpa socket.
 */
class UdpFramingTest {

    @Test
    fun `length prefix round trip`() {
        val payload = "hello-quic".toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        UdpFraming.writeDatagram(out, payload)
        val bytes = out.toByteArray()
        assertEquals(0, bytes[0].toInt())
        assertEquals(payload.size, bytes[1].toInt())
        assertArrayEquals(payload, UdpFraming.readDatagram(ByteArrayInputStream(bytes)))
    }

    @Test
    fun `dua datagram berurutan tidak tercampur`() {
        val out = ByteArrayOutputStream()
        UdpFraming.writeDatagram(out, "satu".toByteArray())
        UdpFraming.writeDatagram(out, "dua-tiga".toByteArray())
        val input = ByteArrayInputStream(out.toByteArray())
        assertArrayEquals("satu".toByteArray(), UdpFraming.readDatagram(input))
        assertArrayEquals("dua-tiga".toByteArray(), UdpFraming.readDatagram(input))
        assertNull(UdpFraming.readDatagram(input))
    }

    @Test
    fun `datagram kosong ditolak`() {
        assertThrows(IllegalArgumentException::class.java) {
            UdpFraming.writeDatagram(ByteArrayOutputStream(), ByteArray(0))
        }
    }

    @Test
    fun `datagram di atas 65535 ditolak`() {
        assertThrows(IllegalArgumentException::class.java) {
            UdpFraming.writeDatagram(ByteArrayOutputStream(), ByteArray(65536))
        }
    }

    @Test
    fun `paket Trojan UDP round trip domain`() {
        val payload = "dns-query-bytes".toByteArray()
        val encoded = TrojanUdpPacket.encode("example.com", 53, payload)
        val (target, decoded) = TrojanUdpPacket.decode(ByteArrayInputStream(encoded))
        assertEquals("example.com", target.host)
        assertEquals(53, target.port)
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun `paket Trojan UDP round trip ipv4 dan ipv6`() {
        for ((host, port) in listOf("8.8.8.8" to 53, "2001:db8::1" to 443)) {
            val payload = byteArrayOf(1, 2, 3, 4)
            val encoded = TrojanUdpPacket.encode(host, port, payload)
            val (target, decoded) = TrojanUdpPacket.decode(ByteArrayInputStream(encoded))
            assertEquals(port, target.port)
            assertArrayEquals(payload, decoded)
            if (host.contains(':')) {
                assertArrayEquals(
                    java.net.InetAddress.getByName(host).address,
                    java.net.InetAddress.getByName(target.host).address,
                )
            } else {
                assertEquals(host, target.host)
            }
        }
    }

    @Test
    fun `paket Trojan UDP tanpa CRLF ditolak`() {
        val encoded = TrojanUdpPacket.encode("example.com", 53, "x".toByteArray())
        val truncated = encoded.copyOf(encoded.size - 2)
        assertThrows(Exception::class.java) {
            TrojanUdpPacket.decode(ByteArrayInputStream(truncated))
        }
    }
}
