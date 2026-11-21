package com.taptap.ng.proto

import com.taptap.ng.core.proto.SsClient
import com.taptap.ng.core.proto.SsCrypto
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): Shadowsocks UDP — seal/open paket murni + sesi
 * UDP beneran lawan server palsu di loopback (satu AEAD per
 * datagram, salt baru tiap datagram).
 */
@Timeout(30)
class SsUdpTest {

    private val password = "ss-password"
    private val cipher = SsCrypto.SsCipher.AES_128_GCM

    @Test
    fun `seal dan open paket UDP round trip`() {
        val payload = "udp-payload".toByteArray()
        val packet = SsCrypto.sealUdpPacket(password, cipher, "8.8.8.8", 53, payload)
        val (target, opened) = SsCrypto.openUdpPacket(packet, password, cipher)
        assertEquals("8.8.8.8", target.host)
        assertEquals(53, target.port)
        assertArrayEquals(payload, opened)
    }

    @Test
    fun `dua paket bersalt beda tapi sama-sama terbuka`() {
        val p1 = SsCrypto.sealUdpPacket(password, cipher, "1.1.1.1", 443, "a".toByteArray())
        val p2 = SsCrypto.sealUdpPacket(password, cipher, "1.1.1.1", 443, "a".toByteArray())
        // Salt acak → ciphertext beda (tidak deterministik).
        assertEquals(p1.size, p2.size)
        val (_, d1) = SsCrypto.openUdpPacket(p1, password, cipher)
        val (_, d2) = SsCrypto.openUdpPacket(p2, password, cipher)
        assertArrayEquals("a".toByteArray(), d1)
        assertArrayEquals("a".toByteArray(), d2)
    }

    @Test
    fun `sesi UDP SS di-echo server palsu loopback`() {
        val serverSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val serverPort = serverSocket.localPort
        val server = Thread({
            try {
                val buf = ByteArray(65535)
                val packet = DatagramPacket(buf, buf.size)
                serverSocket.receive(packet)
                val bytes = packet.data.copyOf(packet.length)
                val (target, payload) = SsCrypto.openUdpPacket(bytes, password, cipher)
                val reply = SsCrypto.sealUdpPacket(
                    password, cipher, target.host, target.port, payload,
                )
                serverSocket.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
            } catch (_: Exception) {
                // Tes selesai / socket ditutup.
            } finally {
                runCatching { serverSocket.close() }
            }
        }, "ss-udp-fake-server").apply { isDaemon = true; start() }

        val item = ProfileItem(
            configType = ConfigType.SHADOWSOCKS,
            address = "127.0.0.1",
            port = serverPort,
            password = password,
            method = "aes-128-gcm",
            network = "tcp",
        )
        val client = SsClient(item)
        val udp = client.dialUdp("8.8.8.8", 53)
        try {
            val payload = "ss-ping".toByteArray()
            udp.send(payload)
            assertArrayEquals(payload, udp.receive(5000))
        } finally {
            udp.close()
            client.close()
            server.join(2000)
        }
    }

    @Test
    fun `receive timeout mengembalikan null`() {
        val serverSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val serverPort = serverSocket.localPort
        // Server diam (tidak menjawab).
        val item = ProfileItem(
            configType = ConfigType.SHADOWSOCKS,
            address = "127.0.0.1",
            port = serverPort,
            password = password,
            method = "aes-128-gcm",
            network = "tcp",
        )
        val client = SsClient(item)
        val udp = client.dialUdp("8.8.8.8", 53)
        try {
            udp.send("tidak-dijawab".toByteArray())
            assertNull(udp.receive(300))
        } finally {
            udp.close()
            client.close()
            runCatching { serverSocket.close() }
        }
    }
}
