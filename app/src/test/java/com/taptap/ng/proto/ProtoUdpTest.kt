package com.taptap.ng.proto

import com.taptap.ng.core.proto.LazyHeaderInputStream
import com.taptap.ng.core.proto.LengthPrefixedUdpSession
import com.taptap.ng.core.proto.TrojanUdpPacket
import com.taptap.ng.core.proto.TrojanUdpSession
import com.taptap.ng.core.proto.UdpFraming
import com.taptap.ng.core.proto.VlessCrypto
import com.taptap.ng.core.proto.VmessBodyInputStream
import com.taptap.ng.core.proto.VmessBodyOutputStream
import com.taptap.ng.core.proto.VmessCrypto
import com.taptap.ng.core.proto.VmessSession
import com.taptap.ng.core.proto.readExactBytes
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): UDP di atas VMess / VLESS / Trojan, lawan server
 * palsu in-memory (Piped streams). Server palsu mengimplementasikan
 * sisi server dari framing yang sama (buka header VMess via
 * [VmessCrypto.openRequestHeader], header VLESS/Trojan byte-per-byte)
 * dan meng-echo datagram — jadi tes ini mengunci format wire, bukan
 * hanya codec klien.
 */
@Timeout(30)
class VmessUdpTest {

    private val uuid = "123e4567-e89b-12d3-a456-426614174000"

    @Test
    fun `datagram VMess UDP di-echo server palsu`() {
        val item = ProfileItem(configType = ConfigType.VMESS, uuid = uuid, security = "auto")
        val c2sOut = PipedOutputStream()
        val c2sIn = PipedInputStream(c2sOut, 16384)
        val s2cOut = PipedOutputStream()
        val s2cIn = PipedInputStream(s2cOut, 16384)
        val server = Thread({
            try {
                val cmdKey = VmessCrypto.cmdKey(uuid)
                val opened = VmessCrypto.openRequestHeader(cmdKey, c2sIn)
                assertEquals(VmessCrypto.CMD_UDP.toInt(), opened.header.command)
                assertEquals("8.8.8.8", opened.header.target.host)
                assertEquals(53, opened.header.target.port)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = com.taptap.ng.core.proto.Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = com.taptap.ng.core.proto.Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = opened.header.security,
                )
                s2cOut.write(VmessCrypto.sealResponseHeader(session, opened.header.responseV))
                s2cOut.flush()
                val bodyIn = VmessBodyInputStream(
                    c2sIn, session,
                    key = session.bodyKey, iv = session.bodyIV,
                )
                val bodyOut = VmessBodyOutputStream(
                    s2cOut, session,
                    key = session.responseBodyKey, iv = session.responseBodyIV,
                )
                val datagram = UdpFraming.readDatagram(bodyIn)!!
                val echo = byteArrayOf(0, datagram.size.toByte()) + datagram
                // Echo sebagai length-prefix di dalam body stream.
                bodyOut.write(echo)
                bodyOut.flush()
            } catch (_: Exception) {
                // Client menutup duluan — tes tetap dinilai dari sisi klien.
            }
        }, "vmess-udp-fake-server").apply { isDaemon = true; start() }

        val session = VmessCrypto.newSession(item, "8.8.8.8", 53, VmessCrypto.CMD_UDP)
        c2sOut.write(session.requestBytes)
        c2sOut.flush()
        val bodyOut = VmessBodyOutputStream(c2sOut, session)
        val bodyIn = VmessBodyInputStream(s2cIn, session)
        val lazyIn = LazyHeaderInputStream(bodyIn) {
            VmessCrypto.readResponseHeader(s2cIn, session)
        }
        val udp = LengthPrefixedUdpSession(lazyIn, bodyOut) {}
        try {
            val payload = "dns-query".toByteArray()
            udp.send(payload)
            assertArrayEquals(payload, udp.receive(5000))
        } finally {
            udp.close()
            server.join(2000)
        }
    }

    @Test
    fun `header VMess command UDP ter-parse kembali`() {
        val header = VmessCrypto.buildLogicalHeader(
            ByteArray(16) { it.toByte() }, ByteArray(16) { (it + 1).toByte() },
            0x42, com.taptap.ng.core.proto.VmessSecurity.AES_128_GCM,
            "8.8.8.8", 53, VmessCrypto.CMD_UDP,
        )
        val parsed = VmessCrypto.parseLogicalHeader(header)
        assertEquals(VmessCrypto.CMD_UDP.toInt(), parsed.command)
        assertEquals("8.8.8.8", parsed.target.host)
        assertEquals(53, parsed.target.port)
    }
}

@Timeout(30)
class VlessUdpTest {

    private val uuid = "123e4567-e89b-12d3-a456-426614174000"

    private fun InputStream.readN(n: Int): ByteArray = readExactBytes(n)

    @Test
    fun `datagram VLESS UDP di-echo server palsu`() {
        val c2sOut = PipedOutputStream()
        val c2sIn = PipedInputStream(c2sOut, 16384)
        val s2cOut = PipedOutputStream()
        val s2cIn = PipedInputStream(s2cOut, 16384)
        val server = Thread({
            try {
                // Baca header request byte-per-byte (independen dari
                // VlessCrypto.buildRequestHeader sisi klien).
                val fixed = c2sIn.readN(19)
                assertEquals(0, fixed[0].toInt())
                assertEquals(VlessCrypto.CMD_UDP.toInt(), fixed[18].toInt() and 0xFF)
                val portBytes = c2sIn.readN(2)
                val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                assertEquals(53, port)
                val atyp = c2sIn.read()
                assertEquals(0x01, atyp)
                val addr = c2sIn.readN(4)
                assertEquals("8.8.8.8", addr.joinToString(".") { (it.toInt() and 0xFF).toString() })
                val addonLen = fixed[17].toInt() and 0xFF
                if (addonLen > 0) c2sIn.readN(addonLen)
                // Response header: version 0 + addon 0.
                s2cOut.write(byteArrayOf(0, 0))
                s2cOut.flush()
                val datagram = UdpFraming.readDatagram(c2sIn)!!
                UdpFraming.writeDatagram(s2cOut, datagram)
            } catch (_: Exception) {
                // Client menutup duluan.
            }
        }, "vless-udp-fake-server").apply { isDaemon = true; start() }

        val item = ProfileItem(configType = ConfigType.VLESS, uuid = uuid, method = "none")
        val header = VlessCrypto.buildRequestHeader(item.uuid, "8.8.8.8", 53, VlessCrypto.CMD_UDP)
        c2sOut.write(header)
        c2sOut.flush()
        val lazyIn = LazyHeaderInputStream(s2cIn) {
            VlessCrypto.readResponseHeader(s2cIn)
        }
        val udp = LengthPrefixedUdpSession(lazyIn, c2sOut) {}
        try {
            val payload = "vless-ping".toByteArray()
            udp.send(payload)
            assertArrayEquals(payload, udp.receive(5000))
        } finally {
            udp.close()
            server.join(2000)
        }
    }

    @Test
    fun `header VLESS command UDP ter-parse kembali`() {
        val header = VlessCrypto.buildRequestHeader(uuid, "8.8.8.8", 53, VlessCrypto.CMD_UDP)
        val parsed = VlessCrypto.parseRequestHeader(header)
        assertEquals("8.8.8.8", parsed.target?.host)
        assertEquals(53, parsed.target?.port)
    }
}

@Timeout(30)
class TrojanUdpTest {

    @Test
    fun `datagram Trojan UDP di-echo server palsu`() {
        val c2sOut = PipedOutputStream()
        val c2sIn = PipedInputStream(c2sOut, 16384)
        val s2cOut = PipedOutputStream()
        val s2cIn = PipedInputStream(s2cOut, 16384)
        val server = Thread({
            try {
                // Header: hash(56) + CRLF + CMD + target + CRLF.
                val head = c2sIn.readExactBytes(59)
                assertEquals(0x03, head[58].toInt())
                val atyp = c2sIn.read()
                assertEquals(0x01, atyp)
                c2sIn.readExactBytes(4) // IPv4
                c2sIn.readExactBytes(2) // port
                val crlf = c2sIn.readExactBytes(2)
                assertEquals('\r'.code.toByte(), crlf[0])
                assertEquals('\n'.code.toByte(), crlf[1])
                val (target, payload) = TrojanUdpPacket.decode(c2sIn)
                s2cOut.write(TrojanUdpPacket.encode(target.host, target.port, payload))
                s2cOut.flush()
            } catch (_: Exception) {
                // Client menutup duluan.
            }
        }, "trojan-udp-fake-server").apply { isDaemon = true; start() }

        val item = ProfileItem(configType = ConfigType.TROJAN, password = "secret")
        val header = com.taptap.ng.core.proto.TrojanCrypto.buildRequestHeader(
            item.password, "8.8.8.8", 53, com.taptap.ng.core.proto.TrojanCrypto.CMD_UDP,
        )
        c2sOut.write(header)
        c2sOut.flush()
        val udp = TrojanUdpSession(s2cIn, c2sOut, "8.8.8.8", 53) {}
        try {
            val payload = "trojan-ping".toByteArray()
            udp.send(payload)
            assertArrayEquals(payload, udp.receive(5000))
        } finally {
            udp.close()
            server.join(2000)
        }
    }

    @Test
    fun `header Trojan command UDP ter-parse kembali`() {
        val header = com.taptap.ng.core.proto.TrojanCrypto.buildRequestHeader(
            "secret", "8.8.8.8", 53, com.taptap.ng.core.proto.TrojanCrypto.CMD_UDP,
        )
        val parsed = com.taptap.ng.core.proto.TrojanCrypto.parseRequestHeader(header)
        assertEquals("8.8.8.8", parsed.target.host)
        assertEquals(53, parsed.target.port)
    }
}
