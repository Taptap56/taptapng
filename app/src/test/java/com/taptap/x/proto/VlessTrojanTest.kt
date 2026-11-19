package com.taptap.x.proto
import com.taptap.x.core.proto.*

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.net.InetAddress
import java.net.ServerSocket
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * VLESS + Trojan: header build/parse-back and loopback relay against
 * minimal fake servers (no TLS here — plain TCP transport).
 * Loopback uses ::1, not 127.0.0.1: the dev VM's sandbox blackholes
 * JVM client connects to IPv4 loopback, while ::1 connects fine.
 */
class VlessTrojanTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    @Test
    fun `vless header parses back for domain ipv4 ipv6`() {
        for ((host, port) in listOf(
            "example.com" to 8443,
            "1.2.3.4" to 80,
            "2001:db8::1" to 443,
        )) {
            val header = VlessCrypto.buildRequestHeader(uuid, host, port)
            val parsed = VlessCrypto.parseRequestHeader(header)
            assertArrayEquals(AddrCodec.parseUuidBytes(uuid), parsed.uuidBytes)
            if (host.contains(':')) {
                // IPv6: InetAddress expands "::" — compare by bytes,
                // not by the compressed string form.
                assertArrayEquals(
                    InetAddress.getByName(host).address,
                    InetAddress.getByName(parsed.target.host).address,
                )
            } else {
                assertEquals(host, parsed.target.host)
            }
            assertEquals(port, parsed.target.port)
        }
    }

    @Test
    fun `vless dial relays raw bytes`() {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                // Read the whole header: 19 bytes + port(2) + atyp(1) +
                // domain len(1) + domain(11) = 34 bytes total.
                val head = input.readExactBytes(19)
                val parsed = VlessCrypto.parseRequestHeader(head + input.readExactBytes(15))
                assertEquals("example.com", parsed.target.host)
                assertEquals(443, parsed.target.port)
                output.write(byteArrayOf(0x00, 0x00)) // version + addon length
                output.flush()
                val buf = ByteArray(4)
                var filled = 0
                while (filled < buf.size) {
                    val r = input.read(buf, filled, buf.size - filled)
                    if (r == -1) break
                    filled += r
                }
                assertArrayEquals("ping".toByteArray(), buf)
                output.write("pong".toByteArray())
                output.flush()
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VLESS,
            address = "::1", port = port,
            uuid = uuid, method = "none", network = "tcp",
        )
        val client = VlessClient(item)
        val stream = client.dial("example.com", 443)
        try {
            stream.output.write("ping".toByteArray())
            stream.output.flush()
            val buf = ByteArray(4)
            var filled = 0
            while (filled < buf.size) {
                val r = stream.input.read(buf, filled, buf.size - filled)
                if (r == -1) break
                filled += r
            }
            assertArrayEquals("pong".toByteArray(), buf)
        } finally {
            client.close()
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake VLESS server gagal", it) }
    }

    @Test
    fun `vless rejects non-none encryption`() {
        val item = ProfileItem(
            configType = ConfigType.VLESS,
            address = "127.0.0.1", port = 1,
            uuid = uuid, method = "mlkem768x25519plus", network = "tcp",
        )
        assertThrows(IllegalArgumentException::class.java) {
            VlessClient(item).dial("example.com", 443)
        }
    }

    @Test
    fun `trojan header parses back`() {
        val header = TrojanCrypto.buildRequestHeader("secret-password", "example.com", 443)
        val parsed = TrojanCrypto.parseRequestHeader(header)
        assertEquals(TrojanCrypto.passwordHashHex("secret-password"), parsed.passwordHashHex)
        assertEquals(56, parsed.passwordHashHex.length)
        assertTrue(parsed.passwordHashHex.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals("example.com", parsed.target.host)
        assertEquals(443, parsed.target.port)
    }

    @Test
    fun `trojan dial relays raw bytes`() {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                // Header: 56 hex + CRLF + 1 CMD + 1 ATYP + 1 len +
                // 11 domain + 2 port + CRLF = 76 bytes.
                val head = input.readExactBytes(76)
                val parsed = TrojanCrypto.parseRequestHeader(head)
                assertEquals(TrojanCrypto.passwordHashHex("secret"), parsed.passwordHashHex)
                assertEquals("example.com", parsed.target.host)
                assertEquals(443, parsed.target.port)
                val buf = ByteArray(4)
                var filled = 0
                while (filled < buf.size) {
                    val r = input.read(buf, filled, buf.size - filled)
                    if (r == -1) break
                    filled += r
                }
                assertArrayEquals("ping".toByteArray(), buf)
                output.write("pong".toByteArray())
                output.flush()
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.TROJAN,
            address = "::1", port = port,
            password = "secret", network = "tcp",
        )
        val client = TrojanClient(item)
        val stream = client.dial("example.com", 443)
        try {
            stream.output.write("ping".toByteArray())
            stream.output.flush()
            val buf = ByteArray(4)
            var filled = 0
            while (filled < buf.size) {
                val r = stream.input.read(buf, filled, buf.size - filled)
                if (r == -1) break
                filled += r
            }
            assertArrayEquals("pong".toByteArray(), buf)
        } finally {
            client.close()
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake Trojan server gagal", it) }
    }

    @Test
    fun `trojan rejects empty password`() {
        val item = ProfileItem(
            configType = ConfigType.TROJAN,
            address = "127.0.0.1", port = 1,
            password = "", network = "tcp",
        )
        assertThrows(IllegalArgumentException::class.java) {
            TrojanClient(item).dial("example.com", 443)
        }
    }
}
