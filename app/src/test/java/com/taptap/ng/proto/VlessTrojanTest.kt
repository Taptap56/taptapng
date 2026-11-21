package com.taptap.ng.proto
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.*

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

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
    fun `vless probe dial succeeds against xray-like server`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val probeBody = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
            .toByteArray(Charsets.UTF_8)
        var serverError: Throwable? = null
        var receivedProbe: ByteArray? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val head = input.readExactBytes(19)
                val parsed = VlessCrypto.parseRequestHeader(head + input.readExactBytes(15))
                assertEquals("example.com", parsed.target.host)
                assertEquals(443, parsed.target.port)
                // xray-like: response header only flushes once data
                // flows — wait for the probe body first.
                receivedProbe = input.readExactBytes(probeBody.size)
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
        val stream = client.dial("example.com", 443, probeBody)
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
        assertTrue(!serverThread.isAlive, "fake server thread must finish")
        serverError?.let { throw AssertionError("Fake VLESS server gagal", it) }
        assertArrayEquals(probeBody, receivedProbe)
    }

    // v1.0.12: same deadlock as VMess, same fix — the relay dial
    // must not read the response header before the app's first data
    // is sent (the xray-like server flushes the header only once
    // data flows). A relay dial returns at once; the header is read
    // lazily on the first read.

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `vless relay dial succeeds against xray-like server when app data is sent first`() {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val head = input.readExactBytes(19)
                val parsed = VlessCrypto.parseRequestHeader(head + input.readExactBytes(15))
                assertEquals("example.com", parsed.target.host)
                assertEquals(443, parsed.target.port)
                // xray-like: response header only after the first
                // body bytes arrive.
                val buf = ByteArray(4)
                var filled = 0
                while (filled < buf.size) {
                    val r = input.read(buf, filled, buf.size - filled)
                    if (r == -1) break
                    filled += r
                }
                assertArrayEquals("ping".toByteArray(), buf)
                output.write(byteArrayOf(0x00, 0x00)) // version + addon length
                output.flush()
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
        val logBefore = DialLog.lines().size
        val client = VlessClient(item)
        // On v1.0.11 dial() itself throws SocketTimeoutException
        // here (~10 s): it reads the response header before any
        // body exists to unblock the server.
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
        assertTrue(!serverThread.isAlive, "fake server thread must finish")
        serverError?.let { throw AssertionError("Fake VLESS server gagal", it) }
        val logLines = DialLog.lines().drop(logBefore)
        assertTrue(
            logLines.any { it.contains("body 4B untuk example.com:443") },
            "log harus ada 'body 4B ...': $logLines",
        )
        assertTrue(
            logLines.any { it.contains("Xray VLESS handshake & transport ready!") },
            "log harus ada 'Xray VLESS handshake & transport ready!': $logLines",
        )
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `vless relay dial returns at once but first read times out with no body`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 15_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val head = input.readExactBytes(19)
                VlessCrypto.parseRequestHeader(head + input.readExactBytes(15))
                // Waits for the first body bytes — a relay that never
                // sends a body never gets a response header.
                val buf = ByteArray(4)
                var filled = 0
                while (filled < buf.size) {
                    val r = input.read(buf, filled, buf.size - filled)
                    if (r == -1) break
                    filled += r
                }
                output.write(byteArrayOf(0x00, 0x00))
                output.flush()
            } catch (_: Throwable) {
                // Expected: the client times out on its first read
                // (~10 s) and closes the transport (EOF), or the
                // server's own 15 s read timeout fires.
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
        val dialStart = System.currentTimeMillis()
        val stream = client.dial("example.com", 443)
        val dialMs = System.currentTimeMillis() - dialStart
        assertTrue(dialMs < 5_000, "dial() harus kembali seketika, butuh ${dialMs}ms")
        try {
            assertThrows(SocketTimeoutException::class.java) {
                stream.input.read()
            }
        } finally {
            runCatching { stream.close() }
            client.close()
        }
        serverThread.join(5_000)
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
