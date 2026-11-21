package com.taptap.ng.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.10 (XVEON proxy): the full dial ladder through a fake
 * proxy on ::1 — payload -> CONNECT -> 200 -> plain TCP / WS.
 * Loopback convention is ::1 (JVM IPv4 loopback is blackholed
 * in the dev VM; CI runners are fine either way).
 */
class TransportProxyTest {

    /** Read one HTTP block (until the blank line) from a stream. */
    private fun readHttpBlock(input: InputStream): String {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw IOException("EOF saat baca blok HTTP")
            out.write(b)
            tail.addLast(b)
            if (tail.size > 4) tail.removeFirst()
            if (tail.size == 4 && tail[0] == '\r'.code && tail[1] == '\n'.code &&
                tail[2] == '\r'.code && tail[3] == '\n'.code
            ) {
                return out.toString(Charsets.UTF_8)
            }
        }
    }

    /** One-shot fake proxy on ::1 running [script] on accept. */
    private class FakeProxy(
        private val script: (InputStream, OutputStream, MutableList<String>) -> Unit,
    ) {
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port: Int get() = server.localPort
        val blocks = mutableListOf<String>()
        var error: Throwable? = null
        private var thread: Thread? = null

        fun start() {
            thread = Thread {
                try {
                    val socket = server.accept()
                    socket.soTimeout = 5_000
                    script(socket.getInputStream(), socket.getOutputStream(), blocks)
                    socket.close()
                } catch (e: Throwable) {
                    error = e
                } finally {
                    runCatching { server.close() }
                }
            }.also { it.isDaemon = true; it.start() }
        }

        fun join() = thread?.join(5_000)
    }

    private fun vmessItem(
        network: String = "tcp",
        tls: Boolean = false,
        proxyEnabled: Boolean = true,
        proxyHost: String = "::1",
        proxyPort: Int? = null,
        proxyMode: String = "connect",
        xrayUsePayload: Boolean = true,
        xrayPayload: String = "GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]",
        configType: ConfigType = ConfigType.VMESS,
        address: String = "target.invalid",
        port: Int = 443,
        path: String = "",
    ) = ProfileItem(
        configType = configType,
        address = address,
        port = port,
        uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
        network = network,
        tls = tls,
        proxyEnabled = proxyEnabled,
        proxyHost = proxyHost,
        proxyPort = proxyPort,
        proxyMode = proxyMode,
        xrayUsePayload = xrayUsePayload,
        xrayPayload = xrayPayload,
        path = path,
    )

    /** Read exactly [n] bytes or throw. */
    private fun readExactBytes(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val r = input.read(out, filled, n - filled)
            if (r == -1) throw IOException("EOF saat baca $n byte")
            filled += r
        }
        return out
    }

    /** True when [head] is a TLS record header (ClientHello: 0x16 0x03 0x01). */
    private fun isClientHello(head: ByteArray): Boolean =
        head.size >= 3 && head[0] == 0x16.toByte() && head[1] == 0x03.toByte() && head[2] == 0x01.toByte()

    @Test
    fun `proxy dial sends payload then CONNECT 200 then plain tcp stream`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input) // proxy payload
            blocks += readHttpBlock(input) // CONNECT
            output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            val buf = ByteArray(5)
            var got = 0
            while (got < 5) {
                val n = input.read(buf, got, 5 - got)
                if (n == -1) throw IOException("EOF saat baca echo")
                got += n
            }
            output.write(buf)
            output.flush()
        }
        proxy.start()
        try {
            val item = vmessItem(proxyPort = proxy.port)
            val stream = Transport.open(item)
            try {
                stream.output.write("hello".toByteArray(Charsets.UTF_8))
                stream.output.flush()
                val buf = ByteArray(5)
                var got = 0
                while (got < 5) {
                    val n = stream.input.read(buf, got, 5 - got)
                    if (n == -1) throw IOException("EOF saat baca balasan")
                    got += n
                }
                assertEquals("hello", buf.toString(Charsets.UTF_8))
            } finally {
                runCatching { stream.close() }
            }
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(2, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(proxy.blocks[0].contains("Host: bug.example"), "payload: ${proxy.blocks[0]}")
        assertTrue(
            proxy.blocks[1].startsWith("CONNECT target.invalid:443 HTTP/1.1"),
            "connect: ${proxy.blocks[1]}",
        )
    }

    @Test
    fun `proxy dial with payload off sends only CONNECT`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input) // CONNECT (first thing)
            output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        proxy.start()
        try {
            val item = vmessItem(proxyPort = proxy.port, xrayUsePayload = false, xrayPayload = "")
            val stream = Transport.open(item)
            runCatching { stream.close() }
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(1, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(
            proxy.blocks[0].startsWith("CONNECT target.invalid:443 HTTP/1.1"),
            "connect: ${proxy.blocks[0]}",
        )
    }

    @Test
    fun `proxy dial fails when CONNECT rejected`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input)
            blocks += readHttpBlock(input)
            output.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        proxy.start()
        try {
            val item = vmessItem(proxyPort = proxy.port)
            val e = assertThrows(IOException::class.java) { Transport.open(item) }
            assertTrue(e.message!!.contains("Proxy CONNECT ditolak"), "pesan: ${e.message}")
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
    }

    @Test
    fun `proxy off leaves the old direct path unchanged`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port = server.localPort
        var error: Throwable? = null
        val t = Thread {
            try {
                val s = server.accept()
                s.close()
            } catch (e: Throwable) {
                error = e
            } finally {
                runCatching { server.close() }
            }
        }
        t.isDaemon = true
        t.start()
        try {
            val item = vmessItem(
                proxyEnabled = false, xrayUsePayload = false, xrayPayload = "",
                address = "::1", port = port,
            )
            val stream = Transport.open(item)
            runCatching { stream.close() }
        } finally {
            t.join(5_000)
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(error, "server error: $error")
    }

    @Test
    fun `proxy is ignored for SS and SSH entries`() {
        TunnelState.up = false
        Transport.protectSocket = null
        for (type in listOf(ConfigType.SHADOWSOCKS, ConfigType.SSH)) {
            val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
            val port = server.localPort
            var sawBytes = false
            var error: Throwable? = null
            val t = Thread {
                try {
                    val s = server.accept()
                    s.soTimeout = 800
                    try {
                        if (s.getInputStream().read() != -1) sawBytes = true
                    } catch (_: SocketTimeoutException) {
                        // Nothing sent — expected: the proxy was skipped.
                    }
                    s.close()
                } catch (e: Throwable) {
                    error = e
                } finally {
                    runCatching { server.close() }
                }
            }
            t.isDaemon = true
            t.start()
            try {
                val item = vmessItem(
                    configType = type,
                    address = "::1",
                    port = port,
                    proxyPort = port,
                )
                val stream = Transport.open(item)
                runCatching { stream.close() }
            } finally {
                t.join(5_000)
                Transport.protectSocket = null
                TunnelState.up = false
            }
            assertNull(error, "server error ($type): $error")
            assertTrue(!sawBytes, "$type sent bytes to the proxy — proxy must be ignored")
        }
    }

    @Test
    fun `ws handshake over proxy uses expanded template`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input) // proxy payload (default template)
            blocks += readHttpBlock(input) // CONNECT
            output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            blocks += readHttpBlock(input) // WS handshake
            val key = blocks[2].lines()
                .first { it.startsWith("Sec-WebSocket-Key:", ignoreCase = true) }
                .substringAfter(":").trim()
            val accept = Base64Util.encode(
                MessageDigest.getInstance("SHA-1").digest(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.UTF_8),
                ),
            )
            output.write(
                ("HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Accept: $accept\r\n\r\n").toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        proxy.start()
        try {
            // Blank template + chip on -> the XVEON default template.
            // Path /vmess like a real entry, so [path] expands to it.
            val item = vmessItem(
                network = "ws", tls = false, proxyPort = proxy.port, xrayPayload = "",
                path = "/vmess",
            )
            val stream = Transport.open(item)
            runCatching { stream.close() }
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(3, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(proxy.blocks[0].contains("GET /vmess HTTP/1.1"), "payload: ${proxy.blocks[0]}")
        assertTrue(proxy.blocks[0].contains("Host: target.invalid"), "payload: ${proxy.blocks[0]}")
        assertTrue(!proxy.blocks[0].contains("Sec-WebSocket-Key"), "payload must not carry a key")
        assertTrue(
            proxy.blocks[1].startsWith("CONNECT target.invalid:443 HTTP/1.1"),
            "connect: ${proxy.blocks[1]}",
        )
        assertTrue(proxy.blocks[2].contains("Sec-WebSocket-Key: "), "ws: ${proxy.blocks[2]}")
        assertTrue(proxy.blocks[2].contains("Sec-WebSocket-Version: 13"), "ws: ${proxy.blocks[2]}")
    }

    @Test
    fun `proxy enabled with blank host fails fast`() {
        TunnelState.up = false
        Transport.protectSocket = null
        try {
            val item = vmessItem(proxyHost = "", proxyPort = null)
            val e = assertThrows(IllegalArgumentException::class.java) { Transport.open(item) }
            assertTrue(e.message!!.contains("host proxy kosong"), "pesan: ${e.message}")
        } finally {
            Transport.protectSocket = null
            TunnelState.up = false
        }
    }

    @Test
    fun `proxy host rotate dials per call`() {
        TunnelState.up = false
        Transport.protectSocket = null
        var accepted = 0
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port = server.localPort
        var error: Throwable? = null
        val t = Thread {
            try {
                repeat(2) {
                    val socket = server.accept()
                    socket.soTimeout = 5_000
                    readHttpBlock(socket.getInputStream()) // payload
                    readHttpBlock(socket.getInputStream()) // CONNECT
                    socket.getOutputStream().write(
                        "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.UTF_8),
                    )
                    socket.getOutputStream().flush()
                    accepted++
                    socket.close()
                }
            } catch (e: Throwable) {
                error = e
            } finally {
                runCatching { server.close() }
            }
        }
        t.isDaemon = true
        t.start()
        try {
            val item = vmessItem(proxyHost = "[rotate=::1;::1]", proxyPort = port)
            repeat(2) {
                val stream = Transport.open(item)
                runCatching { stream.close() }
            }
        } finally {
            t.join(5_000)
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(error, "server error: $error")
        assertEquals(2, accepted)
    }

    // ---- v1.0.11: mode "Payload saja" (tanpa CONNECT, seperti SSH) ----

    /** SSH-style template for the payload-only tests (GET bug + PATCH + [split]). */
    private val sshStyleTemplate =
        "GET / HTTP/1.1[crlf]Host: [proxy_host][crlf][crlf]" +
            "PATCH [path] HTTP/1.1[crlf]Host: [ws_host][crlf]Upgrade: websocket[crlf]" +
            "Connection: Upgrade[crlf][crlf][split]HTTP/ 69[crlf][crlf]"

    @Test
    fun `payload-only dial sends payload then TLS ClientHello, no CONNECT`() {
        TunnelState.up = false
        Transport.protectSocket = null
        var sawClientHello = false
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input) // proxy payload (default template)
            output.write("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            // The next bytes must be the TLS ClientHello record, not
            // a CONNECT request (the server closes after reading it,
            // so the client dies with "TLS gagal" — that is expected).
            val head = readExactBytes(input, 5)
            sawClientHello = isClientHello(head)
        }
        proxy.start()
        try {
            val item = vmessItem(
                network = "tcp", tls = true, proxyPort = proxy.port,
                proxyMode = "payload_only", xrayPayload = "",
            )
            val e = assertThrows(IOException::class.java) { Transport.open(item) }
            assertTrue(e.message!!.contains("TLS gagal"), "pesan: ${e.message}")
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(1, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(proxy.blocks[0].contains("GET / HTTP/1.1"), "payload: ${proxy.blocks[0]}")
        assertTrue(proxy.blocks[0].contains("Upgrade: websocket"), "payload: ${proxy.blocks[0]}")
        assertTrue(sawClientHello, "server harus menerima ClientHello TLS, bukan CONNECT")
    }

    @Test
    fun `payload-only with payload off goes straight to TLS`() {
        TunnelState.up = false
        Transport.protectSocket = null
        var sawClientHello = false
        val proxy = FakeProxy { input, output, blocks ->
            // First bytes on the wire must be the ClientHello — no
            // payload block, no CONNECT.
            val head = readExactBytes(input, 5)
            sawClientHello = isClientHello(head)
        }
        proxy.start()
        try {
            val item = vmessItem(
                network = "tcp", tls = true, proxyPort = proxy.port,
                proxyMode = "payload_only", xrayUsePayload = false, xrayPayload = "",
            )
            val e = assertThrows(IOException::class.java) { Transport.open(item) }
            assertTrue(e.message!!.contains("TLS gagal"), "pesan: ${e.message}")
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(0, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(sawClientHello, "server harus menerima ClientHello TLS sebagai byte pertama")
    }

    @Test
    fun `payload-only split timing through Transport`() {
        TunnelState.up = false
        Transport.protectSocket = null
        var sawClientHello = false
        val proxy = FakeProxy { input, output, blocks ->
            val get = readHttpBlock(input)
            assertTrue(get.contains("GET / HTTP/1.1"), "GET: $get")
            assertTrue(get.contains("Host: ::1"), "GET host harus proxy host: $get")
            // The PATCH must not be sent before the GET response.
            assertEquals(0, input.available(), "PATCH terkirim sebelum respons GET")
            output.write("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            val patch = readHttpBlock(input)
            assertTrue(patch.contains("PATCH /vmess HTTP/1.1"), "PATCH: $patch")
            assertTrue(patch.contains("Host: target.invalid"), "PATCH: $patch")
            assertTrue(patch.contains("Upgrade: websocket"), "PATCH: $patch")
            output.write("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            val junk = readHttpBlock(input)
            assertTrue(junk.contains("HTTP/ 69"), "junk: $junk")
            blocks += get
            blocks += patch
            blocks += junk
            sawClientHello = isClientHello(readExactBytes(input, 5))
        }
        proxy.start()
        try {
            val item = vmessItem(
                network = "tcp", tls = true, proxyPort = proxy.port,
                proxyMode = "payload_only", xrayPayload = sshStyleTemplate, path = "/vmess",
            )
            val e = assertThrows(IOException::class.java) { Transport.open(item) }
            assertTrue(e.message!!.contains("TLS gagal"), "pesan: ${e.message}")
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(3, proxy.blocks.size, "blok: ${proxy.blocks}")
        assertTrue(sawClientHello, "sesudah payload harus langsung TLS ClientHello")
    }

    @Test
    fun `payload-only ws handshake is standard, not the ssh-style template`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeProxy { input, output, blocks ->
            blocks += readHttpBlock(input) // GET (bug)
            output.write("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            blocks += readHttpBlock(input) // PATCH (WS upgrade)
            output.write("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            blocks += readHttpBlock(input) // [split] junk
            // WS handshake after TLS (tls=false here): the STANDARD
            // request — the SSH-style template is the proxy payload,
            // not the handshake.
            blocks += readHttpBlock(input)
            val ws = blocks[3]
            val key = ws.lines()
                .first { it.startsWith("Sec-WebSocket-Key:", ignoreCase = true) }
                .substringAfter(":").trim()
            val accept = Base64Util.encode(
                MessageDigest.getInstance("SHA-1").digest(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.UTF_8),
                ),
            )
            output.write(
                ("HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Accept: $accept\r\n\r\n").toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        proxy.start()
        try {
            val item = vmessItem(
                network = "ws", tls = false, proxyPort = proxy.port,
                proxyMode = "payload_only", xrayPayload = sshStyleTemplate, path = "/vmess",
            )
            val stream = Transport.open(item)
            runCatching { stream.close() }
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
        assertEquals(4, proxy.blocks.size, "blok: ${proxy.blocks}")
        val ws = proxy.blocks[3]
        assertTrue(ws.contains("GET /vmess HTTP/1.1"), "ws: $ws")
        assertTrue(ws.contains("Host: target.invalid"), "ws: $ws")
        assertTrue(ws.contains("Upgrade: websocket"), "ws: $ws")
        assertTrue(ws.contains("Sec-WebSocket-Key: "), "ws: $ws")
        assertTrue(ws.contains("Sec-WebSocket-Version: 13"), "ws: $ws")
        assertFalse(ws.contains("PATCH"), "ws harus standar, bukan template SSH: $ws")
        assertFalse(ws.contains("HTTP/ 69"), "ws harus standar, bukan template SSH: $ws")
        assertFalse(ws.contains("[split]"), "ws harus standar, bukan template SSH: $ws")
    }
}
