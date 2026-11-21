package com.taptap.ng.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.core.LinkParser
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.proto.HttpUpgradeTransport
import com.taptap.ng.core.proto.ProxyClientFactory
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.core.proto.VlessClient
import com.taptap.ng.core.slowdns.TlsEngine
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.13 (Xray HTTPUpgrade): the upgrade handshake against a fake
 * server on ::1, raw-stream behaviour after the 101, rejection
 * rules, httpupgrade inside a TLS tunnel (TlsEngine stream pair),
 * the full ladder through Transport.open (plain + over proxy
 * CONNECT), factory gating, and link round-trip.
 *
 * Loopback uses ::1, not 127.0.0.1: the dev VM's sandbox blackholes
 * JVM client connects to IPv4 loopback, while ::1 connects fine.
 * TLS over a loopback socket is intercepted in the dev VM (and the
 * same test failed on the CI runner over a socket pair — see
 * TlsEngineTest), so the TLS case runs over in-memory QueueChannel
 * stream pairs with a real SSLEngine server (test-tls.p12).
 */
class HttpUpgradeTransportTest {

    /** Read one HTTP block (until the blank line) from a stream. */
    private fun readHttpBlock(input: InputStream): String {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw EOFException("EOF saat baca blok HTTP")
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

    /** Read exactly [n] bytes or throw. */
    private fun readExactBytes(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val r = input.read(out, filled, n - filled)
            if (r == -1) throw EOFException("EOF saat baca $n byte")
            filled += r
        }
        return out
    }

    /** One-shot fake server on ::1 running [script] on accept. */
    private class FakeServer(
        private val script: (InputStream, OutputStream) -> Unit,
    ) {
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port: Int get() = server.localPort
        var error: Throwable? = null
        private var thread: Thread? = null

        fun start() {
            thread = Thread {
                try {
                    val socket = server.accept()
                    socket.soTimeout = 5_000
                    script(socket.getInputStream(), socket.getOutputStream())
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

    private fun upgrade101(output: OutputStream) {
        output.write(
            ("HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: upgrade\r\n\r\n").toByteArray(Charsets.UTF_8),
        )
        output.flush()
    }

    @Test
    fun `httpupgrade handshake plus raw round-trip`() {
        val server = FakeServer { input, output ->
            val request = readHttpBlock(input)
            assertTrue(request.startsWith("GET /hup HTTP/1.1\r\n"), "request: $request")
            assertTrue(request.contains("Host: example.com\r\n"), "request: $request")
            assertTrue(request.contains("Upgrade: websocket\r\n"), "request: $request")
            assertTrue(request.contains("Connection: Upgrade\r\n"), "request: $request")
            assertTrue(request.contains("Sec-WebSocket-Key: "), "request: $request")
            assertTrue(request.contains("Sec-WebSocket-Version: 13\r\n"), "request: $request")
            // No Sec-WebSocket-Accept is expected from the server —
            // httpupgrade has none (xray's client never checks it).
            upgrade101(output)
            // Raw bytes, no WS framing: the client writes 5 bytes and
            // the server must see exactly those 5 bytes, unframed.
            val raw = readExactBytes(input, 5)
            assertEquals("vless", raw.toString(Charsets.UTF_8))
            output.write("sless".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        server.start()
        val socket = java.net.Socket("::1", server.port)
        socket.soTimeout = 5_000
        try {
            val stream = HttpUpgradeTransport.connect(
                socket.getInputStream(), socket.getOutputStream(), "example.com", "/hup",
            )
            stream.output.write("vless".toByteArray(Charsets.UTF_8))
            stream.output.flush()
            val echo = readExactBytes(stream.input, 5)
            assertEquals("sless", echo.toString(Charsets.UTF_8))
        } finally {
            runCatching { socket.close() }
        }
        server.join()
        assertNull(server.error, "server error: ${server.error}")
    }

    @Test
    fun `httpupgrade rejection on 200`() {
        val server = FakeServer { input, output ->
            readHttpBlock(input)
            output.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        server.start()
        val socket = java.net.Socket("::1", server.port)
        socket.soTimeout = 5_000
        try {
            val e = assertThrows(IOException::class.java) {
                HttpUpgradeTransport.connect(
                    socket.getInputStream(), socket.getOutputStream(), "example.com", "/hup",
                )
            }
            assertTrue(e.message!!.contains("200 OK"), "pesan: ${e.message}")
        } finally {
            runCatching { socket.close() }
        }
        server.join()
        assertNull(server.error, "server error: ${server.error}")
    }

    @Test
    fun `httpupgrade rejection on 101 without Upgrade header`() {
        val server = FakeServer { input, output ->
            readHttpBlock(input)
            output.write(
                ("HTTP/1.1 101 Switching Protocols\r\n" +
                    "Connection: upgrade\r\n\r\n").toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        server.start()
        val socket = java.net.Socket("::1", server.port)
        socket.soTimeout = 5_000
        try {
            assertThrows(IOException::class.java) {
                HttpUpgradeTransport.connect(
                    socket.getInputStream(), socket.getOutputStream(), "example.com", "/hup",
                )
            }
        } finally {
            runCatching { socket.close() }
        }
        server.join()
        assertNull(server.error, "server error: ${server.error}")
    }

    @Test
    fun `httpupgrade rejection on 101 with wrong Connection`() {
        val server = FakeServer { input, output ->
            readHttpBlock(input)
            output.write(
                ("HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: keep-alive\r\n\r\n").toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        server.start()
        val socket = java.net.Socket("::1", server.port)
        socket.soTimeout = 5_000
        try {
            assertThrows(IOException::class.java) {
                HttpUpgradeTransport.connect(
                    socket.getInputStream(), socket.getOutputStream(), "example.com", "/hup",
                )
            }
        } finally {
            runCatching { socket.close() }
        }
        server.join()
        assertNull(server.error, "server error: ${server.error}")
    }

    @Test
    fun `httpupgrade inside TLS tunnel`() {
        // Same shape as TlsEngineTest: in-memory queue channels, a
        // real SSLEngine server (test-tls.p12), client via
        // TlsEngine.wrap (insecure=true). The upgrade request and
        // the 101 both travel inside TLS; after the 101 the VLESS
        // bytes are raw on the TLS stream.
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        var serverError: Throwable? = null
        var serverSawRaw = ""
        val serverThread = Thread({
            try {
                serverSession.handshake()
                val request = readHttpBlock(serverSession.inputStream)
                assertTrue(request.startsWith("GET /hup HTTP/1.1\r\n"), "request (TLS): $request")
                assertTrue(request.contains("Upgrade: websocket\r\n"), "request (TLS): $request")
                serverSession.outputStream.write(
                    ("HTTP/1.1 101 Switching Protocols\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: upgrade\r\n\r\n").toByteArray(Charsets.UTF_8),
                )
                serverSession.outputStream.flush()
                val raw = ByteArray(5)
                var filled = 0
                while (filled < raw.size) {
                    val r = serverSession.inputStream.read(raw, filled, raw.size - filled)
                    if (r == -1) break
                    filled += r
                }
                serverSawRaw = raw.copyOf(filled).toString(Charsets.UTF_8)
                serverSession.outputStream.write("sless".toByteArray(Charsets.UTF_8))
                serverSession.outputStream.flush()
            } catch (e: Throwable) {
                serverError = e
            }
        }, "hup-tls-server").apply { isDaemon = true }
        serverThread.start()

        val tlsItem = ProfileItem(address = "example.com", port = 443, tls = true, insecure = true)
        val (tlsIn, tlsOut) = TlsEngine.wrap(serverToClient.input, clientToServer.output, tlsItem)
        try {
            val stream = HttpUpgradeTransport.connect(tlsIn, tlsOut, "example.com", "/hup")
            stream.output.write("vless".toByteArray(Charsets.UTF_8))
            stream.output.flush()
            val echo = ByteArray(5)
            var filled = 0
            while (filled < echo.size) {
                val r = stream.input.read(echo, filled, echo.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals("sless", echo.toString(Charsets.UTF_8))
        } finally {
            runCatching { tlsIn.close() }
            runCatching { tlsOut.close() }
        }
        serverThread.join(5_000)
        assertNull(serverError, "server TLS error: $serverError")
        assertEquals("vless", serverSawRaw)
    }

    @Test
    fun `httpupgrade through Transport open delivers raw stream`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val server = FakeServer { input, output ->
            val request = readHttpBlock(input)
            assertTrue(request.startsWith("GET /hup HTTP/1.1\r\n"), "request: $request")
            assertTrue(request.contains("Upgrade: websocket\r\n"), "request: $request")
            upgrade101(output)
            val raw = readExactBytes(input, 5)
            assertEquals("vless", raw.toString(Charsets.UTF_8))
            output.write("sless".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        server.start()
        try {
            val item = ProfileItem(
                configType = ConfigType.VLESS,
                address = "::1",
                port = server.port,
                uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
                network = "httpupgrade",
                tls = false,
                path = "/hup",
            )
            val stream = Transport.open(item)
            try {
                stream.output.write("vless".toByteArray(Charsets.UTF_8))
                stream.output.flush()
                val echo = readExactBytes(stream.input, 5)
                assertEquals("sless", echo.toString(Charsets.UTF_8))
            } finally {
                runCatching { stream.close() }
            }
        } finally {
            server.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(server.error, "server error: ${server.error}")
    }

    @Test
    fun `httpupgrade over proxy CONNECT through Transport open`() {
        TunnelState.up = false
        Transport.protectSocket = null
        val proxy = FakeServer { input, output ->
            val connect = readHttpBlock(input)
            assertTrue(connect.startsWith("CONNECT target.invalid:443 HTTP/1.1"), "CONNECT: $connect")
            output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
            val request = readHttpBlock(input)
            assertTrue(request.startsWith("GET /hup HTTP/1.1\r\n"), "request: $request")
            assertTrue(request.contains("Upgrade: websocket\r\n"), "request: $request")
            assertTrue(request.contains("Sec-WebSocket-Version: 13\r\n"), "request: $request")
            upgrade101(output)
            val raw = readExactBytes(input, 5)
            assertEquals("vless", raw.toString(Charsets.UTF_8))
            output.write("sless".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        proxy.start()
        try {
            val item = ProfileItem(
                configType = ConfigType.VLESS,
                address = "target.invalid",
                port = 443,
                uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
                network = "httpupgrade",
                tls = false,
                path = "/hup",
                proxyEnabled = true,
                proxyHost = "::1",
                proxyPort = proxy.port,
                proxyMode = "connect",
                xrayUsePayload = false,
            )
            val stream = Transport.open(item)
            try {
                stream.output.write("vless".toByteArray(Charsets.UTF_8))
                stream.output.flush()
                val echo = readExactBytes(stream.input, 5)
                assertEquals("sless", echo.toString(Charsets.UTF_8))
            } finally {
                runCatching { stream.close() }
            }
        } finally {
            proxy.join()
            Transport.protectSocket = null
            TunnelState.up = false
        }
        assertNull(proxy.error, "proxy error: ${proxy.error}")
    }

    @Test
    fun `factory accepts httpupgrade for vmess vless trojan`() {
        val vmess = ProfileItem(
            configType = ConfigType.VMESS, address = "127.0.0.1", port = 1,
            uuid = "de305d54-75b4-431b-adb2-eb6b9e546014", network = "httpupgrade",
        )
        val vless = vmess.copy(configType = ConfigType.VLESS)
        val trojan = vmess.copy(configType = ConfigType.TROJAN)
        assertTrue(ProxyClientFactory.create(vmess) is com.taptap.ng.core.proto.VmessClient)
        assertTrue(ProxyClientFactory.create(vless) is VlessClient)
        assertTrue(ProxyClientFactory.create(trojan) is com.taptap.ng.core.proto.TrojanClient)
    }

    @Test
    fun `factory rejects httpupgrade for shadowsocks and still rejects kcp grpc`() {
        val ss = ProfileItem(
            configType = ConfigType.SHADOWSOCKS, address = "127.0.0.1", port = 1,
            method = "aes-256-gcm", network = "httpupgrade",
        )
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(ss)
        }
        val kcp = ProfileItem(
            configType = ConfigType.VMESS, address = "127.0.0.1", port = 1,
            uuid = "de305d54-75b4-431b-adb2-eb6b9e546014", network = "kcp",
        )
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(kcp)
        }
        val grpc = kcp.copy(network = "grpc")
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(grpc)
        }
    }

    @Test
    fun `vless link with type httpupgrade parses and round trips`() {
        val item = LinkParser.parse(
            "vless://de305d54-75b4-431b-adb2-eb6b9e546014@104.17.3.81:80" +
                "?encryption=none&security=none&type=httpupgrade&host=104.17.3.81&path=%2F#hack-VLESS-H2-NonTLS",
        )
        assertTrue(item != null, "link httpupgrade harus ter-parse")
        item!!
        assertEquals(ConfigType.VLESS, item.configType)
        assertEquals("httpupgrade", item.network)
        assertEquals("104.17.3.81", item.address)
        assertEquals(80, item.port)
        assertEquals("/", item.path)
        assertEquals(false, item.tls)
        val uri = LinkParser.toUri(item)
        assertTrue(uri != null && uri.contains("type=httpupgrade"), "toUri: $uri")
        val reparsed = LinkParser.parse(uri!!)
        assertTrue(reparsed != null && reparsed.network == "httpupgrade", "round trip: $uri")
    }

    @Test
    fun `vmess json link with net httpupgrade parses`() {
        val json = """{"v":"2","ps":"HU","add":"104.17.3.81","port":"80","id":"de305d54-75b4-431b-adb2-eb6b9e546014","aid":"0","scy":"auto","net":"httpupgrade","type":"none","host":"104.17.3.81","path":"/","tls":"","sni":"","fp":"","alpn":""}"""
        val b64 = Base64Util.encodeUrlSafe(json.toByteArray(Charsets.UTF_8))
        val item = LinkParser.parse("vmess://$b64")
        assertTrue(item != null, "vmess net=httpupgrade harus ter-parse")
        item!!
        assertEquals(ConfigType.VMESS, item.configType)
        assertEquals("httpupgrade", item.network)
        assertEquals("/", item.path)
        assertEquals(false, item.tls)
    }

    // ---- TLS test support (mirrors TlsEngineTest) ----

    private fun serverContext(): SSLContext {
        val ks = KeyStore.getInstance("PKCS12")
        val res: InputStream = javaClass.classLoader
            .getResourceAsStream("test-tls.p12")
            ?: throw IllegalStateException("test-tls.p12 tidak ada di test resources")
        res.use { ks.load(it, "taptapx-test".toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "taptapx-test".toCharArray())
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, null)
        }
    }

    /**
     * In-memory byte channel (M3 test only): an unbounded queue of
     * chunks; reads block up to [readTimeoutMs] then throw
     * SocketTimeoutException, so a stalled peer fails fast instead
     * of hanging the test (and CI) forever.
     */
    private class QueueChannel(private val readTimeoutMs: Long = 15_000) {
        private val queue = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        val input: InputStream = object : InputStream() {
            private var current: ByteArray? = null
            private var pos = 0
            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n == -1) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                while (current == null || pos >= current!!.size) {
                    if (closed.get() && queue.isEmpty()) return -1
                    val chunk = queue.poll(readTimeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                        ?: throw java.net.SocketTimeoutException(
                            "QueueChannel baca menggantung > ${readTimeoutMs}ms",
                        )
                    if (chunk.isEmpty()) return -1 // EOF marker
                    current = chunk
                    pos = 0
                }
                val cur = current!!
                val take = minOf(len, cur.size - pos)
                cur.copyInto(b, off, pos, pos + take)
                pos += take
                return take
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                queue.offer(b.copyOfRange(off, off + len))
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }
    }
}
