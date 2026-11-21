package com.taptap.ng.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.core.proto.HttpConnectProxy
import com.taptap.ng.core.proto.PayloadOnlyProxy
import com.taptap.ng.core.proto.WsTransport
import com.taptap.ng.core.proto.XrayPayload
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.ServerSocket
import java.security.MessageDigest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.10 (XVEON proxy): HTTP CONNECT request/response, payload
 * template expansion ([rotate], all placeholders, [split]),
 * proxy-target parsing, and the WS handshake with a custom
 * template — all pure / piped / loopback, no real proxy needed.
 */
class XrayProxyTest {

    private fun ctx() = XrayPayload.Ctx(
        wsHost = "h.example",
        path = "/vmess",
        sni = "s.example",
        host = "srv.example",
        ip = "1.2.3.4",
        port = 443,
        wsKey = "KEY==",
    )

    @Test
    fun `connect request is exact CONNECT plus Host`() {
        assertEquals(
            "CONNECT h.example:8080 HTTP/1.1\r\n" +
                "Host: h.example:8080\r\n" +
                "Connection: keep-alive\r\n" +
                "\r\n",
            HttpConnectProxy.buildConnectRequest("h.example", 8080),
        )
    }

    @Test
    fun `connect 200 returns status and leaves trailing bytes unread`() {
        val response =
            "HTTP/1.1 200 Connection Established\r\nX-Foo: bar\r\n\r\nEXTRA-BYTES"
        val input = ByteArrayInputStream(response.toByteArray(Charsets.UTF_8))
        val output = ByteArrayOutputStream()
        val status = HttpConnectProxy.doConnect(input, output, "target.example", 443)
        assertEquals("HTTP/1.1 200 Connection Established", status)
        assertTrue(output.toString(Charsets.UTF_8).contains("CONNECT target.example:443 HTTP/1.1"))
        assertArrayEquals("EXTRA-BYTES".toByteArray(Charsets.UTF_8), input.readAllBytes())
    }

    @Test
    fun `connect non-200 fails with Proxy CONNECT ditolak`() {
        val input = ByteArrayInputStream(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8),
        )
        val e = assertThrows(IOException::class.java) {
            HttpConnectProxy.doConnect(input, ByteArrayOutputStream(), "h", 443)
        }
        assertTrue(e.message!!.contains("Proxy CONNECT ditolak"), "pesan: ${e.message}")
        assertTrue(e.message!!.contains("403"), "pesan: ${e.message}")
    }

    @Test
    fun `connect truncated response fails`() {
        val input = ByteArrayInputStream("HTTP/1.1 200 OK\r\n".toByteArray(Charsets.UTF_8))
        assertThrows(IOException::class.java) {
            HttpConnectProxy.doConnect(input, ByteArrayOutputStream(), "h", 443)
        }
    }

    @Test
    fun `template expands every placeholder`() {
        val out = XrayPayload.expand(
            "GET [path] HTTP/1.1[crlf]Host: [ws_host][crlf]X-SNI: [sni][crlf]X-Key: [ws_key][crlf][crlf]",
            ctx(),
        )
        assertEquals(
            "GET /vmess HTTP/1.1\r\nHost: h.example\r\nX-SNI: s.example\r\nX-Key: KEY==\r\n\r\n",
            out,
        )
    }

    @Test
    fun `template expands host port ip protocol and ua`() {
        val out = XrayPayload.expand("[host_port]|[host]|[port]|[ip]|[protocol]|[ua]", ctx())
        assertTrue(out.startsWith("srv.example:443|srv.example|443|1.2.3.4|HTTP/1.1|Mozilla/5.0"))
        assertTrue(out.endsWith("\r\n\r\n"))
    }

    @Test
    fun `proxy_host expands from ctx and empty without proxy`() {
        val out = XrayPayload.expand(
            "GET / HTTP/1.1[crlf]Host: [proxy_host][crlf][crlf]",
            ctx().copy(proxyHost = "bug.example"),
        )
        assertEquals("GET / HTTP/1.1\r\nHost: bug.example\r\n\r\n", out)
        // No proxy: the placeholder expands empty, [host] untouched.
        val out2 = XrayPayload.expand("Host: [proxy_host] / [host]", ctx())
        assertTrue(out2.startsWith("Host:  / srv.example"), "hasil: $out2")
    }

    @Test
    fun `splitRequests merges split-leading block into previous`() {
        assertEquals(
            listOf(
                "GET / HTTP/1.1\r\nHost: bug\r\n\r\n",
                "PATCH /vmess HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n[split]HTTP/ 69\r\n\r\n",
            ),
            PayloadOnlyProxy.splitRequests(
                "GET / HTTP/1.1\r\nHost: bug\r\n\r\n" +
                    "PATCH /vmess HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n" +
                    "[split]HTTP/ 69\r\n\r\n",
            ),
        )
    }

    // ---- PayloadOnlyProxy chain (v1.0.11, SSH timing) ----

    /** Interactive peer over piped streams: the test thread is the
     * client, [script] runs the server side on a thread. */
    private class PipePeer(private val script: (InputStream, OutputStream) -> Unit) {
        private val clientOut = PipedOutputStream()
        private val serverIn = PipedInputStream(clientOut)
        private val serverOut = PipedOutputStream()
        private val clientIn = PipedInputStream(serverOut)
        var error: Throwable? = null
        private var thread: Thread? = null

        val input: InputStream get() = clientIn
        val output: OutputStream get() = clientOut

        fun start() {
            thread = Thread {
                try {
                    script(serverIn, serverOut)
                } catch (e: Throwable) {
                    error = e
                }
            }.also { it.isDaemon = true; it.start() }
        }

        fun join() = thread?.join(5_000)
    }

    /** Read one HTTP block (until the blank line) from a stream. */
    private fun readBlock(input: InputStream): String {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw IOException("EOF saat baca blok")
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

    private fun writeResponse(output: OutputStream, status: String) {
        output.write("$status\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8))
        output.flush()
    }

    /** SSH-style template: GET (Host: bug) + PATCH (WS upgrade) + [split] junk. */
    private val sshStyleTemplate =
        "GET / HTTP/1.1\r\nHost: bug.example\r\n\r\n" +
            "PATCH /vmess HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" +
            "[split]HTTP/ 69\r\n\r\n"

    @Test
    fun `payload-only chain sends first block waits for response then sends rest`() {
        val peer = PipePeer { input, output ->
            val get = readBlock(input)
            assertTrue(get.contains("Host: bug.example"), "GET: $get")
            // The client must NOT have sent the PATCH yet — it waits
            // for the GET response (the SSH [split] timing rule).
            assertEquals(0, input.available(), "PATCH terkirim sebelum respons")
            writeResponse(output, "HTTP/1.1 301 Moved Permanently")
            val patch = readBlock(input)
            assertTrue(patch.contains("PATCH /vmess HTTP/1.1"), "PATCH: $patch")
            assertTrue(patch.contains("Upgrade: websocket"), "PATCH: $patch")
            output.write(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    .toByteArray(Charsets.UTF_8),
            )
            output.flush()
            val junk = readBlock(input)
            assertTrue(junk.contains("HTTP/ 69"), "junk: $junk")
        }
        peer.start()
        try {
            val result = PayloadOnlyProxy.sendPayload(peer.input, peer.output, sshStyleTemplate)
            assertEquals(
                listOf("HTTP/1.1 301 Moved Permanently", "HTTP/1.1 101 Switching Protocols"),
                result.statuses,
            )
            assertEquals("HTTP/1.1 101 Switching Protocols", result.lastStatus)
            assertTrue(result.wasWsUpgrade)
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    @Test
    fun `payload-only does not send rest on 302`() {
        val template =
            "GET /vmess HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\n\r\n[split]JUNK\r\n\r\n"
        val peer = PipePeer { input, output ->
            val get = readBlock(input)
            assertTrue(get.contains("GET /vmess HTTP/1.1"), "GET: $get")
            assertFalse(get.contains("JUNK"), "junk terkirim sebelum respons: $get")
            writeResponse(output, "HTTP/1.1 302 Found")
            // The client must never send the rest after a 302.
            Thread.sleep(300)
            assertEquals(0, input.available(), "segmen [split] terkirim setelah 302")
        }
        peer.start()
        try {
            val e = assertThrows(IOException::class.java) {
                PayloadOnlyProxy.sendPayload(peer.input, peer.output, template)
            }
            assertTrue(e.message!!.contains("upgrade websocket ditolak"), "pesan: ${e.message}")
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    @Test
    fun `payload-only plain template accepts 2xx and rejects 404`() {
        val template = "GET / HTTP/1.1\r\nHost: h.example\r\n\r\n"
        val okPeer = PipePeer { input, output ->
            readBlock(input)
            writeResponse(output, "HTTP/1.1 200 OK")
        }
        okPeer.start()
        try {
            val result = PayloadOnlyProxy.sendPayload(okPeer.input, okPeer.output, template)
            assertEquals(listOf("HTTP/1.1 200 OK"), result.statuses)
            assertFalse(result.wasWsUpgrade)
        } finally {
            okPeer.join()
        }
        assertEquals(null, okPeer.error, "server error: ${okPeer.error}")

        val badPeer = PipePeer { input, output ->
            readBlock(input)
            writeResponse(output, "HTTP/1.1 404 Not Found")
        }
        badPeer.start()
        try {
            val e = assertThrows(IOException::class.java) {
                PayloadOnlyProxy.sendPayload(badPeer.input, badPeer.output, template)
            }
            assertTrue(e.message!!.contains("proxy menolak payload"), "pesan: ${e.message}")
        } finally {
            badPeer.join()
        }
        assertEquals(null, badPeer.error, "server error: ${badPeer.error}")
    }

    @Test
    fun `payload-only non-HTTP response fails`() {
        val peer = PipePeer { input, output ->
            readBlock(input)
            output.write("SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8))
            output.flush()
        }
        peer.start()
        try {
            val e = assertThrows(IOException::class.java) {
                PayloadOnlyProxy.sendPayload(peer.input, peer.output, sshStyleTemplate)
            }
            assertTrue(e.message!!.contains("bukan HTTP"), "pesan: ${e.message}")
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    // v1.0.11 (selaras 18:57): template gaya SSH yang user gambarkan —
    // GET bug [split] PATCH [host] — [split] DI ANTARA dua request.
    // Rantai memperlakukannya sebagai satu blok: GET dikirim, respons
    // dibaca, PATCH dikirim sesudah 101/2xx, dan respons PATCH-lah
    // yang jadi status blok (bukan respons GET).

    /** GET (Host: bug) [split] PATCH (Host: [host], WS upgrade). */
    private val splitBetweenTemplate =
        "GET / HTTP/1.1\r\nHost: bug.example\r\n\r\n" +
            "[split]PATCH /vmess HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\n" +
            "Connection: Upgrade\r\n\r\n"

    @Test
    fun `payload-only split between requests reads second response`() {
        val peer = PipePeer { input, output ->
            val get = readBlock(input)
            assertTrue(get.contains("Host: bug.example"), "GET: $get")
            assertEquals(0, input.available(), "PATCH terkirim sebelum respons GET")
            writeResponse(output, "HTTP/1.1 200 OK")
            val patch = readBlock(input)
            assertTrue(patch.contains("PATCH /vmess HTTP/1.1"), "PATCH: $patch")
            assertTrue(patch.contains("Host: h.example"), "PATCH: $patch")
            assertTrue(patch.contains("Upgrade: websocket"), "PATCH: $patch")
            output.write(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    .toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        peer.start()
        try {
            val result = PayloadOnlyProxy.sendPayload(peer.input, peer.output, splitBetweenTemplate)
            // Satu blok → satu status: jawaban PATCH (101), bukan
            // jawaban GET (200) — validasi memakai yang terakhir.
            assertEquals(listOf("HTTP/1.1 101 Switching Protocols"), result.statuses)
            assertEquals("HTTP/1.1 101 Switching Protocols", result.lastStatus)
            assertTrue(result.wasWsUpgrade)
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    @Test
    fun `payload-only split between requests does not send second on 301`() {
        val peer = PipePeer { input, output ->
            val get = readBlock(input)
            assertTrue(get.contains("Host: bug.example"), "GET: $get")
            writeResponse(output, "HTTP/1.1 301 Moved Permanently")
            Thread.sleep(300)
            assertEquals(0, input.available(), "PATCH terkirim setelah 301")
        }
        peer.start()
        try {
            val e = assertThrows(IOException::class.java) {
                PayloadOnlyProxy.sendPayload(peer.input, peer.output, splitBetweenTemplate)
            }
            assertTrue(e.message!!.contains("upgrade websocket ditolak"), "pesan: ${e.message}")
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    @Test
    fun `isHttpRequest accepts requests and rejects junk`() {
        assertTrue(PayloadOnlyProxy.isHttpRequest("PATCH /vmess HTTP/1.1\r\nHost: h\r\n\r\n"))
        assertTrue(PayloadOnlyProxy.isHttpRequest("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
        assertFalse(PayloadOnlyProxy.isHttpRequest("HTTP/ 69\r\n\r\n"))
        assertFalse(PayloadOnlyProxy.isHttpRequest("PATCH /vmess HTTP/1.1\r\nHost: h\r\n"))
    }

    @Test
    fun `payload-only drains body and leaves trailing bytes unread`() {
        val template = "GET /vmess HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\n\r\n"
        val peer = PipePeer { input, output ->
            readBlock(input)
            // 101 + a 5-byte body, then trailing bytes that belong to
            // the NEXT stage (TLS) — the chain must not swallow them.
            output.write(
                "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 5\r\n\r\nHELLOEXTRA"
                    .toByteArray(Charsets.UTF_8),
            )
            output.flush()
        }
        peer.start()
        try {
            val result = PayloadOnlyProxy.sendPayload(peer.input, peer.output, template)
            assertEquals("HTTP/1.1 101 Switching Protocols", result.lastStatus)
            assertEquals(5, peer.input.available(), "sisa byte tidak 5")
            val rest = ByteArray(5)
            var got = 0
            while (got < 5) {
                val n = peer.input.read(rest, got, 5 - got)
                if (n == -1) throw IOException("EOF saat baca sisa")
                got += n
            }
            assertEquals("EXTRA", rest.toString(Charsets.UTF_8))
        } finally {
            peer.join()
        }
        assertEquals(null, peer.error, "server error: ${peer.error}")
    }

    @Test
    fun `template brackets ipv6 in host port`() {
        val out = XrayPayload.expand("[host_port]", ctx().copy(host = "::1"))
        assertTrue(out.startsWith("[::1]:443"), "hasil: $out")
    }

    @Test
    fun `template normalises bare newlines to crlf`() {
        val out = XrayPayload.expand("GET / HTTP/1.1\nHost: h.example\n\n", ctx())
        assertEquals("GET / HTTP/1.1\r\nHost: h.example\r\n\r\n", out)
    }

    @Test
    fun `rotate cycles options in order`() {
        XrayPayload.RotatePicker.reset()
        val options = listOf("a", "b", "c")
        assertEquals("a", XrayPayload.RotatePicker.next(options))
        assertEquals("b", XrayPayload.RotatePicker.next(options))
        assertEquals("c", XrayPayload.RotatePicker.next(options))
        assertEquals("a", XrayPayload.RotatePicker.next(options))
    }

    @Test
    fun `rotate in template picks next option per hit`() {
        XrayPayload.RotatePicker.reset()
        val out = XrayPayload.expand("[rotate=x;y] [rotate=x;y] [rotate=x;y]", ctx())
        assertTrue(out.startsWith("x y x"), "hasil: $out")
    }

    @Test
    fun `parse proxy target defaults port to 80`() {
        assertEquals("bug.example" to 80, XrayPayload.parseProxyTarget("bug.example", null))
    }

    @Test
    fun `parse proxy target honours host port and field port`() {
        assertEquals("bug.example" to 8080, XrayPayload.parseProxyTarget("bug.example:8080", null))
        assertEquals("bug.example" to 3128, XrayPayload.parseProxyTarget("bug.example", 3128))
        // Explicit port field wins over a port inside the host text.
        assertEquals("bug.example" to 3128, XrayPayload.parseProxyTarget("bug.example:8080", 3128))
        assertEquals("::1" to 8080, XrayPayload.parseProxyTarget("[::1]:8080", null))
    }

    @Test
    fun `parse proxy target rotates bug per call`() {
        XrayPayload.RotatePicker.reset()
        assertEquals("bug1" to 80, XrayPayload.parseProxyTarget("[rotate=bug1;bug2]", null))
        assertEquals("bug2" to 8080, XrayPayload.parseProxyTarget("[rotate=bug1;bug2]:8080", null))
    }

    @Test
    fun `parse proxy target rejects bad input`() {
        assertThrows(IllegalArgumentException::class.java) {
            XrayPayload.parseProxyTarget("", null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayPayload.parseProxyTarget("bug.example", 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayPayload.parseProxyTarget("bug.example", 70000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayPayload.parseProxyTarget("bug.example:abc", null)
        }
    }

    @Test
    fun `segments split on split marker`() {
        assertEquals(
            listOf("AAA", "BBB", "CCC"),
            XrayPayload.segments("AAA[split]BBB[split]CCC"),
        )
        assertEquals(listOf("AAA"), XrayPayload.segments("AAA"))
        assertEquals(emptyList<String>(), XrayPayload.segments(""))
    }

    @Test
    fun `ws handshake headers injected only for upgrade without key`() {
        val key = "K3Y=="
        val injected = XrayPayload.addWsHandshakeHeaders(
            "GET /vmess HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            key,
        )
        assertTrue(injected.contains("Sec-WebSocket-Key: $key"))
        assertTrue(injected.contains("Sec-WebSocket-Version: 13"))
        // Already has a key: untouched.
        val withKey = XrayPayload.addWsHandshakeHeaders(
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: OLD==\r\n\r\n",
            key,
        )
        assertFalse(withKey.contains(key))
        // Not a WS upgrade: untouched.
        val plain = XrayPayload.addWsHandshakeHeaders("GET / HTTP/1.1\r\nHost: h\r\n\r\n", key)
        assertFalse(plain.contains("Sec-WebSocket-Key"))
    }

    @Test
    fun `templateFor uses default when chip on but template blank`() {
        val blank = ProfileItem(configType = ConfigType.VMESS, xrayUsePayload = true, xrayPayload = "")
        assertEquals(XrayPayload.DEFAULT_TEMPLATE, XrayPayload.templateFor(blank))
        val custom = ProfileItem(
            configType = ConfigType.VMESS,
            xrayUsePayload = true,
            xrayPayload = "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
        )
        assertEquals("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]", XrayPayload.templateFor(custom))
        val off = ProfileItem(configType = ConfigType.VMESS, xrayUsePayload = false, xrayPayload = "x")
        assertEquals("", XrayPayload.templateFor(off))
    }

    /** Read one HTTP request (until the blank line) from a stream. */
    private fun readHttpRequest(input: java.io.InputStream): String {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) break
            out.write(b)
            tail.addLast(b)
            if (tail.size > 4) tail.removeFirst()
            if (tail.size == 4 && tail[0] == '\r'.code && tail[1] == '\n'.code &&
                tail[2] == '\r'.code && tail[3] == '\n'.code
            ) {
                break
            }
        }
        return out.toString(Charsets.UTF_8)
    }

    @Test
    fun `ws handshake sends expanded custom template with injected key`() {
        val server = ServerSocket(0)
        val port = server.localPort
        var seenRequest = ""
        var serverError: Throwable? = null
        val t = Thread {
            try {
                val socket = server.accept()
                socket.soTimeout = 5_000
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val request = readHttpRequest(input)
                seenRequest = request
                val key = request.lines()
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
                Thread.sleep(200)
                socket.close()
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { server.close() }
            }
        }
        t.isDaemon = true
        t.start()
        val socket = java.net.Socket("::1", port)
        socket.soTimeout = 5_000
        try {
            // The template carries no key of its own — WsTransport
            // must inject it (v1.0.10), or the Accept check fails.
            val ws = WsTransport.connect(
                socket.getInputStream(), socket.getOutputStream(), "h.example", "/vmess",
                customHandshake = { key ->
                    XrayPayload.expand(
                        "GET [path] HTTP/1.1[crlf]Host: [ws_host][crlf]Upgrade: websocket[crlf]" +
                            "Connection: Upgrade[crlf][crlf]",
                        XrayPayload.Ctx(
                            wsHost = "h.example", path = "/vmess", sni = "h.example",
                            host = "h.example", ip = "h.example", port = 443, wsKey = key,
                        ),
                    )
                },
            )
            ws.close()
        } finally {
            runCatching { socket.close() }
        }
        t.join(5_000)
        assertEquals(null, serverError, "server error: $serverError")
        assertTrue(seenRequest.contains("GET /vmess HTTP/1.1"), "request: $seenRequest")
        assertTrue(seenRequest.contains("Host: h.example"), "request: $seenRequest")
        assertTrue(seenRequest.contains("Sec-WebSocket-Key: "), "request: $seenRequest")
        assertTrue(seenRequest.contains("Sec-WebSocket-Version: 13"), "request: $seenRequest")
    }
}
