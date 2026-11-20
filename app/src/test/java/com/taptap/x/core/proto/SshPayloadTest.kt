package com.taptap.x.core.proto

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * SSH payload chain tests (v1.0.30) — the TB sing-box fork cases
 * ported to Kotlin (`protocol/ssh/payload_test.go`), byte-exact
 * where TB is byte-exact. All tests are in-memory (ByteArray /
 * Piped streams) — no loopback sockets: JSch cannot run on the
 * intercepted JVM loopback in this VM, and the chain itself needs
 * no socket at all (only streams).
 */
class SshPayloadTest {

    /** The user's entry payload (sociomile pattern), expanded. */
    private val sociomileTemplate =
        "GET / HTTP/1.1[crlf]Host: edu.ruangguru.com[crlf][crlf]" +
            "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]" +
            "[split]HTTP/ 69[crlf][crlf]"

    private fun sshItem(payload: String = "", enhanced: Boolean = false) = ProfileItem(
        remarks = "tes edukasi",
        configType = ConfigType.SSH,
        address = "vip.sshvpn.web.id",
        port = 80,
        username = "user",
        sshUsePayload = payload.isNotBlank(),
        sshPayload = payload,
        sshUseEnhanced = enhanced,
    )

    // ---- expand ----

    @Test
    fun `expand replaces every placeholder and ends with a blank line`() {
        val got = SshPayload.expand(
            "GET / HTTP/1.1[crlf]Host: [host][crlf]X-Target: [host_port] port [port] proto [protocol] ua [ua][crlf][crlf]",
            "example.com", 2222,
        )
        assertTrue(got.contains("Host: example.com\r\n"), "host: $got")
        assertTrue(got.contains("X-Target: example.com:2222 port 2222 proto HTTP/1.1"), "target: $got")
        assertTrue(got.contains("Mozilla/5.0"), "ua: $got")
        assertFalse(got.contains("[host"), "placeholders left: $got")
        assertFalse(got.contains("[crlf]"), "crlf left: $got")
        assertTrue(got.endsWith("\r\n\r\n"), "blank line: $got")
    }

    @Test
    fun `expand appends the blank line when the template lacks it`() {
        val got = SshPayload.expand("GET / HTTP/1.1[crlf]Host: [host]", "h", 22)
        assertTrue(got.endsWith("\r\n\r\n"), "got: $got")
    }

    @Test
    fun `expand of the sociomile payload is byte exact`() {
        val got = SshPayload.expand(sociomileTemplate, "vip.sshvpn.web.id", 80)
        val expected =
            "GET / HTTP/1.1\r\nHost: edu.ruangguru.com\r\n\r\n" +
                "PATCH / HTTP/1.1\r\nHost: vip.sshvpn.web.id\r\nUpgrade: websocket\r\n\r\n" +
                "[split]HTTP/ 69\r\n\r\n"
        assertEquals(expected, got)
    }

    // ---- splitRequests / WS headers / status ----

    @Test
    fun `splitRequests splits two requests and merges the split block`() {
        val reqs = SshPayload.splitRequests(SshPayload.expand(sociomileTemplate, "h", 80))
        assertEquals(2, reqs.size, "reqs: $reqs")
        assertTrue(reqs[0].startsWith("GET"), "req 1: ${reqs[0]}")
        assertTrue(reqs[1].contains("PATCH"), "req 2: ${reqs[1]}")
        assertTrue(reqs[1].contains("[split]HTTP/ 69"), "req 2 must keep [split]: ${reqs[1]}")
    }

    @Test
    fun `splitRequests keeps a single request as one block`() {
        val reqs = SshPayload.splitRequests("GET / HTTP/1.1\r\n\r\n")
        assertEquals(1, reqs.size)
    }

    @Test
    fun `addWsHandshakeHeaders inserts the key into the PATCH request before split`() {
        val expanded = SshPayload.expand(sociomileTemplate, "h", 80)
        val got = SshPayload.addWsHandshakeHeaders(expanded)
        val keyIdx = got.indexOf("Sec-WebSocket-Key:")
        val splitIdx = got.indexOf("[split]")
        assertTrue(keyIdx >= 0, "no key: $got")
        assertTrue(keyIdx < splitIdx, "key must be before [split]: $got")
        assertTrue(got.indexOf("HTTP/ 69") > keyIdx, "key must be before HTTP/ 69: $got")
        // The key must sit INSIDE the header block: the blank line
        // that precedes [split] comes AFTER the key.
        assertTrue(got.indexOf("\r\n\r\n[split]") > keyIdx, "key must be before the blank line: $got")
        assertTrue(got.contains("Sec-WebSocket-Version: 13"), "version: $got")
    }

    @Test
    fun `addWsHandshakeHeaders is a no-op when a key is already present`() {
        val payload = "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\n\r\n"
        assertEquals(payload, SshPayload.addWsHandshakeHeaders(payload))
    }

    @Test
    fun `addWsHandshakeHeaders is a no-op without an upgrade`() {
        val payload = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
        assertEquals(payload, SshPayload.addWsHandshakeHeaders(payload))
    }

    @Test
    fun `statusCode parses the status line`() {
        assertEquals("101", SshPayload.statusCode("HTTP/1.1 101 Switching Protocols"))
        assertEquals("301", SshPayload.statusCode("HTTP/1.1 301 Moved Permanently"))
        assertEquals("", SshPayload.statusCode("garbage"))
        assertEquals("", SshPayload.statusCode(""))
    }

    // ---- framing ----

    @Test
    fun `detectFraming maps banner to raw and frames to ws`() {
        assertEquals(SshPayload.Framing.RAW, SshPayload.detectFraming("SSH-2.0-OpenSSH".toByteArray(Charsets.UTF_8)))
        assertEquals(SshPayload.Framing.WS, SshPayload.detectFraming(byteArrayOf(0x81.toByte(), 0x05, 'h'.code.toByte(), 'i'.code.toByte())))
        assertEquals(SshPayload.Framing.WS, SshPayload.detectFraming(byteArrayOf(0x82.toByte(), 0x10, 'x'.code.toByte(), 'y'.code.toByte())))
        assertEquals(SshPayload.Framing.UNKNOWN, SshPayload.detectFraming(byteArrayOf(0x81.toByte())))
        assertEquals(SshPayload.Framing.UNKNOWN, SshPayload.detectFraming("HTTP/1.1 101".toByteArray(Charsets.UTF_8)))
        // Masked server frame (mask bit set) is not a plain WS frame.
        assertEquals(SshPayload.Framing.UNKNOWN, SshPayload.detectFraming(byteArrayOf(0x81.toByte(), 0x85.toByte(), 'x'.code.toByte(), 'y'.code.toByte())))
    }

    @Test
    fun `chooseFraming prefers detection over the payload`() {
        // WS upgrade + banner seen = raw pipe (the common case).
        assertEquals(
            SshPayload.Framing.RAW,
            SshPayload.chooseFraming(SshPayload.Framing.RAW, true, "HTTP/1.1 101 Switching Protocols"),
        )
        // WS upgrade + WS frame seen = WS.
        assertEquals(
            SshPayload.Framing.WS,
            SshPayload.chooseFraming(SshPayload.Framing.WS, true, "HTTP/1.1 101 Switching Protocols"),
        )
        // WS upgrade + silence + 101 = WS.
        assertEquals(
            SshPayload.Framing.WS,
            SshPayload.chooseFraming(SshPayload.Framing.UNKNOWN, true, "HTTP/1.1 101 Switching Protocols"),
        )
        // Non-WS payload + silence + 200 = raw.
        assertEquals(
            SshPayload.Framing.RAW,
            SshPayload.chooseFraming(SshPayload.Framing.UNKNOWN, false, "HTTP/1.1 200 OK"),
        )
    }

    @Test
    fun `chooseFraming rejects a refused WS upgrade`() {
        val e = assertThrows(IOException::class.java) {
            SshPayload.chooseFraming(SshPayload.Framing.UNKNOWN, true, "HTTP/1.1 403 Forbidden")
        }
        assertTrue(e.message!!.contains("upgrade websocket ditolak"), "msg: ${e.message}")
    }

    @Test
    fun `chooseFraming rejects a refused plain payload`() {
        val e = assertThrows(IOException::class.java) {
            SshPayload.chooseFraming(SshPayload.Framing.UNKNOWN, false, "HTTP/1.1 403 Forbidden")
        }
        assertTrue(e.message!!.contains("proxy menolak payload"), "msg: ${e.message}")
    }

    // ---- response drain ----

    @Test
    fun `readHttpResponse drains a chunked 301 body so the 101 reads clean`() {
        // TB v1.0.15: chunk pertama "216" (0x216 = 534 byte) must not
        // leak into the next response read.
        val body = "x".repeat(0x216)
        val bytes = (
            "HTTP/1.1 301 Moved Permanently\r\nTransfer-Encoding: chunked\r\n\r\n" +
                "216\r\n" + body + "\r\n0\r\n\r\n" +
                "HTTP/1.1 101 Switching Protocols\r\n\r\n"
            ).toByteArray(Charsets.UTF_8)
        val input = BufferedInputStream(ByteArrayInputStream(bytes))
        assertTrue(SshPayload.readHttpResponse(input, false)!!.contains("301"))
        assertTrue(SshPayload.readHttpResponse(input, false)!!.contains("101"))
    }

    @Test
    fun `readHttpResponse drains a Content-Length body so the 101 reads clean`() {
        val body = "y".repeat(100)
        val bytes = (
            "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 100\r\n\r\n" +
                body +
                "HTTP/1.1 101 Switching Protocols\r\n\r\n"
            ).toByteArray(Charsets.UTF_8)
        val input = BufferedInputStream(ByteArrayInputStream(bytes))
        assertTrue(SshPayload.readHttpResponse(input, false)!!.contains("301"))
        assertTrue(SshPayload.readHttpResponse(input, false)!!.contains("101"))
    }

    @Test
    fun `readHttpResponse fails on EOF mid-header`() {
        val input = BufferedInputStream(ByteArrayInputStream("HTTP/1.1 200 OK\r\nContent-Len".toByteArray(Charsets.UTF_8)))
        assertThrows(EOFException::class.java) { SshPayload.readHttpResponse(input, false) }
    }

    @Test
    fun `readHttpResponse rejects a non-HTTP answer without Enhanced`() {
        val input = BufferedInputStream(ByteArrayInputStream("SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8)))
        val e = assertThrows(IOException::class.java) { SshPayload.readHttpResponse(input, false) }
        assertTrue(e.message!!.contains("bukan HTTP"), "msg: ${e.message}")
    }

    @Test
    fun `readHttpResponse with Enhanced puts the banner back for framing`() {
        val banner = "SSH-2.0-OpenSSH_8.9\r\n"
        val input = BufferedInputStream(ByteArrayInputStream(banner.toByteArray(Charsets.UTF_8)))
        assertNull(SshPayload.readHttpResponse(input, true))
        // The banner bytes are still there — framing sees them.
        assertEquals(SshPayload.Framing.RAW, SshPayload.peekFraming(input))
        val rest = input.readBytes()
        assertEquals(banner, String(rest, Charsets.UTF_8))
    }

    // ---- [split] timing + full chain over piped streams ----

    /** One pipe pair (client->server, server->client), in-memory. */
    private class PipePair {
        val clientIn: PipedInputStream = PipedInputStream()
        val serverOut: PipedOutputStream = PipedOutputStream(clientIn)
        val serverIn: PipedInputStream = PipedInputStream()
        val clientOut: PipedOutputStream = PipedOutputStream(serverIn)
    }

    /** Read one request block (until the blank line) from the server side. */
    private fun readBlock(input: java.io.InputStream): String {
        val out = ByteArrayOutputStream()
        var b: Int
        while (input.read().also { b = it } != -1) {
            out.write(b)
            if (out.toString(Charsets.UTF_8.name()).endsWith("\r\n\r\n")) break
        }
        return out.toString(Charsets.UTF_8.name())
    }

    @Test
    fun `sendRequest sends the split segment only after the 101`() {
        val pipes = PipePair()
        val serverGot = ArrayDeque<String>()
        val serverThread = thread(name = "fake-proxy-split") {
            val patch = readBlock(pipes.serverIn)
            serverGot.addLast(patch)
            pipes.serverOut.write("HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
            serverGot.addLast(readBlock(pipes.serverIn))
        }
        val clientIn = BufferedInputStream(pipes.clientIn)
        val req = "PATCH / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n[split]HTTP/ 69\r\n\r\n"
        val status = SshPayload.sendRequest(pipes.clientOut, clientIn, req, false)
        serverThread.join(5000)
        assertTrue(status!!.contains("101"), "status: $status")
        val patch = serverGot.removeFirst()
        assertTrue(patch.contains("PATCH"), "server must get PATCH first: $patch")
        assertFalse(patch.contains("[split]"), "PATCH must not carry [split]: $patch")
        assertFalse(patch.contains("HTTP/ 69"), "PATCH must not carry the fragment: $patch")
        val frag = serverGot.removeFirst()
        assertFalse(frag.contains("[split]"), "marker must not be sent: $frag")
        assertTrue(frag.contains("HTTP/ 69"), "fragment must arrive after the 101: $frag")
    }

    @Test
    fun `sendRequests runs the full sociomile flow in order`() {
        val pipes = PipePair()
        val serverGot = ArrayDeque<String>()
        val serverThread = thread(name = "fake-proxy-sociomile") {
            // GET -> 301 with a chunked body (must be drained).
            serverGot.addLast(readBlock(pipes.serverIn))
            val body = "x".repeat(0x216)
            pipes.serverOut.write(
                ("HTTP/1.1 301 Moved Permanently\r\nTransfer-Encoding: chunked\r\n\r\n" +
                    "216\r\n" + body + "\r\n0\r\n\r\n").toByteArray(Charsets.UTF_8),
            )
            pipes.serverOut.flush()
            // PATCH -> 101, then the [split] fragment.
            serverGot.addLast(readBlock(pipes.serverIn))
            pipes.serverOut.write("HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
            serverGot.addLast(readBlock(pipes.serverIn))
            // Banner right after the 101 (framing detection input).
            pipes.serverOut.write("SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
        }
        val clientIn = BufferedInputStream(pipes.clientIn)
        val result = SshPayload.sendRequests(clientIn, pipes.clientOut, sshItem(sociomileTemplate))
        serverThread.join(5000)
        assertEquals(2, result.statuses.size, "statuses: ${result.statuses}")
        assertTrue(result.statuses[0].contains("301"), "first: ${result.statuses[0]}")
        assertTrue(result.statuses[1].contains("101"), "second: ${result.statuses[1]}")
        assertTrue(result.wasWsUpgrade, "payload upgrades to WS")
        assertFalse(result.bannerPassthrough, "no banner passthrough here")
        val get = serverGot.removeFirst()
        assertTrue(get.startsWith("GET / HTTP/1.1"), "first block: $get")
        assertTrue(get.contains("Host: edu.ruangguru.com"), "front host: $get")
        val patch = serverGot.removeFirst()
        assertTrue(patch.contains("PATCH"), "second block: $patch")
        assertTrue(patch.contains("Sec-WebSocket-Key:"), "PATCH must carry the WS key: $patch")
        val frag = serverGot.removeFirst()
        assertEquals("HTTP/ 69\r\n\r\n", frag, "fragment: $frag")
        // Framing sees the banner that followed the 101.
        assertEquals(SshPayload.Framing.RAW, SshPayload.peekFraming(clientIn))
    }

    @Test
    fun `sendRequests stops after a 101 with requests still queued`() {
        val pipes = PipePair()
        val serverGot = ArrayDeque<String>()
        val serverThread = thread(name = "fake-proxy-stop-101") {
            serverGot.addLast(readBlock(pipes.serverIn))
            pipes.serverOut.write("HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
            // A third request must never arrive: read with a short
            // deadline by closing after a pause.
            Thread.sleep(300)
            runCatching { pipes.serverOut.close() }
        }
        val clientIn = BufferedInputStream(pipes.clientIn)
        val payload =
            "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n" +
                "GET / HTTP/1.1\r\nHost: b\r\n\r\n"
        val result = SshPayload.sendRequests(clientIn, pipes.clientOut, sshItem(payload))
        serverThread.join(5000)
        assertEquals(1, result.statuses.size, "must stop after the 101: ${result.statuses}")
        assertEquals(1, serverGot.size, "server must get one request only")
    }

    @Test
    fun `sendRequests with Enhanced proceeds when the proxy answers with the banner`() {
        val pipes = PipePair()
        val serverThread = thread(name = "fake-proxy-banner") {
            readBlock(pipes.serverIn)
            pipes.serverOut.write("SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
        }
        val clientIn = BufferedInputStream(pipes.clientIn)
        val result = SshPayload.sendRequests(
            clientIn, pipes.clientOut,
            sshItem("GET / HTTP/1.1[crlf]Host: h[crlf][crlf]", enhanced = true),
        )
        serverThread.join(5000)
        assertTrue(result.bannerPassthrough, "Enhanced must accept the banner answer")
        assertTrue(result.statuses.isEmpty(), "no HTTP status: ${result.statuses}")
        assertEquals(SshPayload.Framing.RAW, SshPayload.peekFraming(clientIn))
    }

    @Test
    fun `sendRequests without Enhanced fails when the proxy answers with the banner`() {
        val pipes = PipePair()
        val serverThread = thread(name = "fake-proxy-banner-strict") {
            readBlock(pipes.serverIn)
            pipes.serverOut.write("SSH-2.0-OpenSSH_8.9\r\n".toByteArray(Charsets.UTF_8))
            pipes.serverOut.flush()
        }
        val clientIn = BufferedInputStream(pipes.clientIn)
        val e = assertThrows(IOException::class.java) {
            SshPayload.sendRequests(
                clientIn, pipes.clientOut,
                sshItem("GET / HTTP/1.1[crlf]Host: h[crlf][crlf]", enhanced = false),
            )
        }
        assertTrue(e.message!!.contains("bukan HTTP"), "msg: ${e.message}")
        serverThread.join(5000)
    }

    // ---- target / TLS version ----

    @Test
    fun `chainTarget uses the remote proxy when set`() {
        val item = sshItem().apply { sshRemoteProxy = "1.2.3.4:443" }
        assertEquals("1.2.3.4" to 443, SshPayload.chainTarget(item, "ssh.example.com", 22))
        val noPortTls = sshItem().apply {
            sshRemoteProxy = "proxy.example.com"
            sshUseTls = true
        }
        assertEquals("proxy.example.com" to 443, SshPayload.chainTarget(noPortTls, "ssh.example.com", 22))
        val noPortPlain = sshItem().apply { sshRemoteProxy = "proxy.example.com" }
        assertEquals("proxy.example.com" to 80, SshPayload.chainTarget(noPortPlain, "ssh.example.com", 22))
        assertEquals("ssh.example.com" to 22, SshPayload.chainTarget(sshItem(), "ssh.example.com", 22))
    }

    @Test
    fun `chainTarget rejects a malformed proxy`() {
        val item = sshItem().apply { sshRemoteProxy = ":99999" }
        assertThrows(IllegalArgumentException::class.java) {
            SshPayload.chainTarget(item, "ssh.example.com", 22)
        }
    }

    @Test
    fun `tlsProtocols maps sshSniVersion`() {
        assertNull(SshPayload.tlsProtocols("default"))
        assertNull(SshPayload.tlsProtocols(""))
        assertNull(SshPayload.tlsProtocols("bogus"))
        assertEquals(listOf("TLSv1.2"), SshPayload.tlsProtocols("tls1.2")!!.toList())
        assertEquals(listOf("TLSv1.3"), SshPayload.tlsProtocols("tls1.3")!!.toList())
        assertEquals(listOf("TLSv1"), SshPayload.tlsProtocols("tls1")!!.toList())
        assertEquals(listOf("TLSv1.1"), SshPayload.tlsProtocols("tls1.1")!!.toList())
    }
}
