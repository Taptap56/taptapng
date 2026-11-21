package com.taptap.ng.core.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.core.DialLog
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Xray HTTPUpgrade client (v1.0.13), written from scratch — no OkHttp,
 * to keep the APK small. Works over plain TCP or over an SSLSocket:
 * the caller passes the already-connected streams (Transport.open
 * runs it after the TCP / TLS stages, exactly like the WS stage).
 *
 * Handshake verified against xray-core main branch
 * (transport/internet/httpupgrade/dialer.go) and the config doc
 * https://xtls.github.io/config/transports/httpupgrade.html — see
 * README-v1.0.13.md for the verification notes. In short:
 * - Request: `GET <path> HTTP/1.1` + Host + `Upgrade: websocket` +
 *   `Connection: Upgrade` + `Sec-WebSocket-Key` (random 16 byte
 *   base64) + `Sec-WebSocket-Version: 13`. Byte-identical to the WS
 *   upgrade request (WsTransport) — the server validates the same
 *   upgrade headers. xray-core's newer versions ALSO apply a Chrome
 *   browser-masquerade header block (TryDefaultHeadersWith, "ws")
 *   on top of this; TaptapNG omits it, exactly like its WS
 *   handshake — the server never validates those headers, and the
 *   mandatory wire items above are what the 101 depends on.
 * - Response: must be status 101 AND `Upgrade: websocket` AND
 *   `Connection: upgrade` (both case-insensitive) — xray's
 *   ConnRF.Read rejects anything else ("unrecognized reply").
 *   There is NO Sec-WebSocket-Accept check (httpupgrade has none).
 *   One deliberate leniency vs xray: the reason phrase is not
 *   checked, only the code 101 — a bare "HTTP/1.1 101" still
 *   upgrades; xray demands the exact string "101 Switching
 *   Protocols".
 * - After the 101 the stream is RAW: no WS framing, no masking,
 *   no ping/pong — the protocol (VLESS/VMess/Trojan) runs directly
 *   on the socket. The header is read byte-by-byte so no post-101
 *   bytes are ever swallowed by a buffered reader (xray drains its
 *   bufio reader the same way).
 * - Early Data (`?ed=` in the path): NOT implemented — the dial
 *   always validates the 101 eagerly (xray's Ed==0 path). A path
 *   carrying `?ed=` is sent as-is; the server still answers 101
 *   and TaptapNG never sends early data.
 */
object HttpUpgradeTransport {

    private const val MAX_HEADER_BYTES = 8192

    /** Raw stream after the 101 — no framing of any kind. */
    class HttpUpgradeStream(
        val input: InputStream,
        val output: OutputStream,
    )

    fun connect(
        rawIn: InputStream,
        rawOut: OutputStream,
        host: String,
        path: String,
    ): HttpUpgradeStream {
        val key = Base64Util.encode(Crypto.randomBytes(16))
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        rawOut.write(request.toByteArray(Charsets.UTF_8))
        rawOut.flush()
        val headerBytes = readHttpHeader(rawIn)
        val header = String(headerBytes, Charsets.UTF_8)
        val lines = header.split("\r\n")
        val statusLine = lines.firstOrNull() ?: ""
        val code = SshPayload.statusCode(statusLine)
        if (code != "101") {
            throw IOException("HTTPUpgrade handshake gagal: $statusLine")
        }
        val upgrade = lines.firstOrNull { it.startsWith("Upgrade:", ignoreCase = true) }
            ?.substringAfter(":", "")?.trim() ?: ""
        if (!upgrade.equals("websocket", ignoreCase = true)) {
            throw IOException("HTTPUpgrade tanpa header Upgrade: websocket ($statusLine)")
        }
        val connection = lines.firstOrNull { it.startsWith("Connection:", ignoreCase = true) }
            ?.substringAfter(":", "")?.trim() ?: ""
        if (!connection.equals("upgrade", ignoreCase = true)) {
            throw IOException("HTTPUpgrade tanpa header Connection: upgrade ($statusLine)")
        }
        // v1.0.2 (XVEON order): the server's own status line.
        DialLog.log("HTTPUpgrade", "Server response: $statusLine")
        return HttpUpgradeStream(rawIn, rawOut)
    }

    /** Read HTTP response headers byte-by-byte until the blank line. */
    private fun readHttpHeader(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw EOFException("HTTPUpgrade handshake terpotong (EOF)")
            out.write(b)
            if (out.size() > MAX_HEADER_BYTES) {
                throw IOException("HTTPUpgrade handshake header terlalu besar")
            }
            tail.addLast(b)
            if (tail.size > 4) tail.removeFirst()
            if (tail.size == 4 &&
                tail[0] == '\r'.code && tail[1] == '\n'.code &&
                tail[2] == '\r'.code && tail[3] == '\n'.code
            ) {
                return out.toByteArray()
            }
        }
    }
}
