package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * HTTP CONNECT proxy (v1.0.10) — the XVEON Tunnel Pro 6.1 step
 * between the payload and TLS: after the TCP socket is connected
 * to the proxy (a bug host:port), the client sends
 * `CONNECT <target-host>:<target-port> HTTP/1.1` + Host and waits
 * for `200` before TLS wraps the same socket. Pure wire work on
 * caller-supplied streams (no sockets created here), so the
 * request format and the 200 / non-200 paths are JVM-testable
 * over piped streams.
 *
 * The response headers are read byte-by-byte until the blank line
 * and no further — nothing past the headers is ever swallowed, so
 * the TLS handshake that follows reads the exact stream the proxy
 * sent (same rule as [WsTransport]'s header reader).
 */
object HttpConnectProxy {

    private const val MAX_HEADER_BYTES = 8192

    /** The exact CONNECT request XVEON sends (minus auth — v1.0.10 has none). */
    fun buildConnectRequest(host: String, port: Int): String =
        "CONNECT $host:$port HTTP/1.1\r\n" +
            "Host: $host:$port\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n"

    /**
     * Send CONNECT for [host]:[port] over [output] and read the
     * proxy's response from [input]. Returns the status line on
     * 200. Anything else fails the dial with a tagged stage
     * ("Proxy CONNECT ditolak: ...") so the phone status shows
     * WHERE the dial died.
     */
    fun doConnect(input: InputStream, output: OutputStream, host: String, port: Int): String {
        DialLog.log("PROXY", "HTTP Proxy CONNECT -> $host:$port")
        output.write(buildConnectRequest(host, port).toByteArray(Charsets.UTF_8))
        output.flush()
        val header = readHttpHeader(input)
        val statusLine = String(header, Charsets.UTF_8).split("\r\n").firstOrNull().orEmpty()
        DialLog.log("PROXY", "Proxy response: $statusLine")
        val code = SshPayload.statusCode(statusLine)
        if (code != "200") {
            throw IOException("Proxy CONNECT ditolak: $statusLine")
        }
        return statusLine
    }

    /** Read HTTP response headers byte-by-byte until the blank line. */
    private fun readHttpHeader(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw EOFException("Proxy CONNECT terpotong (EOF)")
            out.write(b)
            if (out.size() > MAX_HEADER_BYTES) {
                throw IOException("Proxy CONNECT header terlalu besar")
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
