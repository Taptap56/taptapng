package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Payload-only proxy (v1.0.11) — the SSH way of using a bug host,
 * for VMess/VLESS/Trojan: TCP to the proxy (bug:port) → the custom
 * payload is sent → TLS wraps the SAME socket straight away, with
 * NO CONNECT step. The edge is expected to forward the stream by
 * Host/SNI, exactly like the SSH payload chain in [SshPayload]
 * (whose proven template is `GET Host: bug` + `PATCH Host: [host]`
 * + `[split]`).
 *
 * The [split] timing and the request-chain rules are ported from
 * [SshPayload] (semantics only):
 * - The template is split into request blocks on "\r\n\r\n"
 *   (empty blocks dropped; a "[split]"-leading block merges into
 *   the previous one, so the "[split]" part stays in the same
 *   send unit as its PATCH).
 * - Per block: the first [split] segment is written, ONE response
 *   is read, and the remaining segments are written only after a
 *   101/2xx response. Sending them before the 101 made the proxy
 *   wait for a valid HTTP request and never answer (TB lesson,
 *   v1.0.14).
 * - A block that answers 101/2xx with blocks still queued ends
 *   the chain early (the connection is upgraded; the rest would
 *   pollute the TLS stream).
 * - Validation mirrors [SshPayload.chooseFraming] with no framing
 *   detection (TLS follows, not SSH/WS framing): a WS-upgrade
 *   template needs a 101, a plain template needs a 1xx/2xx.
 *
 * Unlike [SshPayload], every read here is byte-by-byte on the
 * RAW stream — no BufferedInputStream. The TLS layer after this
 * stage reads from the same socket directly (TlsUtil.wrap takes
 * the Socket), so a buffered reader would swallow bytes TLS
 * needs. Responses are drained exactly (Content-Length /
 * chunked), so the stream is clean when TLS starts.
 */
object PayloadOnlyProxy {

    private const val MAX_HEADER_LINES = 64
    private const val MAX_HEADER_BYTES = 8192
    private const val DRAIN_BUF_SIZE = 8192

    /** Result of sending the whole payload (all request blocks). */
    data class ChainResult(
        /** Status line per request block that got an HTTP answer. */
        val statuses: List<String>,
        /** True when the (expanded) payload asks for a WS upgrade. */
        val wasWsUpgrade: Boolean,
        /** Last status line, or "" when no request got an answer. */
        val lastStatus: String,
    )

    /**
     * Send the whole (expanded) payload over [output], reading one
     * response per request block from [input]. Throws when the
     * edge rejects the payload (see the class doc). Returns the
     * statuses that were read.
     */
    fun sendPayload(
        input: InputStream,
        output: OutputStream,
        expanded: String,
    ): ChainResult {
        val requests = splitRequests(expanded)
        val wasWsUpgrade = SshPayload.isWsUpgrade(expanded)
        val statuses = mutableListOf<String>()
        for ((i, req) in requests.withIndex()) {
            val status = sendRequest(output, input, req)
            if (status.isNotEmpty()) {
                statuses += status
                DialLog.log("PROXY", "Payload saja: payload respons: ${status.take(80)}")
                val code = SshPayload.statusCode(status)
                if (i < requests.size - 1 && (code == "101" || code.startsWith("2"))) break
            }
        }
        val lastStatus = statuses.lastOrNull() ?: ""
        // Validation — SshPayload.chooseFraming with framing UNKNOWN
        // (no peek here; TLS follows, not SSH/WS framing).
        if (wasWsUpgrade) {
            if (SshPayload.statusCode(lastStatus) != "101") {
                throw IOException("Payload saja: upgrade websocket ditolak: $lastStatus")
            }
        } else if (lastStatus.isNotEmpty()) {
            val code = SshPayload.statusCode(lastStatus)
            if (!code.startsWith("1") && !code.startsWith("2")) {
                throw IOException("Payload saja: proxy menolak payload: $lastStatus")
            }
        }
        return ChainResult(
            statuses = statuses,
            wasWsUpgrade = wasWsUpgrade,
            lastStatus = lastStatus,
        )
    }

    /**
     * Split an expanded payload into request blocks, each ending
     * "\r\n\r\n" (same rule as [SshPayload.splitRequests]). Empty
     * blocks are dropped. A block starting with "[split]" is a
     * continuation of the previous block: it is merged into it,
     * keeping the "[split]" marker so the write step can send it
     * as a separate packet after the 101.
     */
    fun splitRequests(payload: String): List<String> {
        val parts = payload.split("\r\n\r\n")
        val out = mutableListOf<String>()
        for (p in parts) {
            if (p.isBlank()) continue
            val block = p + "\r\n\r\n"
            if (block.trimStart(' ', '\t').startsWith("[split]") && out.isNotEmpty()) {
                out[out.lastIndex] += block
                continue
            }
            out += block
        }
        return if (out.isEmpty()) listOf(payload) else out
    }

    /**
     * Send one request block with [split] timing (same rule as
     * [SshPayload.sendRequest]). Returns the response status line;
     * "" when the block had no HTTP request (it starts with
     * [split] — its segments are sent as data, no response read).
     */
    internal fun sendRequest(
        output: OutputStream,
        input: InputStream,
        request: String,
    ): String {
        val segs = request.split("[split]")
        if (segs[0].isBlank()) {
            // Payload starts with [split]: no HTTP request — send
            // the segments as data without reading a response.
            for (s in segs.drop(1)) {
                if (s.isEmpty()) continue
                output.write(s.toByteArray(Charsets.UTF_8))
            }
            output.flush()
            return ""
        }
        output.write(segs[0].toByteArray(Charsets.UTF_8))
        output.flush()
        val status = readHttpResponse(input)
        val code = SshPayload.statusCode(status)
        if (segs.size > 1 && (code == "101" || code.startsWith("2"))) {
            for (s in segs.drop(1)) {
                if (s.isEmpty()) continue
                output.write(s.toByteArray(Charsets.UTF_8))
            }
            output.flush()
            DialLog.log("PROXY", "Payload saja: mengirim ${segs.size - 1} segmen [split] pasca-101")
        }
        return status
    }

    /**
     * Read one HTTP response (headers + body) and return the status
     * line. The body is drained (discarded) so the next response
     * read — and the TLS handshake after the chain — starts clean.
     * Throws when the answer is not HTTP, when the stream ends, or
     * when the header is too long. Reads byte-by-byte on the raw
     * stream: nothing past the response is ever swallowed.
     */
    internal fun readHttpResponse(input: InputStream): String {
        val first = readLine(input)
            ?: throw EOFException("Payload saja: respons payload terpotong (EOF)")
        if (!first.startsWith("HTTP/")) {
            throw IOException("Payload saja: respons payload bukan HTTP: ${first.take(60)}")
        }
        var contentLength = -1
        var chunked = false
        for (i in 0 until MAX_HEADER_LINES) {
            val line = readLine(input)
                ?: throw EOFException("Payload saja: header respons payload terpotong (EOF)")
            if (line.isEmpty()) break
            val lower = line.lowercase()
            if (lower.startsWith("content-length:")) {
                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: -1
            }
            if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
                chunked = true
            }
            if (i == MAX_HEADER_LINES - 1) {
                throw IOException("Payload saja: header respons payload terlalu panjang")
            }
        }
        // Drain the body so the next response read starts clean.
        if (chunked) {
            while (true) {
                val sizeLine = readLine(input)
                    ?: throw EOFException("Payload saja: body chunked terpotong (EOF)")
                val sizeStr = sizeLine.substringBefore(";").trim()
                val size = sizeStr.toLongOrNull(16)
                    ?: throw IOException("Payload saja: ukuran chunk tidak valid: $sizeStr")
                if (size == 0L) {
                    // Trailer until the blank line.
                    while (true) {
                        val trailer = readLine(input)
                            ?: throw EOFException("Payload saja: trailer chunked terpotong (EOF)")
                        if (trailer.isEmpty()) break
                    }
                    break
                }
                skipExact(input, size + 2) // chunk + trailing CRLF
            }
        } else if (contentLength > 0) {
            skipExact(input, contentLength.toLong())
        }
        return first
    }

    /** Read one line (up to LF, CR stripped). Null on EOF before any byte. */
    private fun readLine(input: InputStream): String? {
        val out = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b == -1) return if (out.size() == 0) null else String(out.toByteArray(), Charsets.UTF_8)
            if (b == '\n'.code) break
            out.write(b)
            if (out.size() > MAX_HEADER_BYTES) {
                throw IOException("Payload saja: baris header payload terlalu panjang")
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8).removeSuffix("\r")
    }

    /** Skip exactly [n] bytes (chunked / Content-Length body drain). */
    private fun skipExact(input: InputStream, n: Long) {
        val buf = ByteArray(DRAIN_BUF_SIZE)
        var remaining = n
        while (remaining > 0) {
            val take = minOf(DRAIN_BUF_SIZE.toLong(), remaining).toInt()
            val r = input.read(buf, 0, take)
            if (r == -1) throw EOFException("Payload saja: body respons terpotong (EOF)")
            remaining -= r
        }
    }
}
