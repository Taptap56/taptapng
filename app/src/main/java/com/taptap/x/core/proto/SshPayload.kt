package com.taptap.x.core.proto

import com.taptap.x.core.Base64Util
import com.taptap.x.core.DialLog
import com.taptap.x.data.ProfileItem
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException

/**
 * SSH payload chain (v1.0.30) — port of the TaptapBox/TaptapClash
 * sing-box fork chain (`protocol/ssh/payload.go`, semantics only,
 * no Go code copied): an HTTP payload is sent on the raw socket
 * BEFORE the SSH handshake, so an SSH server behind an HTTP front
 * proxy (the classic injector setup: port 80 + payload) can be
 * dialled by the in-app client.
 *
 * Chain (per session connect):
 *   TCP (via [Transport.open], same protect/DNS/buffer/watchdog
 *   as the other protocols) → TLS when sshUseTls (SNI = sshSni
 *   or the SSH host) → payload requests, one response read per
 *   request → framing detection from the server's first bytes.
 *
 * Semantics ported from TB (each with its TB lesson):
 * - Expand: `[host_port]` FIRST (before `[host]`), then `[host]`,
 *   `[port]`, `[protocol]` → "HTTP/1.1", `[ua]` → default UA,
 *   `[crlf]` → CR+LF; line endings normalised to CRLF; a trailing
 *   blank line is appended when missing.
 * - Split requests: split on `\r\n\r\n`, drop empty blocks; a block
 *   starting with `[split]` is merged into the previous block (so
 *   the `[split]` part stays in the same send unit as its PATCH).
 * - `[split]` timing (v1.0.14): the first segment is written, ONE
 *   response is read, and the remaining segments are written only
 *   after a 101/2xx response. Sending them before the 101 made the
 *   proxy wait for a valid HTTP request and never answer.
 * - Response drain (v1.0.15): the body is always drained (chunked
 *   or Content-Length) so the NEXT response read starts clean — a
 *   301 body left unread was once read back as the PATCH response
 *   ("ditolak: 216" instead of 101).
 * - WS handshake headers: when the payload asks for a WS upgrade,
 *   `Sec-WebSocket-Key` + `Sec-WebSocket-Version: 13` are inserted
 *   into the upgrading request, before its terminating blank line
 *   (NOT appended at the end of the whole payload).
 * - Framing detection: the server's first 4 bytes decide — "SSH-"
 *   → raw pipe (the common case: the proxy pipes the SSH banner
 *   straight after the 101), an unmasked WS frame → WS framing,
 *   nothing within 2 s → the payload's own WS-ness decides.
 * - Validation: a WS upgrade with no data and no 101 fails
 *   ("upgrade websocket ditolak"); a non-WS payload with no data
 *   and a non-1xx/2xx status fails ("proxy menolak payload").
 *   A raw pipe (no WS upgrade) never rejects on status — the
 *   Simple-Injector style: let the SSH layer try.
 *
 * Enhanced (`sshUseEnhanced`): TB treats Enhanced as implicit —
 * the chain always reads the response. TaptapX does the same
 * (the drain above runs in both modes), and Enhanced additionally
 * tolerates a NON-HTTP answer: when the proxy pipes the SSH banner
 * straight through instead of an HTTP response, the dial proceeds
 * to framing instead of failing. Without Enhanced that answer
 * fails the dial (strict, like TB). The banner bytes are put back
 * with mark/reset, so framing still sees them.
 *
 * No extra buffering is introduced anywhere: responses are read
 * byte-by-byte (like [WsTransport.readHttpHeader]) and bodies are
 * drained with exact reads, so no bytes are ever swallowed past
 * the headers — the SSH layer after the chain sees the exact
 * stream the server sent.
 */
object SshPayload {

    /** Replacement for the [ua] placeholder (same generic UA as TB). */
    const val DEFAULT_UA =
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"

    /** Wait for the server's first bytes (framing detection). */
    const val PEEK_PERIOD_MS = 2000

    private const val MAX_HEADER_LINES = 64
    private const val MAX_HEADER_BYTES = 8192
    private const val DRAIN_BUF_SIZE = 8192

    enum class Framing { RAW, WS, UNKNOWN }

    /** Result of sending the whole payload (all request blocks). */
    data class ChainResult(
        /** Status line per request block that got an HTTP answer. */
        val statuses: List<String>,
        /** True when the (expanded) payload asks for a WS upgrade. */
        val wasWsUpgrade: Boolean,
        /** Last status line, or "" when no request got an answer. */
        val lastStatus: String,
        /** True when a request was answered with the SSH banner
         * instead of HTTP (Enhanced only) — the loop stopped and
         * framing must run on the banner bytes. */
        val bannerPassthrough: Boolean,
    )

    // ---- target / TLS version ----

    /**
     * Chain dial target: the remote proxy (`sshRemoteProxy`) when
     * set, else the SSH server itself. A proxy without a port gets
     * 443 when TLS is on, 80 otherwise (TB rule). The payload's
     * [host]/[port] always stay the SSH server, never the proxy.
     */
    fun chainTarget(item: ProfileItem, sshHost: String, sshPort: Int): Pair<String, Int> {
        val proxy = item.sshRemoteProxy.trim()
        if (proxy.isEmpty()) return sshHost to sshPort
        val (host, port) = splitHostPort(proxy)
            ?: throw IllegalArgumentException("SSH gagal: proxy tidak valid: $proxy")
        val p = port ?: if (item.sshUseTls) 443 else 80
        require(p in 1..65535) { "SSH gagal: port proxy di luar 1..65535: $p" }
        return host to p
    }

    /** Split "host[:port]" (bracketed IPv6 allowed). Null on garbage. */
    internal fun splitHostPort(target: String): Pair<String, Int?>? {
        val t = target.trim()
        if (t.isEmpty()) return null
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close < 0) return null
            val host = t.substring(1, close)
            if (host.isEmpty()) return null
            val rest = t.substring(close + 1)
            if (rest.isEmpty()) return host to null
            if (!rest.startsWith(":")) return null
            val port = rest.substring(1).toIntOrNull() ?: return null
            return host to port
        }
        val colon = t.lastIndexOf(':')
        if (colon < 0) return t to null
        // A bare IPv6 literal has several colons and no brackets —
        // treat the whole thing as the host (no port).
        if (t.indexOf(':') != colon) return t to null
        val host = t.substring(0, colon)
        if (host.isEmpty()) return null
        val port = t.substring(colon + 1).toIntOrNull() ?: return null
        return host to port
    }

    /**
     * SSLSocket protocol names for `sshSniVersion` ("default" =
     * negotiate, null). Anything unknown also negotiates instead of
     * failing the dial.
     */
    fun tlsProtocols(version: String): Array<String>? = when (version.trim().lowercase()) {
        "", "default" -> null
        "tls1", "1.0", "1" -> arrayOf("TLSv1")
        "tls1.1", "1.1" -> arrayOf("TLSv1.1")
        "tls1.2", "1.2" -> arrayOf("TLSv1.2")
        "tls1.3", "1.3" -> arrayOf("TLSv1.3")
        else -> null
    }

    // ---- template ----

    /**
     * Expand a payload template (TB `sshChainExpandPayloadFull`).
     * `[host_port]` is replaced FIRST, before `[host]`, so no raw
     * placeholder is left behind. IPv6 hosts are bracketed in
     * `[host_port]`.
     */
    fun expand(template: String, host: String, port: Int): String {
        val hostPort = if (host.contains(':') && !host.startsWith("[")) "[$host]:$port" else "$host:$port"
        var out = template
        out = out.replace("[host_port]", hostPort)
        out = out.replace("[host]", host)
        out = out.replace("[port]", port.toString())
        out = out.replace("[protocol]", "HTTP/1.1")
        out = out.replace("[ua]", DEFAULT_UA)
        out = out.replace("[crlf]", "\r\n")
        // Normalise line endings: pasted templates may contain bare \n.
        out = out.replace("\r\n", "\n").replace("\n", "\r\n")
        if (!out.endsWith("\r\n\r\n")) {
            out = out.trimEnd('\r', '\n') + "\r\n\r\n"
        }
        return out
    }

    /** True when the (expanded) payload asks for a WS upgrade. */
    fun isWsUpgrade(payload: String): Boolean =
        payload.contains("upgrade: websocket", ignoreCase = true)

    /**
     * Add the WS handshake headers to the upgrading request (TB
     * `sshChainAddWSHandshakeHeaders`): the `Sec-WebSocket-Key` +
     * `Sec-WebSocket-Version: 13` go into the request that carries
     * "Upgrade: websocket", right before that request's terminating
     * blank line — NOT appended to the end of the whole payload
     * (which lands in the wrong request for a multi-request
     * payload, and would also break the [split] packet boundary).
     * No-op when the payload is not a WS upgrade or already has a
     * key.
     */
    fun addWsHandshakeHeaders(payload: String): String {
        if (!isWsUpgrade(payload)) return payload
        if (payload.contains("sec-websocket-key", ignoreCase = true)) return payload
        val key = Base64Util.encode(Crypto.randomBytes(16))
        val lower = payload.lowercase()
        val idx = lower.indexOf("upgrade: websocket")
        if (idx < 0) return payload
        val end = payload.indexOf("\r\n\r\n", idx)
        if (end < 0) return payload
        val wsHeaders = "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13"
        return payload.substring(0, end) + "\r\n" + wsHeaders + payload.substring(end)
    }

    /**
     * Split an expanded payload into request blocks, each ending
     * "\r\n\r\n" (TB `sshChainSplitRequests`). Empty blocks are
     * dropped. A block starting with "[split]" is a continuation
     * of the previous block: it is merged into it, keeping the
     * "[split]" marker so the write step can send it as a separate
     * packet after the 101.
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

    /** "HTTP/1.1 101 ..." -> "101" ("" when unparseable). */
    fun statusCode(statusLine: String): String {
        val fields = statusLine.trim().split(Regex("\\s+"))
        return if (fields.size >= 2) fields[1] else ""
    }

    // ---- wire: requests / responses ----

    /**
     * Send the whole payload over [output], reading one response
     * per request block from [input] (TB `sshChainDialOnce` loop).
     * Stops early once a 101/2xx arrives with requests still
     * queued (the connection is upgraded; the rest would pollute
     * the SSH stream), and stops at once on a banner passthrough
     * (Enhanced). Returns the statuses that were read.
     *
     * [input] must be a [BufferedInputStream] over the transport
     * stream: the Enhanced banner path puts bytes back with
     * mark/reset, and the framing peek after this call reads from
     * the same buffer.
     */
    fun sendRequests(
        input: BufferedInputStream,
        output: OutputStream,
        item: ProfileItem,
    ): ChainResult {
        val expanded = expand(item.sshPayload, item.address, item.port)
        val withWs = addWsHandshakeHeaders(expanded)
        val requests = splitRequests(withWs)
        val statuses = mutableListOf<String>()
        var bannerPassthrough = false
        for ((i, req) in requests.withIndex()) {
            val status = sendRequest(output, input, req, item.sshUseEnhanced)
                ?: run {
                    bannerPassthrough = true
                    break
                }
            if (status.isNotEmpty()) {
                statuses += status
                DialLog.log("SSH", "payload respons: ${status.take(80)}")
                val code = statusCode(status)
                if (i < requests.size - 1 && (code == "101" || code.startsWith("2"))) break
            }
        }
        return ChainResult(
            statuses = statuses,
            wasWsUpgrade = isWsUpgrade(expanded),
            lastStatus = statuses.lastOrNull() ?: "",
            bannerPassthrough = bannerPassthrough,
        )
    }

    /**
     * Send one request block with [split] timing (TB
     * `sshChainSendRequest`). Returns the response status line;
     * "" when the block had no HTTP request (it starts with
     * [split] — its segments are sent as data, no response read);
     * null on a banner passthrough (Enhanced only — the server
     * answered with non-HTTP bytes instead of a response, and the
     * caller must stop the whole payload loop).
     */
    fun sendRequest(
        output: OutputStream,
        input: BufferedInputStream,
        request: String,
        enhanced: Boolean,
    ): String? {
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
        val status = readHttpResponse(input, enhanced) ?: return null
        val code = statusCode(status)
        if (segs.size > 1 && (code == "101" || code.startsWith("2"))) {
            for (s in segs.drop(1)) {
                if (s.isEmpty()) continue
                output.write(s.toByteArray(Charsets.UTF_8))
            }
            output.flush()
            DialLog.log("SSH", "mengirim ${segs.size - 1} segmen [split] pasca-101")
        }
        return status
    }

    /**
     * Read one HTTP response (headers + body) and return the status
     * line (TB `sshChainReadHTTPResponse`). The body is drained
     * (discarded) so the next response read starts clean.
     * Returns null on a banner passthrough: the first line was not
     * HTTP and [enhanced] is on — the line is put back with
     * mark/reset so framing still sees the banner bytes.
     * Throws when the answer is not HTTP and [enhanced] is off,
     * or when the stream ends / the header is too long.
     */
    fun readHttpResponse(input: BufferedInputStream, enhanced: Boolean): String? {
        input.mark(MAX_HEADER_BYTES)
        val first = readLine(input)
            ?: throw EOFException("SSH gagal: respons payload terpotong (EOF)")
        if (!first.startsWith("HTTP/")) {
            if (enhanced) {
                input.reset()
                DialLog.log("SSH", "respons bukan HTTP (banner?) — Enhanced: lanjut ke framing")
                return null
            }
            throw IOException("SSH gagal: respons payload bukan HTTP: ${first.take(60)}")
        }
        var contentLength = -1
        var chunked = false
        for (i in 0 until MAX_HEADER_LINES) {
            val line = readLine(input)
                ?: throw EOFException("SSH gagal: header respons payload terpotong (EOF)")
            if (line.isEmpty()) break
            val lower = line.lowercase()
            if (lower.startsWith("content-length:")) {
                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: -1
            }
            if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
                chunked = true
            }
            if (i == MAX_HEADER_LINES - 1) {
                throw IOException("SSH gagal: header respons payload terlalu panjang")
            }
        }
        // Drain the body so the next response read starts clean.
        if (chunked) {
            while (true) {
                val sizeLine = readLine(input)
                    ?: throw EOFException("SSH gagal: body chunked terpotong (EOF)")
                val sizeStr = sizeLine.substringBefore(";").trim()
                val size = sizeStr.toLongOrNull(16)
                    ?: throw IOException("SSH gagal: ukuran chunk tidak valid: $sizeStr")
                if (size == 0L) {
                    // Trailer until the blank line.
                    while (true) {
                        val trailer = readLine(input)
                            ?: throw EOFException("SSH gagal: trailer chunked terpotong (EOF)")
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
                throw IOException("SSH gagal: baris header payload terlalu panjang")
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
            if (r == -1) throw EOFException("SSH gagal: body respons terpotong (EOF)")
            remaining -= r
        }
    }

    // ---- framing ----

    /**
     * Guess the framing from the server's first 4 bytes (TB
     * `sshChainDetectFraming`): "raw" for a plain SSH banner, "ws"
     * for an unmasked WS frame (FIN + text/binary), UNKNOWN when it
     * cannot be told yet.
     */
    fun detectFraming(first: ByteArray): Framing {
        if (first.size < 4) return Framing.UNKNOWN
        if (first[0] == 'S'.code.toByte() && first[1] == 'S'.code.toByte() &&
            first[2] == 'H'.code.toByte() && first[3] == '-'.code.toByte()
        ) {
            return Framing.RAW
        }
        val b0 = first[0].toInt() and 0xFF
        val b1 = first[1].toInt() and 0xFF
        if ((b0 == 0x81 || b0 == 0x82) && b1 and 0x80 == 0 && b1 > 0) {
            return Framing.WS
        }
        return Framing.UNKNOWN
    }

    /**
     * Peek the next 4 bytes without consuming them (mark/reset on
     * the [BufferedInputStream]). The caller sets the socket read
     * timeout to [PEEK_PERIOD_MS] first: a [SocketTimeoutException]
     * means no data arrived in time and the framing stays UNKNOWN.
     * Bytes already buffered (e.g. the Enhanced banner) are read
     * at once without blocking.
     */
    fun peekFraming(input: BufferedInputStream): Framing {
        input.mark(4)
        val first = ByteArray(4)
        var filled = 0
        try {
            while (filled < 4) {
                val r = input.read(first, filled, 4 - filled)
                if (r == -1) break
                filled += r
            }
        } catch (e: SocketTimeoutException) {
            input.reset()
            return Framing.UNKNOWN
        }
        input.reset()
        if (filled < 4) return Framing.UNKNOWN
        return detectFraming(first)
    }

    /**
     * Decide the final framing (TB `sshChainDialOnce` tail).
     * Detection wins over the payload's WS-ness; with no data the
     * payload decides. A WS upgrade with no data and no 101 fails
     * ("upgrade websocket ditolak"); a non-WS payload with no data
     * and a non-1xx/2xx status fails ("proxy menolak payload").
     * A raw pipe never rejects on status (Simple-Injector style).
     */
    fun chooseFraming(detected: Framing, wasWsUpgrade: Boolean, lastStatus: String): Framing {
        var useWs = wasWsUpgrade
        if (detected == Framing.WS) useWs = true
        if (detected == Framing.RAW) useWs = false
        if (useWs) {
            if (detected == Framing.UNKNOWN && statusCode(lastStatus) != "101") {
                throw IOException("SSH gagal: upgrade websocket ditolak: $lastStatus")
            }
            return Framing.WS
        }
        if (detected == Framing.UNKNOWN && lastStatus.isNotEmpty()) {
            val code = statusCode(lastStatus)
            if (!code.startsWith("1") && !code.startsWith("2")) {
                throw IOException("SSH gagal: proxy menolak payload: $lastStatus")
            }
        }
        return Framing.RAW
    }
}
