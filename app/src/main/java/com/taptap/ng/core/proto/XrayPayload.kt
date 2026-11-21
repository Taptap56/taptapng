package com.taptap.ng.core.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.data.ProfileItem
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger

/**
 * Xray payload template + HTTP CONNECT proxy target (v1.0.10) —
 * port of the XVEON Tunnel Pro 6.1 mechanism, verified from its
 * dex (2026-11-21): TCP to the proxy (proxyHost:proxyPort, the
 * host may be a bug domain) → the custom payload is sent to the
 * proxy ("Sending proxy custom payload...") → `CONNECT
 * <target-host>:<target-port> HTTP/1.1` + Host, wait for 200 →
 * TLS (SNI, ALPN) → WS handshake with the same template.
 *
 * Template placeholders (XVEON's set): [ws_host], [path], [sni],
 * [ws_key], [split], [rotate=a;b], [host], [ip], [port],
 * [proxy_auth], [ua], [auth], plus the TB set this app already
 * knows ([host_port], [protocol], [real_raw], [crlf], [cr], [lf]).
 * v1.0.11 adds [proxy_host] — the proxy host used this dial
 * (after [rotate] expansion), so an SSH-style template can write
 * `Host: [proxy_host]` for its first GET. [split] is NOT expanded
 * — it marks a segment boundary: the template is written in
 * segments, one flush per segment (SshPayload does the same for
 * its [split] timing).
 *
 * This file is pure string work (no sockets) so every behaviour
 * below is JVM-testable. The dial itself lives in [Transport]
 * (proxy ladder) and [HttpConnectProxy] (CONNECT) /
 * [PayloadOnlyProxy] (v1.0.11: payload, then straight to TLS).
 */
object XrayPayload {

    /**
     * XVEON's default WS template, used when the Payload chip is
     * ON but the template box is empty — the user never has to
     * type the standard WS upgrade by hand.
     */
    const val DEFAULT_TEMPLATE =
        "GET [path] HTTP/1.1[crlf]Host: [ws_host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"

    /** The template that actually runs for this entry (""). */
    fun templateFor(item: ProfileItem): String =
        if (item.xrayUsePayload) item.xrayPayload.ifBlank { DEFAULT_TEMPLATE } else ""

    /** Values the template placeholders are filled from. */
    data class Ctx(
        /** WS Host header value (item.host, else the proxy address). */
        val wsHost: String,
        /** WS request path ("/" default, leading slash). */
        val path: String,
        /** SNI (item.sni, else the proxy address). */
        val sni: String,
        /** The proxy server host (item.address). */
        val host: String,
        /** The proxy server IP (resolved, best effort; else [host]). */
        val ip: String,
        /** The proxy server port (item.port). */
        val port: Int,
        /** Sec-WebSocket-Key for this dial ("" at the proxy stage). */
        val wsKey: String = "",
        /** Proxy-Authorization value ("" — no auth in v1.0.10). */
        val proxyAuth: String = "",
        /** Authorization value ("" — unused in v1.0.10). */
        val auth: String = "",
        /** User-Agent (same generic UA as the SSH payload). */
        val ua: String = SshPayload.DEFAULT_UA,
        /**
         * v1.0.11: the proxy host used this dial (after [rotate]
         * expansion) — fills the [proxy_host] placeholder. "" when
         * no proxy is used (the placeholder then expands empty).
         */
        val proxyHost: String = "",
    )

    // ---- [rotate=a;b] ----

    /**
     * Round-robin picker for `[rotate=a;b]` (XVEON's `Ly` counter):
     * each expansion takes the next option, wrapping around. One
     * shared counter per process — a proxy host and a template in
     * the same dial rotate independently per occurrence, like XVEON.
     */
    object RotatePicker {
        private val counter = AtomicInteger(0)

        fun next(options: List<String>): String {
            require(options.isNotEmpty()) { "rotate: daftar bug kosong" }
            val idx = (counter.getAndIncrement() and Int.MAX_VALUE) % options.size
            return options[idx]
        }

        /** Test-only: restart the rotation from the first option. */
        fun reset() {
            counter.set(0)
        }
    }

    private val ROTATE_RE = Regex("\\[rotate=([^\\]]+)\\]")

    /** Expand every `[rotate=a;b]` in [text] (round-robin per hit). */
    fun expandRotate(
        text: String,
        pick: (List<String>) -> String = RotatePicker::next,
    ): String = ROTATE_RE.replace(text) { m ->
        val options = m.groupValues[1].split(';').map { it.trim() }.filter { it.isNotEmpty() }
        require(options.isNotEmpty()) { "rotate: daftar bug kosong di '${m.value}'" }
        pick(options)
    }

    // ---- template expansion ----

    /**
     * Expand a payload template. `[host_port]` is replaced FIRST,
     * before `[host]` (same order as [SshPayload.expand], for the
     * same reason); `[rotate=...]` is expanded before both, its
     * values are plain domains. Line endings are normalised to
     * CRLF and a trailing blank line is appended when missing.
     * `[split]` survives expansion — see [segments].
     */
    fun expand(
        template: String,
        ctx: Ctx,
        pick: (List<String>) -> String = RotatePicker::next,
    ): String {
        val hostPort = if (ctx.host.contains(':') && !ctx.host.startsWith("[")) {
            "[${ctx.host}]:${ctx.port}"
        } else {
            "${ctx.host}:${ctx.port}"
        }
        var out = expandRotate(template, pick)
        out = out.replace("[host_port]", hostPort)
        // v1.0.11: [proxy_host] BEFORE [host] — same reason as
        // [host_port] (a later [host] replace must not touch it).
        out = out.replace("[proxy_host]", ctx.proxyHost)
        out = out.replace("[host]", ctx.host)
        out = out.replace("[ip]", ctx.ip)
        out = out.replace("[port]", ctx.port.toString())
        out = out.replace("[sni]", ctx.sni)
        out = out.replace("[ws_host]", ctx.wsHost)
        out = out.replace("[path]", ctx.path)
        out = out.replace("[ws_key]", ctx.wsKey)
        out = out.replace("[protocol]", "HTTP/1.1")
        out = out.replace("[ua]", ctx.ua)
        out = out.replace("[auth]", ctx.auth)
        out = out.replace("[proxy_auth]", ctx.proxyAuth)
        out = out.replace("[real_raw]", "\n\n")
        out = out.replace("[crlf][crlf]", "\r\n\r\n")
        out = out.replace("[crlf]", "\r\n")
        out = out.replace("[cr]", "\r")
        out = out.replace("[lf]", "\n")
        // Normalise line endings: pasted templates may contain bare \n.
        out = out.replace("\r\n", "\n").replace("\n", "\r\n")
        if (!out.endsWith("\r\n\r\n")) {
            out = out.trimEnd('\r', '\n') + "\r\n\r\n"
        }
        return out
    }

    /**
     * Split an expanded template into write segments on `[split]`
     * (empty segments dropped). One segment = one write + flush.
     */
    fun segments(expanded: String): List<String> =
        expanded.split("[split]").filter { it.isNotEmpty() }

    /** Write the segments of [expanded] in order, flushing each. */
    fun writeSegments(output: OutputStream, expanded: String) {
        for (seg in segments(expanded)) {
            output.write(seg.toByteArray(Charsets.UTF_8))
            output.flush()
        }
    }

    /**
     * Add the WS handshake headers to the upgrading request (same
     * rule as [SshPayload.addWsHandshakeHeaders], but with the
     * caller's key): `Sec-WebSocket-Key` + `Sec-WebSocket-Version:
     * 13` go into the request that carries "Upgrade: websocket",
     * right before that request's terminating blank line. No-op
     * when the payload is not a WS upgrade or already has a key —
     * XVEON's default template carries no key, so without this the
     * Sec-WebSocket-Accept check in [WsTransport] could never pass.
     */
    fun addWsHandshakeHeaders(payload: String, key: String): String {
        if (!payload.contains("upgrade: websocket", ignoreCase = true)) return payload
        if (payload.contains("sec-websocket-key", ignoreCase = true)) return payload
        val idx = payload.lowercase().indexOf("upgrade: websocket")
        if (idx < 0) return payload
        val end = payload.indexOf("\r\n\r\n", idx)
        if (end < 0) return payload
        val wsHeaders = "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13"
        return payload.substring(0, end) + "\r\n" + wsHeaders + payload.substring(end)
    }

    /** Fresh random Sec-WebSocket-Key (Base64 of 16 random bytes). */
    fun newWsKey(): String = Base64Util.encode(Crypto.randomBytes(16))

    // ---- proxy target ----

    /**
     * Parse the proxy target from the editor fields: [rawHost] may
     * be a plain host/IP, `[rotate=bug1;bug2]`, or `host:port`
     * (bracketed IPv6 allowed). The explicit [portField] wins over
     * a port inside the host text; empty means 80 (XVEON's rule).
     * @throws IllegalArgumentException on a blank host or a bad port.
     */
    fun parseProxyTarget(rawHost: String, portField: Int?): Pair<String, Int> {
        val expanded = expandRotate(rawHost.trim())
        val (host, portInHost) = SshPayload.splitHostPort(expanded)
            ?: throw IllegalArgumentException("Proxy gagal: host proxy tidak valid: $rawHost")
        val port = portField ?: portInHost ?: 80
        require(port in 1..65535) { "Proxy gagal: port proxy di luar 1..65535: $port" }
        return host to port
    }
}
