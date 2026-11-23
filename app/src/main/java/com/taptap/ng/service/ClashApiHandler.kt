package com.taptap.ng.service

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.net.URLDecoder
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * One live connection as the Clash API reports it
 * (GET /connections). Byte counts come from the forwarder's
 * per-session SpeedStats; UDP sessions report 0 (the forwarder
 * does not count UDP bytes per session).
 */
data class ConnectionInfo(
    val id: String,
    val network: String,
    val host: String?,
    val destinationIp: String,
    val destinationPort: Int,
    val sourceIp: String,
    val sourcePort: Int,
    val upload: Long,
    val download: Long,
    val startMs: Long,
)

/** One parsed HTTP request (the server fills this in; the handler is pure). */
data class ApiRequest(
    val method: String,
    /** Path without query string, URL-decoded, no trailing slash (except root). */
    val path: String,
    val query: Map<String, String>,
    /** Header names lowercased. */
    val headers: Map<String, String>,
    val body: String,
) {
    fun header(name: String): String? = headers[name.lowercase()]
}

/** What the handler returns. [Stream] means "keep the connection open and call [produce]". */
sealed class ApiResponse {
    /** One-shot response. */
    data class Immediate(
        val status: Int,
        val contentType: String,
        val body: ByteArray,
        val extraHeaders: Map<String, String> = emptyMap(),
    ) : ApiResponse() {
        constructor(status: Int, json: String) : this(
            status, "application/json", json.toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * Streaming response: the server calls [produce] repeatedly and
     * sends each non-null line — as WebSocket text frames when the
     * client upgraded, as HTTP chunked lines otherwise. Null means
     * "nothing new right now, try again later"; the stream only
     * ends when the client disconnects.
     */
    data class Stream(val produce: () -> String?) : ApiResponse()
}

/**
 * Everything the handler needs from the app, behind one interface
 * so tests can stub it without Android, sockets, or the tunnel.
 * The production implementation is [LiveClashApiDeps] (in
 * ClashApiServer.kt).
 */
interface ClashApiDeps {
    val versionName: String
    fun secret(): String
    fun baseUrl(): String
    fun port(): Int
    fun allowLan(): Boolean
    fun mode(): String
    fun setMode(mode: String)
    /** Groups, refreshed from disk (see ClashApiRuntime). */
    fun groups(): List<ProxyGroup>
    fun rules(): List<RouteRule>
    fun profiles(): List<ProfileItem>
    fun delays(): Map<String, Long?>
    fun delayMeasuredAtMs(guid: String): Long?
    /** Change a SELECT group's selected member by display name. False = unknown group/proxy. */
    fun selectProxy(groupName: String, proxyName: String): Boolean
    /** Measure one profile's delay (null = failed / unknown profile). */
    fun delayTest(guid: String, url: String, timeoutMs: Int): Long?
    /** (up, down) bytes through the tunnel since start; (0, 0) when the VPN is down. */
    fun traffic(): Pair<Long, Long>
    fun connections(): List<ConnectionInfo>
    fun closeConnection(id: String): Boolean
    fun closeAllConnections()
    fun logLines(): List<String>
    /** Raw bytes of one bundled yacd asset (path relative to yacd/), or null. */
    fun assetBytes(path: String): ByteArray?
}

/**
 * Clash external-controller API (M7, W3): routing + JSON for the
 * bundled yacd dashboard. Pure over [ClashApiDeps] — no sockets,
 * no Android — so the JVM tests drive it in-memory.
 *
 * Endpoint surface (verified against the bundled yacd-meta,
 * `app/src/main/assets/yacd/assets/index-*.js`):
 * - GET /version, GET/PATCH/PUT /configs, POST /restart,
 *   POST /cache/fakeip/flush, POST /upgrade[/ui|/geo]
 * - GET /proxies, GET/PUT/DELETE /proxies/{name},
 *   GET /proxies/{name}/delay, GET /group/{name}/delay
 * - GET /providers/proxies, PUT /providers/proxies/{name},
 *   GET /providers/proxies/{name}/healthcheck,
 *   GET /providers/proxies/{provider}/{proxy}/healthcheck,
 *   GET /providers/rules, PUT /providers/rules/{name}
 * - GET /rules, PATCH /rules/disable
 * - GET /connections (+DELETE), GET /traffic, GET /logs, GET /memory
 *   — all four stream: WebSocket when the client upgrades (what
 *   yacd does), HTTP chunked lines otherwise (yacd's fetch fallback).
 * - GET /ui/ and /ui/<path> serve the bundled dashboard; GET / redirects
 *   to /ui/#/proxies. index.html's data-base-url is rewritten to
 *   the local API base URL.
 *
 * Auth: when a secret is set, every API path requires
 * `Authorization: Bearer <secret>` (Clash standard) and answers
 * 401 otherwise. The static UI (/ui/ tree) is served WITHOUT auth —
 * like mihomo's external-ui — the API calls from the page carry
 * the token; open the dashboard as `/ui/?secret=<secret>` or set
 * the secret in yacd's own API-config dialog. The secret is NEVER
 * written to a log or echoed in a response.
 *
 * CORS: `Access-Control-Allow-Origin: *` on every response, so the
 * hosted yacd (yacd.metacubex.one) can drive this API too.
 *
 * Honest gaps (documented, not faked): /connections lists only
 * what the forwarder tracks (empty when the VPN is down);
 * /traffic is 0 when the VPN is down; /logs streams DialLog's ring
 * buffer (snapshot + tail); /memory reports the app JVM heap;
 * /restart, /upgrade paths, /cache/fakeip/flush, PUT /providers paths and
 * PATCH /rules/disable are accepted no-ops (there is no core to
 * restart or provider to reload).
 */
class ClashApiHandler(private val deps: ClashApiDeps) {

    private val gson = Gson()

    companion object {
        /** The base URL baked into the bundled yacd index.html — rewritten on serve. */
        const val BUNDLED_BASE_URL = "http://127.0.0.1:9090"

        /** WebSocket accept key (RFC 6455). Pure — unit-tested. */
        fun websocketAcceptKey(clientKey: String): String {
            val accept = clientKey.trim() +
                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            val sha1 = MessageDigest.getInstance("SHA-1")
                .digest(accept.toByteArray(Charsets.US_ASCII))
            return Base64.getEncoder().encodeToString(sha1)
        }

        /** Rewrite the baked data-base-url in index.html to the local API base URL. */
        fun rewriteBaseUrl(indexHtml: String, baseUrl: String): String =
            indexHtml.replace(
                "data-base-url=\"$BUNDLED_BASE_URL\"",
                "data-base-url=\"$baseUrl\"",
            )

        /** MIME type for a bundled yacd asset, by extension. */
        fun contentTypeFor(path: String): String = when (path.substringAfterLast('.', "").lowercase()) {
            "html" -> "text/html; charset=utf-8"
            "js" -> "text/javascript; charset=utf-8"
            "css" -> "text/css; charset=utf-8"
            "json" -> "application/json"
            "png" -> "image/png"
            "jpg", "jpeg" -> "image/jpeg"
            "ico" -> "image/x-icon"
            "svg" -> "image/svg+xml"
            "woff" -> "font/woff"
            "woff2" -> "font/woff2"
            "webmanifest" -> "application/manifest+json"
            else -> "application/octet-stream"
        }

        fun parseQuery(raw: String): Map<String, String> {
            if (raw.isBlank()) return emptyMap()
            val out = LinkedHashMap<String, String>()
            for (part in raw.split('&')) {
                val eq = part.indexOf('=')
                val k = URLDecoder.decode(if (eq < 0) part else part.substring(0, eq), "UTF-8")
                val v = if (eq < 0) "" else URLDecoder.decode(part.substring(eq + 1), "UTF-8")
                out[k] = v
            }
            return out
        }

        fun isoTime(ms: Long): String {
            val f = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            f.timeZone = TimeZone.getTimeZone("UTC")
            return f.format(Date(ms))
        }
    }

    fun handle(req: ApiRequest): ApiResponse {
        // Preflight first (no auth needed — the browser asks before it knows the secret).
        if (req.method == "OPTIONS") {
            return ApiResponse.Immediate(204, "text/plain", ByteArray(0))
        }
        val isUi = req.path == "/" || req.path == "/ui" || req.path.startsWith("/ui/")
        if (!isUi && !authorized(req)) {
            return json(401, obj { addProperty("message", "Unauthorized") })
        }
        return when {
            req.method == "GET" && req.path == "/" -> redirect()
            req.method == "GET" && (req.path == "/ui" || req.path == "/ui/" || req.path.startsWith("/ui/")) ->
                serveUi(req)
            req.method == "GET" && req.path == "/version" -> json(200, obj {
                addProperty("version", deps.versionName)
                addProperty("meta", true)
            })
            req.path == "/configs" -> handleConfigs(req)
            req.method == "POST" && req.path == "/restart" -> ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            req.method == "POST" && req.path == "/cache/fakeip/flush" ->
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            req.method == "POST" && (req.path == "/upgrade" || req.path == "/upgrade/ui" || req.path == "/upgrade/geo") ->
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            req.path == "/proxies" || req.path.startsWith("/proxies/") -> handleProxies(req)
            req.path == "/group" || req.path.startsWith("/group/") -> handleGroupDelay(req)
            req.path == "/providers/proxies" || req.path.startsWith("/providers/proxies/") -> handleProvidersProxies(req)
            req.path == "/providers/rules" || req.path.startsWith("/providers/rules/") -> handleProvidersRules(req)
            req.path == "/rules" || req.path == "/rules/disable" -> handleRules(req)
            req.path == "/connections" || req.path.startsWith("/connections/") -> handleConnections(req)
            req.method == "GET" && req.path == "/traffic" -> trafficStream()
            req.method == "GET" && req.path == "/logs" -> logsStream()
            req.method == "GET" && req.path == "/memory" -> memoryStream()
            else -> json(404, obj { addProperty("message", "not found") })
        }
    }

    // ---- Auth / helpers ----

    private fun authorized(req: ApiRequest): Boolean {
        val secret = deps.secret()
        if (secret.isEmpty()) return true
        return req.header("Authorization") == "Bearer $secret"
    }

    private fun obj(init: JsonObject.() -> Unit): JsonObject = JsonObject().apply(init)

    private fun json(status: Int, body: JsonObject): ApiResponse.Immediate =
        ApiResponse.Immediate(status, gson.toJson(body))

    private fun jsonArray(status: Int, body: JsonArray): ApiResponse.Immediate =
        ApiResponse.Immediate(status, gson.toJson(body))

    private fun redirect(): ApiResponse.Immediate = ApiResponse.Immediate(
        302, "text/plain", ByteArray(0),
        extraHeaders = mapOf("Location" to "/ui/#/proxies"),
    )

    /** Unique display name per profile (Clash proxy names must be unique). */
    internal fun displayNames(): Map<String, String> {
        val seen = HashMap<String, Int>()
        val out = LinkedHashMap<String, String>()
        for (p in deps.profiles()) {
            val base = p.displayName()
            val n = (seen[base] ?: 0) + 1
            seen[base] = n
            out[p.guid] = if (n == 1) base else "$base #$n"
        }
        return out
    }

    private fun historyFor(guid: String): JsonArray {
        val arr = JsonArray()
        val delay = deps.delays()[guid]
        val at = deps.delayMeasuredAtMs(guid)
        if (delay != null && at != null) {
            arr.add(obj {
                addProperty("time", isoTime(at))
                addProperty("delay", delay)
            })
        }
        return arr
    }

    private fun proxyType(item: ProfileItem): String = when (item.configType) {
        ConfigType.VMESS -> "vmess"
        ConfigType.VLESS -> "vless"
        ConfigType.TROJAN -> "trojan"
        ConfigType.SHADOWSOCKS -> "ss"
        ConfigType.SSH -> "ssh"
    }

    private fun groupTypeName(type: ProxyGroupType): String = when (type) {
        ProxyGroupType.SELECT -> "Selector"
        ProxyGroupType.URL_TEST -> "URLTest"
        ProxyGroupType.FALLBACK -> "Fallback"
    }

    // ---- UI ----

    private fun serveUi(req: ApiRequest): ApiResponse.Immediate {
        val rel = when (req.path) {
            "/ui", "/ui/" -> "index.html"
            else -> req.path.removePrefix("/ui/")
        }
        if (rel.contains("..")) return ApiResponse.Immediate(403, "text/plain", ByteArray(0))
        val bytes = deps.assetBytes(rel)
            ?: return ApiResponse.Immediate(404, "text/plain", "not found".toByteArray(Charsets.UTF_8))
        if (rel == "index.html") {
            val rewritten = rewriteBaseUrl(bytes.toString(Charsets.UTF_8), deps.baseUrl())
            return ApiResponse.Immediate(200, "text/html; charset=utf-8", rewritten.toByteArray(Charsets.UTF_8))
        }
        return ApiResponse.Immediate(200, contentTypeFor(rel), bytes)
    }

    // ---- /configs ----

    private fun handleConfigs(req: ApiRequest): ApiResponse {
        return when (req.method) {
            "GET" -> json(200, obj {
                addProperty("port", deps.port())
                addProperty("socks-port", 0)
                addProperty("redir-port", 0)
                addProperty("tproxy-port", 0)
                addProperty("mixed-port", 0)
                addProperty("mode", deps.mode())
                addProperty("log-level", "info")
                addProperty("ipv6", false)
                addProperty("allow-lan", deps.allowLan())
                addProperty("external-controller", "127.0.0.1:${deps.port()}")
                addProperty("external-ui", "/ui")
                addProperty("secret", "")
            })
            "PATCH" -> {
                val body = runCatching { JsonParser.parseString(req.body).asJsonObject }.getOrNull()
                val mode = body?.get("mode")?.takeIf { it.isJsonPrimitive }?.asString
                if (mode != null) {
                    val normalized = mode.trim().lowercase()
                    if (normalized !in setOf(RouteEngine.MODE_RULE, RouteEngine.MODE_GLOBAL, RouteEngine.MODE_DIRECT)) {
                        return json(400, obj { addProperty("message", "unknown mode: $mode") })
                    }
                    deps.setMode(normalized)
                }
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            "PUT" -> {
                // yacd "reload config": no core to reload — accept, nothing changes.
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    // ---- /proxies ----

    private fun proxiesObject(): JsonObject {
        val names = displayNames()
        val delays = deps.delays()
        val groups = deps.groups()
        val out = obj {}
        val proxies = JsonObject()
        // "GLOBAL" pseudo-group (Clash shape): every proxy, now = selected entry.
        val allNames = JsonArray().apply { names.values.forEach { add(it) } }
        val selectedGuid = groups.firstOrNull { it.name == RouteEngine.FALLBACK_GROUP_NAME }
            ?.effectiveSelectedMemberGuid()
            ?: groups.firstOrNull()?.effectiveSelectedMemberGuid()
        proxies.add("GLOBAL", obj {
            addProperty("name", "GLOBAL")
            addProperty("type", "Selector")
            addProperty("now", names[selectedGuid] ?: "")
            add("all", allNames)
            add("history", JsonArray())
        })
        for (g in groups) {
            val nowGuid = RouteEngine.selectMember(g, delays)
            val all = JsonArray().apply {
                g.members.forEach { guid -> names[guid]?.let { add(it) } }
            }
            val history = when (g.type) {
                ProxyGroupType.SELECT -> nowGuid?.let { historyFor(it) } ?: JsonArray()
                ProxyGroupType.URL_TEST -> {
                    // Best known member of the last round.
                    val best = g.members.minByOrNull { delays[it] ?: Long.MAX_VALUE }
                    best?.let { historyFor(it) } ?: JsonArray()
                }
                ProxyGroupType.FALLBACK -> {
                    val first = g.members.firstOrNull { delays[it] != null }
                    first?.let { historyFor(it) } ?: JsonArray()
                }
            }
            proxies.add(g.name, obj {
                addProperty("name", g.name)
                addProperty("type", groupTypeName(g.type))
                addProperty("now", names[nowGuid] ?: "")
                add("all", all)
                add("history", history)
            })
        }
        for (p in deps.profiles()) {
            proxies.add(names[p.guid] ?: p.displayName(), obj {
                addProperty("name", names[p.guid] ?: p.displayName())
                addProperty("type", proxyType(p))
                add("history", historyFor(p.guid))
                addProperty("udp", false)
            })
        }
        out.add("proxies", proxies)
        return out
    }

    private fun handleProxies(req: ApiRequest): ApiResponse {
        val rest = req.path.removePrefix("/proxies").trimStart('/')
        val segments = if (rest.isEmpty()) emptyList() else rest.split('/').map {
            URLDecoder.decode(it, "UTF-8")
        }
        return when (req.method) {
            "GET" -> when {
                segments.isEmpty() -> json(200, proxiesObject())
                segments.size == 2 && segments[1] == "delay" -> delayFor(segments[0], req)
                segments.size == 1 -> {
                    val all = proxiesObject().getAsJsonObject("proxies")
                    val one = all.get(segments[0])
                        ?: return json(404, obj { addProperty("message", "proxy not found") })
                    ApiResponse.Immediate(200, gson.toJson(one))
                }
                else -> json(404, obj { addProperty("message", "not found") })
            }
            "PUT" -> {
                // yacd: PUT /proxies/{selector} body {"name": "<proxy>"}.
                // Also accept the Clash path form PUT /proxies/{selector}/{proxy}.
                val selector = segments.getOrNull(0)
                    ?: return json(400, obj { addProperty("message", "missing selector") })
                val proxyName = segments.getOrNull(1) ?: run {
                    runCatching { JsonParser.parseString(req.body).asJsonObject }
                        .getOrNull()?.get("name")?.takeIf { it.isJsonPrimitive }?.asString
                } ?: return json(400, obj { addProperty("message", "missing proxy name") })
                if (!deps.selectProxy(selector, proxyName)) {
                    return json(404, obj { addProperty("message", "group or proxy not found") })
                }
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            "DELETE" -> {
                // No provider to delete from — accept so the dashboard stays quiet.
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    /** GET /proxies/{name}/delay — group name tests its effective member, proxy name tests itself. */
    private fun delayFor(name: String, req: ApiRequest): ApiResponse {
        val timeoutMs = req.query["timeout"]?.toIntOrNull()?.coerceIn(1, 60_000) ?: 5000
        val url = req.query["url"].orEmpty()
        val names = displayNames()
        val group = deps.groups().firstOrNull { it.name == name }
        val guid = when {
            group != null -> RouteEngine.selectMember(group, deps.delays())
            name == "GLOBAL" -> deps.groups().firstOrNull { it.name == RouteEngine.FALLBACK_GROUP_NAME }
                ?.effectiveSelectedMemberGuid()
            else -> names.entries.firstOrNull { it.value == name }?.key
        } ?: return json(404, obj { addProperty("message", "proxy not found") })
        val delay = deps.delayTest(guid, url, timeoutMs)
            ?: return json(504, obj { addProperty("message", "timeout") })
        return json(200, obj { addProperty("delay", delay) })
    }

    /** GET /group/{name}/delay — same measurement as /proxies/{name}/delay. */
    private fun handleGroupDelay(req: ApiRequest): ApiResponse {
        if (req.method != "GET") return json(405, obj { addProperty("message", "method not allowed") })
        val name = req.path.removePrefix("/group").trimStart('/')
            .split('/').firstOrNull()?.let { URLDecoder.decode(it, "UTF-8") }.orEmpty()
        if (name.isEmpty()) return json(400, obj { addProperty("message", "missing group") })
        return delayFor(name, req)
    }

    // ---- /providers ----

    private fun handleProvidersProxies(req: ApiRequest): ApiResponse {
        val rest = req.path.removePrefix("/providers/proxies").trimStart('/')
        val segments = if (rest.isEmpty()) emptyList() else rest.split('/').map {
            URLDecoder.decode(it, "UTF-8")
        }
        return when (req.method) {
            "GET" -> when {
                segments.isEmpty() -> json(200, obj {
                    add("providers", obj {
                        add("default", obj {
                            addProperty("name", "default")
                            addProperty("type", "Proxy")
                            addProperty("vehicleType", "HTTP")
                            add("proxies", proxiesObject().getAsJsonObject("proxies"))
                        })
                    })
                })
                segments.size == 2 && segments[1] == "healthcheck" -> {
                    // Single-provider healthcheck: nothing to check — accept.
                    ApiResponse.Immediate(204, "text/plain", ByteArray(0))
                }
                segments.size == 3 && segments[2] == "healthcheck" -> {
                    // Provider + proxy healthcheck: measure like a delay test.
                    val proxyName = segments[1]
                    val timeoutMs = req.query["timeout"]?.toIntOrNull()?.coerceIn(1, 60_000) ?: 5000
                    val url = req.query["url"].orEmpty()
                    val guid = displayNames().entries.firstOrNull { it.value == proxyName }?.key
                        ?: return json(404, obj { addProperty("message", "proxy not found") })
                    val delay = deps.delayTest(guid, url, timeoutMs)
                        ?: return json(504, obj { addProperty("message", "timeout") })
                    json(200, obj { addProperty("delay", delay) })
                }
                else -> json(404, obj { addProperty("message", "not found") })
            }
            "PUT" -> ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    private fun handleProvidersRules(req: ApiRequest): ApiResponse {
        val rest = req.path.removePrefix("/providers/rules").trimStart('/')
        return when (req.method) {
            "GET" -> {
                if (rest.isNotEmpty()) return json(404, obj { addProperty("message", "not found") })
                json(200, obj {
                    add("providers", obj {
                        add("default", obj {
                            addProperty("name", "default")
                            addProperty("type", "Rule")
                            addProperty("vehicleType", "HTTP")
                            add("rules", rulesArray())
                        })
                    })
                })
            }
            "PUT" -> ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    // ---- /rules ----

    private fun rulesArray(): JsonArray {
        val arr = JsonArray()
        val groupNames = deps.groups().associateBy({ it.id }, { it.name })
        for (r in deps.rules()) {
            val type = when (r.type) {
                RouteRuleType.DOMAIN -> "DOMAIN"
                RouteRuleType.DOMAIN_SUFFIX -> "DOMAIN-SUFFIX"
                RouteRuleType.DOMAIN_KEYWORD -> "DOMAIN-KEYWORD"
                RouteRuleType.IP_CIDR -> "IP-CIDR"
                RouteRuleType.FINAL -> "FINAL"
            }
            val proxy = when (r.target) {
                RouteRule.TARGET_DIRECT -> RouteRule.TARGET_DIRECT
                RouteRule.TARGET_REJECT -> RouteRule.TARGET_REJECT
                else -> groupNames[r.target] ?: r.target
            }
            arr.add(obj {
                addProperty("type", type)
                addProperty("payload", if (r.type == RouteRuleType.FINAL) "" else r.normalizedPattern)
                addProperty("proxy", proxy)
            })
        }
        return arr
    }

    private fun handleRules(req: ApiRequest): ApiResponse {
        return when (req.method) {
            "GET" -> jsonArray(200, rulesArray())
            "PATCH" -> {
                // yacd "disable rules": no per-rule enable flag exists — accept, no-op.
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    // ---- /connections ----

    private fun handleConnections(req: ApiRequest): ApiResponse {
        return when (req.method) {
            "GET" -> {
                if (req.path != "/connections") {
                    return json(404, obj { addProperty("message", "not found") })
                }
                ApiResponse.Stream { connectionsSnapshotJson() }
            }
            "DELETE" -> {
                val id = req.path.removePrefix("/connections").trimStart('/')
                    .takeIf { it.isNotEmpty() }?.let { URLDecoder.decode(it, "UTF-8") }
                if (id == null) deps.closeAllConnections() else deps.closeConnection(id)
                ApiResponse.Immediate(204, "text/plain", ByteArray(0))
            }
            else -> json(405, obj { addProperty("message", "method not allowed") })
        }
    }

    internal fun connectionsSnapshotJson(): String {
        val conns = deps.connections()
        var up = 0L
        var down = 0L
        val arr = JsonArray()
        for (c in conns) {
            up += c.upload
            down += c.download
            arr.add(obj {
                addProperty("id", c.id)
                add("metadata", obj {
                    addProperty("host", c.host ?: "")
                    addProperty("destinationIP", c.destinationIp)
                    addProperty("destinationPort", c.destinationPort)
                    addProperty("sourceIP", c.sourceIp)
                    addProperty("sourcePort", c.sourcePort)
                    addProperty("type", "TCP")
                    addProperty("network", c.network)
                    addProperty("process", "")
                })
                addProperty("upload", c.upload)
                addProperty("download", c.download)
                addProperty("start", isoTime(c.startMs))
            })
        }
        // Totals are tunnel-wide (closed sessions included), not just the live list.
        val (totalUp, totalDown) = deps.traffic()
        return gson.toJson(obj {
            add("connections", arr)
            addProperty("total", conns.size)
            addProperty("uploadTotal", totalUp)
            addProperty("downloadTotal", totalDown)
        })
    }

    // ---- Streams ----

    private fun trafficStream(): ApiResponse.Stream = ApiResponse.Stream {
        val (up, down) = deps.traffic()
        gson.toJson(obj {
            addProperty("up", up)
            addProperty("down", down)
        })
    }

    private fun memoryStream(): ApiResponse.Stream = ApiResponse.Stream {
        val rt = Runtime.getRuntime()
        val inuse = rt.totalMemory() - rt.freeMemory()
        gson.toJson(obj {
            addProperty("inuse", inuse)
            addProperty("total", rt.totalMemory())
        })
    }

    /**
     * Log tail: snapshot of DialLog's ring buffer on connect, then
     * only lines appended after the last one sent. Lines are sent
     * one per produce() call as Clash log objects
     * {"type":"info","payload":"...","time":"..."}.
     */
    internal fun logsTailer(): () -> String? {
        val pending = ArrayDeque<String>()
        var lastSent: String? = null
        var primed = false
        val tailer: () -> String? = tailer@{
            if (!primed) {
                primed = true
                val lines = deps.logLines()
                pending.addAll(lines)
                lastSent = lines.lastOrNull()
            } else {
                val lines = deps.logLines()
                val idx = lastSent?.let { lines.lastIndexOf(it) } ?: -1
                val fresh = if (idx < 0) lines else lines.drop(idx + 1)
                pending.addAll(fresh)
                if (fresh.isNotEmpty()) lastSent = fresh.last()
            }
            val line = pending.removeFirstOrNull() ?: return@tailer null
            gson.toJson(obj {
                addProperty("type", "info")
                addProperty("payload", line)
                addProperty("time", isoTime(System.currentTimeMillis()))
            })
        }
        return tailer
    }

    private fun logsStream(): ApiResponse.Stream = ApiResponse.Stream(logsTailer())
}
