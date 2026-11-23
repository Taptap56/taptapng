package com.taptap.ng.service

import com.google.gson.JsonParser
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.SettingsStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Clash API handler tests (M7, W3): endpoint routing + JSON shape
 * + PUT select + CORS + index.html rewrite + WebSocket accept key
 * + Bearer auth — all in-memory, no sockets (loopback JVM in this
 * VM is intercepted; a live bind test belongs to CI / the phone).
 *
 * The fake deps mirror a two-server setup: one SELECT group
 * "taptap" (both members, first selected), one URL_TEST group,
 * rules DOMAIN-SUFFIX google.com -> taptap + FINAL -> taptap.
 */
class ClashApiHandlerTest {

    private class FakeDeps(
        var secret: String = "",
        var modeValue: String = "rule",
        var groups: MutableList<ProxyGroup> = mutableListOf(),
        var rules: MutableList<RouteRule> = mutableListOf(),
        var profiles: List<ProfileItem> = listOf(
            ProfileItem(guid = "guid-a", remarks = "Server A", configType = ConfigType.VMESS),
            ProfileItem(guid = "guid-b", remarks = "Server B", configType = ConfigType.VLESS),
        ),
        var delays: MutableMap<String, Long?> = mutableMapOf("guid-a" to 123L),
        var measuredAt: MutableMap<String, Long> = mutableMapOf("guid-a" to 1_792_000_000_000L),
        var delayTestResult: Long? = 42L,
        var trafficUp: Long = 1000L,
        var trafficDown: Long = 2000L,
        var conns: List<ConnectionInfo> = listOf(
            ConnectionInfo(
                id = "tcp:10.0.0.2:1234>93.184.216.34:443",
                network = "tcp", host = "example.com",
                destinationIp = "93.184.216.34", destinationPort = 443,
                sourceIp = "10.0.0.2", sourcePort = 1234,
                upload = 10L, download = 20L, startMs = 1_792_000_000_000L,
            ),
        ),
        var closedIds: MutableList<String> = mutableListOf(),
        var logLines: List<String> = listOf("[10:00:00.000] START ok"),
        var assets: Map<String, ByteArray> = mapOf(
            "index.html" to "<div id=\"app\" data-base-url=\"http://127.0.0.1:9090\"></div>".toByteArray(),
            "assets/app.js" to "console.log(1)".toByteArray(),
        ),
    ) : ClashApiDeps {
        override val versionName: String = "1.0.17"
        override fun secret(): String = secret
        override fun baseUrl(): String = "http://127.0.0.1:9091"
        override fun port(): Int = 9091
        override fun allowLan(): Boolean = false
        override fun mode(): String = modeValue
        override fun setMode(mode: String) { modeValue = mode }
        override fun groups(): List<ProxyGroup> = groups.toList()
        override fun rules(): List<RouteRule> = rules.toList()
        override fun profiles(): List<ProfileItem> = profiles
        override fun delays(): Map<String, Long?> = delays.toMap()
        override fun delayMeasuredAtMs(guid: String): Long? = measuredAt[guid]
        override fun selectProxy(groupName: String, proxyName: String): Boolean {
            val idx = groups.indexOfFirst { it.name == groupName }
            if (idx < 0) return false
            val g = groups[idx]
            if (g.type != ProxyGroupType.SELECT) return false
            val guid = profiles.firstOrNull { it.displayName() == proxyName }?.guid ?: return false
            if (guid !in g.members) return false
            groups[idx] = g.copy(selectedMemberGuid = guid)
            return true
        }
        override fun delayTest(guid: String, url: String, timeoutMs: Int): Long? =
            if (profiles.any { it.guid == guid }) delayTestResult else null
        override fun traffic(): Pair<Long, Long> = trafficUp to trafficDown
        override fun connections(): List<ConnectionInfo> = conns
        override fun closeConnection(id: String): Boolean {
            closedIds += id
            return conns.any { it.id == id }
        }
        override fun closeAllConnections() {
            conns.forEach { closedIds += it.id }
        }
        override fun logLines(): List<String> = logLines
        override fun assetBytes(path: String): ByteArray? = assets[path]
    }

    private fun defaultDeps(): FakeDeps {
        val deps = FakeDeps()
        deps.groups += ProxyGroup(
            id = "g-proxy", name = "taptap", type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
        )
        deps.groups += ProxyGroup(
            id = "g-test", name = "Cepat", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-a", "guid-b"),
        )
        deps.rules += RouteRule(
            id = "r1", type = RouteRuleType.DOMAIN_SUFFIX,
            pattern = "google.com", target = "g-proxy",
        )
        deps.rules += RouteRule(id = "r2", type = RouteRuleType.FINAL, target = "g-proxy")
        return deps
    }

    private fun get(deps: FakeDeps, path: String, headers: Map<String, String> = emptyMap()): ApiResponse {
        val (p, q) = path.split('?', limit = 2).let { it[0] to (it.getOrNull(1) ?: "") }
        return ClashApiHandler(deps).handle(
            ApiRequest("GET", p, ClashApiHandler.parseQuery(q), headers, ""),
        )
    }

    private fun bodyText(response: ApiResponse): String {
        val imm = response as ApiResponse.Immediate
        return imm.body.toString(Charsets.UTF_8)
    }

    private fun bodyJson(response: ApiResponse) =
        JsonParser.parseString(bodyText(response)).asJsonObject

    // ---- /version + /configs ----

    @Test
    fun versionReturnsVersionNameAndMeta() {
        val json = bodyJson(get(defaultDeps(), "/version"))
        assertEquals("1.0.17", json.get("version").asString)
        assertTrue(json.get("meta").asBoolean)
    }

    @Test
    fun configsGetReturnsModeAndPort() {
        val json = bodyJson(get(defaultDeps(), "/configs"))
        assertEquals("rule", json.get("mode").asString)
        assertEquals(9091, json.get("port").asInt)
        assertEquals("127.0.0.1:9091", json.get("external-controller").asString)
        assertFalse(json.has("secret") && json.get("secret").asString.isNotEmpty())
    }

    @Test
    fun configsPatchModePersistsAndRejectsUnknown() {
        val deps = defaultDeps()
        val handler = ClashApiHandler(deps)
        val ok = handler.handle(
            ApiRequest("PATCH", "/configs", emptyMap(), emptyMap(), "{\"mode\":\"global\"}"),
        ) as ApiResponse.Immediate
        assertEquals(204, ok.status)
        assertEquals("global", deps.modeValue)
        val bad = handler.handle(
            ApiRequest("PATCH", "/configs", emptyMap(), emptyMap(), "{\"mode\":\"nope\"}"),
        ) as ApiResponse.Immediate
        assertEquals(400, bad.status)
        assertEquals("global", deps.modeValue)
    }

    // ---- /proxies ----

    @Test
    fun proxiesListsGroupsAndIndividualsWithClashShape() {
        val json = bodyJson(get(defaultDeps(), "/proxies"))
        val proxies = json.getAsJsonObject("proxies")
        val proxy = proxies.getAsJsonObject("taptap")
        assertEquals("Selector", proxy.get("type").asString)
        assertEquals("Server A", proxy.get("now").asString)
        assertEquals(2, proxy.getAsJsonArray("all").size())
        assertEquals(1, proxy.getAsJsonArray("history").size())
        assertEquals(123L, proxy.getAsJsonArray("history")[0].asJsonObject.get("delay").asLong)
        val cepat = proxies.getAsJsonObject("Cepat")
        assertEquals("URLTest", cepat.get("type").asString)
        assertEquals("Server A", cepat.get("now").asString)
        val serverB = proxies.getAsJsonObject("Server B")
        assertEquals("vless", serverB.get("type").asString)
        assertEquals(0, serverB.getAsJsonArray("history").size())
        // v1.0.21: no "GLOBAL" pseudo-group — only real groups +
        // individual proxies (2 groups + 2 servers).
        assertFalse(proxies.has("GLOBAL"))
        assertEquals(4, proxies.size())
    }

    @Test
    fun proxiesSingleGroupReturnsItselfAndUnknownIs404() {
        val ok = get(defaultDeps(), "/proxies/taptap") as ApiResponse.Immediate
        assertEquals(200, ok.status)
        assertEquals("taptap", bodyJson(ok).get("name").asString)
        val missing = get(defaultDeps(), "/proxies/Nope") as ApiResponse.Immediate
        assertEquals(404, missing.status)
    }

    @Test
    fun putSelectChangesGroupAndRejectsUnknown() {
        val deps = defaultDeps()
        val handler = ClashApiHandler(deps)
        val ok = handler.handle(
            ApiRequest("PUT", "/proxies/taptap", emptyMap(), emptyMap(), "{\"name\":\"Server B\"}"),
        ) as ApiResponse.Immediate
        assertEquals(204, ok.status)
        assertEquals("guid-b", deps.groups.first { it.name == "taptap" }.selectedMemberGuid)
        // Path form (Clash) works too.
        val ok2 = handler.handle(
            ApiRequest("PUT", "/proxies/taptap/Server A", emptyMap(), emptyMap(), ""),
        ) as ApiResponse.Immediate
        assertEquals(204, ok2.status)
        assertEquals("guid-a", deps.groups.first { it.name == "taptap" }.selectedMemberGuid)
        val bad = handler.handle(
            ApiRequest("PUT", "/proxies/taptap", emptyMap(), emptyMap(), "{\"name\":\"Nope\"}"),
        ) as ApiResponse.Immediate
        assertEquals(404, bad.status)
    }

    @Test
    fun putGlobalAliasSelectsFallbackGroup() {
        // v1.0.21: "GLOBAL" is never listed, but PUT to it is accepted
        // as an alias for the fallback group (stale dashboard tab /
        // external client). The fixture group is named through
        // RouteEngine.FALLBACK_GROUP_NAME, so this follows its rename.
        val deps = FakeDeps()
        deps.groups += ProxyGroup(
            id = "g-fb", name = RouteEngine.FALLBACK_GROUP_NAME,
            type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
        )
        val handler = ClashApiHandler(deps)
        val ok = handler.handle(
            ApiRequest("PUT", "/proxies/GLOBAL", emptyMap(), emptyMap(), "{\"name\":\"Server B\"}"),
        ) as ApiResponse.Immediate
        assertEquals(204, ok.status)
        assertEquals(
            "guid-b",
            deps.groups.first { it.name == RouteEngine.FALLBACK_GROUP_NAME }.selectedMemberGuid,
        )
        // Path form (Clash) works too.
        val ok2 = handler.handle(
            ApiRequest("PUT", "/proxies/GLOBAL/Server A", emptyMap(), emptyMap(), ""),
        ) as ApiResponse.Immediate
        assertEquals(204, ok2.status)
        assertEquals(
            "guid-a",
            deps.groups.first { it.name == RouteEngine.FALLBACK_GROUP_NAME }.selectedMemberGuid,
        )
    }

    @Test
    fun putGlobalAliasIs404WithoutFallbackGroup() {
        // No fallback group at all -> the alias has nothing to select.
        val deps = FakeDeps()
        deps.groups += ProxyGroup(
            id = "g-test", name = "Cepat", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-a", "guid-b"),
        )
        val res = ClashApiHandler(deps).handle(
            ApiRequest("PUT", "/proxies/GLOBAL", emptyMap(), emptyMap(), "{\"name\":\"Server B\"}"),
        ) as ApiResponse.Immediate
        assertEquals(404, res.status)
    }

    @Test
    fun putGlobalSelectsRealGroupNamedGlobalOverAlias() {
        // A real SELECT group literally named "GLOBAL" wins over the alias.
        val deps = FakeDeps()
        deps.groups += ProxyGroup(
            id = "g-global", name = "GLOBAL", type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
        )
        deps.groups += ProxyGroup(
            id = "g-fb", name = RouteEngine.FALLBACK_GROUP_NAME,
            type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
        )
        val res = ClashApiHandler(deps).handle(
            ApiRequest("PUT", "/proxies/GLOBAL", emptyMap(), emptyMap(), "{\"name\":\"Server B\"}"),
        ) as ApiResponse.Immediate
        assertEquals(204, res.status)
        assertEquals("guid-b", deps.groups.first { it.name == "GLOBAL" }.selectedMemberGuid)
        assertEquals(
            "guid-a",
            deps.groups.first { it.name == RouteEngine.FALLBACK_GROUP_NAME }.selectedMemberGuid,
        )
    }

    @Test
    fun globalIsUnknownForReads() {
        // v1.0.21: GLOBAL is not a group anymore — reads answer 404
        // like any unknown name (only PUT keeps the alias).
        val getOne = get(defaultDeps(), "/proxies/GLOBAL") as ApiResponse.Immediate
        assertEquals(404, getOne.status)
        val delay = get(
            defaultDeps(), "/proxies/GLOBAL/delay?url=http://example.com",
        ) as ApiResponse.Immediate
        assertEquals(404, delay.status)
        val groupDelay = get(
            defaultDeps(), "/group/GLOBAL/delay?url=http://example.com",
        ) as ApiResponse.Immediate
        assertEquals(404, groupDelay.status)
    }

    @Test
    fun delayEndpointReturnsMeasuredDelayAnd504OnFailure() {
        val deps = defaultDeps()
        val ok = get(deps, "/proxies/Server%20A/delay?url=http://example.com&timeout=5000")
        assertEquals(42L, bodyJson(ok).get("delay").asLong)
        val group = get(deps, "/group/taptap/delay?url=http://example.com")
        assertEquals(42L, bodyJson(group).get("delay").asLong)
        deps.delayTestResult = null
        val fail = get(deps, "/proxies/Server%20A/delay") as ApiResponse.Immediate
        assertEquals(504, fail.status)
    }

    // ---- /rules ----

    @Test
    fun rulesUseClashTypeNamesAndGroupNames() {
        val arr = JsonParser.parseString(bodyText(get(defaultDeps(), "/rules"))).asJsonArray
        assertEquals(2, arr.size())
        val first = arr[0].asJsonObject
        assertEquals("DOMAIN-SUFFIX", first.get("type").asString)
        assertEquals("google.com", first.get("payload").asString)
        assertEquals("taptap", first.get("proxy").asString)
        val final = arr[1].asJsonObject
        assertEquals("FINAL", final.get("type").asString)
        assertEquals("taptap", final.get("proxy").asString)
    }

    // ---- /connections + streams ----

    @Test
    fun connectionsSnapshotHasClashShapeAndTunnelTotals() {
        val deps = defaultDeps()
        val handler = ClashApiHandler(deps)
        val json = JsonParser.parseString(handler.connectionsSnapshotJson()).asJsonObject
        assertEquals(1, json.get("total").asInt)
        assertEquals(1000L, json.get("uploadTotal").asLong)
        assertEquals(2000L, json.get("downloadTotal").asLong)
        val conn = json.getAsJsonArray("connections")[0].asJsonObject
        assertEquals("93.184.216.34", conn.getAsJsonObject("metadata").get("destinationIP").asString)
        assertEquals(443, conn.getAsJsonObject("metadata").get("destinationPort").asInt)
        assertEquals(20L, conn.get("download").asLong)
    }

    @Test
    fun deleteConnectionClosesItAndDeleteAllClosesAll() {
        val deps = defaultDeps()
        val handler = ClashApiHandler(deps)
        val one = handler.handle(
            ApiRequest(
                "DELETE", "/connections/tcp:10.0.0.2:1234>93.184.216.34:443",
                emptyMap(), emptyMap(), "",
            ),
        ) as ApiResponse.Immediate
        assertEquals(204, one.status)
        assertEquals(
            listOf("tcp:10.0.0.2:1234>93.184.216.34:443"),
            deps.closedIds,
        )
        val all = handler.handle(
            ApiRequest("DELETE", "/connections", emptyMap(), emptyMap(), ""),
        ) as ApiResponse.Immediate
        assertEquals(204, all.status)
    }

    @Test
    fun trafficAndLogsStreamsProduceJsonLines() {
        val deps = defaultDeps()
        val handler = ClashApiHandler(deps)
        val traffic = get(deps, "/traffic")
        assertTrue(traffic is ApiResponse.Stream)
        val trafficJson = JsonParser.parseString(
            (traffic as ApiResponse.Stream).produce()!!,
        ).asJsonObject
        assertEquals(1000L, trafficJson.get("up").asLong)
        assertEquals(2000L, trafficJson.get("down").asLong)
        val logs = get(deps, "/logs") as ApiResponse.Stream
        val first = JsonParser.parseString(logs.produce()!!).asJsonObject
        assertEquals("info", first.get("type").asString)
        assertTrue(first.get("payload").asString.contains("START ok"))
        // No new lines -> null (stream stays open, server retries).
        assertEquals(null, logs.produce())
    }

    // ---- UI ----

    @Test
    fun rootRedirectsToProxiesAndIndexRewritesBaseUrl() {
        val deps = defaultDeps()
        val root = get(deps, "/") as ApiResponse.Immediate
        assertEquals(302, root.status)
        assertEquals("/ui/#/proxies", root.extraHeaders["Location"])
        val index = get(deps, "/ui/") as ApiResponse.Immediate
        assertEquals(200, index.status)
        assertTrue(bodyText(index).contains("data-base-url=\"http://127.0.0.1:9091\""))
        assertFalse(bodyText(index).contains("127.0.0.1:9090"))
        val js = get(deps, "/ui/assets/app.js") as ApiResponse.Immediate
        assertEquals("text/javascript; charset=utf-8", js.contentType)
    }

    @Test
    fun rewriteBaseUrlReplacesOnlyTheBakedAttribute() {
        val html = "<div data-base-url=\"http://127.0.0.1:9090\"></div>" +
            "<script src=\"./assets/index.js\"></script>"
        val out = ClashApiHandler.rewriteBaseUrl(html, "http://127.0.0.1:9091")
        assertTrue(out.contains("data-base-url=\"http://127.0.0.1:9091\""))
        assertTrue(out.contains("src=\"./assets/index.js\""))
    }

    // ---- Auth + CORS + WebSocket ----

    @Test
    fun bearerAuthRequiredWhenSecretSetAndFreeWhenEmpty() {
        val deps = defaultDeps().apply { secret = "s3cret" }
        val noAuth = get(deps, "/proxies") as ApiResponse.Immediate
        assertEquals(401, noAuth.status)
        val wrong = get(
            deps, "/proxies",
            mapOf("authorization" to "Bearer salah"),
        ) as ApiResponse.Immediate
        assertEquals(401, wrong.status)
        val ok = get(
            deps, "/proxies",
            mapOf("authorization" to "Bearer s3cret"),
        ) as ApiResponse.Immediate
        assertEquals(200, ok.status)
        // Static UI stays open without auth (mihomo external-ui behaviour).
        val ui = get(deps, "/ui/") as ApiResponse.Immediate
        assertEquals(200, ui.status)
    }

    @Test
    fun optionsPreflightAnswersCorsWithoutAuth() {
        val deps = defaultDeps().apply { secret = "s3cret" }
        val res = ClashApiHandler(deps).handle(
            ApiRequest("OPTIONS", "/proxies", emptyMap(), emptyMap(), ""),
        ) as ApiResponse.Immediate
        assertEquals(204, res.status)
        // /version without auth is 401 when a secret is set...
        val noAuth = get(deps, "/version") as ApiResponse.Immediate
        assertEquals(401, noAuth.status)
        // ...and 200 with the Bearer token.
        val ok = get(
            deps, "/version",
            mapOf("authorization" to "Bearer s3cret"),
        ) as ApiResponse.Immediate
        assertEquals(200, ok.status)
        // CORS headers are added by the server layer, not the handler —
        // the handler contract is status + body; see ClashApiServer.
    }

    @Test
    fun websocketAcceptKeyMatchesRfc6455Example() {
        // RFC 6455 section 1.3 example.
        assertEquals(
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            ClashApiHandler.websocketAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="),
        )
    }

    @Test
    fun unknownPathIs404() {
        val res = get(defaultDeps(), "/nope") as ApiResponse.Immediate
        assertEquals(404, res.status)
    }

    @Test
    fun clashApiModeKeyAndDefaultAreStable() {
        assertEquals("clash_mode", SettingsStore.KEY_CLASH_MODE)
        assertEquals("rule", SettingsStore.DEFAULT_CLASH_MODE)
    }

    @Test
    fun routeEngineModeConstantsAreStable() {
        assertEquals("rule", RouteEngine.MODE_RULE)
        assertEquals("global", RouteEngine.MODE_GLOBAL)
        assertEquals("direct", RouteEngine.MODE_DIRECT)
    }
}
