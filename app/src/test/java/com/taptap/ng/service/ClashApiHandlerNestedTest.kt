package com.taptap.ng.service

import com.google.gson.JsonParser
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.27: nested groups on the Clash API — GET /proxies lists a
 * nested group inside its parent (so yacd renders it as a node in
 * the parent card, with the nested group's delay), and PUT
 * /proxies/{parent} can select the nested group node. These tests
 * fail on v1.0.26: `all` only ever lists server names, so yacd
 * has no nested node to render, and selecting a group name
 * answers 404 because it is not a server guid.
 *
 * The fake deps mirror the production [LiveClashApiDeps] select
 * path by calling the same shared rule
 * ([ClashApiHandler.selectMemberRef]), so the selection behaviour
 * tested here is the behaviour the phone runs.
 */
class ClashApiHandlerNestedTest {

    private class FakeDeps(
        var groups: MutableList<ProxyGroup> = mutableListOf(),
        var profiles: List<ProfileItem> = listOf(
            ProfileItem(guid = "guid-a", remarks = "Server A", configType = ConfigType.VMESS),
            ProfileItem(guid = "guid-b", remarks = "Server B", configType = ConfigType.VLESS),
        ),
        var delays: MutableMap<String, Long?> = mutableMapOf("guid-a" to 123L, "guid-b" to 456L),
        var measuredAt: MutableMap<String, Long> = mutableMapOf("guid-a" to 1_792_000_000_000L),
        var delayTestResult: Long? = 42L,
        var lastDelayTestGuid: String? = null,
    ) : ClashApiDeps {
        override val versionName: String = "1.0.27"
        override fun secret(): String = ""
        override fun baseUrl(): String = "http://127.0.0.1:9091"
        override fun port(): Int = 9091
        override fun allowLan(): Boolean = false
        override fun mode(): String = "rule"
        override fun setMode(mode: String) {}
        override fun groups(): List<ProxyGroup> = groups.toList()
        override fun mainGroup(): ProxyGroup? =
            groups.firstOrNull { it.name == "taptap" }
        override fun rules(): List<RouteRule> = listOf(
            RouteRule(type = RouteRuleType.FINAL, target = "g-main"),
        )
        override fun profiles(): List<ProfileItem> = profiles
        override fun delays(): Map<String, Long?> = delays.toMap()
        override fun delayMeasuredAtMs(guid: String): Long? = measuredAt[guid]
        override fun selectProxy(groupName: String, proxyName: String): Boolean {
            val idx = groups.indexOfFirst { it.name == groupName }
            if (idx < 0) return false
            val names = ClashApiHandler(this).displayNames()
            val ref = ClashApiHandler.selectMemberRef(groups, names, groupName, proxyName)
                ?: return false
            groups[idx] = groups[idx].copy(selectedMemberGuid = ref)
            return true
        }
        override fun delayTest(guid: String, url: String, timeoutMs: Int): Long? {
            lastDelayTestGuid = guid
            return if (profiles.any { it.guid == guid }) delayTestResult else null
        }
        override fun traffic(): Pair<Long, Long> = 0L to 0L
        override fun connections(): List<ConnectionInfo> = emptyList()
        override fun closeConnection(id: String): Boolean = false
        override fun closeAllConnections() {}
        override fun logLines(): List<String> = emptyList()
        override fun logLinesSince(fromSeq: Long): Pair<Long, List<String>> = 0L to emptyList()
        override fun assetBytes(path: String): ByteArray? = null
    }

    private fun defaultDeps(): FakeDeps {
        val deps = FakeDeps()
        deps.groups += ProxyGroup(
            id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
            groupMembers = listOf("g-tes"),
        )
        deps.groups += ProxyGroup(
            id = "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-a", "guid-b"),
        )
        deps.groups += ProxyGroup(
            id = "g-lain", name = "lain", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-b"),
        )
        return deps
    }

    private fun get(deps: FakeDeps, path: String): ApiResponse {
        val (p, q) = path.split('?', limit = 2).let { it[0] to (it.getOrNull(1) ?: "") }
        return ClashApiHandler(deps).handle(
            ApiRequest("GET", p, ClashApiHandler.parseQuery(q), emptyMap(), ""),
        )
    }

    private fun put(deps: FakeDeps, path: String, body: String): ApiResponse {
        return ClashApiHandler(deps).handle(
            ApiRequest("PUT", path, emptyMap(), emptyMap(), body),
        )
    }

    private fun bodyJson(response: ApiResponse) =
        JsonParser.parseString((response as ApiResponse.Immediate).body.toString(Charsets.UTF_8)).asJsonObject

    private fun proxies(deps: FakeDeps) =
        bodyJson(get(deps, "/proxies")).getAsJsonObject("proxies")

    @Test
    fun `proxies lists the nested group inside taptap with its delay`() {
        val json = proxies(defaultDeps())
        // The nested group is still its own top-level entry…
        assertTrue(json.has("tes"))
        assertTrue(json.has("lain"))
        val tes = json.getAsJsonObject("tes")
        assertEquals("URLTest", tes.get("type").asString)
        // …its `now` is its best member, with that member's delay…
        assertEquals("Server A", tes.get("now").asString)
        assertEquals(123L, tes.getAsJsonArray("history")[0].asJsonObject.get("delay").asLong)
        // …and "taptap" lists it in `all` after its servers.
        val taptap = json.getAsJsonObject("taptap")
        val all = taptap.getAsJsonArray("all").map { it.asString }
        assertEquals(listOf("Server A", "Server B", "tes"), all)
        assertEquals("Server A", taptap.get("now").asString)
        // A group that is NOT nested in taptap is not in its `all`.
        assertFalse("lain" in all)
    }

    @Test
    fun `proxies shows the nested group name as now when it is selected`() {
        val deps = defaultDeps()
        deps.groups[0] = deps.groups[0].copy(selectedMemberGuid = "g-tes")
        val taptap = proxies(deps).getAsJsonObject("taptap")
        assertEquals("tes", taptap.get("now").asString)
        // …and the history still carries the delay traffic would use.
        assertEquals(123L, taptap.getAsJsonArray("history")[0].asJsonObject.get("delay").asLong)
    }

    @Test
    fun `put proxies selects the nested group node`() {
        val deps = defaultDeps()
        val put = put(deps, "/proxies/taptap", "{\"name\":\"tes\"}")
        assertEquals(204, (put as ApiResponse.Immediate).status)
        assertEquals("g-tes", deps.groups[0].selectedMemberGuid)
        assertEquals("tes", proxies(deps).getAsJsonObject("taptap").get("now").asString)
    }

    @Test
    fun `put proxies still selects a plain server`() {
        val deps = defaultDeps()
        val put = put(deps, "/proxies/taptap", "{\"name\":\"Server B\"}")
        assertEquals(204, (put as ApiResponse.Immediate).status)
        assertEquals("guid-b", deps.groups[0].selectedMemberGuid)
    }

    @Test
    fun `put proxies rejects a group that is not nested in the parent`() {
        val deps = defaultDeps()
        val put = put(deps, "/proxies/taptap", "{\"name\":\"lain\"}")
        assertEquals(404, (put as ApiResponse.Immediate).status)
        assertEquals("guid-a", deps.groups[0].selectedMemberGuid)
    }

    @Test
    fun `put proxies rejects an unknown name`() {
        val deps = defaultDeps()
        val put = put(deps, "/proxies/taptap", "{\"name\":\"tidak ada\"}")
        assertEquals(404, (put as ApiResponse.Immediate).status)
    }

    @Test
    fun `proxies group delay resolves through the nested group`() {
        val deps = defaultDeps()
        val json = bodyJson(get(deps, "/proxies/tes/delay?timeout=5000"))
        assertEquals(42L, json.get("delay").asLong)
        // The test ran against the nested group's best member.
        assertEquals("guid-a", deps.lastDelayTestGuid)
    }

    @Test
    fun `selectMemberRef rejects a non-select group and an unknown group`() {
        val deps = defaultDeps()
        val names = mapOf("guid-a" to "Server A", "guid-b" to "Server B")
        assertNull(ClashApiHandler.selectMemberRef(deps.groups, names, "tes", "Server A"))
        assertNull(ClashApiHandler.selectMemberRef(deps.groups, names, "tidak ada", "tes"))
        assertNull(ClashApiHandler.selectMemberRef(deps.groups, names, "taptap", "tidak ada"))
        assertEquals(
            "g-tes",
            ClashApiHandler.selectMemberRef(deps.groups, names, "taptap", "tes"),
        )
    }
}
