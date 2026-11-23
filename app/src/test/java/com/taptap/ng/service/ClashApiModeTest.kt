package com.taptap.ng.service

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

/**
 * Clash routing mode tests (M7, W3): "rule" (default) runs the
 * rule loop, "global" always uses the "taptap" group (or the first
 * group), "direct" always dials direct. Pure [RouteEngine] logic —
 * the same function the forwarder's resolver and the API share.
 */
class ClashApiModeTest {

    private val ip: InetAddress = InetAddress.getByName("93.184.216.34")

    private fun groups() = listOf(
        ProxyGroup(
            id = "g-proxy", name = RouteEngine.FALLBACK_GROUP_NAME, type = ProxyGroupType.SELECT,
            members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-b",
        ),
        ProxyGroup(
            id = "g-test", name = "Cepat", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-a", "guid-b"),
        ),
    )

    private fun rules() = listOf(
        RouteRule(id = "r1", type = RouteRuleType.DOMAIN_SUFFIX, pattern = "google.com", target = "g-proxy"),
        RouteRule(id = "r2", type = RouteRuleType.FINAL, target = RouteRule.TARGET_DIRECT),
    )

    @Test
    fun ruleModeFollowsRulesAndFinalDirect() {
        val decision = RouteEngine.resolve(
            "www.google.com", ip, 443, groups(), rules(), emptyMap(),
            mode = RouteEngine.MODE_RULE,
        )
        assertEquals(RouteDecision.Proxy("guid-b"), decision)
        val other = RouteEngine.resolve(
            "example.com", ip, 443, groups(), rules(), emptyMap(),
            mode = RouteEngine.MODE_RULE,
        )
        assertEquals(RouteDecision.Direct, other)
    }

    @Test
    fun ruleModeIsTheDefaultWhenModeIsMissingOrUnknown() {
        val decision = RouteEngine.resolve("www.google.com", ip, 443, groups(), rules(), emptyMap())
        assertEquals(RouteDecision.Proxy("guid-b"), decision)
        val unknown = RouteEngine.resolve(
            "www.google.com", ip, 443, groups(), rules(), emptyMap(), mode = "nope",
        )
        assertEquals(RouteDecision.Proxy("guid-b"), unknown)
    }

    @Test
    fun globalModeAlwaysUsesDefaultGroupIgnoringRules() {
        // Even a host whose rule says DIRECT goes through the taptap group.
        val decision = RouteEngine.resolve(
            "example.com", ip, 443, groups(), rules(), emptyMap(),
            mode = RouteEngine.MODE_GLOBAL,
        )
        assertEquals(RouteDecision.Proxy("guid-b"), decision)
    }

    @Test
    fun globalModeFallsBackToFirstGroupWhenNoDefaultGroup() {
        val onlyTest = listOf(
            ProxyGroup(
                id = "g-test", name = "Cepat", type = ProxyGroupType.URL_TEST,
                members = listOf("guid-a", "guid-b"),
            ),
        )
        val delays = mapOf<String, Long?>("guid-a" to 300L, "guid-b" to 100L)
        val decision = RouteEngine.resolve(
            "example.com", ip, 443, onlyTest, rules(), delays,
            mode = RouteEngine.MODE_GLOBAL,
        )
        assertEquals(RouteDecision.Proxy("guid-b"), decision)
    }

    @Test
    fun globalModeGoesDirectWhenNoGroupHasAMember() {
        val empty = listOf(
            ProxyGroup(id = "g-proxy", name = RouteEngine.FALLBACK_GROUP_NAME, type = ProxyGroupType.SELECT, members = emptyList()),
        )
        val decision = RouteEngine.resolve(
            "example.com", ip, 443, empty, rules(), emptyMap(),
            mode = RouteEngine.MODE_GLOBAL,
        )
        assertEquals(RouteDecision.Direct, decision)
    }

    @Test
    fun directModeAlwaysGoesDirect() {
        val decision = RouteEngine.resolve(
            "www.google.com", ip, 443, groups(), rules(), emptyMap(),
            mode = RouteEngine.MODE_DIRECT,
        )
        assertEquals(RouteDecision.Direct, decision)
    }

    @Test
    fun corsHeadersAllowAnyOriginWithClashMethods() {
        val headers = ClashApiServer.corsHeaders()
        assertEquals("*", headers["Access-Control-Allow-Origin"])
        assertTrue(headers["Access-Control-Allow-Methods"]!!.contains("PUT"))
        assertTrue(headers["Access-Control-Allow-Methods"]!!.contains("PATCH"))
        assertTrue(headers["Access-Control-Allow-Methods"]!!.contains("DELETE"))
        assertTrue(headers["Access-Control-Allow-Headers"]!!.contains("Authorization"))
    }
}
