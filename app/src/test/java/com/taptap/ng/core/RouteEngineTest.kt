package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

/**
 * Route engine tests (M7, W2): rule order, group member selection
 * by type, empty-group fall-through, and the no-rule fallback.
 */
class RouteEngineTest {

    private fun addr(text: String): InetAddress = InetAddress.getByName(text)

    private fun group(
        id: String,
        name: String = "g-$id",
        type: ProxyGroupType = ProxyGroupType.SELECT,
        members: List<String> = listOf("a", "b"),
        selected: String? = null,
    ) = ProxyGroup(
        id = id,
        name = name,
        type = type,
        members = members,
        selectedMemberGuid = selected,
    )

    private fun rule(
        type: RouteRuleType,
        pattern: String = "",
        target: String,
    ) = RouteRule(type = type, pattern = pattern, target = target)

    private fun proxyGuid(decision: RouteDecision): String {
        assertTrue(decision is RouteDecision.Proxy, "expected Proxy, got $decision")
        return (decision as RouteDecision.Proxy).profileGuid
    }

    @Test
    fun selectGroupUsesSelectedMember() {
        val groups = listOf(group("g1", selected = "b"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        assertEquals("b", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun selectGroupFallsBackToFirstMemberWhenSelectionLeft() {
        val groups = listOf(group("g1", selected = "gone"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun urlTestGroupPicksLowestKnownDelay() {
        val groups = listOf(group("g1", type = ProxyGroupType.URL_TEST))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val delays = mapOf<String, Long?>("a" to 300L, "b" to 120L)
        assertEquals("b", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)))
    }

    @Test
    fun urlTestGroupTreatsUnknownDelayAsInfinite() {
        val groups = listOf(group("g1", type = ProxyGroupType.URL_TEST))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        // "a" has a known slow delay, "b" is unknown: "a" still wins.
        val delays = mapOf<String, Long?>("a" to 9000L, "b" to null)
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)))
    }

    @Test
    fun urlTestGroupWithAllUnknownPicksFirstMember() {
        val groups = listOf(group("g1", type = ProxyGroupType.URL_TEST))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val delays = mapOf<String, Long?>("a" to null, "b" to null)
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)))
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun urlTestGroupTieKeepsMemberOrder() {
        val groups = listOf(group("g1", type = ProxyGroupType.URL_TEST))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val delays = mapOf<String, Long?>("a" to 100L, "b" to 100L)
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)))
    }

    @Test
    fun fallbackGroupPicksFirstKnownDelay() {
        val groups = listOf(group("g1", type = ProxyGroupType.FALLBACK))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val delays = mapOf<String, Long?>("a" to null, "b" to 500L)
        assertEquals("b", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)))
    }

    @Test
    fun fallbackGroupWithNoKnownDelayPicksFirstMember() {
        val groups = listOf(group("g1", type = ProxyGroupType.FALLBACK))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun emptyGroupFallsThroughToNextRule() {
        val empty = group("empty", members = emptyList())
        val direct = rule(RouteRuleType.FINAL, target = RouteRule.TARGET_DIRECT)
        val groups = listOf(empty)
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "example.com", target = "empty"),
            direct,
        )
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap()),
        )
    }

    @Test
    fun unknownGroupTargetFallsThroughToNextRule() {
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "example.com", target = "no-such-group"),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun directRuleReturnsDirect() {
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN_SUFFIX, pattern = "internal.local", target = RouteRule.TARGET_DIRECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("host.internal.local", addr("10.0.0.5"), 443, groups, rules, emptyMap()),
        )
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun rejectRuleReturnsReject() {
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN_KEYWORD, pattern = "ads", target = RouteRule.TARGET_REJECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        assertEquals(
            RouteDecision.Reject,
            RouteEngine.resolve("ads-tracker.example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap()),
        )
    }

    @Test
    fun rulesAreEvaluatedTopDownFirstMatchWins() {
        val groups = listOf(group("g1", selected = "a"), group("g2", selected = "b"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN_SUFFIX, pattern = "example.com", target = "g1"),
            rule(RouteRuleType.DOMAIN, pattern = "example.com", target = "g2"),
            rule(RouteRuleType.FINAL, target = "g2"),
        )
        // Both suffix and exact match; the suffix rule is first.
        assertEquals("a", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun ipOnlyConnectionMatchesCidrRuleAndSkipsDomainRules() {
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "example.com", target = RouteRule.TARGET_REJECT),
            rule(RouteRuleType.IP_CIDR, pattern = "192.168.0.0/16", target = RouteRule.TARGET_DIRECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve(null, addr("192.168.1.10"), 443, groups, rules, emptyMap()),
        )
        // A public IP with no domain falls through to FINAL.
        assertEquals("a", proxyGuid(RouteEngine.resolve(null, addr("8.8.8.8"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun noMatchingRuleFallsBackToProxyGroup() {
        val proxy = group("g-proxy", name = "Proxy", selected = "b")
        val groups = listOf(proxy)
        // No FINAL rule and no matching rule at all.
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "other.com", target = RouteRule.TARGET_DIRECT),
        )
        assertEquals("b", proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())))
    }

    @Test
    fun noMatchingRuleWithoutProxyGroupReturnsDirect() {
        val other = group("g1", name = "Other", selected = "a")
        val groups = listOf(other)
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "other.com", target = RouteRule.TARGET_DIRECT),
        )
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap()),
        )
    }

    @Test
    fun noMatchingRuleWithEmptyProxyGroupReturnsDirect() {
        val proxy = group("g-proxy", name = "Proxy", members = emptyList())
        val groups = listOf(proxy)
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "other.com", target = RouteRule.TARGET_DIRECT),
        )
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap()),
        )
    }

    @Test
    fun finalRuleToDirectReturnsDirect() {
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = RouteRule.TARGET_DIRECT))
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap()),
        )
    }

    @Test
    fun emptyRulesListFallsBackToProxyGroup() {
        val proxy = group("g-proxy", name = "Proxy", selected = "a")
        assertEquals(
            "a",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, listOf(proxy), emptyList(), emptyMap())),
        )
    }
}
