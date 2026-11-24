package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

/**
 * Route record tests (v1.0.29): [RouteEngine.resolveDetailed]
 * returns the same decision as [RouteEngine.resolve] plus the
 * rule that matched and the proxy chain it resolves to — the
 * record the forwarder stores per session for GET /connections.
 * Every case below pins the exact values the API forwards to
 * yacd (rule / rulePayload / chains).
 */
class RouteRecordTest {

    private fun addr(text: String): InetAddress = InetAddress.getByName(text)

    private fun group(
        id: String,
        name: String = "g-$id",
        type: ProxyGroupType = ProxyGroupType.SELECT,
        members: List<String> = listOf("guid-81", "guid-iflix"),
        selected: String? = null,
        nested: List<String>? = null,
    ) = ProxyGroup(
        id = id,
        name = name,
        type = type,
        members = members,
        selectedMemberGuid = selected,
        groupMembers = nested,
    )

    private fun rule(
        type: RouteRuleType,
        pattern: String = "",
        target: String,
    ) = RouteRule(type = type, pattern = pattern, target = target)

    private val names = mapOf("guid-81" to "81", "guid-iflix" to "iflix cloudfront")

    @Test
    fun finalToDirectServerRecordsServerOnlyChain() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap(),
            serverNames = names,
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals("FINAL", r.record.rule)
        assertEquals("", r.record.rulePayload)
        assertEquals(listOf("81"), r.record.chains)
    }

    @Test
    fun domainSuffixRuleRecordsTypeAndPattern() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN_SUFFIX, pattern = "example.com", target = "g1"),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val r = RouteEngine.resolveDetailed(
            "www.example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap(),
            serverNames = names,
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals("DOMAIN-SUFFIX", r.record.rule)
        assertEquals("example.com", r.record.rulePayload)
        assertEquals(listOf("81"), r.record.chains)
    }

    @Test
    fun directRuleRecordsDirectChain() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.IP_CIDR, pattern = "192.168.0.0/16", target = RouteRule.TARGET_DIRECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val r = RouteEngine.resolveDetailed(
            null, addr("192.168.1.5"), 443, groups, rules, emptyMap(),
            serverNames = names,
        )
        assertEquals(RouteDecision.Direct, r.decision)
        assertEquals("IP-CIDR", r.record.rule)
        assertEquals("192.168.0.0/16", r.record.rulePayload)
        assertEquals(listOf("DIRECT"), r.record.chains)
    }

    @Test
    fun rejectRuleRecordsRejectChain() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.DOMAIN, pattern = "blocked.example", target = RouteRule.TARGET_REJECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val r = RouteEngine.resolveDetailed(
            "blocked.example", addr("1.2.3.4"), 443, groups, rules, emptyMap(),
            serverNames = names,
        )
        assertEquals(RouteDecision.Reject, r.decision)
        assertEquals("DOMAIN", r.record.rule)
        assertEquals("blocked.example", r.record.rulePayload)
        assertEquals(listOf("REJECT"), r.record.chains)
    }

    @Test
    fun nestedSelectionRecordsFullGroupChain() {
        val main = group(
            "main", name = "taptap",
            members = emptyList(), selected = "tes",
            nested = listOf("tes"),
        )
        val nested = group(
            "tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-81"),
        )
        val groups = listOf(main, nested)
        val rules = listOf(rule(RouteRuleType.FINAL, target = "main"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, rules,
            mapOf<String, Long?>("guid-81" to 312L),
            serverNames = names,
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals("FINAL", r.record.rule)
        assertEquals("", r.record.rulePayload)
        // v1.0.30: mihomo order — leaf (server) first.
        assertEquals(listOf("81", "tes", "taptap"), r.record.chains)
    }

    @Test
    fun noFinalFallsBackToMainGroupWithFinalRecord() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, emptyList(), emptyMap(),
            serverNames = names,
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals("FINAL", r.record.rule)
        assertEquals("", r.record.rulePayload)
        assertEquals(listOf("81"), r.record.chains)
    }

    @Test
    fun noRuleNoGroupFallsBackToDirectRecord() {
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443,
            emptyList(), emptyList(), emptyMap(),
        )
        assertEquals(RouteDecision.Direct, r.decision)
        assertEquals("FINAL", r.record.rule)
        assertEquals("", r.record.rulePayload)
        assertEquals(listOf("DIRECT"), r.record.chains)
    }

    @Test
    fun globalModeRecordsGlobalRule() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, emptyList(), emptyMap(),
            mode = RouteEngine.MODE_GLOBAL, serverNames = names,
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals("GLOBAL", r.record.rule)
        assertEquals("", r.record.rulePayload)
        assertEquals(listOf("81"), r.record.chains)
    }

    @Test
    fun directModeRecordsDirectRule() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, emptyList(), emptyMap(),
            mode = RouteEngine.MODE_DIRECT, serverNames = names,
        )
        assertEquals(RouteDecision.Direct, r.decision)
        assertEquals("DIRECT", r.record.rule)
        assertEquals("", r.record.rulePayload)
        assertEquals(listOf("DIRECT"), r.record.chains)
    }

    @Test
    fun unknownServerNameFallsBackToGuid() {
        val groups = listOf(group("g1", name = "taptap", selected = "guid-81"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val r = RouteEngine.resolveDetailed(
            "example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap(),
        )
        assertEquals(RouteDecision.Proxy("guid-81"), r.decision)
        assertEquals(listOf("guid-81"), r.record.chains)
    }

    @Test
    fun resolveAndResolveDetailedAgree() {
        val main = group(
            "main", name = "taptap",
            members = emptyList(), selected = "tes",
            nested = listOf("tes"),
        )
        val nested = group(
            "tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-81"),
        )
        val groups = listOf(main, nested)
        val rules = listOf(rule(RouteRuleType.FINAL, target = "main"))
        val delays = mapOf<String, Long?>("guid-81" to 312L)
        assertEquals(
            RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays),
            RouteEngine.resolveDetailed(
                "example.com", addr("1.2.3.4"), 443, groups, rules, delays,
                serverNames = names,
            ).decision,
        )
        assertTrue(
            RouteEngine.resolveChainNames(main, groups, delays, names) ==
                listOf("81", "tes", "taptap"),
        )
    }

    @Test
    fun chainNamesDirectCallIsLeafFirstForNested() {
        // v1.0.30: resolveChainNames on its own (not only via
        // resolveDetailed) returns the mihomo order — server
        // first, outermost group last — for a 3-deep nesting,
        // and just the server for a direct member.
        val main = group(
            "main", name = "taptap",
            members = emptyList(), selected = "tes",
            nested = listOf("tes"),
        )
        val nested = group(
            "tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("guid-81"),
        )
        val groups = listOf(main, nested)
        val delays = mapOf<String, Long?>("guid-81" to 312L)
        assertEquals(
            listOf("81", "tes", "taptap"),
            RouteEngine.resolveChainNames(main, groups, delays, names),
        )
        assertEquals(
            listOf("81"),
            RouteEngine.resolveChainNames(
                group("g1", name = "taptap", selected = "guid-81"),
                listOf(group("g1", name = "taptap", selected = "guid-81")),
                emptyMap(), names,
            ),
        )
    }
}
