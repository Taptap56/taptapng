package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

/**
 * v1.0.27: nested groups — the main group also holds the other
 * groups as members, so a url-test group can be selected inside
 * "taptap" on the dashboard and traffic routes through its best
 * member. These tests fail on v1.0.26: members can only name
 * server guids, so a selection naming a group id resolves to
 * nothing (or to the wrong first server) and a cycle would loop
 * forever instead of falling through.
 */
class RouteEngineNestedTest {

    private fun addr(text: String): InetAddress = InetAddress.getByName(text)

    private fun group(
        id: String,
        name: String = "g-$id",
        type: ProxyGroupType = ProxyGroupType.SELECT,
        members: List<String> = listOf("a", "b"),
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

    private fun rule(type: RouteRuleType, target: String) =
        RouteRule(type = type, target = target)

    private fun proxyGuid(decision: RouteDecision): String {
        assertTrue(decision is RouteDecision.Proxy, "expected Proxy, got $decision")
        return (decision as RouteDecision.Proxy).profileGuid
    }

    private fun resolve(groups: List<ProxyGroup>, delays: Map<String, Long?>): RouteDecision {
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g-main"))
        return RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, delays)
    }

    @Test
    fun `selecting a nested group resolves to its selected server`() {
        val tes = group("g-tes", name = "tes", members = listOf("a", "b"), selected = "b")
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        assertEquals("b", proxyGuid(resolve(listOf(main, tes), emptyMap())))
    }

    @Test
    fun `nested url-test group resolves to its lowest delay member`() {
        val tes = group(
            "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("a", "b"),
        )
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        val delays = mapOf<String, Long?>("a" to 300L, "b" to 120L)
        assertEquals("b", proxyGuid(resolve(listOf(main, tes), delays)))
    }

    @Test
    fun `plain select group without nesting behaves as before`() {
        val main = group("g-main", name = "taptap", selected = "b")
        assertEquals("b", proxyGuid(resolve(listOf(main), emptyMap())))
        assertEquals("b", RouteEngine.selectMemberRef(main, listOf(main), emptyMap()))
    }

    @Test
    fun `cycle between two groups falls through instead of hanging`() {
        val tes = group(
            "g-tes", name = "tes", members = listOf("a", "b"),
            selected = "g-main", nested = listOf("g-main"),
        )
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        // Both selections chase each other: resolution returns
        // null, the FINAL rule falls through, and the no-rule
        // fallback (the same main group) also resolves to null —
        // so traffic fails open to Direct, never loops.
        assertEquals(RouteDecision.Direct, resolve(listOf(main, tes), emptyMap()))
    }

    @Test
    fun `self nesting falls through instead of hanging`() {
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-main", nested = listOf("g-main"),
        )
        assertEquals(RouteDecision.Direct, resolve(listOf(main), emptyMap()))
        assertNull(RouteEngine.resolveToServer(main, listOf(main), emptyMap()))
    }

    @Test
    fun `groupDelay of a nested group is its best member delay`() {
        val tes = group(
            "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("a", "b"),
        )
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        val groups = listOf(main, tes)
        val delays = mapOf<String, Long?>("a" to 300L, "b" to 120L)
        assertEquals(120L, RouteEngine.groupDelay(tes, groups, delays))
        assertEquals(120L, RouteEngine.groupDelay(main, groups, delays))
        assertNull(RouteEngine.groupDelay(tes, groups, emptyMap()))
    }

    @Test
    fun `url-test parent picks the nested group when it is faster than its own servers`() {
        val tes = group(
            "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("b"),
        )
        val main = group(
            "g-main", name = "taptap", type = ProxyGroupType.URL_TEST,
            members = listOf("a"), nested = listOf("g-tes"),
        )
        val delays = mapOf<String, Long?>("a" to 500L, "b" to 120L)
        assertEquals("b", proxyGuid(resolve(listOf(main, tes), delays)))
        assertEquals("g-tes", RouteEngine.selectMemberRef(main, listOf(main, tes), delays))
    }

    @Test
    fun `url-test parent keeps its own server when it is faster than the nested group`() {
        val tes = group(
            "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf("b"),
        )
        val main = group(
            "g-main", name = "taptap", type = ProxyGroupType.URL_TEST,
            members = listOf("a"), nested = listOf("g-tes"),
        )
        val delays = mapOf<String, Long?>("a" to 100L, "b" to 400L)
        assertEquals("a", proxyGuid(resolve(listOf(main, tes), delays)))
    }

    @Test
    fun `nested group with no usable member falls through`() {
        val tes = group("g-tes", name = "tes", members = emptyList())
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        assertEquals(RouteDecision.Direct, resolve(listOf(main, tes), emptyMap()))
    }

    @Test
    fun `selectMemberRef returns the nested group id for a select group`() {
        val main = group(
            "g-main", name = "taptap", members = listOf("a", "b"),
            selected = "g-tes", nested = listOf("g-tes"),
        )
        assertEquals(
            "g-tes",
            RouteEngine.selectMemberRef(main, listOf(main), emptyMap()),
        )
    }
}
