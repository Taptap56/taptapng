package com.taptap.ng.core

import com.google.gson.Gson
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.net.InetAddress
import java.nio.file.Files

/**
 * Per-rule on/off toggle (v1.0.23): the nullable `enabled` flag,
 * the engine skipping switched-off rules, and the upgrade path
 * for files written by v1.0.17–v1.0.22 (no "enabled" key).
 *
 * The Gson note under test: the stored field is `Boolean?`
 * (null = missing key = active) rather than a plain
 * `Boolean = true` default, so the outcome is the same on
 * either Gson instantiation path — the no-arg constructor
 * kotlinc emits while every parameter has a default, or Unsafe
 * allocation if this class ever loses that constructor (where a
 * plain default would read the JVM default `false` and every old
 * rule would silently die). The old-file tests below pin the
 * active-by-default behaviour on the real Gson path.
 *
 * The UI half (Switch per row, hidden for FINAL) lives in
 * GroupsActivity / item_route_rule.xml and cannot run in a JVM
 * test; what is asserted here is the behaviour the UI drives —
 * the stored flag, the engine, and the round-trip through
 * [GroupsStore.updateRule].
 */
class RouteRuleEnabledTest {

    private fun addr(text: String): InetAddress = InetAddress.getByName(text)

    private fun group(id: String, selected: String = "a") =
        ProxyGroup(
            id = id,
            name = "g-$id",
            type = ProxyGroupType.SELECT,
            members = listOf("a", "b"),
            selectedMemberGuid = selected,
        )

    private fun suffixRule(
        pattern: String,
        target: String,
        enabled: Boolean? = null,
    ) = RouteRule(
        type = RouteRuleType.DOMAIN_SUFFIX,
        pattern = pattern,
        target = target,
        enabled = enabled,
    )

    private fun proxyGuid(decision: RouteDecision): String {
        assertTrue(decision is RouteDecision.Proxy, "expected Proxy, got $decision")
        return (decision as RouteDecision.Proxy).profileGuid
    }

    // ---- Stored flag ----

    @Test
    fun `fresh rule is active`() {
        val rule = RouteRule(type = RouteRuleType.DOMAIN_SUFFIX, pattern = "example.com")
        assertNull(rule.enabled)
        assertTrue(rule.isEnabled)
    }

    @Test
    fun `explicit enabled true and false round trip through the accessor`() {
        assertTrue(suffixRule("example.com", "g1", enabled = true).isEnabled)
        assertFalse(suffixRule("example.com", "g1", enabled = false).isEnabled)
    }

    @Test
    fun `old json without enabled field reads as active`() {
        // v1.0.22 file: no "enabled" key at all. This is the
        // regression that a `Boolean = true` default would fail:
        // Gson bypasses the constructor, so the field would read
        // the JVM default `false` and the rule would silently die.
        val rule = Gson().fromJson(
            """{"id":"r1","type":"DOMAIN_SUFFIX","pattern":"example.com","target":"DIRECT"}""",
            RouteRule::class.java,
        )
        assertNull(rule.enabled)
        assertTrue(rule.isEnabled)
    }

    @Test
    fun `json with enabled false reads as inactive, true as active`() {
        val off = Gson().fromJson(
            """{"id":"r1","type":"DOMAIN_SUFFIX","pattern":"example.com","target":"DIRECT","enabled":false}""",
            RouteRule::class.java,
        )
        assertFalse(off.isEnabled)
        val on = Gson().fromJson(
            """{"id":"r1","type":"DOMAIN_SUFFIX","pattern":"example.com","target":"DIRECT","enabled":true}""",
            RouteRule::class.java,
        )
        assertTrue(on.isEnabled)
    }

    // ---- Engine ----

    @Test
    fun `switched-off rule is skipped and the next rule wins`() {
        val groups = listOf(group("g1", selected = "a"), group("g2", selected = "b"))
        val rules = listOf(
            suffixRule("example.com", "g1", enabled = false),
            RouteRule(type = RouteRuleType.FINAL, target = "g2"),
        )
        assertEquals(
            "b",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())),
        )
    }

    @Test
    fun `switched-off rule falls through to the next matching rule, not just FINAL`() {
        val groups = listOf(group("g1", selected = "a"), group("g2", selected = "b"))
        val rules = listOf(
            suffixRule("example.com", "g1", enabled = false),
            RouteRule(type = RouteRuleType.DOMAIN, pattern = "example.com", target = "g2"),
            RouteRule(type = RouteRuleType.FINAL, target = "g1"),
        )
        assertEquals(
            "b",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())),
        )
    }

    @Test
    fun `toggling a rule back on matches it again`() {
        val groups = listOf(group("g1", selected = "a"), group("g2", selected = "b"))
        val base = suffixRule("example.com", "g1")
        val final = RouteRule(type = RouteRuleType.FINAL, target = "g2")
        val off = base.copy(enabled = false)
        assertEquals(
            "b",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, listOf(off, final), emptyMap())),
        )
        val on = off.copy(enabled = true)
        assertEquals(
            "a",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, listOf(on, final), emptyMap())),
        )
    }

    @Test
    fun `FINAL is always evaluated even when stored disabled`() {
        // FINAL has no toggle in the UI, so it can only be
        // switched off by a hand-edited file — the engine still
        // evaluates it, so the last resort can never be lost.
        val groups = listOf(group("g1", selected = "a"))
        val rules = listOf(
            RouteRule(type = RouteRuleType.FINAL, target = "g1", enabled = false),
        )
        assertEquals(
            "a",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())),
        )
    }

    @Test
    fun `rule with no enabled key matches exactly like an enabled rule`() {
        val groups = listOf(group("g1", selected = "a"), group("g2", selected = "b"))
        val rules = listOf(
            suffixRule("example.com", "g1"),
            RouteRule(type = RouteRuleType.FINAL, target = "g2"),
        )
        assertEquals(
            "a",
            proxyGuid(RouteEngine.resolve("example.com", addr("1.2.3.4"), 443, groups, rules, emptyMap())),
        )
    }

    // ---- Persistence (GroupsStore round trip) ----

    @Test
    fun `switching a rule off survives save and load`() {
        val dir = Files.createTempDirectory("rules-enabled-test").toFile()
        val items = listOf(
            ProfileItem(remarks = "A", configType = ConfigType.VMESS, address = "a.example", port = 443),
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        // Drop the default FINAL rule; rebuild the list by hand.
        store.removeRule(store.rules[0].id)
        val groupId = store.groups[0].id
        val rule = suffixRule("example.com", groupId)
        store.addRule(rule)
        store.addRule(RouteRule(type = RouteRuleType.FINAL, target = groupId))

        // The toggle path: updateRule with a copy, as the UI does.
        store.updateRule(rule.copy(enabled = false))

        val reloaded = GroupsStore(File(dir, "groups.json"))
        reloaded.load(items, items[0].guid)
        assertEquals(2, reloaded.rules.size)
        assertFalse(reloaded.rules[0].isEnabled)
        assertEquals(false, reloaded.rules[0].enabled)
        assertTrue(reloaded.rules[1].isEnabled)
        // The never-toggled FINAL rule stays key-less on disk —
        // a v1.0.22-shaped file, not a rewritten one.
        assertEquals(1, File(dir, "groups.json").readText().split("\"enabled\"").size - 1)
    }

    @Test
    fun `v1_0_22 groups_json without enabled loads every rule as active`() {
        val dir = Files.createTempDirectory("rules-enabled-test").toFile()
        val item = ProfileItem(remarks = "A", configType = ConfigType.VMESS, address = "a.example", port = 443)
        val file = File(dir, "groups.json")
        // Hand-written v1.0.22 file: "enabled" appears nowhere.
        file.writeText(
            """{"version":1,"groups":[{"id":"g1","name":"taptap","type":"SELECT","members":["${item.guid}"],"selectedMemberGuid":"${item.guid}","urlTestUrl":"http://www.gstatic.com/generate_204","urlTestIntervalSec":300}],"rules":[{"id":"r1","type":"DOMAIN_SUFFIX","pattern":"example.com","target":"g1"},{"id":"r2","type":"FINAL","pattern":"","target":"g1"}]}""",
        )
        val store = GroupsStore(file)
        store.load(listOf(item), item.guid)
        assertEquals(2, store.rules.size)
        assertTrue(store.rules[0].isEnabled)
        assertTrue(store.rules[1].isEnabled)
        // And the loaded rules still route: the suffix rule wins.
        assertEquals(
            item.guid,
            proxyGuid(
                RouteEngine.resolve(
                    "example.com", addr("1.2.3.4"), 443,
                    store.groups, store.rules, emptyMap(),
                ),
            ),
        )
    }
}
