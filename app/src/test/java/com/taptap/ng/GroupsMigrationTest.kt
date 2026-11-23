package com.taptap.ng

import com.google.gson.Gson
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsConfig
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * Migration: an install from before M7 has profiles.json (+ the
 * persisted selection) and no groups.json. Loading GroupsStore
 * over it must behave exactly like the old app: the single
 * selected server is what gets dialled.
 *
 * v1.0.21: the default group was renamed "Proxy" -> "taptap".
 * A groups.json written by v1.0.18–v1.0.20 still stores a group
 * named "Proxy" — loading it renames the group in place (same
 * id), re-points rules that targeted the literal name "Proxy",
 * and merges instead of duplicating when a "taptap" group
 * already exists. All of that is covered below.
 */
class GroupsMigrationTest {

    private fun oldInstall(dir: File, selectSecond: Boolean): Pair<ProfileStore, List<ProfileItem>> {
        val store = ProfileStore(File(dir, "profiles.json"))
        val a = ProfileItem(remarks = "A", configType = ConfigType.VMESS, address = "a.example", port = 443)
        val b = ProfileItem(remarks = "B", configType = ConfigType.VMESS, address = "b.example", port = 443)
        store.add(a)
        store.add(b)
        if (selectSecond) store.setSelectedGuid(b.guid)
        return store to listOf(a, b)
    }

    private fun writeGroupsJson(dir: File, groups: List<ProxyGroup>, rules: List<RouteRule>) {
        File(dir, "groups.json").writeText(
            Gson().toJson(GroupsConfig(GroupsStore.CURRENT_VERSION, groups, rules)),
        )
    }

    private fun items(vararg remarks: String): List<ProfileItem> =
        remarks.map {
            ProfileItem(remarks = it, configType = ConfigType.VMESS, address = "a.example", port = 443)
        }

    @Test
    fun `old data without groups json keeps the selected server`() {
        val dir = Files.createTempDirectory("groups-migration-test").toFile()
        val (profileStore, items) = oldInstall(dir, selectSecond = true)
        // The old install really has no groups.json.
        assertTrue(!File(dir, "groups.json").exists())

        val groupsStore = GroupsStore(GroupsStore.defaultFile(dir))
        groupsStore.load(profileStore.profiles, profileStore.selectedGuid)

        assertEquals(1, groupsStore.groups.size)
        val group = groupsStore.groups[0]
        assertEquals(ProxyGroupType.SELECT, group.type)
        assertEquals(items.map { it.guid }, group.members)
        // The default group selects the same server the old app had selected.
        assertEquals(items[1].guid, group.selectedMemberGuid)
        assertEquals(items[1].guid, group.effectiveSelectedMemberGuid())
        // And the route engine's first match (FINAL) points at it.
        assertEquals(1, groupsStore.rules.size)
        assertEquals(RouteRuleType.FINAL, groupsStore.rules[0].type)
        assertEquals(group.id, groupsStore.rules[0].target)
        assertTrue(groupsStore.rules[0].matches("anything.example", null))
    }

    @Test
    fun `old data with no selection defaults to the first profile`() {
        val dir = Files.createTempDirectory("groups-migration-test").toFile()
        val (profileStore, items) = oldInstall(dir, selectSecond = false)

        val groupsStore = GroupsStore(GroupsStore.defaultFile(dir))
        groupsStore.load(profileStore.profiles, profileStore.selectedGuid)

        // Old behaviour without a selection: connect dialled profiles[0].
        assertEquals(items[0].guid, groupsStore.groups[0].effectiveSelectedMemberGuid())
    }

    @Test
    fun `second load reads the persisted default instead of rebuilding it`() {
        val dir = Files.createTempDirectory("groups-migration-test").toFile()
        val (profileStore, items) = oldInstall(dir, selectSecond = true)
        val first = GroupsStore(GroupsStore.defaultFile(dir))
        first.load(profileStore.profiles, profileStore.selectedGuid)
        val groupId = first.groups[0].id

        val second = GroupsStore(GroupsStore.defaultFile(dir))
        second.load(profileStore.profiles, profileStore.selectedGuid)
        assertEquals(groupId, second.groups[0].id)
        assertEquals(items[1].guid, second.groups[0].selectedMemberGuid)
        assertEquals(groupId, second.rules[0].target)
    }

    // ---- v1.0.21: "Proxy" -> "taptap" rename ----

    @Test
    fun `load renames a stored Proxy group to taptap keeping its id and FINAL rule`() {
        val dir = Files.createTempDirectory("groups-rename-test").toFile()
        val (a, b) = items("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "group-1", name = "Proxy",
                    members = listOf(a.guid, b.guid), selectedMemberGuid = b.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "rule-1", type = RouteRuleType.FINAL, target = "group-1"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), b.guid)

        assertEquals(1, store.groups.size)
        assertEquals("group-1", store.groups[0].id)
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, store.groups[0].name)
        assertEquals(listOf(a.guid, b.guid), store.groups[0].members)
        assertEquals(b.guid, store.groups[0].selectedMemberGuid)
        // FINAL targeted the group by id, so it needs no change.
        assertEquals("group-1", store.rules[0].target)
        // The migration is persisted: the file no longer mentions
        // the old name at all.
        val text = File(dir, "groups.json").readText()
        assertTrue(text.contains("taptap"), text)
        assertFalse(text.contains("Proxy"), text)

        // Second load is idempotent: same id, still one group.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(a, b), b.guid)
        assertEquals(1, second.groups.size)
        assertEquals("group-1", second.groups[0].id)
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, second.groups[0].name)
    }

    @Test
    fun `load repoints a rule whose target is the literal name Proxy`() {
        val dir = Files.createTempDirectory("groups-rename-test").toFile()
        val (a, b) = items("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "group-1", name = "Proxy",
                    members = listOf(a.guid, b.guid), selectedMemberGuid = a.guid,
                ),
            ),
            rules = listOf(
                // Hand-edited file: the rule names the group instead
                // of its id (production code always stores the id).
                RouteRule(
                    id = "rule-1", type = RouteRuleType.DOMAIN_SUFFIX,
                    pattern = "google.com", target = "Proxy",
                ),
                RouteRule(id = "rule-2", type = RouteRuleType.FINAL, target = "group-1"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)

        assertEquals("group-1", store.rules[0].target)
        assertEquals("group-1", store.rules[1].target)
        // Idempotent: the literal target is gone from the file.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(a, b), a.guid)
        assertEquals("group-1", second.rules[0].target)
        assertEquals("group-1", second.rules[1].target)
    }

    @Test
    fun `load merges a Proxy group into an existing taptap group instead of duplicating`() {
        val dir = Files.createTempDirectory("groups-rename-test").toFile()
        val (a, b) = items("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "g-taptap", name = "taptap",
                    members = listOf(a.guid), selectedMemberGuid = a.guid,
                ),
                ProxyGroup(
                    id = "g-proxy", name = "Proxy",
                    members = listOf(b.guid), selectedMemberGuid = b.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "rule-1", type = RouteRuleType.FINAL, target = "g-proxy"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)

        // Exactly one default group: the survivor keeps its id,
        // the Proxy members join it, its own selection wins.
        assertEquals(1, store.groups.size)
        assertEquals("g-taptap", store.groups[0].id)
        assertEquals("taptap", store.groups[0].name)
        assertEquals(listOf(a.guid, b.guid), store.groups[0].members)
        assertEquals(a.guid, store.groups[0].selectedMemberGuid)
        // The FINAL rule that targeted the dropped group now
        // targets the survivor.
        assertEquals("g-taptap", store.rules[0].target)
        assertTrue(store.groups.none { it.name == "Proxy" })

        // Second load is idempotent: no re-merge, no duplicates.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(a, b), a.guid)
        assertEquals(1, second.groups.size)
        assertEquals("g-taptap", second.groups[0].id)
        assertEquals(listOf(a.guid, b.guid), second.groups[0].members)
        assertEquals("g-taptap", second.rules[0].target)
    }

    @Test
    fun `load with only a taptap group changes nothing`() {
        val dir = Files.createTempDirectory("groups-rename-test").toFile()
        val (a, b) = items("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "g-taptap", name = "taptap",
                    members = listOf(a.guid, b.guid), selectedMemberGuid = b.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "rule-1", type = RouteRuleType.FINAL, target = "g-taptap"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), b.guid)
        assertEquals("g-taptap", store.groups[0].id)
        assertEquals(listOf(a.guid, b.guid), store.groups[0].members)
        assertEquals(b.guid, store.groups[0].selectedMemberGuid)

        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(a, b), b.guid)
        assertEquals("g-taptap", second.groups[0].id)
        assertEquals(1, second.groups.size)
    }
}
