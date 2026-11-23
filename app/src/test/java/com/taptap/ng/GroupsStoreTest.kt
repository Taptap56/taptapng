package com.taptap.ng

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

class GroupsStoreTest {

    private fun profiles(vararg remarks: String): List<ProfileItem> =
        remarks.map {
            ProfileItem(remarks = it, configType = ConfigType.VMESS, address = "a.example", port = 443)
        }

    @Test
    fun `missing file creates the default proxy group with all profiles`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B", "C")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[1].guid)

        assertEquals(1, store.groups.size)
        val group = store.groups[0]
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, group.name)
        assertEquals(ProxyGroupType.SELECT, group.type)
        assertEquals(items.map { it.guid }, group.members)
        assertEquals(items[1].guid, group.selectedMemberGuid)
        assertEquals(1, store.rules.size)
        assertEquals(RouteRuleType.FINAL, store.rules[0].type)
        assertEquals(group.id, store.rules[0].target)
        // The default is persisted, so a fresh store reads the same.
        assertTrue(File(dir, "groups.json").exists())
    }

    @Test
    fun `missing file with no selected server defaults to the first profile`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, null)
        assertEquals(items[0].guid, store.groups[0].selectedMemberGuid)
    }

    @Test
    fun `save and load round trip keeps groups and rules`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val extra = ProxyGroup(
            name = "Video",
            type = ProxyGroupType.URL_TEST,
            members = listOf(items[1].guid),
            urlTestUrl = "http://example.com/ping",
            urlTestIntervalSec = 120,
        )
        store.addGroup(extra)
        store.addRule(
            RouteRule(
                type = RouteRuleType.DOMAIN_SUFFIX,
                pattern = "YouTube.COM",
                target = extra.id,
            )
        )

        val store2 = GroupsStore(File(dir, "groups.json"))
        store2.load(items, items[0].guid)
        assertEquals(2, store2.groups.size)
        assertEquals("Video", store2.groups[1].name)
        assertEquals(ProxyGroupType.URL_TEST, store2.groups[1].type)
        assertEquals("http://example.com/ping", store2.groups[1].urlTestUrl)
        assertEquals(120, store2.groups[1].urlTestIntervalSec)
        assertEquals(2, store2.rules.size)
        // Pattern is stored as written; matching normalises it.
        assertEquals("YouTube.COM", store2.rules[1].pattern)
        assertTrue(store2.rules[1].matches("www.youtube.com", null))
    }

    @Test
    fun `corrupt file falls back to the default`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val file = File(dir, "groups.json")
        file.writeText("{ this is not json")
        val items = profiles("A", "B")
        val store = GroupsStore(file)
        store.load(items, items[1].guid)

        assertEquals(1, store.groups.size)
        assertEquals(items.map { it.guid }, store.groups[0].members)
        assertEquals(items[1].guid, store.groups[0].selectedMemberGuid)
        assertEquals(1, store.rules.size)
        assertEquals(RouteRuleType.FINAL, store.rules[0].type)
        // The corrupt file is replaced by a valid default.
        val store2 = GroupsStore(file)
        store2.load(items, items[1].guid)
        assertEquals(1, store2.groups.size)
    }

    @Test
    fun `prune drops missing members and repoints a select group`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B", "C")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[2].guid) // selected = C
        // C disappears (profile deleted); B stays.
        val changed = store.pruneMissingProfiles(setOf(items[0].guid, items[1].guid))
        assertTrue(changed)
        val group = store.groups[0]
        assertEquals(listOf(items[0].guid, items[1].guid), group.members)
        // SELECT lost its selected member (C) -> first remaining (A).
        assertEquals(items[0].guid, group.selectedMemberGuid)
        assertEquals(items[0].guid, group.effectiveSelectedMemberGuid())
    }

    @Test
    fun `prune with nothing missing changes nothing`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        assertFalse(store.pruneMissingProfiles(items.map { it.guid }.toSet()))
    }

    @Test
    fun `prune keeps an emptied group empty`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        store.pruneMissingProfiles(emptySet())
        assertEquals(emptyList<String>(), store.groups[0].members)
        assertNull(store.groups[0].selectedMemberGuid)
        assertNull(store.groups[0].effectiveSelectedMemberGuid())
    }

    @Test
    fun `load prunes stale members from an existing file`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        // Simulate the file outliving a deleted profile: B is gone.
        val store2 = GroupsStore(File(dir, "groups.json"))
        store2.load(listOf(items[0]), items[0].guid)
        assertEquals(listOf(items[0].guid), store2.groups[0].members)
    }

    @Test
    fun `load without profiles never prunes`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        // Profiles unknown (e.g. service-side load): members stay.
        val store2 = GroupsStore(File(dir, "groups.json"))
        store2.load()
        assertEquals(items.map { it.guid }, store2.groups[0].members)
    }

    @Test
    fun `update and remove work for groups and rules`() {
        val dir = Files.createTempDirectory("groups-test").toFile()
        val items = profiles("A")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val group = store.groups[0].copy(name = "Renamed")
        store.updateGroup(group)
        assertEquals("Renamed", store.findGroup(group.id)?.name)
        assertNotNull(store.findRule(store.rules[0].id))

        val rule = store.rules[0].copy(target = RouteRule.TARGET_DIRECT)
        store.updateRule(rule)
        assertEquals(RouteRule.TARGET_DIRECT, store.findRule(rule.id)?.target)

        store.removeRule(rule.id)
        assertNull(store.findRule(rule.id))
        store.removeGroup(group.id)
        assertTrue(store.groups.isEmpty())
    }
}
