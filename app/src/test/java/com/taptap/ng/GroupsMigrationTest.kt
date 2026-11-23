package com.taptap.ng

import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * Migration: an install from before M7 has profiles.json (+ the
 * persisted selection) and no groups.json. Loading GroupsStore
 * over it must behave exactly like the old app: the single
 * selected server is what gets dialled.
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
}
