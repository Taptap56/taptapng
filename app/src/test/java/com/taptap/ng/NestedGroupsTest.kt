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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * v1.0.27: nested groups — every group except the main group is
 * also a member of the main group, so a url-test group shows up
 * inside "taptap" on the dashboard. These tests fail on v1.0.26:
 * there is no groupMembers field, load never nests anything, a
 * new group never joins the main group, and a deleted group id
 * would linger in any list that referenced it.
 */
class NestedGroupsTest {

    private fun profiles(vararg remarks: String): List<ProfileItem> =
        remarks.map {
            ProfileItem(remarks = it, configType = ConfigType.VMESS, address = "a.example", port = 443)
        }

    private fun mainGroup(
        members: List<String>,
        selected: String? = null,
        nested: List<String>? = null,
    ) = ProxyGroup(
        id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
        members = members, selectedMemberGuid = selected, groupMembers = nested,
    )

    private fun tesGroup(
        members: List<String>,
        nested: List<String>? = null,
    ) = ProxyGroup(
        id = "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
        members = members, groupMembers = nested,
    )

    /** Write groups.json the way v1.0.26 wrote it: no groupMembers key, no mainGroupId key. */
    private fun writeV1026File(dir: File, groups: List<ProxyGroup>, rules: List<RouteRule>) {
        File(dir, "groups.json").writeText(
            Gson().toJson(GroupsConfig(GroupsStore.CURRENT_VERSION, groups, rules)),
        )
    }

    private fun setup(dir: File, items: List<ProfileItem>): GroupsStore {
        val main = mainGroup(items.map { it.guid }, selected = items[0].guid)
        val tes = tesGroup(items.map { it.guid })
        writeV1026File(
            dir, listOf(main, tes),
            listOf(RouteRule(type = RouteRuleType.FINAL, target = main.id)),
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        return store
    }

    @Test
    fun `load nests an existing url-test group into taptap`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val store = setup(dir, items)

        // The dashboard still shows two groups…
        assertEquals(2, store.groups.size)
        // …but "tes" is now also a member of "taptap".
        val main = store.mainGroup()!!
        assertEquals("g-main", main.id)
        assertEquals(listOf("g-tes"), main.nestedGroupIds)
        assertFalse("g-main" in main.nestedGroupIds)
        assertEquals(emptyList<String>(), store.groups[1].nestedGroupIds)
    }

    @Test
    fun `load persists the nesting so a second load is a no-op`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        setup(dir, items)
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(items, items[0].guid)
        assertEquals(listOf("g-tes"), second.mainGroup()!!.nestedGroupIds)
        assertTrue(File(dir, "groups.json").readText().contains("groupMembers"))
    }

    @Test
    fun `addGroup nests the new group into taptap automatically`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        assertEquals(1, store.groups.size)

        val tes = tesGroup(listOf(items[0].guid))
        store.addGroup(tes)
        assertEquals(listOf("g-tes"), store.mainGroup()!!.nestedGroupIds)

        // Reload: the nesting survived the round trip.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(items, items[0].guid)
        assertEquals(listOf("g-tes"), second.mainGroup()!!.nestedGroupIds)
    }

    @Test
    fun `removeGroup removes the group from taptap nested members`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val store = setup(dir, items)
        assertEquals(listOf("g-tes"), store.mainGroup()!!.nestedGroupIds)

        store.removeGroup("g-tes")
        assertEquals(1, store.groups.size)
        assertEquals(emptyList<String>(), store.mainGroup()!!.nestedGroupIds)

        val second = GroupsStore(File(dir, "groups.json"))
        second.load(items, items[0].guid)
        assertEquals(emptyList<String>(), second.mainGroup()!!.nestedGroupIds)
    }

    @Test
    fun `load strips the main group id from a non-main group`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val main = mainGroup(items.map { it.guid }, selected = items[0].guid)
        // A hand-edited file that nests the main group inside "tes".
        val tes = tesGroup(items.map { it.guid }, nested = listOf("g-main"))
        writeV1026File(
            dir, listOf(main, tes),
            listOf(RouteRule(type = RouteRuleType.FINAL, target = main.id)),
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        // The main group is never a member of another group…
        assertEquals(emptyList<String>(), store.groups[1].nestedGroupIds)
        // …but "tes" still joins the main group.
        assertEquals(listOf("g-tes"), store.mainGroup()!!.nestedGroupIds)
    }

    @Test
    fun `load drops stale nested ids and self nesting`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val main = mainGroup(
            items.map { it.guid }, selected = items[0].guid,
            nested = listOf("gone", "g-main", "g-tes"),
        )
        val tes = tesGroup(items.map { it.guid }, nested = listOf("g-tes"))
        writeV1026File(
            dir, listOf(main, tes),
            listOf(RouteRule(type = RouteRuleType.FINAL, target = main.id)),
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        assertEquals(listOf("g-tes"), store.mainGroup()!!.nestedGroupIds)
        assertEquals(emptyList<String>(), store.groups[1].nestedGroupIds)
    }

    @Test
    fun `removing the main group re-nests the rest under the new main group`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val main = mainGroup(items.map { it.guid }, selected = items[0].guid)
        val tes = tesGroup(items.map { it.guid })
        val cepat = ProxyGroup(
            id = "g-cepat", name = "cepat", type = ProxyGroupType.URL_TEST,
            members = items.map { it.guid },
        )
        writeV1026File(
            dir, listOf(main, tes, cepat),
            listOf(RouteRule(type = RouteRuleType.FINAL, target = main.id)),
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        assertEquals(listOf("g-tes", "g-cepat"), store.mainGroup()!!.nestedGroupIds)

        store.removeGroup("g-main")
        assertEquals(2, store.groups.size)
        // "tes" is the new main group (first group left) and
        // "cepat" is nested inside it; the deleted id is gone.
        val newMain = store.mainGroup()!!
        assertEquals("g-tes", newMain.id)
        assertEquals(listOf("g-cepat"), newMain.nestedGroupIds)
        assertFalse(store.groups.any { "g-main" in it.nestedGroupIds })
    }

    @Test
    fun `updateGroup strips the main group id from a non-main group`() {
        val dir = Files.createTempDirectory("nested-test").toFile()
        val items = profiles("A", "B")
        val store = setup(dir, items)
        val tes = store.groups[1]
        store.updateGroup(tes.copy(groupMembers = listOf("g-main", "g-tes")))
        val stored = store.groups[1]
        assertFalse("g-main" in stored.nestedGroupIds)
        assertFalse("g-tes" in stored.nestedGroupIds)
        assertEquals(emptyList<String>(), stored.nestedGroupIds)
    }
}
