package com.taptap.ng

import com.google.gson.Gson
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsConfig
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.service.applyLiveSwitchSelection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.net.InetAddress
import java.nio.file.Files

/**
 * v1.0.23: kartu "Grup utama" — the main group is identified by
 * a stored id ([GroupsStore.mainGroupId]), never by name, so a
 * rename never breaks the route engine, the live switch, the
 * start-sync, or the Clash API's GLOBAL alias. These tests fail
 * on v1.0.22: there is no mainGroupId field, every lookup matches
 * the group by the literal name "taptap", and renaming the group
 * (via the edit dialog) silently drops the fallback, the global
 * mode and the live switch.
 */
class MainGroupTest {

    private fun profiles(vararg remarks: String): List<ProfileItem> =
        remarks.map {
            ProfileItem(remarks = it, configType = ConfigType.VMESS, address = "a.example", port = 443)
        }

    private fun writeGroupsJson(dir: File, groups: List<ProxyGroup>, rules: List<RouteRule>) {
        // No mainGroupId key: Gson omits the null, exactly like a
        // file written by v1.0.17–v1.0.22.
        File(dir, "groups.json").writeText(
            Gson().toJson(GroupsConfig(GroupsStore.CURRENT_VERSION, groups, rules)),
        )
    }

    private fun proxyGuid(decision: RouteDecision): String {
        assertTrue(decision is RouteDecision.Proxy, "expected Proxy, got $decision")
        return (decision as RouteDecision.Proxy).profileGuid
    }

    // ---- rename (the card) ----

    @Test
    fun `rename persists across reload keeping the same id`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val groupId = store.groups[0].id
        assertEquals(groupId, store.mainGroupId)

        val result = store.renameMainGroup("  Utama  ")
        assertTrue(result is GroupsStore.RenameMainGroupResult.Renamed)
        assertEquals("Utama", (result as GroupsStore.RenameMainGroupResult.Renamed).group.name)
        assertEquals(groupId, result.group.id)

        // Reload: the same group, new name, same stored id, and
        // the FINAL rule still targets it by id.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(items, items[0].guid)
        assertEquals(1, second.groups.size)
        assertEquals(groupId, second.groups[0].id)
        assertEquals("Utama", second.groups[0].name)
        assertEquals(groupId, second.mainGroupId)
        assertEquals(groupId, second.mainGroup()?.id)
        assertEquals(groupId, second.rules[0].target)
        assertTrue(File(dir, "groups.json").readText().contains("mainGroupId"))
    }

    @Test
    fun `blank rename is rejected and changes nothing`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val before = File(dir, "groups.json").readText()

        assertEquals(
            GroupsStore.RenameMainGroupResult.Blank,
            store.renameMainGroup("   "),
        )
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, store.groups[0].name)
        assertEquals(before, File(dir, "groups.json").readText())
    }

    @Test
    fun `duplicate rename is rejected and changes nothing`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        store.addGroup(
            ProxyGroup(name = "Video", type = ProxyGroupType.URL_TEST, members = listOf(items[1].guid)),
        )
        val before = File(dir, "groups.json").readText()

        assertEquals(
            GroupsStore.RenameMainGroupResult.Duplicate,
            store.renameMainGroup("Video"),
        )
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, store.groups[0].name)
        assertEquals(before, File(dir, "groups.json").readText())
    }

    @Test
    fun `renaming via updateGroup keeps the main group by id`() {
        // The edit dialog renames through updateGroup, not the
        // card — the stored id must keep pointing at the group.
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val groupId = store.groups[0].id

        store.updateGroup(store.groups[0].copy(name = "Utama"))
        assertEquals(groupId, store.mainGroupId)
        assertEquals("Utama", store.mainGroup()?.name)
    }

    @Test
    fun `removing the main group re-resolves to the next group`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val other = ProxyGroup(name = "Video", members = listOf(items[1].guid))
        store.addGroup(other)
        val mainId = store.mainGroupId
        assertNotNull(mainId)

        store.removeGroup(mainId!!)
        assertEquals(other.id, store.mainGroupId)
        assertEquals("Video", store.mainGroup()?.name)
    }

    @Test
    fun `default creation sets mainGroupId`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        assertEquals(store.groups[0].id, store.mainGroupId)
    }

    // ---- migration of pre-v1.0.23 files (no mainGroupId key) ----

    @Test
    fun `load of an old file resolves mainGroupId to the taptap group`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val (a, b) = profiles("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "g-main", name = "taptap",
                    members = listOf(a.guid, b.guid), selectedMemberGuid = a.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "r1", type = RouteRuleType.FINAL, target = "g-main"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)
        assertEquals("g-main", store.mainGroupId)
        assertEquals("g-main", store.mainGroup()?.id)
        // Persisted: a second load reads the stored id, no re-migration.
        assertTrue(File(dir, "groups.json").readText().contains("\"mainGroupId\":\"g-main\""))
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(a, b), a.guid)
        assertEquals("g-main", second.mainGroupId)
    }

    @Test
    fun `load without a taptap group falls back to the FINAL target`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val (a, b) = profiles("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "g-video", name = "Video",
                    members = listOf(a.guid), selectedMemberGuid = a.guid,
                ),
                ProxyGroup(
                    id = "g-lain", name = "Lain",
                    members = listOf(b.guid), selectedMemberGuid = b.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "r1", type = RouteRuleType.FINAL, target = "g-video"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)
        assertEquals("g-video", store.mainGroupId)
    }

    @Test
    fun `load without taptap or FINAL falls back to the first group`() {
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val (a, b) = profiles("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(id = "g-1", name = "Satu", members = listOf(a.guid)),
                ProxyGroup(id = "g-2", name = "Dua", members = listOf(b.guid)),
            ),
            rules = emptyList(),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)
        assertEquals("g-1", store.mainGroupId)
    }

    @Test
    fun `mainGroupId migration runs after the Proxy rename`() {
        // v1.0.21 ("Proxy" -> "taptap") must run first: a
        // pre-v1.0.21 file has no mainGroupId AND the old name.
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val (a, b) = profiles("A", "B")
        writeGroupsJson(
            dir,
            groups = listOf(
                ProxyGroup(
                    id = "g-1", name = "Proxy",
                    members = listOf(a.guid, b.guid), selectedMemberGuid = b.guid,
                ),
            ),
            rules = listOf(
                RouteRule(id = "r1", type = RouteRuleType.FINAL, target = "g-1"),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), b.guid)
        assertEquals("taptap", store.groups[0].name)
        assertEquals("g-1", store.mainGroupId)
        assertFalse(File(dir, "groups.json").readText().contains("Proxy"))
    }

    // ---- lookups follow the rename (by id) ----

    @Test
    fun `engine fallback and global mode follow the renamed main group`() {
        val groups = listOf(
            ProxyGroup(
                id = "g-main", name = "Utama",
                members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-b",
            ),
            ProxyGroup(
                id = "g-other", name = "Lain",
                members = listOf("guid-a"), selectedMemberGuid = "guid-a",
            ),
        )
        val ip = InetAddress.getByName("1.2.3.4")
        // No rules at all: the fallback must be the renamed main
        // group (by id), not the group still named "taptap"
        // (there is none) and not the first group by accident.
        assertEquals(
            "guid-b",
            proxyGuid(RouteEngine.resolve("example.com", ip, 443, groups, emptyList(), emptyMap(), mainGroupId = "g-main")),
        )
        // Global mode: same group.
        assertEquals(
            "guid-b",
            proxyGuid(RouteEngine.resolve("example.com", ip, 443, groups, emptyList(), emptyMap(), mode = RouteEngine.MODE_GLOBAL, mainGroupId = "g-main")),
        )
        // Without the id, the legacy name lookup finds no
        // "taptap" group and fails open to Direct — the id is
        // what carries the rename.
        assertEquals(
            RouteDecision.Direct,
            RouteEngine.resolve("example.com", ip, 443, groups, emptyList(), emptyMap()),
        )
    }

    @Test
    fun `live switch follows the renamed main group`() {
        val groups = listOf(
            ProxyGroup(
                id = "g-main", name = "Utama",
                members = listOf("guid-a", "guid-b"), selectedMemberGuid = "guid-a",
            ),
            ProxyGroup(
                id = "g-other", name = "Lain",
                members = listOf("guid-a"), selectedMemberGuid = "guid-a",
            ),
        )
        // With the id: the renamed group switches, the other is untouched.
        val updated = applyLiveSwitchSelection(groups, "guid-b", mainGroupId = "g-main")
        assertNotNull(updated)
        assertEquals("guid-b", updated!![0].selectedMemberGuid)
        assertEquals(listOf("guid-a", "guid-b"), updated[0].members)
        assertEquals("guid-a", updated[1].selectedMemberGuid)
        // Without the id: no group is named "taptap" anymore, so
        // the legacy lookup finds nothing to switch.
        assertNull(applyLiveSwitchSelection(groups, "guid-b"))
    }

    @Test
    fun `start-sync shape follows the renamed main group`() {
        // The start path does applyLiveSwitchSelection + updateGroup
        // on the group with the main id — the same shape the
        // service uses (see TaptapVpnService): the renamed group
        // is found by id and its selection moves.
        val dir = Files.createTempDirectory("main-group-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        store.renameMainGroup("Utama")
        val mainId = store.mainGroupId
        assertNotNull(mainId)

        val updated = applyLiveSwitchSelection(store.groups, items[1].guid, mainId)
        assertNotNull(updated)
        updated!!.firstOrNull { it.id == store.mainGroup()?.id }?.let { store.updateGroup(it) }
        assertEquals(items[1].guid, store.mainGroup()?.effectiveSelectedMemberGuid())
        assertEquals("Utama", store.mainGroup()?.name)
    }
}
