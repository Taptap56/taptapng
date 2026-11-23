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
import com.taptap.ng.ui.groups.GroupsActivity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.net.InetAddress
import java.nio.file.Files

/**
 * v1.0.27 (part 1 of 3): FINAL + the main group cannot be
 * edited. From the user's phone report (screenshot 2026-11-24
 * 05:37 + "Harusnya taptap final tidak bisa di edit di grup
 * maupun rute dia cuma bisa di edit namanya saja di grup"):
 *
 * - Route page: the FINAL rule row shows NONE of the four action
 *   buttons (move up/down, edit, delete). Other rules keep all
 *   four. FINAL already had no on/off toggle since v1.0.23.
 * - Group page: the main group row shows NO edit (pencil) /
 *   delete (trash) buttons. The ONLY way to change the main
 *   group is renaming it through the "Grup utama" card
 *   (rename by id, v1.0.23). Other groups ("tes") keep edit +
 *   delete.
 *
 * Root cause, from the code: both adapters bound their action
 * buttons unconditionally — GroupAdapter.onBindViewHolder always
 * wired edit/delete visible, RuleAdapter.onBindViewHolder always
 * wired move/edit/delete visible. Only the toggle had a FINAL
 * guard (v1.0.23). There was no is-main-group / is-FINAL check
 * anywhere in the row binding.
 *
 * These tests fail on v1.0.26: the pure helpers do not exist,
 * the adapter source has no visibility guard, and the store
 * tests pin the pre-fix behaviour. Source assertions only for
 * the adapter (no Robolectric in this tree) — the deciding
 * proof is the phone screenshot. Data-layer tests are real
 * GroupsStore + RouteEngine runs.
 *
 * Deliberately NOT changed: the store stays permissive —
 * removeRule(FINAL) and moveRule*(FINAL) are used by
 * GroupsStoreTest to build no-FINAL fixtures, and
 * removeGroup(main) re-resolves mainGroupId to the next group
 * (pinned by MainGroupTest). The non-UI deletion path is
 * therefore "dialihkan dengan aman", not refused — see the
 * re-resolve test below. The load() mainGroupId fallback is
 * untouched; the last test pins it.
 */
class GroupsNoEditTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/layout/item_proxy_group.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    private fun profiles(vararg remarks: String): List<ProfileItem> =
        remarks.map {
            ProfileItem(remarks = it, configType = ConfigType.VMESS, address = "a.example", port = 443)
        }

    private fun proxyGuid(decision: RouteDecision): String {
        assertTrue(decision is RouteDecision.Proxy, "expected Proxy, got $decision")
        return (decision as RouteDecision.Proxy).profileGuid
    }

    // ---- pure helpers: FINAL ----

    @Test
    fun `FINAL rule shows no actions, every other rule type shows all four`() {
        for (type in RouteRuleType.values()) {
            val rule = RouteRule(type = type)
            if (type == RouteRuleType.FINAL) {
                assertFalse(
                    GroupsActivity.ruleActionsVisible(rule),
                    "FINAL must hide move/edit/delete (v1.0.27)",
                )
            } else {
                assertTrue(
                    GroupsActivity.ruleActionsVisible(rule),
                    "$type must keep move/edit/delete",
                )
            }
        }
    }

    // ---- pure helpers: main group ----

    @Test
    fun `main group shows no actions, other groups show them`() {
        val main = ProxyGroup(id = "g-main", name = "taptap")
        val other = ProxyGroup(id = "g-tes", name = "tes")
        assertFalse(
            GroupsActivity.groupActionsVisible(main, "g-main"),
            "the main group must hide edit/delete (v1.0.27)",
        )
        assertTrue(
            GroupsActivity.groupActionsVisible(other, "g-main"),
            "a non-main group must keep edit/delete",
        )
    }

    @Test
    fun `renaming the main group does not unhide its buttons - identity is the id not the name`() {
        // The card renames by id (v1.0.23): same id, new name —
        // still the main group, still no buttons. A DIFFERENT
        // group that happens to carry the old name "taptap" is
        // not the main group and stays editable.
        val renamedMain = ProxyGroup(id = "g-main", name = "Utama")
        assertFalse(
            GroupsActivity.groupActionsVisible(renamedMain, "g-main"),
            "renamed main group (same id) must still hide edit/delete",
        )
        val impostor = ProxyGroup(id = "g-other", name = "taptap")
        assertTrue(
            GroupsActivity.groupActionsVisible(impostor, "g-main"),
            "a non-main group named taptap must keep edit/delete " +
                "(identity is the id, never the name)",
        )
    }

    @Test
    fun `null mainGroupId leaves every group row editable`() {
        val group = ProxyGroup(id = "g-1", name = "taptap")
        assertTrue(
            GroupsActivity.groupActionsVisible(group, null),
            "with no main group resolved yet, no row may hide its buttons",
        )
    }

    // ---- adapter source: group row ----

    @Test
    fun `group adapter hides edit and delete on the main row only`() {
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(
            src.contains("groupActionsVisible(group, groupsStore.mainGroupId)"),
            "GroupAdapter must gate its buttons on groupActionsVisible(group, groupsStore.mainGroupId)",
        )
        for (id in listOf("holder.edit", "holder.delete")) {
            assertTrue(
                src.contains("$id.visibility = if (actionsVisible) View.VISIBLE else View.GONE"),
                "$id must be VISIBLE for ordinary groups and GONE for the main group " +
                    "(both branches — RecyclerView recycles rows)",
            )
        }
        // The buttons are hidden, not removed: ordinary groups
        // still get their listeners.
        assertTrue(
            src.contains("holder.edit.setOnClickListener { onEdit(group) }"),
            "group edit listener must stay wired for non-main groups",
        )
        assertTrue(
            src.contains("holder.delete.setOnClickListener { onDelete(group) }"),
            "group delete listener must stay wired for non-main groups",
        )
    }

    // ---- adapter source: rule row ----

    @Test
    fun `rule adapter hides all four actions on the FINAL row only`() {
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(
            src.contains("ruleActionsVisible(rule)"),
            "RuleAdapter must gate its buttons on ruleActionsVisible(rule)",
        )
        for (id in listOf("holder.moveUp", "holder.moveDown", "holder.edit", "holder.delete")) {
            assertTrue(
                src.contains("$id.visibility = if (actionsVisible) View.VISIBLE else View.GONE"),
                "$id must be VISIBLE for ordinary rules and GONE for FINAL " +
                    "(both branches — RecyclerView recycles rows)",
            )
        }
        // The buttons are hidden, not removed: ordinary rules
        // still get their listeners.
        assertTrue(
            src.contains("holder.moveUp.setOnClickListener { onMoveUp(rule) }"),
            "rule move-up listener must stay wired for non-FINAL rules",
        )
        assertTrue(
            src.contains("holder.moveDown.setOnClickListener { onMoveDown(rule) }"),
            "rule move-down listener must stay wired for non-FINAL rules",
        )
        assertTrue(
            src.contains("holder.delete.setOnClickListener { onDelete(rule) }"),
            "rule delete listener must stay wired for non-FINAL rules",
        )
    }

    @Test
    fun `FINAL toggle stays hidden - v1-0-23 behaviour untouched`() {
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        val finalBranch = src.substringAfter("if (rule.type == RouteRuleType.FINAL) {")
            .substringBefore("} else {")
        assertTrue(
            finalBranch.contains("holder.enabled.visibility = View.GONE"),
            "FINAL must still have no on/off toggle (v1.0.23) — " +
                "the v1.0.27 button lock must not regress it",
        )
    }

    // ---- data layer: rename keeps FINAL following the group ----

    @Test
    fun `rename main group keeps FINAL target and the engine follows the rename`() {
        val dir = Files.createTempDirectory("noedit-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val groupId = store.groups[0].id
        assertEquals(RouteRuleType.FINAL, store.rules[0].type)
        assertEquals(groupId, store.rules[0].target)

        val result = store.renameMainGroup("Utama")
        assertTrue(result is GroupsStore.RenameMainGroupResult.Renamed)
        // The rename changes ONLY the name: same id, and FINAL
        // still targets that id — no rule was touched.
        assertEquals(groupId, store.mainGroupId)
        assertEquals("Utama", store.mainGroup()?.name)
        assertEquals(groupId, store.rules[0].target)

        // The engine routes through FINAL to the renamed group.
        val ip = InetAddress.getByName("1.2.3.4")
        assertEquals(
            items[0].guid,
            proxyGuid(
                RouteEngine.resolve(
                    "example.com", ip, 443, store.groups, store.rules,
                    emptyMap(), mainGroupId = store.mainGroupId,
                ),
            ),
        )

        // And the same holds after a reload from disk.
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(items, items[0].guid)
        assertEquals(groupId, second.mainGroupId)
        assertEquals("Utama", second.mainGroup()?.name)
        assertEquals(groupId, second.rules[0].target)
        assertEquals(
            items[0].guid,
            proxyGuid(
                RouteEngine.resolve(
                    "example.com", ip, 443, second.groups, second.rules,
                    emptyMap(), mainGroupId = second.mainGroupId,
                ),
            ),
        )
    }

    // ---- data layer: non-UI deletion of the main group is redirected safely ----

    @Test
    fun `deleting the main group off-UI re-resolves safely and routing follows the new main group`() {
        val dir = Files.createTempDirectory("noedit-test").toFile()
        val items = profiles("A", "B")
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val other = ProxyGroup(
            name = "tes", type = ProxyGroupType.URL_TEST,
            members = listOf(items[1].guid),
        )
        store.addGroup(other)
        val mainId = store.mainGroupId!!

        // The non-UI path (e.g. a stale caller): the main group
        // is deleted, mainGroupId must never dangle — it
        // re-resolves to the next group (the behaviour pinned by
        // MainGroupTest, kept in v1.0.27).
        store.removeGroup(mainId)
        assertEquals(other.id, store.mainGroupId)
        assertEquals("tes", store.mainGroup()?.name)
        assertTrue(File(dir, "groups.json").readText().contains("\"mainGroupId\":\"${other.id}\""))

        // FINAL still targets the deleted id — the engine skips
        // the stale target and falls back to the new main group.
        assertEquals(mainId, store.rules[0].target)
        val ip = InetAddress.getByName("1.2.3.4")
        assertEquals(
            items[1].guid,
            proxyGuid(
                RouteEngine.resolve(
                    "example.com", ip, 443, store.groups, store.rules,
                    emptyMap(), mainGroupId = store.mainGroupId,
                ),
            ),
        )
    }

    // ---- data layer: load() fallback re-resolve is intact ----

    @Test
    fun `load of an old file without mainGroupId still re-resolves to the surviving group`() {
        // A pre-v1.0.23 file (no mainGroupId key) whose FINAL
        // target is a deleted group id: load() must still resolve
        // mainGroupId — FINAL target (stale) -> name "taptap"
        // (absent) -> first group — and persist it. This pins the
        // fallback the task orders kept, not deleted.
        val dir = Files.createTempDirectory("noedit-test").toFile()
        val (a, b) = profiles("A", "B")
        File(dir, "groups.json").writeText(
            Gson().toJson(
                GroupsConfig(
                    GroupsStore.CURRENT_VERSION,
                    groups = listOf(
                        ProxyGroup(
                            id = "g-tes", name = "tes",
                            members = listOf(a.guid, b.guid), selectedMemberGuid = b.guid,
                        ),
                    ),
                    rules = listOf(
                        RouteRule(id = "r1", type = RouteRuleType.FINAL, target = "g-gone"),
                    ),
                ),
            ),
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(a, b), a.guid)
        assertEquals("g-tes", store.mainGroupId)
        assertEquals("tes", store.mainGroup()?.name)
        assertTrue(File(dir, "groups.json").readText().contains("\"mainGroupId\":\"g-tes\""))
    }
}
