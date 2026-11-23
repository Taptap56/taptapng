package com.taptap.ng.ui.groups

import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.21: the drawer items "Grup" + "Rute" (like TB/TC) open the
 * single GroupsActivity straight at the requested section, with the
 * toolbar title following the section. No second activity.
 *
 * The section resolution is pure and asserted directly; the wiring
 * (menu ids/titles, handler branches, title mapping, scroll anchor)
 * is asserted on the sources, as in MainToolbarTest — the drawer
 * cannot be exercised on the JVM without an emulator.
 */
class GroupsSectionTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/menu/drawer_menu.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    // ---- Pure section resolution ----

    @Test
    fun `missing extra opens the full default view`() {
        assertEquals(GroupsActivity.SECTION_DEFAULT, GroupsActivity.resolveSection(null))
    }

    @Test
    fun `groups extra resolves to the groups section`() {
        assertEquals(GroupsActivity.SECTION_GROUPS, GroupsActivity.resolveSection("groups"))
    }

    @Test
    fun `routes extra resolves to the routes section`() {
        assertEquals(GroupsActivity.SECTION_ROUTES, GroupsActivity.resolveSection("routes"))
    }

    @Test
    fun `unknown extra falls back to the default view`() {
        assertEquals(GroupsActivity.SECTION_DEFAULT, GroupsActivity.resolveSection("bogus"))
        assertEquals(GroupsActivity.SECTION_DEFAULT, GroupsActivity.resolveSection(""))
    }

    // ---- Drawer menu ----

    @Test
    fun `drawer has Grup above Rute with the new strings`() {
        val xml = read("app/src/main/res/menu/drawer_menu.xml")
        assertTrue(xml.contains("android:id=\"@+id/nav_groups\""), "nav_groups missing")
        assertTrue(xml.contains("android:id=\"@+id/nav_routes\""), "nav_routes missing")
        assertTrue(
            xml.indexOf("nav_groups") < xml.indexOf("nav_routes"),
            "Grup must sit above Rute, like TB/TC",
        )
        assertTrue(xml.contains("@string/drawer_groups"), "Grup title must use drawer_groups")
        assertTrue(xml.contains("@string/drawer_routes"), "Rute title must use drawer_routes")
        assertFalse(xml.contains("nav_per_app_proxy"), "old Per-App Proxy id must be gone")
        assertFalse(xml.contains("nav_routing"), "old routing id must be gone")
        assertFalse(xml.contains("drawer_per_app_proxy"), "old Per-App Proxy string must be gone")
        assertFalse(xml.contains("drawer_routing"), "old routing string must be gone")
    }

    @Test
    fun `drawer strings are Grup and Rute`() {
        val xml = read("app/src/main/res/values/strings.xml")
        assertTrue(
            xml.contains("<string name=\"drawer_groups\">Grup</string>"),
            "drawer_groups must be Grup",
        )
        assertTrue(
            xml.contains("<string name=\"drawer_routes\">Rute</string>"),
            "drawer_routes must be Rute",
        )
    }

    // ---- Handler + activity wiring ----

    @Test
    fun `drawer handler opens GroupsActivity at the requested section`() {
        val kt = read("app/src/main/java/com/taptap/ng/ui/MainActivity.kt")
        assertTrue(
            kt.contains("R.id.nav_groups -> startActivity("),
            "Grup must open GroupsActivity",
        )
        assertTrue(
            kt.contains("GroupsActivity.newIntent(this, GroupsActivity.SECTION_GROUPS)"),
            "Grup must pass the groups section",
        )
        assertTrue(
            kt.contains("R.id.nav_routes -> startActivity("),
            "Rute must open GroupsActivity",
        )
        assertTrue(
            kt.contains("GroupsActivity.newIntent(this, GroupsActivity.SECTION_ROUTES)"),
            "Rute must pass the routes section",
        )
        // Overflow "Grup proxy & rute" still opens the default full view.
        assertTrue(
            kt.contains("R.id.more_groups_routes -> startActivity(Intent(this, GroupsActivity::class.java))"),
            "overflow menu must still open GroupsActivity without an extra",
        )
    }

    @Test
    fun `GroupsActivity titles follow the section and scrolls to Rute`() {
        val kt = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(kt.contains("EXTRA_SECTION"), "section extra must exist")
        assertTrue(
            kt.contains("SECTION_GROUPS -> R.string.drawer_groups"),
            "Grup section title must be drawer_groups",
        )
        assertTrue(
            kt.contains("SECTION_ROUTES -> R.string.drawer_routes"),
            "Rute section title must be drawer_routes",
        )
        assertTrue(
            kt.contains("else -> R.string.groups_title"),
            "default title must stay groups_title",
        )
        assertTrue(
            kt.contains("scrollView.scrollTo(0, rulesHeader.top)"),
            "Rute must scroll to the rules section header",
        )
        val layout = read("app/src/main/res/layout/activity_groups.xml")
        assertTrue(layout.contains("android:id=\"@+id/groups_scroll\""), "scroll view needs an id")
        assertTrue(
            layout.contains("android:id=\"@+id/rules_section_header\""),
            "rules section header needs an id to scroll to",
        )
    }
}
