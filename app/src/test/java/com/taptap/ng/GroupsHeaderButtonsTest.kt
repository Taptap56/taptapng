package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.23 phone report (screenshot
 * 2026-11-24 04:01): the three small header action buttons on the
 * Grup/Rute pages — "Simpan" (kartu Grup utama), "Tambah grup"
 * (seksi Grup proxy), "Tambah aturan" (seksi Aturan rute) — were
 * barely visible next to the section titles and the other buttons.
 *
 * Root cause, from the code:
 * all three used `Widget.Material3.Button.TextButton` (Material
 * 1.13.0), which resolves to 14sp mixed-case medium text in
 * `?attr/colorPrimary` with a TRANSPARENT background and NO stroke
 * (strokeWidth 0dp) — the only borderless, background-less buttons
 * in the app. `colorPrimary` is black (#FF000000) in light mode and
 * light grey (#FFC0C0C0) in dark mode (values-night/colors.xml), so
 * in dark mode the text was grey on the near-black surface
 * (#FF1C1B1F) with nothing marking it as a button at all.
 *
 * v1.0.24 fix: give all three the same style as the other action
 * buttons in the app — `Widget.MaterialComponents.Button
 * .OutlinedButton`, the M2 outlined button already used by
 * "Ambil fingerprint" in the server editor (and the same M2 family
 * as the filled buttons on the main screen) — plus an explicit
 * `android:textSize="15sp"`, the label size used by the status bar
 * and the server-row address everywhere else in the app. The
 * outline (1dp stroke in colorPrimary) + all-caps M2 button text +
 * 15sp is what makes them read as buttons, in both themes. No theme
 * color was changed and no button moved.
 *
 * Source assertions only: visual readability cannot be tested on
 * the JVM (no Robolectric in this tree) — the deciding proof is the
 * phone screenshot. If anyone reverts any part of the fix, a test
 * here fails.
 */
class GroupsHeaderButtonsTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/layout/activity_groups.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    /** The XML block of one button, from its id to its closing "/>". */
    private fun buttonBlock(xml: String, id: String): String =
        xml.substringAfter("android:id=\"@+id/$id\"").substringBefore("/>")

    @Test
    fun `header action buttons use the outlined button style like the other buttons`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        for (id in listOf("save_main_group", "add_group", "add_rule")) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("style=\"@style/Widget.MaterialComponents.Button.OutlinedButton\""),
                "$id must use Widget.MaterialComponents.Button.OutlinedButton " +
                    "(same as the fetch-fingerprint button in the server editor)",
            )
            assertFalse(
                block.contains("Widget.Material3.Button.TextButton"),
                "$id must not use the borderless M3 TextButton anymore " +
                    "(14sp grey/black text, no background, no stroke — invisible in v1.0.23)",
            )
        }
    }

    @Test
    fun `header action buttons are 15sp like the other labels in the app`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        for (id in listOf("save_main_group", "add_group", "add_rule")) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("android:textSize=\"15sp\""),
                "$id must be 15sp (was 14sp M3 LabelLarge in v1.0.23)",
            )
        }
    }

    @Test
    fun `header action buttons keep their ids texts and wiring`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        assertTrue(
            buttonBlock(xml, "save_main_group").contains("android:text=\"@string/groups_main_group_save\""),
            "save_main_group must keep its Simpan text",
        )
        assertTrue(
            buttonBlock(xml, "add_group").contains("android:text=\"@string/groups_add_group\""),
            "add_group must keep its Tambah grup text",
        )
        assertTrue(
            buttonBlock(xml, "add_rule").contains("android:text=\"@string/groups_add_rule\""),
            "add_rule must keep its Tambah aturan text",
        )
        // Positions / containers unchanged: save lives in the main-group
        // card inside groups_section (before add_group), add_group in
        // groups_section, add_rule in rules_section.
        assertTrue(
            xml.indexOf("groups_section") < xml.indexOf("save_main_group") &&
                xml.indexOf("save_main_group") < xml.indexOf("add_group"),
            "save_main_group must stay inside the Grup utama card in groups_section, above add_group",
        )
        assertTrue(
            xml.indexOf("add_group") < xml.indexOf("rules_section"),
            "add_group must stay in the groups section, above the rules section",
        )
        assertTrue(
            xml.indexOf("add_rule") > xml.indexOf("rules_section"),
            "add_rule must stay in the rules section",
        )
        // Click wiring in GroupsActivity untouched.
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(
            src.contains("R.id.add_group"),
            "GroupsActivity must still wire add_group",
        )
        assertTrue(
            src.contains("R.id.add_rule"),
            "GroupsActivity must still wire add_rule",
        )
        assertTrue(
            src.contains("R.id.save_main_group"),
            "GroupsActivity must still wire save_main_group",
        )
    }

    @Test
    fun `reference button in the server editor still uses the outlined style`() {
        // Guard the style this fix copies: if the fetch-fingerprint
        // button ever changes style, the "same as the other buttons"
        // claim above stops being true and this test says so.
        val xml = read("app/src/main/res/layout/activity_server_editor.xml")
        val block = buttonBlock(xml, "button_fetch_fingerprint")
        assertTrue(
            block.contains("style=\"@style/Widget.MaterialComponents.Button.OutlinedButton\""),
            "button_fetch_fingerprint must stay an M2 OutlinedButton " +
                "(the reference style for the Grup/Rute header buttons)",
        )
    }

    @Test
    fun `no M3 TextButton left in the groups layout`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        assertFalse(
            xml.contains("Widget.Material3.Button.TextButton"),
            "activity_groups.xml must not contain any M3 TextButton " +
                "(the invisible style from v1.0.23)",
        )
    }
}
