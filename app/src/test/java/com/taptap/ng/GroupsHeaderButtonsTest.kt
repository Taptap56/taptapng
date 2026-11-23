package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.24 phone report (screenshot
 * 2026-11-24 04:33): the three header action buttons on the
 * Grup/Rute pages — "Simpan" (kartu Grup utama), "Tambah grup"
 * (seksi Grup proxy), "Tambah aturan" (seksi Aturan rute) — were
 * visible now, but the user reported "Tombol2 hitam": they render
 * dark/black, unlike the other buttons in the app.
 *
 * Root cause, from the code:
 * v1.0.24 gave all three `Widget.MaterialComponents.Button
 * .OutlinedButton`, whose text AND 1dp stroke both follow
 * `colorPrimary` — black (#FF000000) in light mode, light grey
 * (#FFC0C0C0) in dark mode (values-night/colors.xml) — on the
 * near-black dark surface (#FF1C1B1F). The "ANGGOTA (PILIH SERVER)"
 * button in the Tambah grup dialog had the same black look for the
 * same reason: a plain `Button(ctx)` whose default M2 filled style
 * fills with `colorPrimary` (black in light mode).
 *
 * v1.0.25 fix: a new app style `Widget.TaptapNG.Button
 * .FilledAccent` (values/themes.xml, next to the existing
 * `Widget.TaptapNG.Chip.Filter`): parent M2 filled Button, with
 * `backgroundTint` = `colorAccent` — which already resolves per
 * theme to #0FB88A (light, values/colors.xml) / #22E6A8 (dark,
 * values-night/colors.xml), exactly the green of the active FAB
 * (`colorFabActive`, same values, MainActivity switches the FAB
 * tint to it while the VPN runs — the only other green filled
 * control in the app; no filled green MaterialButton existed to
 * copy). The text is explicitly black: the M2 filled default text
 * color is white (colorOnPrimary), unreadable on bright mint
 * #22E6A8 / green #0FB88A, while black is readable on both. No
 * theme color was changed and no button moved. The fetch-fingerprint
 * button in the server editor deliberately stays OutlinedButton
 * (different screen, out of scope for this change).
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

    /** The body of one <style> block, from its name to "</style>". */
    private fun styleBlock(xml: String, name: String): String =
        xml.substringAfter("<style name=\"$name\"").substringBefore("</style>")

    @Test
    fun `header action buttons use the green filled accent style`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        for (id in listOf("save_main_group", "add_group", "add_rule")) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("style=\"@style/Widget.TaptapNG.Button.FilledAccent\""),
                "$id must use Widget.TaptapNG.Button.FilledAccent " +
                    "(green filled accent button, v1.0.25)",
            )
            assertFalse(
                block.contains("Widget.MaterialComponents.Button.OutlinedButton"),
                "$id must not use the M2 OutlinedButton anymore " +
                    "(text + stroke in black colorPrimary — the 'tombol hitam' of v1.0.24)",
            )
            assertFalse(
                block.contains("Widget.Material3.Button.TextButton"),
                "$id must not use the borderless M3 TextButton anymore " +
                    "(14sp grey/black text, no background, no stroke — invisible in v1.0.23)",
            )
        }
    }

    @Test
    fun `filled accent style is a filled M2 button tinted with the theme accent`() {
        val xml = read("app/src/main/res/values/themes.xml")
        val block = styleBlock(xml, "Widget.TaptapNG.Button.FilledAccent")
        assertTrue(
            block.contains("parent=\"Widget.MaterialComponents.Button\""),
            "FilledAccent must extend the M2 filled Button style",
        )
        assertTrue(
            block.contains("<item name=\"backgroundTint\">@color/colorAccent</item>"),
            "FilledAccent must tint its fill with @color/colorAccent " +
                "(#0FB88A light / #22E6A8 dark, the app accent)",
        )
        assertTrue(
            block.contains("<item name=\"android:textColor\">@android:color/black</item>"),
            "FilledAccent must use black text — the M2 filled default " +
                "is white, unreadable on the bright mint/green accent",
        )
    }

    @Test
    fun `colorAccent is the green accent in both themes`() {
        val light = read("app/src/main/res/values/colors.xml")
        assertTrue(
            light.contains("<color name=\"colorAccent\">#FF0FB88A</color>"),
            "light colorAccent must be #0FB88A",
        )
        val dark = read("app/src/main/res/values-night/colors.xml")
        assertTrue(
            dark.contains("<color name=\"colorAccent\">#FF22E6A8</color>"),
            "dark colorAccent must be #22E6A8",
        )
        // Same values as the active FAB: the green filled reference.
        assertTrue(
            light.contains("<color name=\"colorFabActive\">#FF0FB88A</color>"),
            "light colorFabActive must match colorAccent (#0FB88A)",
        )
        assertTrue(
            dark.contains("<color name=\"colorFabActive\">#FF22E6A8</color>"),
            "dark colorFabActive must match colorAccent (#22E6A8)",
        )
    }

    @Test
    fun `members button in the add-group dialog uses the same green filled style`() {
        // Plain Button(ctx) filled with black colorPrimary before
        // v1.0.25; now a MaterialButton with the FilledAccent style
        // via ContextThemeWrapper (MaterialButton has no 4-arg
        // constructor), 15sp like the three header buttons.
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(
            src.contains(
                "MaterialButton(ContextThemeWrapper(ctx, R.style.Widget_TaptapNG_Button_FilledAccent))",
            ),
            "membersButton must be a MaterialButton with the FilledAccent style",
        )
        assertTrue(
            src.contains("import com.google.android.material.button.MaterialButton"),
            "GroupsActivity must import MaterialButton",
        )
        assertTrue(
            src.contains("import android.view.ContextThemeWrapper"),
            "GroupsActivity must import ContextThemeWrapper " +
                "(MaterialButton has no 4-arg constructor)",
        )
        assertFalse(
            src.contains("import android.widget.Button"),
            "GroupsActivity must not import the plain widget Button anymore",
        )
        assertFalse(
            src.contains("val membersButton = Button(ctx)"),
            "membersButton must not be a plain Button(ctx) anymore " +
                "(default M2 fill is black colorPrimary)",
        )
        val block = src.substringAfter("val membersButton = MaterialButton")
            .substringBefore("root.addView(membersButton)")
        assertTrue(
            block.contains("textSize = 15f"),
            "membersButton must be 15sp like the header buttons",
        )
        assertTrue(
            block.contains("text = membersButtonText(chosen.size)"),
            "membersButton must keep its ANGGOTA (n) text",
        )
        assertTrue(
            block.contains(".setMultiChoiceItems(names, checked)"),
            "membersButton must keep opening the server multi-choice dialog",
        )
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
        // The fetch-fingerprint button is out of scope for v1.0.25
        // (different screen): it stays an M2 OutlinedButton, and this
        // guards that nobody silently re-styled it with this change.
        val xml = read("app/src/main/res/layout/activity_server_editor.xml")
        val block = buttonBlock(xml, "button_fetch_fingerprint")
        assertTrue(
            block.contains("style=\"@style/Widget.MaterialComponents.Button.OutlinedButton\""),
            "button_fetch_fingerprint must stay an M2 OutlinedButton",
        )
    }

    @Test
    fun `no M3 TextButton and no OutlinedButton left in the groups layout`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        assertFalse(
            xml.contains("Widget.Material3.Button.TextButton"),
            "activity_groups.xml must not contain any M3 TextButton " +
                "(the invisible style from v1.0.23)",
        )
        assertFalse(
            xml.contains("Widget.MaterialComponents.Button.OutlinedButton"),
            "activity_groups.xml must not contain any M2 OutlinedButton " +
                "(the black style from v1.0.24 — all three are FilledAccent now)",
        )
    }
}
