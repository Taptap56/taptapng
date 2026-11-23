package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.24 phone report (screenshot
 * 2026-11-24 04:33): the three section labels on the Grup/Rute
 * pages — "Grup utama" (kartu Grup utama), "Grup proxy" (seksi
 * grup), "Aturan rute" (seksi aturan) — were still small and dim,
 * almost unreadable in the dark theme, even after the v1.0.24
 * header-button fix ("kayanya masih ada tulisan kecil").
 *
 * Root cause, from the code — the same bug class as v1.0.3
 * (ThemeTypographyTest): the labels used
 * `?attr/textAppearanceTitleSmall` ("Grup utama") and
 * `?attr/textAppearanceTitleMedium` ("Grup proxy", "Aturan rute"),
 * but Theme.TaptapNG only defines textAppearanceBodyLarge/Medium/
 * Small and textAppearanceTitleLarge (themes.xml, v1.0.4 fix).
 * The M2 parent theme does not define TitleSmall/TitleMedium
 * either, so both attributes resolved to resource ID 0 and the
 * labels fell back to the small default size with no theme color
 * — the "Invalid resource ID 0x00000000" fallback the v1.0.4
 * comment in themes.xml describes.
 *
 * v1.0.25 fix: give all three labels the same style as the other
 * section headers in the app — `?attr/textAppearanceBodyLarge`,
 * the style of every section header in the server editor
 * ("Protokol", "Metode SSH", "Jaringan", "Keamanan stream",
 * "Metode Xray" in activity_server_editor.xml) and of the
 * settings row titles. BodyLarge IS defined in the theme
 * (TextAppearance.TaptapNG.BodyLarge): 16sp in
 * `?attr/colorOnSurface` — full contrast in both themes (dark
 * #FFE6E1E5 on #FF1C1B1F, light #FF1C1B1F on white). The Settings
 * collapsible header (item_settings_section.xml, 14sp) was NOT
 * copied: 14sp is the "tulisan kecil" size the user complained
 * about. No theme color was changed and no label moved.
 *
 * Source assertions only: visual readability cannot be tested on
 * the JVM (no Robolectric in this tree) — the deciding proof is
 * the phone screenshot. If anyone reverts any part of the fix, a
 * test here fails.
 */
class GroupsSectionLabelsTest {

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

    /** The XML block of one label TextView, from its text to its closing "/>". */
    private fun labelBlock(xml: String, stringName: String): String =
        xml.substringAfter("android:text=\"@string/$stringName\"").substringBefore("/>")

    @Test
    fun `section labels use BodyLarge like the other section headers in the app`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        for (label in listOf("groups_main_group", "groups_section_groups", "groups_section_rules")) {
            val block = labelBlock(xml, label)
            assertTrue(
                block.contains("android:textAppearance=\"?attr/textAppearanceBodyLarge\""),
                "$label must use ?attr/textAppearanceBodyLarge " +
                    "(same as the section headers in the server editor)",
            )
        }
    }

    @Test
    fun `section labels no longer use the undefined TitleSmall and TitleMedium attributes`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        assertFalse(
            xml.contains("textAppearanceTitleSmall"),
            "activity_groups.xml must not use textAppearanceTitleSmall " +
                "(Theme.TaptapNG never defines it — it resolved to ID 0)",
        )
        assertFalse(
            xml.contains("textAppearanceTitleMedium"),
            "activity_groups.xml must not use textAppearanceTitleMedium " +
                "(Theme.TaptapNG never defines it — it resolved to ID 0)",
        )
    }

    @Test
    fun `BodyLarge is defined in the theme at 16sp in onSurface`() {
        // Guard the style this fix copies: if BodyLarge ever stops
        // being defined, the labels fall back to the small default
        // again and this test says so.
        val theme = read("app/src/main/res/values/themes.xml")
        assertTrue(
            theme.contains("<item name=\"textAppearanceBodyLarge\">@style/TextAppearance.TaptapNG.BodyLarge</item>"),
            "Theme.TaptapNG must define textAppearanceBodyLarge",
        )
        val style = theme.substringAfter("TextAppearance.TaptapNG.BodyLarge\"")
            .substringBefore("</style>")
        assertTrue(style.contains("<item name=\"android:textSize\">16sp</item>"), "BodyLarge must be 16sp")
        assertTrue(
            style.contains("?attr/colorOnSurface"),
            "BodyLarge must color its text with ?attr/colorOnSurface (full contrast in both themes)",
        )
    }

    @Test
    fun `reference section headers in the server editor still use BodyLarge`() {
        // Guard the reference: if the editor headers ever change
        // style, the "same as the other section headers" claim
        // above stops being true and this test says so.
        val xml = read("app/src/main/res/layout/activity_server_editor.xml")
        for (text in listOf(
            "field_protocol",
            "section_ssh_method",
            "editor_section_network",
            "editor_section_stream_security",
            "section_xray_method",
        )) {
            val block = xml.substringAfter("android:text=\"@string/$text\"").substringBefore("/>")
            assertTrue(
                block.contains("android:textAppearance=\"?attr/textAppearanceBodyLarge\""),
                "server editor header $text must stay BodyLarge " +
                    "(the reference style for the Grup/Rute section labels)",
            )
        }
    }

    @Test
    fun `section labels keep their texts positions and neighbours`() {
        val xml = read("app/src/main/res/layout/activity_groups.xml")
        // Texts unchanged (only the textAppearance changed).
        assertTrue(xml.contains("android:text=\"@string/groups_main_group\""), "Grup utama text must stay")
        assertTrue(xml.contains("android:text=\"@string/groups_section_groups\""), "Grup proxy text must stay")
        assertTrue(xml.contains("android:text=\"@string/groups_section_rules\""), "Aturan rute text must stay")
        // Order unchanged: Grup utama card first, then Grup proxy,
        // then Aturan rute.
        assertTrue(
            xml.indexOf("groups_main_group") < xml.indexOf("groups_section_groups") &&
                xml.indexOf("groups_section_groups") < xml.indexOf("groups_section_rules"),
            "section labels must stay in order: Grup utama, Grup proxy, Aturan rute",
        )
        // The hint lines under the labels were NOT touched: they
        // still use BodySmall (12sp, onSurfaceVariant) as before.
        assertTrue(
            xml.contains("android:text=\"@string/groups_main_group_hint\""),
            "Grup utama hint must stay",
        )
        assertTrue(
            xml.contains("android:text=\"@string/groups_rules_hint\""),
            "Aturan rute hint must stay",
        )
        // Header buttons untouched by this change (v1.0.24 fix intact).
        for (id in listOf("save_main_group", "add_group", "add_rule")) {
            val block = xml.substringAfter("android:id=\"@+id/$id\"").substringBefore("/>")
            assertTrue(
                block.contains("style=\"@style/Widget.MaterialComponents.Button.OutlinedButton\""),
                "$id must stay an M2 OutlinedButton (v1.0.24)",
            )
            assertTrue(block.contains("android:textSize=\"15sp\""), "$id must stay 15sp (v1.0.24)")
        }
    }
}
