package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.25 phone report (screenshot
 * 2026-11-24 05:03, user circled in red): in every proxy-group
 * row the group name and its type collided — "taptap SELECT"
 * and "tes URL-TEST" read as one cramped blob. On the screenshot
 * the name ("taptap", "tes") renders TINY and dim, the type
 * ("SELECT", "URL-TEST") renders at full size, both on the same
 * baseline row with only 8dp between them.
 *
 * Root cause, from the code (proven against the shipped v1.0.25
 * APK, not just the source — `aapt2 dump resources` on
 * taptapng-v1.0.25.apk):
 * - `group_name` used `?attr/textAppearanceTitleSmall`, but that
 *   attribute is assigned NOWHERE in the APK: Theme.TaptapNG
 *   defines only textAppearanceBodyLarge/Medium/Small and
 *   textAppearanceTitleLarge, and the M2 parent chain
 *   (Theme.MaterialComponents.DayNight.NoActionBar, size=0, up
 *   through Base.Theme.MaterialComponents.Light) assigns it
 *   nowhere either. So it resolved to resource ID 0 — the same
 *   "Invalid resource ID 0x00000000" fallback the v1.0.4 comment
 *   in themes.xml documents — and the name fell back to the
 *   small default size with no theme color, while the type next
 *   to it rendered at its defined 12sp BodySmall. Same defect
 *   class as the v1.0.25 section labels (GroupsSectionLabelsTest).
 * - Neither label had any width bound (both wrap_content, no
 *   weight, no maxLines, no ellipsize, no maxWidth), unlike the
 *   only other two-label row in the app, item_server.xml, where
 *   the name (`remarks`) is 0dp + weight 1 + ellipsize end +
 *   maxLines 2 and the type/delay pair is bounded the same way.
 *   So a long group name could also shove the type clean out of
 *   the row, into the 96dp of edit/delete buttons.
 * - The adapter cannot rescue this at runtime:
 *   GroupAdapter.onBindViewHolder only sets `.text` on the three
 *   labels (GroupsActivity.kt) — no ellipsize, maxWidth or width
 *   is ever set in code.
 *
 * v1.0.26 fix (bug 1 of 3), same pattern as v1.0.25: the name
 * gets the defined `?attr/textAppearanceBodyLarge` (16sp,
 * colorOnSurface — the style of the section headers and of the
 * server-row name) and is bounded 0dp + weight 1 + ellipsize end
 * + maxLines 1, so the NAME yields, never the type. The type
 * keeps its defined BodySmall + colorPrimary and gains maxLines 1
 * so it can never wrap under the name.
 *
 * The route-rule row (item_route_rule.xml:37) had the identical
 * defect — `rule_pattern` used the same undefined TitleSmall and
 * was unbounded, with even less room (toggle + 4 x 48dp buttons)
 * — so it gets the identical fix. The rule type keeps its defined
 * BodySmall.
 *
 * Source assertions only: visual readability cannot be tested on
 * the JVM (no Robolectric in this tree) — the deciding proof is
 * the phone screenshot. If anyone reverts any part of the fix, a
 * test here fails.
 */
class GroupRowLabelsTest {

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

    /** The XML block of one view, from its id to its closing "/>". */
    private fun viewBlock(xml: String, id: String): String =
        xml.substringAfter("android:id=\"@+id/$id\"").substringBefore("/>")

    @Test
    fun `group name uses BodyLarge like the server-row name`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        val block = viewBlock(xml, "group_name")
        assertTrue(
            block.contains("android:textAppearance=\"?attr/textAppearanceBodyLarge\""),
            "group_name must use ?attr/textAppearanceBodyLarge " +
                "(16sp, colorOnSurface — same as the section headers " +
                "in v1.0.25 and the server-row name in item_server.xml)",
        )
    }

    @Test
    fun `group name is bounded so it yields instead of shoving the type out`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        val block = viewBlock(xml, "group_name")
        assertTrue(
            block.contains("android:layout_width=\"0dp\"") &&
                block.contains("android:layout_weight=\"1\""),
            "group_name must be 0dp + weight 1 (it takes the space " +
                "left after the type, like remarks in item_server.xml)",
        )
        assertTrue(
            block.contains("android:ellipsize=\"end\""),
            "group_name must ellipsize (a long name truncates with ..., " +
                "it must never push group_type out of the row)",
        )
        assertTrue(
            block.contains("android:maxLines=\"1\""),
            "group_name must be maxLines 1 (one line next to the type, " +
                "never wrapping under it)",
        )
    }

    @Test
    fun `group type keeps its defined style and stays on one line`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        val block = viewBlock(xml, "group_type")
        assertTrue(
            block.contains("android:textAppearance=\"?attr/textAppearanceBodySmall\""),
            "group_type must keep its defined ?attr/textAppearanceBodySmall (12sp)",
        )
        assertTrue(
            block.contains("android:textColor=\"?attr/colorPrimary\""),
            "group_type must keep its colorPrimary color (the type marker)",
        )
        assertTrue(
            block.contains("android:layout_width=\"wrap_content\""),
            "group_type must stay wrap_content (it keeps its full " +
                "width — the name yields, not the type)",
        )
        assertTrue(
            block.contains("android:maxLines=\"1\""),
            "group_type must be maxLines 1 (never wrap under the name)",
        )
    }

    @Test
    fun `group row no longer uses the undefined TitleSmall and TitleMedium attributes`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        // Match the attribute use, not the mere mention: the XML
        // comments above the fixed views name the old attribute as
        // documentation of the root cause.
        assertFalse(
            xml.contains("android:textAppearance=\"?attr/textAppearanceTitleSmall\""),
            "item_proxy_group.xml must not use textAppearanceTitleSmall " +
                "(Theme.TaptapNG never defines it — it resolved to ID 0 " +
                "and the name rendered tiny and dim, see the 05:03 screenshot)",
        )
        assertFalse(
            xml.contains("android:textAppearance=\"?attr/textAppearanceTitleMedium\""),
            "item_proxy_group.xml must not use textAppearanceTitleMedium " +
                "(Theme.TaptapNG never defines it either)",
        )
    }

    @Test
    fun `rule pattern uses BodyLarge and is bounded like the group name`() {
        val xml = read("app/src/main/res/layout/item_route_rule.xml")
        val block = viewBlock(xml, "rule_pattern")
        assertTrue(
            block.contains("android:textAppearance=\"?attr/textAppearanceBodyLarge\""),
            "rule_pattern must use ?attr/textAppearanceBodyLarge " +
                "(same undefined-TitleSmall defect as group_name, " +
                "item_route_rule.xml:37)",
        )
        assertTrue(
            block.contains("android:layout_width=\"0dp\"") &&
                block.contains("android:layout_weight=\"1\""),
            "rule_pattern must be 0dp + weight 1 (the rule row has " +
                "even less room: toggle + 4 x 48dp buttons)",
        )
        assertTrue(
            block.contains("android:ellipsize=\"end\""),
            "rule_pattern must ellipsize (a long pattern truncates, " +
                "it must never push the target or buttons out)",
        )
        assertTrue(
            block.contains("android:maxLines=\"1\""),
            "rule_pattern must be maxLines 1",
        )
    }

    @Test
    fun `rule type keeps its defined style and rule row drops TitleSmall`() {
        val xml = read("app/src/main/res/layout/item_route_rule.xml")
        val block = viewBlock(xml, "rule_type")
        assertTrue(
            block.contains("android:textAppearance=\"?attr/textAppearanceBodySmall\""),
            "rule_type must keep its defined ?attr/textAppearanceBodySmall (12sp)",
        )
        assertTrue(
            block.contains("android:textColor=\"?attr/colorPrimary\""),
            "rule_type must keep its colorPrimary color",
        )
        assertTrue(
            block.contains("android:maxLines=\"1\""),
            "rule_type must be maxLines 1",
        )
        assertFalse(
            xml.contains("android:textAppearance=\"?attr/textAppearanceTitleSmall\""),
            "item_route_rule.xml must not use textAppearanceTitleSmall " +
                "(Theme.TaptapNG never defines it — it resolved to ID 0)",
        )
        assertFalse(
            xml.contains("android:textAppearance=\"?attr/textAppearanceTitleMedium\""),
            "item_route_rule.xml must not use textAppearanceTitleMedium",
        )
    }

    @Test
    fun `BodyLarge is defined in the theme at 16sp in onSurface`() {
        // Guard the style this fix copies: if BodyLarge ever stops
        // being defined, the names fall back to the small default
        // again and this test says so. (Same guard as
        // GroupsSectionLabelsTest, which owns the section labels.)
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
    fun `group row keeps its ids order and action buttons`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        // Row structure untouched: name + type on the first line,
        // detail below, edit/delete on the right.
        assertTrue(
            xml.indexOf("group_name") < xml.indexOf("group_type") &&
                xml.indexOf("group_type") < xml.indexOf("group_detail"),
            "group row order must stay: name, type, then detail below",
        )
        assertTrue(
            xml.indexOf("group_detail") < xml.indexOf("group_edit") &&
                xml.indexOf("group_edit") < xml.indexOf("group_delete"),
            "group row actions must stay after the text: edit, then delete",
        )
        // Edit/delete buttons untouched by this change (their dark
        // icons are bug 2 of 3, owned by another worker — not here).
        for ((id, icon) in listOf("group_edit" to "ic_edit_24dp", "group_delete" to "ic_delete_24dp")) {
            val block = viewBlock(xml, id)
            assertTrue(block.contains("android:layout_width=\"48dp\""), "$id must stay 48dp")
            assertTrue(block.contains("android:src=\"@drawable/$icon\""), "$id must keep its $icon icon")
        }
        // Adapter binding untouched: the name still shows the group
        // name and the type still shows SELECT / URL-TEST / FALLBACK.
        val src = read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")
        assertTrue(src.contains("holder.name.text = group.name"), "adapter must still bind the group name")
        assertTrue(src.contains("holder.type.text = typeLabel(group.type)"), "adapter must still bind the type label")
        assertTrue(src.contains("holder.detail.text = buildString"), "adapter must still bind the detail line")
    }
}
