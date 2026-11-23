package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.26 phone report (screenshot
 * 2026-11-24 05:03-05:04, circled in red): the row action icons
 * — edit (pencil) + delete (trash) on each proxy-group row, and
 * move-up / move-down + edit + delete on each route-rule row —
 * were nearly invisible on the dark background.
 *
 * Root cause, from the code:
 * all four vector drawables hard-code a black fill
 * (`android:fillColor="#FF000000"` in ic_edit_24dp,
 * ic_delete_24dp, ic_arrow_up_24dp, ic_arrow_down_24dp), and the
 * six ImageButtons in item_proxy_group.xml / item_route_rule.xml
 * carried NO tint, so they rendered raw black on the near-black
 * dark surface. The SAME drawables are perfectly visible in the
 * server row (item_server.xml): btn_share / btn_edit / btn_delete
 * there all carry `android:tint="?attr/colorOnSurface"`.
 *
 * v1.0.26 fix: add `android:tint="?attr/colorOnSurface"` to all
 * six buttons, copying the server row exactly. The tint is
 * theme-adaptive — colorOnSurface is #FF1C1B1F (near-black) in
 * light mode and #FFE6E1E5 (near-white) in dark mode — so the
 * icons stay visible in both themes. The fix is at layout level
 * only: the drawables are shared (ic_edit / ic_delete are also
 * the icons of editor_toolbar.xml and log_toolbar.xml, where the
 * toolbar theme supplies its own icon tint), so changing the
 * drawable fill would leak into the menus. Positions, sizes, ids
 * and wiring are untouched.
 *
 * Source assertions only: visual readability cannot be tested on
 * the JVM (no Robolectric in this tree) — the deciding proof is
 * the phone screenshot. If anyone removes a tint, a test here
 * fails.
 */
class GroupsRowIconsTest {

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

    /** The XML block of one ImageButton, from its id to its closing "/>". */
    private fun buttonBlock(xml: String, id: String): String =
        xml.substringAfter("android:id=\"@+id/$id\"").substringBefore("/>")

    @Test
    fun `group row edit and delete icons carry the on-surface tint`() {
        val xml = read("app/src/main/res/layout/item_proxy_group.xml")
        for ((id, drawable) in listOf(
            "group_edit" to "ic_edit_24dp",
            "group_delete" to "ic_delete_24dp",
        )) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("android:tint=\"?attr/colorOnSurface\""),
                "$id must carry android:tint=\"?attr/colorOnSurface\" " +
                    "(its drawable fill is hard-coded black — without the tint " +
                    "the icon is invisible on the dark surface, v1.0.26)",
            )
            assertTrue(
                block.contains("android:src=\"@drawable/$drawable\""),
                "$id must keep its $drawable drawable",
            )
        }
    }

    @Test
    fun `rule row move edit and delete icons carry the on-surface tint`() {
        val xml = read("app/src/main/res/layout/item_route_rule.xml")
        for ((id, drawable) in listOf(
            "rule_move_up" to "ic_arrow_up_24dp",
            "rule_move_down" to "ic_arrow_down_24dp",
            "rule_edit" to "ic_edit_24dp",
            "rule_delete" to "ic_delete_24dp",
        )) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("android:tint=\"?attr/colorOnSurface\""),
                "$id must carry android:tint=\"?attr/colorOnSurface\" " +
                    "(its drawable fill is hard-coded black — without the tint " +
                    "the icon is invisible on the dark surface, v1.0.26)",
            )
            assertTrue(
                block.contains("android:src=\"@drawable/$drawable\""),
                "$id must keep its $drawable drawable",
            )
        }
    }

    @Test
    fun `row icon tint is the theme attribute not a hard-coded color`() {
        // A fixed white/black tint would fix one theme and break the
        // other; ?attr/colorOnSurface adapts (near-black light,
        // near-white dark). The FAB's @android:color/white lives in
        // activity_main.xml, not in these rows.
        for (rel in listOf(
            "app/src/main/res/layout/item_proxy_group.xml",
            "app/src/main/res/layout/item_route_rule.xml",
        )) {
            val xml = read(rel)
            assertFalse(
                xml.contains("android:tint=\"#"),
                "$rel must not use a hard-coded hex tint",
            )
            assertFalse(
                xml.contains("android:tint=\"@android:color/"),
                "$rel must not use a fixed framework color tint",
            )
            assertFalse(
                xml.contains("android:tint=\"@color/"),
                "$rel must not use a fixed app color tint",
            )
        }
    }

    @Test
    fun `row action icons keep their size background and description`() {
        val groupXml = read("app/src/main/res/layout/item_proxy_group.xml")
        for (id in listOf("group_edit", "group_delete")) {
            val block = buttonBlock(groupXml, id)
            assertTrue(block.contains("android:layout_width=\"48dp\""), "$id must stay 48dp wide")
            assertTrue(block.contains("android:layout_height=\"48dp\""), "$id must stay 48dp tall")
            assertTrue(
                block.contains("android:background=\"?attr/selectableItemBackgroundBorderless\""),
                "$id must keep its borderless ripple background",
            )
        }
        val ruleXml = read("app/src/main/res/layout/item_route_rule.xml")
        for (id in listOf("rule_move_up", "rule_move_down", "rule_edit", "rule_delete")) {
            val block = buttonBlock(ruleXml, id)
            assertTrue(block.contains("android:layout_width=\"48dp\""), "$id must stay 48dp wide")
            assertTrue(block.contains("android:layout_height=\"48dp\""), "$id must stay 48dp tall")
            assertTrue(
                block.contains("android:background=\"?attr/selectableItemBackgroundBorderless\""),
                "$id must keep its borderless ripple background",
            )
        }
        // Content descriptions untouched (accessibility + the only
        // label these icon-only buttons have).
        assertTrue(
            buttonBlock(groupXml, "group_edit").contains("android:contentDescription=\"@string/groups_edit\""),
            "group_edit must keep its edit description",
        )
        assertTrue(
            buttonBlock(groupXml, "group_delete").contains("android:contentDescription=\"@string/groups_delete\""),
            "group_delete must keep its delete description",
        )
        assertTrue(
            buttonBlock(ruleXml, "rule_move_up").contains("android:contentDescription=\"@string/groups_move_up\""),
            "rule_move_up must keep its move-up description",
        )
        assertTrue(
            buttonBlock(ruleXml, "rule_move_down").contains("android:contentDescription=\"@string/groups_move_down\""),
            "rule_move_down must keep its move-down description",
        )
    }

    @Test
    fun `drawables still have a hard-coded black fill so the layout tint stays load-bearing`() {
        // The four drawables are shared with the toolbar menus
        // (editor_toolbar.xml, log_toolbar.xml), where the toolbar
        // theme tints the icons itself — so the fill must NOT be
        // "fixed" in the drawable. This guards that the visibility
        // fix lives in the row layouts, where the tint is.
        for (drawable in listOf("ic_edit_24dp", "ic_delete_24dp", "ic_arrow_up_24dp", "ic_arrow_down_24dp")) {
            val xml = read("app/src/main/res/drawable/$drawable.xml")
            assertTrue(
                xml.contains("android:fillColor=\"#FF000000\""),
                "$drawable must keep its hard-coded black fill " +
                    "(shared drawable — the row tint, not the fill, makes it visible)",
            )
        }
    }

    @Test
    fun `colorOnSurface is dark in light mode and light in dark mode`() {
        // The tint only helps because colorOnSurface flips per theme:
        // near-black on a light surface, near-white on a dark one.
        val themes = read("app/src/main/res/values/themes.xml")
        assertTrue(
            themes.contains("<item name=\"colorOnSurface\">@color/onSurface</item>"),
            "Theme.TaptapNG must map colorOnSurface to @color/onSurface",
        )
        val light = read("app/src/main/res/values/colors.xml")
        assertTrue(
            light.contains("<color name=\"onSurface\">#FF1C1B1F</color>"),
            "light onSurface must be near-black #1C1B1F",
        )
        val dark = read("app/src/main/res/values-night/colors.xml")
        assertTrue(
            dark.contains("<color name=\"onSurface\">#FFE6E1E5</color>"),
            "dark onSurface must be near-white #E6E1E5",
        )
    }

    @Test
    fun `server row reference icons still use the same tint`() {
        // The pattern this fix copies: the server row's share/edit/
        // delete buttons (same ic_edit / ic_delete drawables) are the
        // visible reference. If they lose their tint, the pattern the
        // group/rule rows follow is gone too.
        val xml = read("app/src/main/res/layout/item_server.xml")
        for (id in listOf("btn_share", "btn_edit", "btn_delete")) {
            val block = buttonBlock(xml, id)
            assertTrue(
                block.contains("android:tint=\"?attr/colorOnSurface\""),
                "$id in the server row must keep android:tint=\"?attr/colorOnSurface\" " +
                    "(the visible reference for the group/rule row icons)",
            )
        }
    }
}
