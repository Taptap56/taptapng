package com.taptap.x

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.2 toolbar bug (screenshot 2026-11-20):
 * the MainActivity toolbar's right side was empty — no search, no +,
 * no more menu — so the user could not add any server.
 *
 * Root cause, proven from code + screenshot:
 * 1. The menu was only set via `app:menu` in the layout XML. Once the
 *    Toolbar becomes the support ActionBar, AppCompat owns its menu
 *    and the XML-inflated items do not survive — the menu is empty at
 *    runtime. (Even the white search icon was absent, so it was not
 *    a color problem.) The menu MUST be inflated in
 *    onCreateOptionsMenu.
 * 2. Clicks arrive via onOptionsItemSelected, not via the Toolbar's
 *    own setOnMenuItemClickListener (the ActionBar wrapper replaces
 *    it), so the old listener was dead code.
 * 3. The + / more / save icons were black-filled (#FF000000) on a
 *    dark toolbar (night surface #FF1C1B1F) — invisible even if shown.
 *
 * The same bug also hid the editor's save checkmark, so this test
 * covers ServerEditorActivity as well. LogActivity is a standalone
 * Toolbar (no setSupportActionBar), so its app:menu pattern is fine
 * and is intentionally not covered here.
 *
 * These are source/resource assertions: the toolbar wiring cannot be
 * exercised on the JVM without an emulator, but if anyone reverts
 * any part of the fix, a test here fails.
 */
class MainToolbarTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/menu/main_toolbar.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    @Test
    fun `main toolbar menu defines search add and more`() {
        val xml = read("app/src/main/res/menu/main_toolbar.xml")
        assertTrue(xml.contains("android:id=\"@+id/action_search\""), "search item missing")
        assertTrue(xml.contains("android:icon=\"@drawable/ic_search_24dp\""), "search icon missing")
        assertTrue(
            xml.contains("app:actionViewClass=\"androidx.appcompat.widget.SearchView\""),
            "search must use SearchView action view",
        )
        assertTrue(xml.contains("android:id=\"@+id/action_add\""), "add item missing")
        assertTrue(xml.contains("android:icon=\"@drawable/ic_add_24dp\""), "add icon missing")
        assertTrue(xml.contains("android:id=\"@+id/action_more\""), "more item missing")
        assertTrue(xml.contains("android:icon=\"@drawable/ic_more_vert_24dp\""), "more icon missing")
        // Add and more must always show as action (v2rayNG parity).
        assertTrue(xml.contains("app:showAsAction=\"always\""), "add/more must be always visible")
    }

    @Test
    fun `editor toolbar menu defines save`() {
        val xml = read("app/src/main/res/menu/editor_toolbar.xml")
        assertTrue(xml.contains("android:id=\"@+id/action_save\""), "save item missing")
        assertTrue(xml.contains("android:icon=\"@drawable/ic_action_done\""), "save icon missing")
        assertTrue(xml.contains("app:showAsAction=\"always\""), "save must be always visible")
    }

    @Test
    fun `editor toolbar menu defines delete for existing servers`() {
        val xml = read("app/src/main/res/menu/editor_toolbar.xml")
        assertTrue(xml.contains("android:id=\"@+id/action_delete\""), "delete item missing")
        assertTrue(xml.contains("android:icon=\"@drawable/ic_delete_24dp\""), "delete icon missing")
        val src = read("app/src/main/java/com/taptap/x/ui/server/ServerEditorActivity.kt")
        assertTrue(
            src.contains("menu.findItem(R.id.action_delete)?.isVisible = existing != null"),
            "delete must only show when editing an existing server",
        )
        assertTrue(
            src.contains("R.id.action_delete"),
            "editor must handle the delete menu item",
        )
    }

    @Test
    fun `toolbar icons are white not black`() {
        // Night toolbar surface is #FF1C1B1F (near-black); a black
        // fill would be invisible on it. Search was already white;
        // add / more / done were black in v1.0.2.
        for (icon in listOf("ic_search_24dp", "ic_add_24dp", "ic_more_vert_24dp", "ic_action_done")) {
            val xml = read("app/src/main/res/drawable/$icon.xml")
            assertFalse(
                xml.contains("#FF000000"),
                "$icon must not use black fill on the dark toolbar",
            )
            assertTrue(
                xml.contains("@android:color/white"),
                "$icon must be white-filled to be visible on the dark toolbar",
            )
        }
    }

    @Test
    fun `main activity inflates menu in onCreateOptionsMenu`() {
        val src = read("app/src/main/java/com/taptap/x/ui/MainActivity.kt")
        assertTrue(
            src.contains("override fun onCreateOptionsMenu(menu: Menu): Boolean"),
            "MainActivity must override onCreateOptionsMenu",
        )
        assertTrue(
            src.contains("menuInflater.inflate(R.menu.main_toolbar, menu)"),
            "MainActivity must inflate main_toolbar in onCreateOptionsMenu",
        )
        assertTrue(
            src.contains("override fun onOptionsItemSelected(item: MenuItem): Boolean"),
            "MainActivity must override onOptionsItemSelected (clicks route there)",
        )
        assertFalse(
            src.contains("toolbar.setOnMenuItemClickListener"),
            "Toolbar's own click listener is dead once it is the support ActionBar " +
                "(PopupMenu listeners elsewhere in the file are fine)",
        )
        val layout = read("app/src/main/res/layout/activity_main.xml")
        assertFalse(
            layout.contains("app:menu=\"@menu/main_toolbar\""),
            "layout must not also set app:menu for the toolbar (would duplicate " +
                "items inflated in onCreateOptionsMenu; the drawer NavigationView " +
                "app:menu is unrelated and stays)",
        )
    }

    @Test
    fun `editor activity inflates menu in onCreateOptionsMenu`() {
        val src = read("app/src/main/java/com/taptap/x/ui/server/ServerEditorActivity.kt")
        assertTrue(
            src.contains("override fun onCreateOptionsMenu(menu: Menu): Boolean"),
            "ServerEditorActivity must override onCreateOptionsMenu",
        )
        assertTrue(
            src.contains("menuInflater.inflate(R.menu.editor_toolbar, menu)"),
            "ServerEditorActivity must inflate editor_toolbar in onCreateOptionsMenu",
        )
        assertTrue(
            src.contains("override fun onOptionsItemSelected(item: MenuItem): Boolean"),
            "ServerEditorActivity must override onOptionsItemSelected",
        )
        assertFalse(
            src.contains("toolbar.setOnMenuItemClickListener"),
            "Toolbar's own click listener is dead once it is the support ActionBar",
        )
        val layout = read("app/src/main/res/layout/activity_server_editor.xml")
        assertFalse(
            layout.contains("app:menu=\"@menu/editor_toolbar\""),
            "layout must not also set app:menu for the toolbar (would duplicate items inflated in onCreateOptionsMenu)",
        )
    }
}
