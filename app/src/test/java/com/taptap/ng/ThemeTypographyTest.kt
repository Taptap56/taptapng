package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.3 phone report (screenshot + logcat
 * 2026-11-20 01:06): server-row text was small and dark, row icons
 * black on the dark background, and Settings flooded the log with
 * "Invalid resource ID 0x00000000".
 *
 * Root cause, proven from the compiled v1.0.3 APK (aapt2 dump):
 * Theme.TaptapNG (M2, Theme.MaterialComponents) never defined the M3
 * typography attributes textAppearanceBodyLarge/Medium/Small and
 * textAppearanceTitleLarge, so every `?attr/textAppearance*`
 * reference in the layouts and in androidx.preference 1.2.1's
 * layouts resolved to resource ID 0 — no size, no color, and one
 * "Invalid resource ID" log line per TextView bound (the Settings
 * flood, ~15 lines at inflation + more per scroll rebind).
 *
 * v1.0.4 fix: define the four attributes in the theme with explicit
 * M3-standard sizes and theme-adaptive colors, and put explicit
 * textSize + ?attr/colorOnSurface(Variant) on the row / status
 * TextViews (the explicit color is the mechanism already proven by
 * the address line, which rendered light grey correctly in v1.0.3
 * while the remarks — no explicit color — rendered near-black).
 *
 * Source/resource assertions: runtime rendering cannot be exercised
 * on the JVM, but if anyone reverts any part of the fix, a test here
 * fails.
 */
class ThemeTypographyTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/values/themes.xml").exists()) return dir
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
    fun `theme defines the M3 typography attributes`() {
        val xml = read("app/src/main/res/values/themes.xml")
        for (attr in listOf(
            "textAppearanceBodyLarge",
            "textAppearanceBodyMedium",
            "textAppearanceBodySmall",
            "textAppearanceTitleLarge",
        )) {
            assertTrue(
                xml.contains("<item name=\"$attr\">@style/TextAppearance.TaptapNG."),
                "Theme.TaptapNG must define $attr (M2 theme does not; it resolved to ID 0)",
            )
        }
    }

    @Test
    fun `typography styles use M3 sizes and theme-adaptive colors`() {
        val xml = read("app/src/main/res/values/themes.xml")
        // BodyLarge 16sp / BodyMedium 14sp / BodySmall 12sp /
        // TitleLarge 22sp — M3-standard sizes.
        assertTrue(xml.contains("TextAppearance.TaptapNG.BodyLarge"), "BodyLarge style missing")
        assertTrue(xml.contains("TextAppearance.TaptapNG.BodyMedium"), "BodyMedium style missing")
        assertTrue(xml.contains("TextAppearance.TaptapNG.BodySmall"), "BodySmall style missing")
        assertTrue(xml.contains("TextAppearance.TaptapNG.TitleLarge"), "TitleLarge style missing")
        // No hardcoded black/dark text color in the typography styles:
        // colors must come from ?attr/colorOnSurface(Variant) so they
        // are light in dark mode and dark in light mode.
        for (style in listOf("BodyLarge", "BodyMedium", "BodySmall", "TitleLarge")) {
            val section = xml.substringAfter("TextAppearance.TaptapNG.$style\"")
                .substringBefore("</style>")
            assertTrue(
                section.contains("?attr/colorOnSurface"),
                "$style must color its text with ?attr/colorOnSurface(Variant)",
            )
            assertFalse(
                section.contains("#FF000000") || section.contains("#FF1C1B1F"),
                "$style must not hardcode a dark text color",
            )
        }
        assertTrue(xml.contains("<item name=\"android:textSize\">16sp</item>"), "BodyLarge must be 16sp")
        assertTrue(xml.contains("<item name=\"android:textSize\">14sp</item>"), "BodyMedium must be 14sp")
        assertTrue(xml.contains("<item name=\"android:textSize\">12sp</item>"), "BodySmall must be 12sp")
        assertTrue(xml.contains("<item name=\"android:textSize\">22sp</item>"), "TitleLarge must be 22sp")
    }

    @Test
    fun `server row has explicit v2rayNG-like sizes and adaptive colors`() {
        val xml = read("app/src/main/res/layout/item_server.xml")
        // Remarks: 18sp bold (v2rayNG parity) + onSurface — the
        // v1.0.3 row rendered 14sp near-black because it relied on
        // the broken textAppearance alone.
        val remarks = xml.substringAfter("android:id=\"@+id/remarks\"")
            .substringBefore("/>")
        assertTrue(remarks.contains("android:textSize=\"18sp\""), "remarks must be 18sp")
        assertTrue(
            remarks.contains("android:textColor=\"?attr/colorOnSurface\""),
            "remarks must use ?attr/colorOnSurface (light in dark mode)",
        )
        // Address: 15sp + onSurfaceVariant (already correct in v1.0.3).
        val stats = xml.substringAfter("android:id=\"@+id/statistics\"")
            .substringBefore("/>")
        assertTrue(stats.contains("android:textSize=\"15sp\""), "address must be 15sp")
        assertTrue(
            stats.contains("android:textColor=\"?attr/colorOnSurfaceVariant\""),
            "address must use ?attr/colorOnSurfaceVariant",
        )
        // Type + delay: 13sp.
        val type = xml.substringAfter("android:id=\"@+id/type_desc\"")
            .substringBefore("/>")
        assertTrue(type.contains("android:textSize=\"13sp\""), "type_desc must be 13sp")
        val delay = xml.substringAfter("android:id=\"@+id/delay\"")
            .substringBefore("/>")
        assertTrue(delay.contains("android:textSize=\"13sp\""), "delay must be 13sp")
        // Row action icons: theme-adaptive tint, not black fill.
        for (btn in listOf("btn_share", "btn_edit", "btn_delete")) {
            val section = xml.substringAfter("android:id=\"@+id/$btn\"")
                .substringBefore("/>")
            assertTrue(
                section.contains("android:tint=\"?attr/colorOnSurface\""),
                "$btn must tint its icon with ?attr/colorOnSurface",
            )
        }
    }

    @Test
    fun `status bar and empty view have explicit sizes and adaptive colors`() {
        val xml = read("app/src/main/res/layout/activity_main.xml")
        val status = xml.substringAfter("android:id=\"@+id/status_text\"")
            .substringBefore("/>")
        assertTrue(status.contains("android:textSize=\"15sp\""), "status_text must be 15sp")
        assertTrue(
            status.contains("android:textColor=\"?attr/colorOnSurface\""),
            "status_text must use ?attr/colorOnSurface (v1.0.3 showed it near-black)",
        )
        val empty = xml.substringAfter("android:id=\"@+id/empty_servers\"")
            .substringBefore("/>")
        assertTrue(empty.contains("android:textSize=\"15sp\""), "empty_servers must be 15sp")
    }

    @Test
    fun `toolbar and log menu icons use theme-adaptive iconTint`() {
        // White-filled icons from v1.0.3 are invisible in light mode;
        // black-filled log icons were invisible in dark mode. iconTint
        // with ?attr/colorOnSurface fixes both directions.
        for (menu in listOf("main_toolbar", "editor_toolbar", "log_toolbar")) {
            val xml = read("app/src/main/res/menu/$menu.xml")
            assertTrue(
                xml.contains("app:iconTint=\"?attr/colorOnSurface\""),
                "$menu must tint its icons with ?attr/colorOnSurface",
            )
        }
    }

    @Test
    fun `server remarks are always bold like v2rayNG`() {
        val src = read("app/src/main/java/com/taptap/x/ui/main/ServerAdapter.kt")
        assertTrue(
            src.contains("holder.remarks.setTypeface(null, Typeface.BOLD)"),
            "remarks must be bold on every row, not only the selected one",
        )
        assertFalse(
            src.contains("if (selected) Typeface.BOLD else Typeface.NORMAL"),
            "selected-only bold left unselected rows thin and hard to read",
        )
    }
}
