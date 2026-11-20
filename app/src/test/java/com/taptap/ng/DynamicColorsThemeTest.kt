package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the leftover 1x "Invalid resource ID 0x00000000"
 * per LogActivity open in v1.0.4 (log taptapng-2.txt: 01:40:58.221 and
 * 01:41:21.705; same single line at LogActivity creation in v1.0.3,
 * taptapng.txt 01:05:21.028 — so it is NOT the log_toolbar iconTint
 * added in v1.0.4, and NOT the M3 typography attributes fixed there).
 *
 * Root cause, proven from the shipped v1.0.4 APK (aapt2 dump + dexdump):
 * Theme.TaptapNG (M2, Theme.MaterialComponents) never defined the
 * `dynamicColorThemeOverlay` attribute — only M3 themes do — while
 * TaptapNGApp registers DynamicColors.applyToActivitiesIfAvailable
 * (dynamic_color default ON, SDK 31+). Material 1.13.0's DynamicColors
 * callback resolves the overlay from that theme attribute on EVERY
 * activity creation (onActivityPreCreated) and calls
 * theme.applyStyle(id, true) WITHOUT a zero check, so the undefined
 * attribute resolved to resource ID 0 and AssetManager2 logged
 * "Invalid resource ID 0x00000000." once per activity — no crash, no
 * visual defect (applyStyle(0) is a silent no-op), and dynamic colors
 * never actually applied. It is not LogActivity-specific at all:
 * Main/Editor/Settings creations log the same single line, their
 * creations just predate both log windows.
 *
 * Fix: define the attribute in Theme.TaptapNG with an intentionally
 * EMPTY overlay, so applyStyle becomes a no-op on a valid style ID:
 * the error disappears and the fixed v2rayNG palette is untouched.
 * (Pointing it at ThemeOverlay.Material3.DynamicColors instead would
 * recolor the app with wallpaper-derived Material You colors.)
 *
 * Source assertions: runtime theming cannot be exercised on the JVM,
 * but if anyone removes the attribute or fills the overlay, a test
 * here fails.
 */
class DynamicColorsThemeTest {

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
    fun `theme defines dynamicColorThemeOverlay`() {
        val xml = read("app/src/main/res/values/themes.xml")
        assertTrue(
            xml.contains(
                "<item name=\"dynamicColorThemeOverlay\">" +
                    "@style/ThemeOverlay.TaptapNG.DynamicColors</item>"
            ),
            "Theme.TaptapNG must define dynamicColorThemeOverlay (M2 theme " +
                "does not; DynamicColors then resolves it to ID 0 and " +
                "applyStyle(0) logs 'Invalid resource ID 0x00000000' " +
                "once per activity creation)",
        )
    }

    @Test
    fun `dynamic colors overlay is intentionally empty`() {
        val xml = read("app/src/main/res/values/themes.xml")
        // The overlay style must exist (a missing style would break the
        // reference above) and define NO items: applying it must not
        // recolor the fixed v2rayNG palette.
        assertTrue(
            xml.contains("style name=\"ThemeOverlay.TaptapNG.DynamicColors\""),
            "ThemeOverlay.TaptapNG.DynamicColors style missing",
        )
        val block = xml.substringAfter("style name=\"ThemeOverlay.TaptapNG.DynamicColors\"")
            .substringBefore("</style>")
        assertFalse(
            block.contains("<item"),
            "ThemeOverlay.TaptapNG.DynamicColors must stay empty — any " +
                "<item> in it would be applied to every activity theme " +
                "and change the fixed v2rayNG colors",
        )
    }

    @Test
    fun `dynamic colors registration is still present`() {
        // The fix lives in the theme, not by removing the registration:
        // TaptapNGApp must still register DynamicColors, otherwise this
        // test and `theme defines dynamicColorThemeOverlay` go away
        // together (deliberate removal of the registration is the only
        // other correct fix, and it must be a conscious decision).
        val src = read("app/src/main/java/com/taptap/x/TaptapNGApp.kt")
        assertTrue(
            src.contains("DynamicColors.applyToActivitiesIfAvailable"),
            "TaptapNGApp must still register DynamicColors — the error " +
                "is fixed by defining dynamicColorThemeOverlay in the " +
                "theme, not by dropping the registration",
        )
    }
}
