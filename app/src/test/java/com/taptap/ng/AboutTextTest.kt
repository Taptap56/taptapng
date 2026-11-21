package com.taptap.ng

import com.taptap.ng.ui.formatAboutText
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * v1.0.8: the About dialog showed "TaptapNG 1.0.4" on every version
 * since v1.0.5 because AppConfig.VERSION_NAME was hardcoded. The
 * dialog now formats the APK's real versionName (BuildConfig) — the
 * formatter must display exactly the version it is given, nothing
 * hardcoded.
 */
class AboutTextTest {

    private val template =
        "TaptapNG %1\$s\n\nv2rayNG-style UI, rebuilt with Android Views.\n" +
            "Protocols run in-app (SSH via JSch, no xray-core bundled)."

    @Test
    fun `about text shows the version it is given`() {
        assertEquals(
            "TaptapNG 1.0.8\n\nv2rayNG-style UI, rebuilt with Android Views.\n" +
                "Protocols run in-app (SSH via JSch, no xray-core bundled).",
            formatAboutText(template, "1.0.8"),
        )
    }

    @Test
    fun `about text does not hardcode a version`() {
        // A different version string must pass through unchanged —
        // the value that used to be frozen at "1.0.4".
        assertEquals("TaptapNG 9.9.9", formatAboutText("TaptapNG %1\$s", "9.9.9"))
    }
}
