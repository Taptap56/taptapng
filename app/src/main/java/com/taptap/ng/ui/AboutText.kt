package com.taptap.ng.ui

/**
 * About dialog body (v1.0.8): the version shown is the APK's real
 * versionName — [com.taptap.ng.BuildConfig.VERSION_NAME], generated
 * from the same versionName aapt2 reports. v1.0.7 and earlier showed
 * a hardcoded AppConfig.VERSION_NAME = "1.0.4" on every version
 * since v1.0.5 (phone screenshot 2026-11-21 14:08: About said 1.0.4
 * on the v1.0.7 APK). Pure, so it is unit testable without an
 * Application; the body template stays in strings.xml (about_text),
 * this only substitutes the version into it.
 */
fun formatAboutText(template: String, versionName: String): String =
    template.format(versionName)
