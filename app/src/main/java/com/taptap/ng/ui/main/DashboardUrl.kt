package com.taptap.ng.ui.main

import java.net.URLEncoder

/**
 * M7 (W5): pure builder for the bundled yacd dashboard URL.
 *
 * The dashboard is served by the local Clash API (W3) at
 * `http://127.0.0.1:<port>/ui/` — never loaded from
 * `file:///android_asset/...`, so the service worker, fetch and
 * WebSocket traffic behave like a normal HTTP origin. The WebView
 * opens straight at the proxies page (`#/proxies`); when a secret
 * is set, it is passed as `?secret=` (URL-encoded) exactly like
 * yacd expects — the `/ui/` path itself is served without auth.
 *
 * Pure functions only, so this is unit-testable on the JVM. The
 * full URL (which may contain the secret) must NEVER be logged.
 */
object DashboardUrl {

    /** Default Clash API port — mirrors SettingsStore.DEFAULT_CLASH_API_PORT. */
    const val DEFAULT_PORT = 9091

    /** A TCP port is valid in 1..65535. */
    fun isValidPort(port: Int): Boolean = port in 1..65535

    /**
     * Build the dashboard URL for [port] and [secret].
     * Out-of-range ports fall back to [DEFAULT_PORT]; a blank
     * secret adds no query string.
     */
    fun build(port: Int, secret: String): String {
        val p = if (isValidPort(port)) port else DEFAULT_PORT
        val query = if (secret.isBlank()) {
            ""
        } else {
            "?secret=" + URLEncoder.encode(secret, "UTF-8")
        }
        return "http://127.0.0.1:$p/ui/$query#/proxies"
    }
}
