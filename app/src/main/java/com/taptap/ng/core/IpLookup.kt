package com.taptap.ng.core

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * "Current connection info" lookup (v1.0.5, group A — v2rayNG's
 * IP API test, Settings > Advanced > "Current connection info
 * test URL").
 *
 * No lookup existed in the app before this: [ipApiUrl] was stored
 * and shown, but never fetched. The lookup runs on demand from the
 * main screen's More menu ("Cek IP") and shows the result as a
 * toast — it never writes into the status bar, which reflects the
 * CONNECTION state (v1.0.9). An empty stored URL falls back to
 * the v2rayNG default, https://api.ip.sb/geoip.
 *
 * The fetch itself is injectable ([fetcher]) so tests can prove
 * the custom URL is used without touching the network. The real
 * fetch is a plain GET with a 10 s timeout; only the "ip" field
 * of the JSON reply is shown (the full geoip body is not logged
 * or displayed). Never called with a proxy URL — only the
 * configured IP API URL.
 */
object IpLookup {

    const val DEFAULT_URL = "https://api.ip.sb/geoip"

    /** Stored URL, or the default when blank (v2rayNG rule). */
    fun effectiveUrl(stored: String): String =
        stored.ifBlank { DEFAULT_URL }

    private val IP_FIELD = Regex(""""ip"\s*:\s*"([^"]+)"""")

    /**
     * The public IP from a geoip JSON body ("1.2.3.4"), or the
     * trimmed body itself when it carries no "ip" field (e.g. a
     * plain-text IP API). Truncated to 200 chars for display.
     */
    fun extractIp(body: String): String {
        val ip = IP_FIELD.find(body)?.groupValues?.getOrNull(1)
        if (!ip.isNullOrBlank()) return ip
        return body.trim().take(200)
    }

    /** GET [url], return the response body. Throws on HTTP error / timeout. */
    fun httpGet(url: String): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("User-Agent", "TaptapNG")
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) throw IOException("HTTP $code")
            return conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Look the public IP up through the configured URL (blank =
     * default). Returns the display string; throws on failure —
     * callers turn that into a toast, never a status-bar write.
     */
    fun fetchIp(stored: String, fetcher: (String) -> String = ::httpGet): String =
        extractIp(fetcher(effectiveUrl(stored)))
}
