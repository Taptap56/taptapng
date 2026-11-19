package com.taptap.x.core

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Structured dial logging (v1.0.6, fix E).
 *
 * Phone evidence (taptapx-3.txt, 2026-11-20 02:47): the v1.0.5 log
 * contained ZERO dial lines — only UI navigation. The app never
 * logged a dial stage to logcat, so a failed connect left no trace
 * anywhere. Every dial stage now logs here, with a stable tag
 * ("TaptapX-Dial") that logcat and the in-app Log page both show.
 *
 * Two surfaces, one write:
 * - logcat, via [logcatSink] (wired in TaptapXApp to android.util.Log;
 *   null in unit tests, where android.util.Log is a stub).
 * - an in-memory ring buffer ([lines]), shown at the top of the
 *   LogActivity — it survives `logcat -c` and rotation.
 *
 * NEVER log credentials: [failure] includes the exception message
 * only for network exception types (our own stage tags and system
 * socket messages — neither carries a UUID, password, or key) and
 * for IllegalStateException (our own state errors: "protect() gagal",
 * "Entry Onering belum didukung", "Gagal establish TUN" — audited,
 * all throw sites are static messages with no user input). Anything
 * else (e.g. IllegalArgumentException, which UUID parsing throws
 * with the raw input in the message) logs the class name only.
 */
object DialLog {

    const val TAG = "TaptapX-Dial"
    /**
     * Ring buffer size. v1.0.10: 500, up from 200 — the forwarder
     * log now flows like v2rayNG's (a line per connection/DNS
     * query), and 200 lines evict during one page load, so the
     * dial stages the user needs disappear before they open the
     * Log page. 500 lines is still ~50 KB in memory.
     */
    const val MAX_LINES = 500

    /** Set by the app to forward lines to logcat. Null = ring buffer only. */
    @Volatile
    var logcatSink: ((tag: String, message: String) -> Unit)? = null

    private val lock = Any()
    private val lines = ArrayDeque<String>()

    fun log(stage: String, message: String) {
        add("$stage $message")
    }

    fun failure(stage: String, e: Throwable) {
        add("$stage GAGAL: ${safeFailure(e)}")
    }

    private fun safeFailure(e: Throwable): String {
        val cls = e.javaClass.simpleName
        return when (e) {
            is java.net.SocketTimeoutException,
            is java.net.ConnectException,
            is javax.net.ssl.SSLException,
            is java.io.EOFException,
            is java.io.IOException,
            // v1.0.7: our own state errors carry the diagnosis
            // ("protect() gagal — dial tidak bisa bypass VPN") — the
            // v1.0.6 phone log only ever said "IllegalStateException",
            // which named nothing. Deliberately NOT extended to
            // IllegalArgumentException: UUID.fromString throws that
            // type with the raw UUID in the message.
            is IllegalStateException -> "$cls: ${e.message}"
            else -> cls
        }
    }

    private fun add(text: String) {
        val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val line = "[$stamp] $text"
        synchronized(lock) {
            if (lines.size >= MAX_LINES) lines.removeFirst()
            lines.addLast(line)
        }
        runCatching { logcatSink?.invoke(TAG, line) }
    }

    fun lines(): List<String> = synchronized(lock) { lines.toList() }

    fun clear() = synchronized(lock) { lines.clear() }
}
