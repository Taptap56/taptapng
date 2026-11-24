package com.taptap.ng.core

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Structured dial logging (v1.0.6, fix E).
 *
 * Phone evidence (taptapng-3.txt, 2026-11-20 02:47): the v1.0.5 log
 * contained ZERO dial lines — only UI navigation. The app never
 * logged a dial stage to logcat, so a failed connect left no trace
 * anywhere. Every dial stage now logs here, with a stable tag
 * ("TaptapNG-Dial") that logcat and the in-app Log page both show.
 *
 * Two surfaces, one write:
 * - logcat, via [logcatSink] (wired in TaptapNGApp to android.util.Log;
 *   null in unit tests, where android.util.Log is a stub).
 * - an in-memory ring buffer ([lines]), shown at the top of the
 *   LogActivity — it survives `logcat -c` and rotation.
 *
 * NEVER log credentials: [failure] includes the exception message
 * only for network exception types (our own stage tags and system
 * socket messages — neither carries a UUID, password, or key) and
 * for IllegalStateException (our own state errors: "protect() gagal",
 * "Entry Onering belum didukung" (v1.0.4–v1.0.22, M4 belum dibangun), "Gagal establish TUN" — audited,
 * all throw sites are static messages with no user input). Anything
 * else (e.g. IllegalArgumentException, which UUID parsing throws
 * with the raw input in the message) logs the class name only.
 */
object DialLog {

    const val TAG = "TaptapNG-Dial"

    /**
     * Log verbosity (v1.0.5, group A): maps [SettingsStore.coreLogLevel]
     * ("debug" / "info" / "warning" / "error") onto the ring buffer +
     * logcat. Plain [log] lines are INFO, [failure] lines are ERROR,
     * [debug] lines are DEBUG. A line is kept only when its level is
     * at or above [minLevel]; "none" keeps nothing, and any unknown
     * value falls back to DEBUG (show everything) — see [levelFor].
     *
     * The UNCONFIGURED default is DEBUG (show everything): the
     * v1.0.4 behaviour and the XVEON-parity log sequence are
     * unchanged until the stored setting is applied (TaptapNGApp
     * applies it at startup, Settings applies it on change). The
     * stored default is "info" (v1.0.5 integration — NOT v2rayNG's
     * "warning", which would hide every INFO dial line by default),
     * so a fresh install keeps the full dial log; the user can pick
     * "warning" or "error" in Settings > Core to narrow it.
     */
    enum class Level { DEBUG, INFO, WARNING, ERROR, NONE }

    /** Lowest level kept. Volatile: set on the main thread, read on dial threads. */
    @Volatile
    var minLevel: Level = Level.DEBUG

    /** Parse a stored coreLogLevel value ("debug"/"info"/"warning"/"error"/"none"). */
    fun levelFor(value: String): Level = when (value.trim().lowercase()) {
        "debug" -> Level.DEBUG
        "info" -> Level.INFO
        "warning", "warn" -> Level.WARNING
        "error" -> Level.ERROR
        "none" -> Level.NONE
        else -> Level.DEBUG
    }

    /** Apply a stored coreLogLevel value to [minLevel]. */
    fun applyLevel(value: String) {
        minLevel = levelFor(value)
    }
    /**
     * Ring buffer size. v1.0.10: 500, up from 200 — the forwarder
     * log now flows like v2rayNG's (a line per connection/DNS
     * query), and 200 lines evict during one page load, so the
     * dial stages the user needs disappear before they open the
     * Log page. v1.0.17: 5000 — a Speedtest + background traffic
     * produces well over 500 lines, so the download phase was
     * evicted before the user exported the log (phone logs
     * taptapng-40774e0e.txt / taptapng-9c8c1aca.txt, 2026-11-20:
     * log 1 kept only the upload phase, log 2 only background
     * traffic). 5000 lines is still ~500 KB in memory.
     */
    const val MAX_LINES = 5000

    /** Set by the app to forward lines to logcat. Null = ring buffer only. */
    @Volatile
    var logcatSink: ((tag: String, message: String) -> Unit)? = null

    private val lock = Any()
    /** Ring entries, oldest first. [Entry.seq] is monotonic per line. */
    private data class Entry(val seq: Long, val line: String)
    private val lines = ArrayDeque<Entry>()

    /** Monotonic line counter; never reset (see [linesSince]). */
    private val seqCounter = AtomicLong(0L)

    /**
     * v1.0.31 (battery, H4a): the newest SPEED line, cached at
     * write time so the status-bar refresh no longer copies the
     * whole ring every 2 s to find it (see
     * [com.taptap.ng.ui.main.SpeedDisplay.latestSpeedSummaryFromLine]).
     * A SPEED line's message starts with "SPEED " (see
     * [com.taptap.ng.core.proto.SpeedStats.windowLine] /
     * [com.taptap.ng.core.proto.SpeedStats.totalLine]); the stage
     * is not rendered, so the message itself is the marker.
     * Cleared by [clear]; a SPEED line evicted by the ring cap
     * stays cached — it is still the newest SPEED line.
     */
    private val latestSpeedLine = AtomicReference<String?>(null)

    /** Newest SPEED line, or null when none was logged yet. */
    fun latestSpeedLine(): String? = latestSpeedLine.get()

    /** Sequence of the newest line written so far (0 = none). */
    fun currentSequence(): Long = seqCounter.get()

    /**
     * v1.0.31 (battery, H4b): lines appended after [fromSeq],
     * in order, with the current sequence — O(new lines), never
     * a full-ring copy. A [fromSeq] older than the ring (or -1)
     * returns the whole ring (snapshot); a [fromSeq] at/after
     * the newest line returns an empty list. [clear] does NOT
     * reset the counter, so a tailer holding a pre-clear
     * sequence correctly receives only lines written after it.
     */
    fun linesSince(fromSeq: Long): Pair<Long, List<String>> = synchronized(lock) {
        val fresh = ArrayList<String>()
        for (i in lines.indices.reversed()) {
            val e = lines[i]
            if (e.seq <= fromSeq) break
            fresh.add(e.line)
        }
        fresh.reverse()
        seqCounter.get() to fresh
    }

    /**
     * v1.0.3 (XVEON parity): a line is timestamp + message ONLY —
     * no "[STAGE]" prefix. XVEON's log has no stage tags
     * ("Connecting TCP socket to ...", not "TCP Connecting TCP
     * socket to ..."). The [stage] parameter stays so the 70+
     * call sites keep compiling and so the failure label below
     * keeps working; it is deliberately NOT rendered here.
     * Messages are self-describing ("TLS handshake -> SNI: ...",
     * "PRIME OK ..."), and [failure] still renders the stage as
     * the failure label ("TLS GAGAL: ...") — see below.
     */
    fun log(stage: String, message: String) = log(stage, message, Level.INFO)

    /** Verbose line, kept only at level debug. */
    fun debug(stage: String, message: String) = log(stage, message, Level.DEBUG)

    fun log(stage: String, message: String, level: Level) {
        if (level < minLevel || level == Level.NONE) return
        // The stage is deliberately NOT rendered (see KDoc above).
        add(message)
    }

    fun failure(stage: String, e: Throwable) {
        if (Level.ERROR < minLevel) return
        add("$stage GAGAL: ${safeFailure(e)}${failureTrace(e)}")
    }

    /**
     * v1.0.18: the full stack trace rides along with the failure
     * line (capped at [MAX_FAILURE_TRACE_FRAMES] frames) so a
     * START GAGAL on the phone can actually be diagnosed from the
     * exported log — v1.0.17 only ever printed the exception class
     * name ("ClassCastException"), which named nothing. Frames
     * only, never the exception message: [stackTraceToString]
     * would print the message verbatim, and for unsafe types
     * (e.g. IllegalArgumentException from UUID parsing) the
     * message carries the raw input — see [safeFailure]. The
     * trace stays in the log (ring buffer + logcat); the toast /
     * status text comes from [com.taptap.ng.service.TaptapVpnService]
     * via `dialFailureReason` and is untouched by this.
     */
    const val MAX_FAILURE_TRACE_FRAMES = 30

    private fun failureTrace(e: Throwable): String {
        val frames = e.stackTrace.take(MAX_FAILURE_TRACE_FRAMES)
        if (frames.isEmpty()) return ""
        return buildString {
            append("\n    stack trace (${e.javaClass.simpleName}):")
            for (f in frames) append("\n    at $f")
        }
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

    /**
     * v1.0.16 (battery/CPU): SimpleDateFormat dibuat SEKALI per thread.
     * Sebelumnya satu objek baru per baris log — tiap koneksi / query
     * DNS menulis beberapa baris, jadi ini alokasi + parse pola yang
     * terus berulang selama VPN hidup.
     */
    private val stampFormat = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat =
            SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }

    private fun add(text: String) {
        val stamp = stampFormat.get()!!.format(Date())
        val line = "[$stamp] $text"
        val seq = seqCounter.incrementAndGet()
        synchronized(lock) {
            if (lines.size >= MAX_LINES) lines.removeFirst()
            lines.addLast(Entry(seq, line))
        }
        if (text.startsWith("SPEED ")) latestSpeedLine.set(line)
        runCatching { logcatSink?.invoke(TAG, line) }
    }

    fun lines(): List<String> = synchronized(lock) { lines.map { it.line } }

    fun clear() {
        synchronized(lock) { lines.clear() }
        latestSpeedLine.set(null)
    }
}
