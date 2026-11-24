package com.taptap.ng.ui.main

/**
 * Speed display in the main status bar (v1.0.5, group A — v2rayNG
 * "Enable speed display").
 *
 * There is no live throughput counter to read: the per-connection
 * SPEED lines already logged to DialLog by TunForwarder (one per
 * 5 s window while transferring) are the only speed data the app
 * has, and TunForwarder is owned by another work group — so the
 * status bar shows the latest SPEED line instead of inventing a
 * second measurement. [latestSpeedSummary] pulls the download
 * rate out of the newest SPEED line; [formatSpeedText] gates it
 * on the setting (OFF = hidden). Pure string logic — unit-testable
 * without an Application.
 */
object SpeedDisplay {

    private val RATE = Regex("""([\d.]+)\s*MB/s""")

    /**
     * Download rate of the newest "SPEED ..." DialLog line, as
     * "↓ 1.23 MB/s" — or null when no SPEED line has been logged
     * yet (VPN never transferred, or log cleared).
     */
    fun latestSpeedSummary(lines: List<String>): String? {
        val line = lines.asReversed().firstOrNull { it.contains("SPEED ") } ?: return null
        return latestSpeedSummaryFromLine(line)
    }

    /**
     * v1.0.31 (battery, H4a): same rate, from the newest SPEED
     * line already cached by [DialLog.latestSpeedLine] — no ring
     * copy, no scan. Null = no SPEED line yet.
     */
    fun latestSpeedSummaryFromLine(line: String?): String? {
        if (line == null) return null
        val rate = RATE.find(line)?.groupValues?.getOrNull(1) ?: return null
        return "↓ $rate MB/s"
    }

    /** Text for the status-bar speed view, or null when it must be hidden. */
    fun formatSpeedText(speedEnabled: Boolean, summary: String?): String? =
        if (speedEnabled) summary else null
}
