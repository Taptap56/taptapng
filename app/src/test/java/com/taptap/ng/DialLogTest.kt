package com.taptap.ng

import com.taptap.ng.core.DialLog
import java.net.SocketTimeoutException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.5 phone report (taptapng-3.txt,
 * 2026-11-20 02:47): the log contained ZERO dial lines — the app
 * never logged a dial stage anywhere, so a failed connect left no
 * trace. v1.0.6 logs every stage to DialLog (logcat + in-app ring
 * buffer), and the log must never carry credentials.
 */
class DialLogTest {

    @Test
    fun `clear empties the dial log`() {
        // v1.0.1: the Log screen's clear button calls DialLog.clear()
        // — without it the PROBE/DIAL/PRIME lines (shown first since
        // v1.0.6) could never be cleared by the button.
        DialLog.clear()
        try {
            DialLog.log("PRIME", "front.wetv.vip ok")
            DialLog.log("DIAL", "iflix ok")
            assertEquals(2, DialLog.lines().size)
            DialLog.clear()
            assertEquals(0, DialLog.lines().size)
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `lines are stored and returned in order`() {
        DialLog.clear()
        try {
            DialLog.log("DNS", "example.com -> 1.2.3.4")
            DialLog.log("TCP", "example.com:443 ok")
            val lines = DialLog.lines()
            assertEquals(2, lines.size)
            // v1.0.3 (XVEON parity): no "[STAGE]" prefix — the
            // line is timestamp + message only.
            assertTrue(lines[0].contains("example.com -> 1.2.3.4"), lines[0])
            assertTrue(lines[1].contains("example.com:443 ok"), lines[1])
            assertFalse(lines[0].contains("DNS example.com"), lines[0])
            assertFalse(lines[1].contains("TCP example.com"), lines[1])
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `ring buffer caps at MAX_LINES`() {
        DialLog.clear()
        try {
            repeat(DialLog.MAX_LINES + 10) { DialLog.log("TEST", "line $it") }
            assertEquals(DialLog.MAX_LINES, DialLog.lines().size)
            assertTrue(DialLog.lines().last().contains("line ${DialLog.MAX_LINES + 9}"))
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `ring buffer holds 5000 lines`() {
        // Phone logs taptapng-40774e0e.txt / taptapng-9c8c1aca.txt
        // (2026-11-20): a Speedtest + background traffic produces
        // well over 500 lines, so the 500-line buffer evicted the
        // whole download phase before the user exported the log.
        // 5000 lines must hold a full Speedtest run.
        assertEquals(5000, DialLog.MAX_LINES)
        DialLog.clear()
        try {
            repeat(5001) { DialLog.log("TEST", "line $it") }
            val lines = DialLog.lines()
            assertEquals(5000, lines.size)
            assertTrue(lines.first().contains("line 1"), lines.first())
            assertTrue(lines.last().contains("line 5000"), lines.last())
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `failure never logs a UUID or other credential`() {
        DialLog.clear()
        try {
            val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"
            DialLog.failure(
                "VMess",
                IllegalArgumentException("bad uuid $uuid"),
            )
            val lines = DialLog.lines()
            assertEquals(1, lines.size)
            assertFalse(lines[0].contains(uuid), "UUID leaked into dial log: ${lines[0]}")
            assertTrue(lines[0].contains("IllegalArgumentException"), lines[0])
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `failure keeps network messages with their stage tag`() {
        DialLog.clear()
        try {
            DialLog.failure("TCP", SocketTimeoutException("TCP gagal: Read timed out"))
            val lines = DialLog.lines()
            assertEquals(1, lines.size)
            assertTrue(lines[0].contains("TCP gagal: Read timed out"), lines[0])
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `failure includes the message for IllegalStateException`() {
        // v1.0.7 (taptapng-4.txt, 2026-11-20 03:19): the phone log
        // only ever said "IllegalStateException" — the message
        // ("protect() gagal — dial tidak bisa bypass VPN") only
        // appeared in the status bar, so the DialLog alone could
        // not say where the dial died. On v1.0.6 code this line
        // carries the class name only.
        DialLog.clear()
        try {
            DialLog.failure(
                "PROBE",
                IllegalStateException("protect() gagal — dial tidak bisa bypass VPN"),
            )
            val lines = DialLog.lines()
            assertEquals(1, lines.size)
            assertTrue(
                lines[0].contains("protect() gagal — dial tidak bisa bypass VPN"),
                lines[0],
            )
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `logcat sink receives every line`() {
        DialLog.clear()
        val seen = mutableListOf<Pair<String, String>>()
        DialLog.logcatSink = { tag, msg -> seen.add(tag to msg) }
        try {
            DialLog.log("PROBE", "dial test ok")
            assertEquals(1, seen.size)
            assertEquals(DialLog.TAG, seen[0].first)
            // v1.0.3 (XVEON parity): the tag is not rendered.
            assertTrue(seen[0].second.contains("dial test ok"), seen[0].second)
            assertFalse(seen[0].second.contains("PROBE dial test ok"), seen[0].second)
        } finally {
            DialLog.logcatSink = null
            DialLog.clear()
        }
    }

    // ---- coreLogLevel mapping (v1.0.5, group A) ----

    @Test
    fun `levelFor parses the stored core log level values`() {
        assertEquals(DialLog.Level.DEBUG, DialLog.levelFor("debug"))
        assertEquals(DialLog.Level.INFO, DialLog.levelFor("info"))
        assertEquals(DialLog.Level.WARNING, DialLog.levelFor("warning"))
        assertEquals(DialLog.Level.WARNING, DialLog.levelFor("warn"))
        assertEquals(DialLog.Level.ERROR, DialLog.levelFor("error"))
        assertEquals(DialLog.Level.NONE, DialLog.levelFor("none"))
        // Unknown / blank falls back to debug (show everything),
        // never to silent.
        assertEquals(DialLog.Level.DEBUG, DialLog.levelFor("bogus"))
        assertEquals(DialLog.Level.DEBUG, DialLog.levelFor(""))
    }

    @Test
    fun `debug level keeps every line`() {
        DialLog.clear()
        DialLog.applyLevel("debug")
        try {
            DialLog.debug("TEST", "verbose detail")
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            assertEquals(3, DialLog.lines().size)
        } finally {
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }

    @Test
    fun `info level drops debug lines but keeps info and failures`() {
        DialLog.clear()
        DialLog.applyLevel("info")
        try {
            DialLog.debug("TEST", "verbose detail")
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            val lines = DialLog.lines()
            assertEquals(2, lines.size)
            assertTrue(lines[0].contains("normal line"), lines[0])
            assertTrue(lines[1].contains("boom"), lines[1])
        } finally {
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }

    @Test
    fun `warning level keeps only failures`() {
        DialLog.clear()
        DialLog.applyLevel("warning")
        try {
            DialLog.debug("TEST", "verbose detail")
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            val lines = DialLog.lines()
            assertEquals(1, lines.size)
            assertTrue(lines[0].contains("boom"), lines[0])
        } finally {
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }

    @Test
    fun `error level keeps only failures`() {
        DialLog.clear()
        DialLog.applyLevel("error")
        try {
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            val lines = DialLog.lines()
            assertEquals(1, lines.size)
            assertTrue(lines[0].contains("boom"), lines[0])
        } finally {
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }

    @Test
    fun `none level keeps nothing`() {
        DialLog.clear()
        DialLog.applyLevel("none")
        try {
            DialLog.debug("TEST", "verbose detail")
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            assertEquals(0, DialLog.lines().size)
        } finally {
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }

    @Test
    fun `failure logs stack frames but never the exception message for unsafe types`() {
        // v1.0.18: failure() appends the stack trace (frames only)
        // so a START GAGAL can be diagnosed from the exported log.
        // The message itself must NOT ride along: for unsafe types
        // (IllegalArgumentException from UUID parsing) it carries
        // the raw input — stackTraceToString would leak it.
        DialLog.clear()
        try {
            val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"
            DialLog.failure(
                "START",
                IllegalArgumentException("bad uuid $uuid"),
            )
            val lines = DialLog.lines()
            assertEquals(1, lines.size, "trace rides in the same line: $lines")
            assertFalse(lines[0].contains(uuid), "UUID leaked into dial log: ${lines[0]}")
            assertTrue(
                lines[0].contains("stack trace (IllegalArgumentException)"),
                lines[0],
            )
            assertTrue(lines[0].contains("at com.taptap.ng.DialLogTest"), lines[0])
            // Capped: summary + header + at most MAX frames.
            assertTrue(
                lines[0].lines().size <= 2 + DialLog.MAX_FAILURE_TRACE_FRAMES,
                "uncapped trace: ${lines[0].lines().size} lines",
            )
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `level filter applies to the logcat sink too`() {
        DialLog.clear()
        val seen = mutableListOf<String>()
        DialLog.logcatSink = { _, msg -> seen.add(msg) }
        DialLog.applyLevel("error")
        try {
            DialLog.log("TEST", "normal line")
            DialLog.failure("TEST", IllegalStateException("boom"))
            assertEquals(1, seen.size)
            assertTrue(seen[0].contains("boom"), seen[0])
        } finally {
            DialLog.logcatSink = null
            DialLog.minLevel = DialLog.Level.DEBUG
            DialLog.clear()
        }
    }
}
