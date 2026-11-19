package com.taptap.x

import com.taptap.x.core.DialLog
import java.net.SocketTimeoutException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.5 phone report (taptapx-3.txt,
 * 2026-11-20 02:47): the log contained ZERO dial lines — the app
 * never logged a dial stage anywhere, so a failed connect left no
 * trace. v1.0.6 logs every stage to DialLog (logcat + in-app ring
 * buffer), and the log must never carry credentials.
 */
class DialLogTest {

    @Test
    fun `lines are stored and returned in order`() {
        DialLog.clear()
        try {
            DialLog.log("DNS", "example.com -> 1.2.3.4")
            DialLog.log("TCP", "example.com:443 ok")
            val lines = DialLog.lines()
            assertEquals(2, lines.size)
            assertTrue(lines[0].contains("DNS example.com -> 1.2.3.4"), lines[0])
            assertTrue(lines[1].contains("TCP example.com:443 ok"), lines[1])
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
    fun `logcat sink receives every line`() {
        DialLog.clear()
        val seen = mutableListOf<Pair<String, String>>()
        DialLog.logcatSink = { tag, msg -> seen.add(tag to msg) }
        try {
            DialLog.log("PROBE", "dial test ok")
            assertEquals(1, seen.size)
            assertEquals(DialLog.TAG, seen[0].first)
            assertTrue(seen[0].second.contains("PROBE dial test ok"), seen[0].second)
        } finally {
            DialLog.logcatSink = null
            DialLog.clear()
        }
    }
}
