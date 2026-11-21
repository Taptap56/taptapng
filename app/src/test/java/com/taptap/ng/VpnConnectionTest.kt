package com.taptap.ng

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.service.VpnConnection
import com.taptap.ng.service.connectedLabel
import com.taptap.ng.service.dialLabel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.5 phone report (2026-11-20 02:49–02:53):
 * the user ran entry B ("Taptap WS (CDN) TLS", 104.17.3.81) but the
 * status stayed "Connecting: Zoom onering..." — the old entry's
 * connection and status kept running. The v1.0.5 service silently
 * ignored a second ACTION_START while already running (its `started`
 * flag), so the new entry never dialled and the status never changed.
 *
 * v1.0.6: a start with another entry RESTARTS with the new entry,
 * and the status names the entry being dialled from the first moment
 * — never another entry's remark.
 */
class VpnConnectionTest {

    private val entryA = "Zoom onering (support.zoom.us)"
    private val entryB = "Taptap WS (CDN) TLS (104.17.3.81)"

    @Test
    fun `second start with another entry restarts and shows the new remark`() {
        val conn = VpnConnection()
        assertEquals(VpnConnection.Decision.START_FRESH, conn.requestStart(entryA))
        assertTrue(conn.status.contains("Zoom onering"), "status must name A: ${conn.status}")
        assertTrue(conn.isRunning)

        // The phone case: start B while A is running.
        assertEquals(VpnConnection.Decision.RESTART, conn.requestStart(entryB))
        assertTrue(conn.status.contains("Taptap WS (CDN) TLS"), "status must show B: ${conn.status}")
        assertFalse(conn.status.contains("Zoom onering"), "status must not show A anymore: ${conn.status}")
        assertEquals(entryB, conn.runningEntry)

        // Starting the same entry again is a no-op, not a restart.
        assertEquals(VpnConnection.Decision.ALREADY_RUNNING, conn.requestStart(entryB))
        assertTrue(conn.status.contains("Taptap WS (CDN) TLS"))

        conn.requestStop()
        assertEquals("Stopped", conn.status)
        assertFalse(conn.isRunning)
    }

    @Test
    fun `failure status names the failed entry`() {
        val conn = VpnConnection()
        conn.requestStart(entryA)
        conn.reportFailure("Konek gagal (TLS gagal): $entryA")
        assertEquals(VpnConnection.State.FAILED, conn.state)
        assertTrue(conn.status.contains("TLS gagal"), "status must carry the stage: ${conn.status}")
        assertTrue(conn.status.contains("Zoom onering"), "status must name the entry: ${conn.status}")
        // A fresh start after a failure is a clean start, not a restart.
        assertEquals(VpnConnection.Decision.START_FRESH, conn.requestStart(entryB))
    }

    @Test
    fun `dial status from the forwarder carries the running entry`() {
        val conn = VpnConnection()
        conn.requestStart(entryA)
        conn.reportDialStatus("Konek gagal (timeout)")
        assertTrue(conn.status.contains("Konek gagal (timeout)"), conn.status)
        assertTrue(conn.status.contains("Zoom onering"), conn.status)
        conn.reportDialStatus("Connected")
        assertEquals(VpnConnection.State.RUNNING, conn.state)
        // v1.0.7: the Connected status shows the remark only.
        assertEquals("Connected: Zoom onering", conn.status)
    }

    @Test
    fun `dial failure while running must not overwrite the Connected status`() {
        // v1.0.13, fix C: phone screenshot 2026-11-20 08:57:42 —
        // the status read "Konek gagal (WS gagal: Read timed out)"
        // while the VPN icon was up and video played. One failed
        // app dial overwrote the good status. Fails on v1.0.12
        // code (status becomes "Konek gagal ...").
        val conn = VpnConnection()
        conn.requestStart(entryA)
        conn.reportConnected(entryA)
        // v1.0.7: the Connected status shows the remark only.
        assertEquals("Connected: Zoom onering", conn.status)
        conn.reportDialStatus("Konek gagal (WS gagal: Read timed out)")
        assertEquals("Connected: Zoom onering", conn.status)
        assertEquals(VpnConnection.State.RUNNING, conn.state)
        // A later success keeps it.
        conn.reportDialStatus("Connected")
        assertEquals("Connected: Zoom onering", conn.status)
    }

    @Test
    fun `connected label drops the address suffix but keeps the remark`() {
        // v1.0.7 (user order 2026-11-21): "Connected: iflix
        // cloudfront", not "... (front.wetv.vip)".
        assertEquals(
            "iflix cloudfront",
            connectedLabel("iflix cloudfront (front.wetv.vip)"),
        )
        // Only the LAST parenthesised group is the address — a
        // remark's own parentheses survive.
        assertEquals(
            "Taptap WS (CDN) TLS",
            connectedLabel("Taptap WS (CDN) TLS (104.17.3.81)"),
        )
        // No remark: the bare address is shown unchanged.
        assertEquals("104.17.3.81", connectedLabel("104.17.3.81"))
        // No suffix at all: unchanged.
        assertEquals("Zoom onering", connectedLabel("Zoom onering"))
    }

    @Test
    fun `dial label disambiguates entries that share a remark`() {
        val zoomOnering = ProfileItem(
            remarks = "Zoom onering",
            configType = ConfigType.VMESS,
            address = "support.zoom.us",
            port = 443,
        )
        assertEquals("Zoom onering (support.zoom.us)", dialLabel(zoomOnering))
        val noRemarks = ProfileItem(
            remarks = "",
            configType = ConfigType.VMESS,
            address = "104.17.3.81",
            port = 443,
        )
        assertEquals("104.17.3.81", dialLabel(noRemarks))
    }
}
