package com.taptap.ng

import com.taptap.ng.service.VpnConnection
import com.taptap.ng.ui.main.DashboardGate
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.32: the dashboard tab only runs while the VPN is actually
 * connected. VPN off -> a static placeholder, no WebView is created
 * or loaded, no polling/stream; VPN on -> the dashboard as in
 * v1.0.30; VPN stopped while the dashboard is open -> the WebView
 * is torn down (stopLoading + detach + destroy + null + URL marker
 * reset) and the tab falls back to the placeholder.
 *
 * These tests fail on v1.0.30: there is no [DashboardGate] and no
 * `VpnConnection.isConnected` there (the gate tests do not compile
 * against the old code at all), and the old `showDashboard()` loaded
 * the WebView whenever the Clash API was enabled, whatever the VPN
 * state — so every source assertion about the gate / teardown /
 * placeholder fails on the old source.
 */
class DashboardGateTest {

    // ---- pure gate ----

    @Test
    fun `api on plus vpn connected shows the webview`() {
        assertEquals(
            DashboardGate.State.WEBVIEW,
            DashboardGate.decide(vpnConnected = true, clashApiEnabled = true),
        )
    }

    @Test
    fun `api on plus vpn off shows the vpn placeholder`() {
        assertEquals(
            DashboardGate.State.VPN_OFF,
            DashboardGate.decide(vpnConnected = false, clashApiEnabled = true),
        )
    }

    @Test
    fun `api off wins over vpn off`() {
        assertEquals(
            DashboardGate.State.API_DISABLED,
            DashboardGate.decide(vpnConnected = false, clashApiEnabled = false),
        )
    }

    @Test
    fun `api off wins over vpn connected`() {
        assertEquals(
            DashboardGate.State.API_DISABLED,
            DashboardGate.decide(vpnConnected = true, clashApiEnabled = false),
        )
    }

    // ---- the predicate: RUNNING only, never STARTING ----

    @Test
    fun `idle is not connected`() {
        val conn = VpnConnection()
        assertEquals(VpnConnection.State.IDLE, conn.state)
        assertFalse(conn.isConnected)
        assertFalse(conn.isRunning)
    }

    @Test
    fun `starting counts as running but not as connected`() {
        // This is the discrimination that matters: the old code only
        // had isRunning, which is already true while STARTING
        // (requestStart sets STARTING + "Connecting: ..."), so a
        // gate built on it would open the dashboard before the
        // tunnel is up. STARTING must stay on the placeholder.
        val conn = VpnConnection()
        conn.requestStart("iflix cloudfront (front.wetv.vip)")
        assertEquals(VpnConnection.State.STARTING, conn.state)
        assertTrue(conn.isRunning)
        assertFalse(conn.isConnected)
    }

    @Test
    fun `running after probe success is connected`() {
        val conn = VpnConnection()
        conn.requestStart("iflix cloudfront (front.wetv.vip)")
        conn.reportConnected("iflix cloudfront (front.wetv.vip)")
        assertEquals(VpnConnection.State.RUNNING, conn.state)
        assertTrue(conn.isRunning)
        assertTrue(conn.isConnected)
        assertEquals("Connected: iflix cloudfront", conn.status)
    }

    @Test
    fun `failed start is not connected`() {
        val conn = VpnConnection()
        conn.requestStart("iflix cloudfront (front.wetv.vip)")
        conn.reportFailure("Konek gagal (TLS gagal): iflix cloudfront (front.wetv.vip)")
        assertEquals(VpnConnection.State.FAILED, conn.state)
        assertFalse(conn.isRunning)
        assertFalse(conn.isConnected)
    }

    @Test
    fun `stop after running is not connected`() {
        val conn = VpnConnection()
        conn.requestStart("iflix cloudfront (front.wetv.vip)")
        conn.reportConnected("iflix cloudfront (front.wetv.vip)")
        assertTrue(conn.isConnected)
        conn.requestStop()
        assertEquals(VpnConnection.State.IDLE, conn.state)
        assertFalse(conn.isConnected)
    }

    // ---- source assertions: the Activity wires the gate in ----
    //
    // No Robolectric in this tree, so the WebView teardown itself
    // cannot run on the JVM — the deciding proof is the phone
    // screenshot. These assertions pin the wiring so a revert of
    // any part of it fails here.

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/layout/activity_main.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    @Test
    fun `showDashboard decides through the gate on the connected predicate`() {
        val src = read("app/src/main/java/com/taptap/ng/ui/MainActivity.kt")
        assertTrue(src.contains("DashboardGate.decide(TaptapVpnService.isConnected"))
        assertTrue(src.contains("DashboardGate.State.VPN_OFF"))
        assertTrue(src.contains("DashboardGate.State.API_DISABLED"))
        assertTrue(src.contains("DashboardGate.State.WEBVIEW"))
    }

    @Test
    fun `vpn off branch destroys the webview and forgets the loaded url`() {
        val src = read("app/src/main/java/com/taptap/ng/ui/MainActivity.kt")
        assertTrue(src.contains("destroyDashboardWebView()"))
        assertTrue(src.contains("webView.stopLoading()"))
        assertTrue(src.contains("webView.destroy()"))
        assertTrue(src.contains("dashboardUrlLoaded = null"))
        assertTrue(src.contains("dashboardWebView = null"))
    }

    @Test
    fun `service state sync re-evaluates the dashboard when its tab is open`() {
        // The 2 s poll (plus resume / post-start sync) is the
        // transition driver: a VPN stop/start must flip the tab
        // within ~2 s without any extra hook on the FAB toggle.
        val src = read("app/src/main/java/com/taptap/ng/ui/MainActivity.kt")
        val sync = src.substringAfter("private fun syncServiceState()")
            .substringBefore("private fun updateSpeedDisplay()")
        assertTrue(sync.contains("if (dashboardMode) showDashboard()"))
    }

    @Test
    fun `vpn off placeholder exists in layout and strings`() {
        val layout = read("app/src/main/res/layout/activity_main.xml")
        assertTrue(layout.contains("android:id=\"@+id/dashboard_vpn_off\""))
        assertTrue(layout.contains("@string/dashboard_vpn_off"))
        val strings = read("app/src/main/res/values/strings.xml")
        assertTrue(strings.contains("name=\"dashboard_vpn_off\""))
        assertTrue(strings.contains("nyalakan VPN untuk membuka dashboard"))
    }

    @Test
    fun `webview keeps its 80dp bottom margin`() {
        // v1.0.30: the scroll-to-bottom fix must survive the gating
        // rework untouched.
        val src = read("app/src/main/java/com/taptap/ng/ui/MainActivity.kt")
        assertTrue(src.contains("bottomMargin = (80 * resources.displayMetrics.density).toInt()"))
    }
}
