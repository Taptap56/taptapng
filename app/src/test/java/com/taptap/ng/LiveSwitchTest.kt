package com.taptap.ng

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.service.LiveSwitchDecision
import com.taptap.ng.service.VpnConnection
import com.taptap.ng.service.applyLiveSwitchSelection
import com.taptap.ng.service.decideLiveSwitch
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

/**
 * v1.0.19 (Issue 2): tapping another server while the VPN runs
 * must switch LIVE, Clash-style — no stop/start. The user reported
 * it twice (2026-11-23 18:58, 2026-11-24 00:45): "clash kalau
 * konek kan bisa pindah server tanpa restart core" / "Pindah
 * server masih restart, ini juga belum kebuka".
 *
 * These tests fail on v1.0.18: there is no [decideLiveSwitch]
 * (the tap path called shouldRestartOnSelect and restarted the
 * service), no [applyLiveSwitchSelection] (nothing ever moved the
 * "taptap" group's selected member — the route engine kept routing
 * new connections to the old member even after a restart), and no
 * [VpnConnection.switchEntry] (the label could only change via a
 * (re)start).
 */
class LiveSwitchTest {

    private fun proxyGroup(
        selected: String?,
        members: List<String> = listOf("guid-a", "guid-b", "guid-c"),
        type: ProxyGroupType = ProxyGroupType.SELECT,
        name: String = GroupsStore.DEFAULT_GROUP_NAME,
    ) = ProxyGroup(
        name = name,
        type = type,
        members = members,
        selectedMemberGuid = selected,
    )

    // ---- tap decision ----

    @Test
    fun `running plus different server switches live, not restart`() {
        assertEquals(
            LiveSwitchDecision.SWITCH_LIVE,
            decideLiveSwitch(true, "guid-a", "guid-b"),
        )
    }

    @Test
    fun `running plus same server is a no-op`() {
        assertEquals(
            LiveSwitchDecision.NO_OP,
            decideLiveSwitch(true, "guid-a", "guid-a"),
        )
    }

    @Test
    fun `stopped tap only selects, never switches`() {
        assertEquals(
            LiveSwitchDecision.SELECT_ONLY,
            decideLiveSwitch(false, "guid-a", "guid-b"),
        )
        assertEquals(
            LiveSwitchDecision.SELECT_ONLY,
            decideLiveSwitch(false, null, "guid-b"),
        )
    }

    @Test
    fun `running with nothing selected switches live`() {
        assertEquals(
            LiveSwitchDecision.SWITCH_LIVE,
            decideLiveSwitch(true, null, "guid-b"),
        )
    }

    // ---- group selection update ----

    @Test
    fun `selection moves to the tapped server in the Proxy group`() {
        val groups = listOf(proxyGroup(selected = "guid-a"))
        val updated = applyLiveSwitchSelection(groups, "guid-b")
        assertNotNull(updated)
        assertEquals("guid-b", updated!![0].selectedMemberGuid)
        assertEquals(listOf("guid-a", "guid-b", "guid-c"), updated[0].members)
    }

    @Test
    fun `no change when the Proxy group already selects the tapped server`() {
        val groups = listOf(proxyGroup(selected = "guid-b"))
        assertNull(applyLiveSwitchSelection(groups, "guid-b"))
    }

    @Test
    fun `stored null selection falls back to first member, switch still moves`() {
        // selectedMemberGuid null = first member (guid-a) in effect.
        val groups = listOf(proxyGroup(selected = null))
        val updated = applyLiveSwitchSelection(groups, "guid-a")
        assertNull(updated, "tapping the effective member must be a no-op")
        assertNotNull(applyLiveSwitchSelection(groups, "guid-c"))
    }

    @Test
    fun `server added after groups json was created joins the group on switch`() {
        val groups = listOf(proxyGroup(selected = "guid-a", members = listOf("guid-a")))
        val updated = applyLiveSwitchSelection(groups, "guid-new")
        assertNotNull(updated)
        assertEquals(listOf("guid-a", "guid-new"), updated!![0].members)
        assertEquals("guid-new", updated[0].selectedMemberGuid)
    }

    @Test
    fun `other groups are untouched`() {
        val other = proxyGroup(selected = "guid-a", name = "Lain")
        val groups = listOf(proxyGroup(selected = "guid-a"), other)
        val updated = applyLiveSwitchSelection(groups, "guid-b")
        assertNotNull(updated)
        assertEquals("guid-b", updated!![0].selectedMemberGuid)
        assertEquals(other, updated[1])
    }

    @Test
    fun `non-SELECT Proxy group cannot be switched by selection`() {
        val groups = listOf(proxyGroup(selected = "guid-a", type = ProxyGroupType.URL_TEST))
        assertNull(applyLiveSwitchSelection(groups, "guid-b"))
    }

    @Test
    fun `no Proxy group means no switch`() {
        val groups = listOf(proxyGroup(selected = "guid-a", name = "Lain"))
        assertNull(applyLiveSwitchSelection(groups, "guid-b"))
    }

    // ---- new connections really route through the new server ----

    @Test
    fun `route engine follows the moved selection for new connections`() {
        val group = proxyGroup(selected = "guid-a")
        val rules = listOf(RouteRule(type = RouteRuleType.FINAL, target = group.id))
        val ip = InetAddress.getByName("93.184.216.34")
        // Before the switch: new connections go to A.
        assertEquals(
            RouteDecision.Proxy("guid-a"),
            RouteEngine.resolve("example.com", ip, 443, listOf(group), rules, emptyMap()),
        )
        // After the switch: the same resolver call goes to B —
        // this is the step the v1.0.18 restart path never took
        // (the group selection stayed on A, so traffic stayed on
        // A while the status already named B).
        val updated = applyLiveSwitchSelection(listOf(group), "guid-b")
        assertNotNull(updated)
        assertEquals(
            RouteDecision.Proxy("guid-b"),
            RouteEngine.resolve("example.com", ip, 443, updated!!, rules, emptyMap()),
        )
    }

    // ---- Connected label follows without leaving RUNNING ----

    @Test
    fun `switchEntry keeps RUNNING and renames the Connected label`() {
        val conn = VpnConnection()
        conn.requestStart("Zoom onering (support.zoom.us)")
        conn.reportConnected("Zoom onering (support.zoom.us)")
        assertEquals(VpnConnection.State.RUNNING, conn.state)

        assertTrue(conn.switchEntry("iflix cloudfront (front.wetv.vip)"))
        assertEquals(VpnConnection.State.RUNNING, conn.state)
        assertTrue(conn.isRunning)
        assertEquals("Connected: iflix cloudfront", conn.status)
        assertEquals("iflix cloudfront (front.wetv.vip)", conn.runningEntry)
    }

    @Test
    fun `switchEntry refuses while starting, so the start worker cannot be raced`() {
        val conn = VpnConnection()
        conn.requestStart("Zoom onering (support.zoom.us)")
        assertEquals(VpnConnection.State.STARTING, conn.state)
        assertFalse(conn.switchEntry("iflix cloudfront (front.wetv.vip)"))
        assertEquals("Zoom onering (support.zoom.us)", conn.runningEntry)
        assertTrue(conn.status.contains("Zoom onering"))
    }

    @Test
    fun `switchEntry refuses while idle`() {
        val conn = VpnConnection()
        assertFalse(conn.switchEntry("iflix cloudfront (front.wetv.vip)"))
        assertEquals("Stopped", conn.status)
        assertFalse(conn.isRunning)
    }
}
