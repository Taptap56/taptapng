package com.taptap.x

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.service.TaptapVpnService
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.3 phone report (2026-11-20 01:06):
 * the selected entry was Onering, but M4 (the Onering engine) is not
 * built yet — the entry dialled as plain VMess, TLS hung on the
 * closed window, and the status stuck on "Connecting..." with no
 * honest explanation.
 *
 * v1.0.4: starting with an Onering or SlowDNS entry fails fast with
 * a clear status (like SSH already did), telling the user to pick a
 * plain VMess entry instead. The guard lives in
 * TaptapVpnService.requireStartable so it is testable on the JVM.
 */
class VpnStartGuardTest {

    private fun vmess(remarks: String = "Zoom wc") = ProfileItem(
        remarks = remarks,
        configType = ConfigType.VMESS,
        address = "support.zoom.us",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
        network = "ws",
        tls = true,
    )

    @Test
    fun `plain VMess entry is startable`() {
        assertDoesNotThrow { TaptapVpnService.requireStartable(vmess()) }
    }

    @Test
    fun `SSH entry is rejected with a clear message`() {
        val item = ProfileItem(configType = ConfigType.SSH, address = "example.com", port = 22)
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("SSH"), "message must name SSH: ${e.message}")
    }

    @Test
    fun `Onering entry is rejected with a clear message`() {
        val item = vmess("Zoom onering").apply {
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("M4"), "message must point at M4: ${e.message}")
    }

    // ---- v1.0.14 (M3): SlowDNS is startable for VMess/VLESS ----

    @Test
    fun `SlowDNS VMess entry is startable in v1_0_14 (M3)`() {
        // The DNSTT tunnel is built in-app now (M3): a SlowDNS VMess
        // entry must pass the guard — the old v1.0.4 rejection only
        // made sense while M3 was not built.
        val item = vmess("SSH SlowDNS").apply {
            dnsttEnabled = true
            dnsttNS = "ns.example.com"
            dnsttPubkey = "deadbeef"
        }
        assertDoesNotThrow { TaptapVpnService.requireStartable(item) }
    }

    @Test
    fun `SlowDNS Trojan entry is rejected with a clear message`() {
        // The DNSTT ladder is only plugged into the VMess/VLESS
        // clients — a SlowDNS Trojan entry would otherwise dial as
        // plain Trojan to the entry address, which is wrong.
        val item = vmess("Trojan SlowDNS").apply {
            configType = ConfigType.TROJAN
            dnsttEnabled = true
            dnsttNS = "ns.example.com"
            dnsttPubkey = "deadbeef"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("SlowDNS"), "message must name SlowDNS: ${e.message}")
        assertTrue(e.message!!.contains("VMess/VLESS"), "message must name VMess/VLESS: ${e.message}")
    }

    @Test
    fun `prepareStart accepts SlowDNS VMess entry`() {
        val item = vmess("SlowDNS VMess").apply {
            dnsttEnabled = true
            dnsttNS = "ns.example.com"
            dnsttPubkey = "deadbeef"
        }
        val prepared = TaptapVpnService.prepareStart(item)
        assertTrue(
            prepared is TaptapVpnService.PreparedStart.Ready,
            "expected Ready, got $prepared",
        )
    }

    // ---- v1.0.6, fix D: the guard runs on EVERY start attempt ----

    @Test
    fun `prepareStart rejects Onering entry without dialling`() {
        // The guard existed in v1.0.5 but only ran on a fresh start:
        // a second start while running was silently ignored, so an
        // Onering entry selected after the first start got dialled
        // as plain VMess (phone report 2026-11-20 02:49). prepareStart
        // is the single entry point the service uses for every start.
        val item = vmess("Zoom onering").apply {
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val prepared = TaptapVpnService.prepareStart(item)
        assertTrue(
            prepared is TaptapVpnService.PreparedStart.Rejected,
            "expected Rejected, got $prepared",
        )
        val msg = (prepared as TaptapVpnService.PreparedStart.Rejected).message
        assertTrue(msg.contains("Onering"), "message must name Onering: $msg")
        assertTrue(msg.contains("M4"), "message must point at M4: $msg")
    }

    @Test
    fun `prepareStart rejects SSH entry`() {
        val item = ProfileItem(configType = ConfigType.SSH, address = "example.com", port = 22)
        val prepared = TaptapVpnService.prepareStart(item)
        assertTrue(prepared is TaptapVpnService.PreparedStart.Rejected)
        val msg = (prepared as TaptapVpnService.PreparedStart.Rejected).message
        assertTrue(msg.contains("SSH"), "message must name SSH: $msg")
    }

    @Test
    fun `prepareStart accepts plain VMess and labels it with remark and address`() {
        val prepared = TaptapVpnService.prepareStart(vmess("Zoom wc"))
        assertTrue(
            prepared is TaptapVpnService.PreparedStart.Ready,
            "expected Ready, got $prepared",
        )
        val ready = prepared as TaptapVpnService.PreparedStart.Ready
        assertEquals("Zoom wc (support.zoom.us)", ready.label)
    }
}
