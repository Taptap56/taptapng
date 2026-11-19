package com.taptap.x

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.service.TaptapVpnService
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
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

    @Test
    fun `SlowDNS entry is rejected with a clear message`() {
        val item = vmess("SSH SlowDNS").apply {
            dnsttEnabled = true
            dnsttNS = "ns.example.com"
            dnsttPubkey = "deadbeef"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("SlowDNS"), "message must name SlowDNS: ${e.message}")
        assertTrue(e.message!!.contains("M3"), "message must point at M3: ${e.message}")
    }
}
