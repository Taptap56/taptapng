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
 * a clear status, telling the user to pick a plain VMess entry
 * instead. The guard lives in
 * TaptapVpnService.requireStartable so it is testable on the JVM.
 *
 * v1.0.30: SSH entries ARE startable now (SshProxyClient + payload
 * chain) — the old blanket SSH rejection is gone. SSH+SlowDNS and
 * SSH+Onering are still rejected by the checks below.
 *
 * v1.0.23 (M4): a well-formed Onering entry (VMess/VLESS/Trojan +
 * TLS + WS + bug domain) IS startable now — the 0xff00 engine is
 * built in-app. The rejection tests below cover the shapes that
 * are still invalid (no TLS/WS/bug, SS/SSH, SlowDNS combined).
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
    fun `SSH entry is startable in v1_0_30`() {
        // v1.0.30: SSH rides the tunnel (SshProxyClient + payload
        // chain) — the old blanket rejection is gone. Fails on
        // v1.0.29 code (requireStartable threw for every SSH entry).
        val item = ProfileItem(configType = ConfigType.SSH, address = "vip.sshvpn.web.id", port = 80, username = "user")
        assertDoesNotThrow { TaptapVpnService.requireStartable(item) }
    }

    @Test
    fun `SSH entry with TLS and SNI is startable`() {
        // v1.0.30: SSH+TLS/SNI is supported (the chain dials TLS
        // with SNI = sshSni, or the SSH host when blank).
        val item = ProfileItem(
            configType = ConfigType.SSH, address = "vip.sshvpn.web.id", port = 443, username = "user",
            sshUseTls = true, sshSni = "example.com",
        )
        assertDoesNotThrow { TaptapVpnService.requireStartable(item) }
    }

    @Test
    fun `SSH SlowDNS entry is still rejected`() {
        // The DNSTT ladder is only plugged into the VMess/VLESS
        // clients — SSH over SlowDNS has no path.
        val item = ProfileItem(
            configType = ConfigType.SSH, address = "vip.sshvpn.web.id", port = 80, username = "user",
            dnsttEnabled = true, dnsttNS = "dnsv.sshvpn.web.id", dnsttPubkey = "deadbeef",
        )
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("SlowDNS"), "msg: ${e.message}")
        assertTrue(e.message!!.contains("VMess/VLESS"), "msg: ${e.message}")
    }

    @Test
    fun `SSH Onering entry is still rejected`() {
        // Onering is only built for VMess/VLESS/Trojan.
        val item = ProfileItem(
            configType = ConfigType.SSH, address = "vip.sshvpn.web.id", port = 443, username = "user",
            tls = true, network = "ws", oneringEnabled = true, oneringBug = "support.zoom.us",
        )
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "msg: ${e.message}")
        assertTrue(e.message!!.contains("VMess/VLESS/Trojan"), "msg: ${e.message}")
    }

    @Test
    fun `Onering VMess entry is startable in v1_0_23 (M4)`() {
        // The 0xff00 extension is built in-app now (M4, Bouncy
        // Castle): a well-formed Onering VMess entry (TLS + WS +
        // bug domain) must pass the guard — the old v1.0.4 rejection
        // only made sense while M4 was not built.
        val item = vmess("Zoom onering").apply {
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        assertDoesNotThrow { TaptapVpnService.requireStartable(item) }
    }

    @Test
    fun `Onering entry without TLS is rejected with a clear message`() {
        // No TLS = no ClientHello = nowhere to carry the bug.
        val item = vmess("Zoom onering").apply {
            tls = false
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("TLS"), "message must name TLS: ${e.message}")
    }

    @Test
    fun `Onering entry without WS is rejected with a clear message`() {
        val item = vmess("Zoom onering").apply {
            network = "tcp"
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("WS"), "message must name WS: ${e.message}")
    }

    @Test
    fun `Onering entry without bug domain is rejected with a clear message`() {
        val item = vmess("Zoom onering").apply {
            oneringEnabled = true
            oneringBug = ""
            sni = "support.zoom.us"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("Bug"), "message must name Bug: ${e.message}")
    }

    @Test
    fun `Onering SS entry is rejected with a clear message`() {
        // SS has no TLS handshake, so there is no ClientHello to
        // carry the bug in.
        val item = vmess("Onering SS").apply {
            configType = ConfigType.SHADOWSOCKS
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("VMess/VLESS/Trojan"), "message must name scope: ${e.message}")
    }

    @Test
    fun `Onering plus SlowDNS entry is rejected with a clear message`() {
        val item = vmess("Onering SlowDNS").apply {
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
            dnsttEnabled = true
            dnsttNS = "ns.example.com"
            dnsttPubkey = "deadbeef"
        }
        val e = assertThrows(IllegalStateException::class.java) {
            TaptapVpnService.requireStartable(item)
        }
        assertTrue(e.message!!.contains("Onering"), "message must name Onering: ${e.message}")
        assertTrue(e.message!!.contains("SlowDNS"), "message must name SlowDNS: ${e.message}")
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
    fun `prepareStart accepts Onering entry without dialling`() {
        // v1.0.23 (M4): a well-formed Onering entry passes the
        // guard — prepareStart is the single entry point the
        // service uses for every start, so it must accept it here
        // (the v1.0.5 bug was the opposite: an entry that should
        // have been rejected got dialled because the guard only ran
        // on a fresh start).
        val item = vmess("Zoom onering").apply {
            oneringEnabled = true
            oneringBug = "live.iflix.com"
            sni = "support.zoom.us"
        }
        val prepared = TaptapVpnService.prepareStart(item)
        assertTrue(
            prepared is TaptapVpnService.PreparedStart.Ready,
            "expected Ready, got $prepared",
        )
    }

    @Test
    fun `prepareStart rejects invalid Onering entry without dialling`() {
        // Same entry point, invalid shape (no TLS): must be
        // Rejected here, never dialled.
        val item = vmess("Zoom onering").apply {
            tls = false
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
        assertTrue(msg.contains("TLS"), "message must name TLS: $msg")
    }

    @Test
    fun `prepareStart accepts SSH entry`() {
        // v1.0.30: creating the SSH client is lazy (no session is
        // opened until the first dial), so prepareStart returns
        // Ready without touching the network. Fails on v1.0.29
        // code (requireStartable rejected every SSH entry).
        val item = ProfileItem(configType = ConfigType.SSH, address = "example.com", port = 22)
        val prepared = TaptapVpnService.prepareStart(item)
        assertTrue(prepared is TaptapVpnService.PreparedStart.Ready, "got: $prepared")
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
