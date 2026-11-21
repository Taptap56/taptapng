package com.taptap.ng

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.service.TaptapVpnService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * The "Initializing Xray Core (...)" line (v1.0.3, XVEON parity).
 *
 * Verified from the XVEON APK: its engine-init method logs
 * "Initializing Xray Core (<Transport> over <Network>[ + TLS][ +
 * DNSTT])" — transport/network from the profile, " + TLS" when TLS
 * is on, " + DNSTT" when SlowDNS is on. The line is a LABEL for the
 * in-app engine init (no xray-core behind it, in XVEON or here).
 * SSH has no line: XVEON's transport enum has no SSH.
 */
class XrayInitLineTest {

    private fun item(
        type: ConfigType,
        network: String = "tcp",
        tls: Boolean = false,
        dnstt: Boolean = false,
    ) = ProfileItem(
        remarks = "test",
        configType = type,
        address = "example.com",
        port = 443,
        network = network,
        tls = tls,
        dnsttEnabled = dnstt,
    )

    @Test
    fun `VMess over WS plus TLS`() {
        assertEquals(
            "Initializing Xray Core (VMess over WebSocket (WS) + TLS)",
            TaptapVpnService.initializingLine(item(ConfigType.VMESS, "ws", tls = true)),
        )
    }

    @Test
    fun `VMess over TCP without TLS`() {
        assertEquals(
            "Initializing Xray Core (VMess over TCP)",
            TaptapVpnService.initializingLine(item(ConfigType.VMESS, "tcp")),
        )
    }

    @Test
    fun `VLESS over WS plus TLS plus DNSTT`() {
        assertEquals(
            "Initializing Xray Core (VLESS over WebSocket (WS) + TLS + DNSTT)",
            TaptapVpnService.initializingLine(item(ConfigType.VLESS, "ws", tls = true, dnstt = true)),
        )
    }

    @Test
    fun `Trojan over TCP plus TLS`() {
        assertEquals(
            "Initializing Xray Core (Trojan over TCP + TLS)",
            TaptapVpnService.initializingLine(item(ConfigType.TROJAN, "tcp", tls = true)),
        )
    }

    @Test
    fun `Shadowsocks over TCP`() {
        assertEquals(
            "Initializing Xray Core (Shadowsocks over TCP)",
            TaptapVpnService.initializingLine(item(ConfigType.SHADOWSOCKS, "tcp")),
        )
    }

    @Test
    fun `SSH has no Initializing line`() {
        assertNull(TaptapVpnService.initializingLine(item(ConfigType.SSH, "tcp")))
    }

    @Test
    fun `tunnel DNS is the fixed XVEON pair`() {
        assertEquals("1.1.1.1", TaptapVpnService.PRIMARY_DNS)
        assertEquals("1.0.0.1", TaptapVpnService.SECONDARY_DNS)
    }
}
