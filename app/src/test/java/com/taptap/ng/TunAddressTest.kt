package com.taptap.ng

import com.taptap.ng.service.TaptapVpnService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * v1.0.10: the TUN address comes from the user's interface-address
 * setting (v2rayNG's VpnInterfaceAddressConfig, default index 0 =
 * 10.10.14.1). v1.0.9 hardcoded 172.19.0.1 and ignored the setting
 * entirely — changing it in Settings did nothing.
 */
class TunAddressTest {

    @Test
    fun `all seven v2rayng options map correctly`() {
        val expected = listOf(
            "10.10.14.1", "10.1.0.1", "10.0.0.1", "172.31.0.1",
            "172.20.0.1", "172.16.0.1", "192.168.100.1",
        )
        expected.forEachIndexed { i, addr ->
            assertEquals(addr, TaptapVpnService.tunIpv4ClientAddress(i.toString()))
        }
    }

    @Test
    fun `default is v2rayng default 10_10_14_1`() {
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress("0"))
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress(null))
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress(""))
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress("abc"))
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress("99"))
        assertEquals("10.10.14.1", TaptapVpnService.tunIpv4ClientAddress("-1"))
        assertEquals("10.0.0.1", TaptapVpnService.tunIpv4ClientAddress(" 2 "))
    }
}
