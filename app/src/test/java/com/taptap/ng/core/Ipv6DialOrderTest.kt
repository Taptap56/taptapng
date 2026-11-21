package com.taptap.ng.core

import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for the v1.0.5 integration wiring of [SettingsStore.preferIpv6]
 * into the dial path: [DnsResolver.resolveAll] orders the returned
 * addresses with [Ipv6Support.orderAddresses] — IPv4 first by default
 * (v1.0.4 behaviour, now explicit for every resolve path), IPv6 first
 * when preferIpv6 is on. The system hook returns IPv6 first on
 * purpose, so the test proves the ordering comes from the wiring,
 * not from the hook. Globals are restored after every test.
 */
class Ipv6DialOrderTest {

    private fun <T> runWithHook(
        preferIpv6: Boolean,
        body: () -> T,
    ): T {
        val oldHook = DnsResolver.operatorResolve
        val oldSystemHook = DnsResolver.systemResolveHook
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        val oldMethod = DnsResolver.resolveMethod
        val oldHosts = DnsResolver.staticHosts
        val oldPrefer = DnsResolver.preferIpv6
        DnsResolver.clearAddrCache()
        try {
            DnsResolver.operatorResolve = null
            // Hook returns IPv6 FIRST on purpose.
            DnsResolver.systemResolveHook = { _, _ ->
                listOf(
                    InetAddress.getByName("2001:db8::1"),
                    InetAddress.getByName("10.0.0.1"),
                )
            }
            DnsResolver.resolveMethod = OutboundResolveMethod.SYSTEM_ONLY
            DnsResolver.preferIpv6 = preferIpv6
            return body()
        } finally {
            DnsResolver.operatorResolve = oldHook
            DnsResolver.systemResolveHook = oldSystemHook
            DnsResolver.dnsServer = oldServer
            DnsResolver.dnsPort = oldPort
            DnsResolver.resolveMethod = oldMethod
            DnsResolver.staticHosts = oldHosts
            DnsResolver.preferIpv6 = oldPrefer
            DnsResolver.clearAddrCache()
        }
    }

    @Test
    fun `default preferIpv6 false returns IPv4 first`() {
        val all = runWithHook(preferIpv6 = false) {
            DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
        }
        assertEquals(2, all.size)
        assertTrue(all[0] is java.net.Inet4Address, "first must be IPv4, was ${all[0]}")
        assertEquals("10.0.0.1", all[0].hostAddress)
        assertEquals("2001:db8::1", all[1].hostAddress)
    }

    @Test
    fun `preferIpv6 true returns IPv6 first`() {
        val all = runWithHook(preferIpv6 = true) {
            DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
        }
        assertEquals(2, all.size)
        assertEquals("2001:db8::1", all[0].hostAddress)
        assertEquals("10.0.0.1", all[1].hostAddress)
    }

    @Test
    fun `cached path keeps the same ordering`() {
        val (first, second) = runWithHook(preferIpv6 = true) {
            val a = DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
            // Second call hits the cache — ordering must still apply.
            val b = DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
            listOf(a, b)
        }
        assertEquals(first.map { it.hostAddress }, second.map { it.hostAddress })
        assertEquals("2001:db8::1", second[0].hostAddress)
    }

    @Test
    fun `IP literal is untouched by ordering`() {
        val all = runWithHook(preferIpv6 = true) {
            DnsResolver.resolveAll("2001:db8::9", 443, timeoutMs = 1000)
        }
        assertEquals(listOf("2001:db8::9"), all.map { it.hostAddress })
    }
}
