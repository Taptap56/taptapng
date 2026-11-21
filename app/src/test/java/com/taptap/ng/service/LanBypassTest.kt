package com.taptap.ng.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * LAN bypass routes (v1.0.5, group A — v2rayNG "Bypass LAN"):
 * with "1" the TUN gets the public-space complement of the LAN
 * ranges, so LAN traffic never enters the tunnel; with anything
 * else it gets the single catch-all route (v1.0.4 behaviour).
 * Pure IPv4 math — no Android APIs.
 */
class LanBypassTest {

    @Test
    fun `bypass is on only for stored value 1`() {
        assertTrue(LanBypass.bypassEnabled("1"))
        assertFalse(LanBypass.bypassEnabled("0"))
        // "2" (Bypass mainland China) needs a geoip database this
        // app does not bundle — it behaves like off.
        assertFalse(LanBypass.bypassEnabled("2"))
        assertFalse(LanBypass.bypassEnabled(""))
        // Stored values come from the list dialog, but a padded
        // value still means bypass (trimmed before comparing).
        assertTrue(LanBypass.bypassEnabled(" 1 "))
    }

    @Test
    fun `bypass off means the single catch-all route`() {
        assertEquals(
            listOf(LanBypass.Route("0.0.0.0", 0)),
            LanBypass.tunnelRoutes("0"),
        )
        assertEquals(
            listOf(LanBypass.Route("0.0.0.0", 0)),
            LanBypass.tunnelRoutes("2"),
        )
    }

    @Test
    fun `bypass on means many routes and no catch-all`() {
        val routes = LanBypass.tunnelRoutes("1")
        assertTrue(routes.size > 10, "expected the public-space split, got $routes")
        assertFalse(routes.any { it.prefixLength == 0 }, "catch-all must not survive: $routes")
    }

    @Test
    fun `lan addresses are not covered when bypass is on`() {
        val routes = LanBypass.tunnelRoutes("1")
        for (ip in listOf(
            "10.0.0.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.255",
            "192.168.0.1", "192.168.100.1",
            "169.254.1.1", "169.254.255.254",
        )) {
            assertTrue(LanBypass.isLanAddress(ip), "$ip should be LAN")
            assertFalse(
                LanBypass.isCoveredBy(routes, ip),
                "$ip must NOT be routed into the tunnel",
            )
        }
    }

    @Test
    fun `public addresses stay covered when bypass is on`() {
        val routes = LanBypass.tunnelRoutes("1")
        for (ip in listOf(
            "8.8.8.8", "1.1.1.1", "104.17.3.81",
            "9.255.255.255", "11.0.0.1",
            "172.15.255.255", "172.32.0.1",
            "192.167.255.255", "192.169.0.1",
            "169.253.255.255", "169.255.0.1",
            "0.0.0.1", "223.255.255.255",
        )) {
            assertFalse(LanBypass.isLanAddress(ip), "$ip should not be LAN")
            assertTrue(
                LanBypass.isCoveredBy(routes, ip),
                "$ip must still be routed into the tunnel",
            )
        }
    }

    @Test
    fun `public routes do not overlap each other`() {
        val routes = LanBypass.tunnelRoutes("1")
        for (i in routes.indices) {
            for (j in i + 1 until routes.size) {
                val a = routes[i]
                val b = routes[j]
                val minPrefix = minOf(a.prefixLength, b.prefixLength)
                val aNet = LanBypass.parseIpv4(a.address)!!
                val bNet = LanBypass.parseIpv4(b.address)!!
                val mask = -1L shl (32 - minPrefix)
                assertFalse(
                    (aNet and mask) == (bNet and mask),
                    "$a overlaps $b",
                )
            }
        }
    }

    @Test
    fun `parseIpv4 rejects non literals`() {
        assertEquals(null, LanBypass.parseIpv4("example.com"))
        assertEquals(null, LanBypass.parseIpv4("1.2.3"))
        assertEquals(null, LanBypass.parseIpv4("1.2.3.256"))
        assertEquals(null, LanBypass.parseIpv4("01.2.3.4"))
        assertEquals(0x01020304L, LanBypass.parseIpv4("1.2.3.4"))
    }
}
