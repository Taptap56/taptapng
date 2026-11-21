package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * IP lookup (v1.0.5, group A — v2rayNG's IP API test): the stored
 * URL is used as-is, an empty stored URL falls back to
 * https://api.ip.sb/geoip, and the "ip" field of the geoip JSON
 * is what gets shown. The fetcher is injected, so no test touches
 * the network.
 */
class IpLookupTest {

    @Test
    fun `blank stored url falls back to the default`() {
        assertEquals("https://api.ip.sb/geoip", IpLookup.effectiveUrl(""))
        assertEquals("https://api.ip.sb/geoip", IpLookup.effectiveUrl("   "))
    }

    @Test
    fun `custom stored url is used as-is`() {
        val custom = "https://ifconfig.me/ip"
        assertEquals(custom, IpLookup.effectiveUrl(custom))
    }

    @Test
    fun `fetchIp calls the custom url`() {
        val seen = mutableListOf<String>()
        val ip = IpLookup.fetchIp("https://example.test/ip") { url ->
            seen.add(url)
            "203.0.113.7"
        }
        assertEquals(listOf("https://example.test/ip"), seen)
        assertEquals("203.0.113.7", ip)
    }

    @Test
    fun `fetchIp calls the default url when stored is blank`() {
        val seen = mutableListOf<String>()
        val ip = IpLookup.fetchIp("") { url ->
            seen.add(url)
            """{"ip":"198.51.100.9","country":"ID"}"""
        }
        assertEquals(listOf("https://api.ip.sb/geoip"), seen)
        assertEquals("198.51.100.9", ip)
    }

    @Test
    fun `extractIp pulls the ip field out of geoip json`() {
        assertEquals(
            "198.51.100.9",
            IpLookup.extractIp("""{"ip":"198.51.100.9","country_code":"ID","country":"Indonesia"}"""),
        )
    }

    @Test
    fun `extractIp falls back to the raw body for plain text apis`() {
        assertEquals("203.0.113.7", IpLookup.extractIp("203.0.113.7\n"))
    }

    @Test
    fun `fetchIp failure propagates to the caller`() {
        val result = runCatching {
            IpLookup.fetchIp("https://example.test/ip") { throw java.io.IOException("timeout") }
        }
        assertTrue(result.isFailure)
    }
}
