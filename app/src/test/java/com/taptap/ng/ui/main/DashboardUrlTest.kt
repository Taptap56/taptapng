package com.taptap.ng.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * M7 (W5): the Dashboard tab opens the bundled yacd at
 * `http://127.0.0.1:<port>/ui/#/proxies`, with `?secret=` (encoded)
 * only when a secret is set.
 */
class DashboardUrlTest {

    @Test
    fun defaultPortWithoutSecretHasNoQuery() {
        assertEquals(
            "http://127.0.0.1:9091/ui/#/proxies",
            DashboardUrl.build(9091, ""),
        )
    }

    @Test
    fun blankSecretIsTreatedAsNoSecret() {
        assertEquals(
            "http://127.0.0.1:9091/ui/#/proxies",
            DashboardUrl.build(9091, "   "),
        )
    }

    @Test
    fun plainSecretAppendsEncodedQuery() {
        assertEquals(
            "http://127.0.0.1:9091/ui/?secret=abc123#/proxies",
            DashboardUrl.build(9091, "abc123"),
        )
    }

    @Test
    fun secretWithSpecialCharsIsUrlEncoded() {
        assertEquals(
            "http://127.0.0.1:9091/ui/?secret=a+b%26c%3Dd%3Fe%2Ff#/proxies",
            DashboardUrl.build(9091, "a b&c=d?e/f"),
        )
    }

    @Test
    fun customPortIsUsed() {
        assertEquals(
            "http://127.0.0.1:18090/ui/#/proxies",
            DashboardUrl.build(18090, ""),
        )
    }

    @Test
    fun outOfRangePortFallsBackToDefault() {
        assertEquals(
            "http://127.0.0.1:9091/ui/#/proxies",
            DashboardUrl.build(0, ""),
        )
        assertEquals(
            "http://127.0.0.1:9091/ui/#/proxies",
            DashboardUrl.build(70000, ""),
        )
        assertEquals(
            "http://127.0.0.1:9091/ui/#/proxies",
            DashboardUrl.build(-1, ""),
        )
    }

    @Test
    fun portRangeBoundaries() {
        assertTrue(DashboardUrl.isValidPort(1))
        assertTrue(DashboardUrl.isValidPort(65535))
        assertFalse(DashboardUrl.isValidPort(0))
        assertFalse(DashboardUrl.isValidPort(65536))
        assertFalse(DashboardUrl.isValidPort(-1))
    }
}
