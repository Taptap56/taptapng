package com.taptap.ng.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Clash API bind-address regression test (v1.0.20): on the phone
 * `InetAddress.getLoopbackAddress()` resolves to `::1` (IPv6
 * loopback) while the dashboard URL is hardcoded to
 * `http://127.0.0.1:<port>/ui/`, so the WebView got
 * ERR_CONNECTION_REFUSED. The non-LAN branch must therefore bind
 * the IPv4 loopback `127.0.0.1` explicitly; the LAN branch keeps
 * the `0.0.0.0` wildcard.
 *
 * Pure function test only — no socket is bound here (loopback JVM
 * in this VM is intercepted; a live bind check belongs to CI /
 * the phone, see ClashApiHandlerTest).
 */
class ClashApiServerBindTest {

    @Test
    fun nonLanBindsIpv4Loopback() {
        assertEquals("127.0.0.1", ClashApiServer.bindAddress(false).hostAddress)
    }

    @Test
    fun nonLanBindIsIpv4NotIpv6() {
        val addr = ClashApiServer.bindAddress(false)
        // IPv4 address = 4 bytes; ::1 would be 16 bytes.
        assertEquals(4, addr.address.size)
        assertFalse(addr.hostAddress.contains(":"))
    }

    @Test
    fun lanBindsWildcard() {
        assertEquals("0.0.0.0", ClashApiServer.bindAddress(true).hostAddress)
    }

    @Test
    fun nonLanBindMatchesDashboardUrlHost() {
        // The dashboard URL logged by ClashApiServer.start is
        // http://127.0.0.1:<port>/ui/ — the bind address must be
        // the same host, or the WebView cannot connect.
        assertEquals("127.0.0.1", ClashApiServer.bindAddress(false).hostAddress)
        assertTrue(ClashApiServer.bindAddress(false).isLoopbackAddress)
    }
}
