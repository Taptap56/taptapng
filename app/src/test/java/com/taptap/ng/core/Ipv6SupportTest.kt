package com.taptap.ng.core

import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class Ipv6SupportTest {

    private val v4a = InetAddress.getByName("1.2.3.4")
    private val v4b = InetAddress.getByName("5.6.7.8")
    private val v6a = InetAddress.getByName("2001:db8::1")
    private val v6b = InetAddress.getByName("::1")

    @Test
    fun `default order is ipv4 first`() {
        val ordered = Ipv6Support.orderAddresses(listOf(v6a, v4a, v6b, v4b), preferIpv6 = false)
        assertEquals(listOf(v4a, v4b, v6a, v6b), ordered)
    }

    @Test
    fun `prefer ipv6 puts ipv6 first and keeps relative order`() {
        val ordered = Ipv6Support.orderAddresses(listOf(v4a, v6a, v4b, v6b), preferIpv6 = true)
        assertEquals(listOf(v6a, v6b, v4a, v4b), ordered)
    }

    @Test
    fun `ordering a single family list is a no op`() {
        assertEquals(listOf(v4a, v4b), Ipv6Support.orderAddresses(listOf(v4a, v4b), true))
        assertEquals(emptyList<InetAddress>(), Ipv6Support.orderAddresses(emptyList(), true))
    }

    @Test
    fun `resolve ordered returns literals without a lookup`() {
        // Literals never touch the network: safe on the JVM runner.
        assertEquals(
            listOf(InetAddress.getByName("127.0.0.1")),
            Ipv6Support.resolveOrdered("127.0.0.1", preferIpv6 = true),
        )
        assertEquals(
            listOf(InetAddress.getByName("::1")),
            Ipv6Support.resolveOrdered("::1", preferIpv6 = false),
        )
        // AAAA answers already flow through the forwarder relay (opaque
        // UDP/53) — the resolver path itself is covered by DnsResolverTest.
        assertTrue(InetAddress.getByName("::1").hostAddress.contains(':'))
    }
}
