package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class OriginalDstTest {

    @Test
    fun `sockaddr_in parses address and port`() {
        // sa_family AF_INET=2 (LE), port 443 (BE), 1.2.3.4.
        val bytes = byteArrayOf(
            2, 0, 0x01, 0xBB.toByte(), 1, 2, 3, 4,
            0, 0, 0, 0, 0, 0, 0, 0,
        )
        val parsed = OriginalDst.parseSockaddr(bytes)!!
        assertEquals("1.2.3.4", parsed.address.hostAddress)
        assertEquals(443, parsed.port)
    }

    @Test
    fun `sockaddr_in6 parses address and port`() {
        val addr = java.net.InetAddress.getByName("2001:db8::1").address
        val bytes = ByteArray(28)
        bytes[0] = 10 // AF_INET6 (LE)
        bytes[1] = 0
        bytes[2] = 0x01 // port 443 (BE)
        bytes[3] = 0xBB.toByte()
        addr.copyInto(bytes, 8)
        val parsed = OriginalDst.parseSockaddr(bytes)!!
        assertEquals("2001:db8::1", parsed.address.hostAddress)
        assertEquals(443, parsed.port)
    }

    @Test
    fun `too short or unknown family returns null`() {
        assertNull(OriginalDst.parseSockaddr(ByteArray(15)))
        assertNull(OriginalDst.parseSockaddr(ByteArray(0)))
        val unknown = ByteArray(16)
        unknown[0] = 99
        assertNull(OriginalDst.parseSockaddr(unknown))
        // IPv6 but truncated.
        val v6short = ByteArray(20)
        v6short[0] = 10
        assertNull(OriginalDst.parseSockaddr(v6short))
    }
}
