package com.taptap.x.proto
import com.taptap.x.core.proto.*

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * ProbeBody (v1.0.8, fix B): the probe's first body bytes. The
 * ClientHello is parsed back field by field — a malformed hello
 * would make the target stay silent, which is exactly the deadlock
 * the probe body exists to break.
 */
class ProbeBodyTest {

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun u24(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 16) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            (b[off + 2].toInt() and 0xFF)

    /** Parse the ClientHello record; returns the SNI host or null. */
    private fun parseClientHello(bytes: ByteArray): String? {
        assertEquals(0x16, bytes[0].toInt() and 0xFF, "record type must be handshake")
        assertEquals(0x03, bytes[1].toInt() and 0xFF, "record version major")
        assertEquals(0x01, bytes[2].toInt() and 0xFF, "record version minor")
        assertEquals(bytes.size - 5, u16(bytes, 3), "record length")
        assertEquals(0x01, bytes[5].toInt() and 0xFF, "handshake type must be ClientHello")
        assertEquals(bytes.size - 9, u24(bytes, 6), "handshake length")
        assertEquals(0x03, bytes[9].toInt() and 0xFF, "client version major")
        assertEquals(0x03, bytes[10].toInt() and 0xFF, "client version minor")
        var pos = 11 + 32 // random
        val sessionLen = bytes[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        val csLen = u16(bytes, pos)
        assertTrue(csLen >= 2 && csLen % 2 == 0, "cipher suites length")
        pos += 2 + csLen
        val compLen = bytes[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extLen = u16(bytes, pos)
        pos += 2
        val extEnd = pos + extLen
        assertEquals(bytes.size, extEnd, "extensions must end at the record end")
        var sni: String? = null
        while (pos < extEnd) {
            val type = u16(bytes, pos)
            val len = u16(bytes, pos + 2)
            val data = bytes.copyOfRange(pos + 4, pos + 4 + len)
            if (type == 0x0000) {
                val listLen = u16(data, 0)
                assertEquals(data.size - 2, listLen, "server_name list length")
                assertEquals(0x00, data[2].toInt() and 0xFF, "name type must be host_name")
                val nameLen = u16(data, 3)
                sni = String(data, 5, nameLen, Charsets.UTF_8)
            }
            pos += 4 + len
        }
        return sni
    }

    @Test
    fun `client hello parses back with sni`() {
        val hello = ProbeBody.clientHello("leaseweb4.svrkencang.web.id")
        assertEquals("leaseweb4.svrkencang.web.id", parseClientHello(hello))
    }

    @Test
    fun `client hello without sni has no server_name extension`() {
        val hello = ProbeBody.clientHello(null)
        assertNull(parseClientHello(hello))
        // No 0x0000 extension type anywhere in the extension block.
        val bytes = hello
        var pos = 11 + 32
        pos += 1 + (bytes[pos].toInt() and 0xFF)
        pos += 2 + u16(bytes, pos)
        pos += 1 + (bytes[pos].toInt() and 0xFF)
        pos += 2 // extensions length
        while (pos < bytes.size) {
            val type = u16(bytes, pos)
            val len = u16(bytes, pos + 2)
            assertTrue(type != 0x0000, "server_name must be absent, found type 0x0000")
            pos += 4 + len
        }
    }

    @Test
    fun `client hellos differ per random`() {
        // Random must actually be random: two hellos for the same
        // host must differ (else every probe looks identical).
        val a = ProbeBody.clientHello("example.com")
        val b = ProbeBody.clientHello("example.com")
        assertTrue(!a.contentEquals(b), "two ClientHellos must differ in the random")
    }

    @Test
    fun `forEntry picks client hello for tls and http get otherwise`() {
        val tlsItem = ProfileItem(
            configType = ConfigType.VMESS, address = "leaseweb4.svrkencang.web.id",
            port = 443, uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            tls = true, network = "ws",
        )
        val hello = ProbeBody.forEntry(tlsItem)
        assertEquals("leaseweb4.svrkencang.web.id", parseClientHello(hello))
        assertEquals("leaseweb4.svrkencang.web.id", ProbeBody.sniHost(tlsItem))

        val plainItem = ProfileItem(
            configType = ConfigType.VMESS, address = "example.com",
            port = 80, uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            tls = false, network = "tcp",
        )
        val get = ProbeBody.forEntry(plainItem)
        assertEquals(
            "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
            String(get, Charsets.UTF_8),
        )
    }

    @Test
    fun `sni is skipped for ip literals`() {
        val ipItem = ProfileItem(
            configType = ConfigType.VMESS, address = "104.17.3.81",
            port = 443, uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            tls = true, network = "ws",
        )
        assertNull(ProbeBody.sniHost(ipItem))
        assertNull(parseClientHello(ProbeBody.forEntry(ipItem)))
    }

    @Test
    fun `http get includes non-standard port`() {
        val get = ProbeBody.httpGet("example.com", 8080)
        assertEquals(
            "GET / HTTP/1.0\r\nHost: example.com:8080\r\n\r\n",
            String(get, Charsets.UTF_8),
        )
    }
}
