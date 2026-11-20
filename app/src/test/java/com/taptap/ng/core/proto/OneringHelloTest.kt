package com.taptap.ng.core.proto

import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Onering hello tests (M4, v1.0.23): the 0xff00 extension data must
 * be byte-identical to the TC mihomo fork's oneringBugExtensionData
 * (port of dharak36/xray-onering, DeemXray-proven 2026-11-17), and
 * the extension must enumerate FIRST in the ClientHello extensions
 * (BC serializes by iterating Hashtable.keys()).
 */
class OneringHelloTest {

    @Test
    fun `bug extension data matches the TC fork formula`() {
        // Go: listLen = 3 + len(bug); data = listLen(2B) + type 0
        // (1B) + hostLen (2B) + bug. "live.iflix.com" = 14 bytes,
        // so listLen = 17.
        val data = OneringHello.bugExtensionData("live.iflix.com")
        val expected = byteArrayOf(
            0x00, 0x11, // list_len = 17
            0x00, // name_type host_name
            0x00, 0x0E, // host_len = 14
        ) + "live.iflix.com".toByteArray(Charsets.US_ASCII)
        assertArrayEquals(expected, data)
    }

    @Test
    fun `bug extension data round-trips through the parser`() {
        listOf("live.iflix.com", "support.zoom.us", "a.b").forEach { bug ->
            assertEquals(bug, OneringHello.parseBugExtensionData(OneringHello.bugExtensionData(bug)))
        }
    }

    @Test
    fun `parser rejects malformed bug data`() {
        assertNull(OneringHello.parseBugExtensionData(byteArrayOf()))
        assertNull(OneringHello.parseBugExtensionData(byteArrayOf(0, 5, 0, 0, 1, 'x'.code.toByte())))
        // list_len says 17 but only 5 bytes follow.
        assertNull(
            OneringHello.parseBugExtensionData(
                byteArrayOf(0, 17, 0, 0, 14) + "live.iflix.com".toByteArray(Charsets.US_ASCII).copyOf(3),
            ),
        )
        // name_type is not host_name.
        val wrongType = OneringHello.bugExtensionData("live.iflix.com").copyOf().also { it[2] = 1 }
        assertNull(OneringHello.parseBugExtensionData(wrongType))
    }

    @Test
    fun `bug extension data rejects bad input`() {
        assertThrows(IllegalArgumentException::class.java) { OneringHello.bugExtensionData("") }
        assertThrows(IllegalArgumentException::class.java) { OneringHello.bugExtensionData("   ") }
        assertThrows(IllegalArgumentException::class.java) { OneringHello.bugExtensionData("bügs.example.com") }
        assertThrows(IllegalArgumentException::class.java) { OneringHello.bugExtensionData("a:b.com") }
        assertThrows(IllegalArgumentException::class.java) { OneringHello.bugExtensionData("x".repeat(254)) }
    }

    @Test
    fun `ordered extensions enumerate 0xff00 first`() {
        val ext = OrderedExtensions()
        // Insert in a scrambled order, like BC's getClientExtensions
        // would (SNI, ALPN, supported_groups...): 0xff00 must still
        // come out first, because the DPI reads the first extension.
        ext[0x0000] = byteArrayOf(0, 5, 0, 0, 1, 'a'.code.toByte())
        ext[0x0010] = byteArrayOf(0, 1, 0)
        ext[OneringHello.EXTENSION_TYPE] = OneringHello.bugExtensionData("live.iflix.com")
        ext[0x000A] = byteArrayOf(0, 2, 0, 1)
        val keys = ext.keys().toList()
        assertEquals(OneringHello.EXTENSION_TYPE, keys[0])
        assertEquals(4, keys.size)
        // get() still works — BC reads extension data by key.
        assertArrayEquals(
            OneringHello.bugExtensionData("live.iflix.com"),
            ext[OneringHello.EXTENSION_TYPE],
        )
    }

    @Test
    fun `ordered extensions reflect later puts`() {
        // BC adds key_share / supported_versions AFTER
        // getClientExtensions() returns, so the order must be
        // computed live at serialization time, not snapshotted.
        val ext = OrderedExtensions()
        ext[OneringHello.EXTENSION_TYPE] = OneringHello.bugExtensionData("live.iflix.com")
        ext[0x0033] = byteArrayOf(1, 2, 3) // key_share, added later
        val keys = ext.keys().toList()
        assertEquals(OneringHello.EXTENSION_TYPE, keys[0])
        assertTrue(keys.contains(0x0033))
    }

    @Test
    fun `ordered extensions without 0xff00 behave like a plain table`() {
        val ext = OrderedExtensions()
        ext[0x0000] = byteArrayOf(1)
        ext[0x0010] = byteArrayOf(2)
        val keys = ext.keys().toList()
        assertEquals(2, keys.size)
        assertTrue(keys.containsAll(listOf(0x0000, 0x0010)))
    }

    @Test
    fun `isOnering needs the chip and a bug domain`() {
        val base = ProfileItem(remarks = "x", address = "support.zoom.us", port = 443)
        assertFalse(OneringTls.isOnering(base))
        assertFalse(OneringTls.isOnering(base.copy(oneringEnabled = true, oneringBug = "")))
        assertFalse(OneringTls.isOnering(base.copy(oneringEnabled = false, oneringBug = "live.iflix.com")))
        assertTrue(OneringTls.isOnering(base.copy(oneringEnabled = true, oneringBug = "live.iflix.com")))
    }
}
