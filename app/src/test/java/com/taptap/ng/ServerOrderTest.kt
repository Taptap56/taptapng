package com.taptap.ng

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.ui.main.buildExportClipboardText
import com.taptap.ng.ui.main.reorderGroupProfiles
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Drag-reorder + clipboard export (v1.0.28, v2rayNG parity).
 * Both functions are pure, so they run without an Application.
 */
class ServerOrderTest {

    private fun item(guid: String, group: String) =
        ProfileItem(guid = guid, group = group, remarks = guid)

    private fun vmess(guid: String, remarks: String) = ProfileItem(
        guid = guid,
        remarks = remarks,
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "11111111-2222-3333-4444-555555555555",
    )

    @Test
    fun `reorder moves group members and leaves other groups in place`() {
        val full = listOf(
            item("a", ""), item("b", ""), item("x", "G"),
            item("c", ""), item("d", ""),
        )
        val reordered = reorderGroupProfiles(full, "", listOf("d", "b", "a", "c"))
        assertEquals(listOf("d", "b", "x", "a", "c"), reordered.map { it.guid })
    }

    @Test
    fun `reorder appends unlisted group members in original order`() {
        val full = listOf(item("a", ""), item("b", ""), item("c", ""))
        val reordered = reorderGroupProfiles(full, "", listOf("c"))
        assertEquals(listOf("c", "a", "b"), reordered.map { it.guid })
    }

    @Test
    fun `reorder ignores unknown guids and duplicates`() {
        val full = listOf(item("a", ""), item("b", ""))
        val reordered = reorderGroupProfiles(full, "", listOf("zzz", "b", "b", "a"))
        assertEquals(listOf("b", "a"), reordered.map { it.guid })
    }

    @Test
    fun `reorder of an empty group returns the list unchanged`() {
        val full = listOf(item("a", ""), item("b", ""))
        assertEquals(full, reorderGroupProfiles(full, "missing", listOf("b", "a")))
    }

    @Test
    fun `export joins one share link per line`() {
        val text = buildExportClipboardText(
            listOf(vmess("a", "Satu"), vmess("b", "Dua"))
        )
        val lines = text.split("\n")
        assertEquals(2, lines.size)
        assertTrue(lines.all { it.startsWith("vmess://") })
    }

    @Test
    fun `export of an empty list is empty`() {
        assertEquals("", buildExportClipboardText(emptyList()))
    }
}
