package com.taptap.ng.ui.main

import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * groupAllDisplay (v1.0.5, group A — v2rayNG "Show an All group
 * tab"): with the setting on, the All tab (GROUP_ALL_ID) shows
 * every server regardless of group; with it off, or on any other
 * tab, the list is filtered to that group. The search filter
 * applies either way. Pure — no Application needed.
 */
class GroupAllDisplayTest {

    private fun item(guid: String, group: String, remarks: String = guid) =
        ProfileItem(guid = guid, group = group, remarks = remarks, address = "1.2.3.4")

    private val profiles = listOf(
        item("a", "", "Alpha"),
        item("b", "G1", "Beta"),
        item("c", "G2", "Gamma"),
        item("d", "G1", "Delta"),
    )

    @Test
    fun `all tab shows every group when setting is on`() {
        assertEquals(
            listOf("a", "b", "c", "d"),
            filterVisibleProfiles(profiles, GROUP_ALL_ID, true, "").map { it.guid },
        )
    }

    @Test
    fun `all tab selects nothing when setting is off`() {
        assertEquals(
            emptyList<String>(),
            filterVisibleProfiles(profiles, GROUP_ALL_ID, false, "").map { it.guid },
        )
    }

    @Test
    fun `a group tab still filters when setting is on`() {
        assertEquals(
            listOf("b", "d"),
            filterVisibleProfiles(profiles, "G1", true, "").map { it.guid },
        )
    }

    @Test
    fun `off behaves exactly like before`() {
        assertEquals(
            listOf("b", "d"),
            filterVisibleProfiles(profiles, "G1", false, "").map { it.guid },
        )
        assertEquals(
            listOf("a"),
            filterVisibleProfiles(profiles, "", false, "").map { it.guid },
        )
    }

    @Test
    fun `search still filters on the all tab`() {
        assertEquals(
            listOf("c"),
            filterVisibleProfiles(profiles, GROUP_ALL_ID, true, "gamma").map { it.guid },
        )
        assertEquals(
            listOf("b"),
            filterVisibleProfiles(profiles, GROUP_ALL_ID, true, "beta").map { it.guid },
        )
    }

    @Test
    fun `search matches address on the all tab`() {
        assertEquals(
            4,
            filterVisibleProfiles(profiles, GROUP_ALL_ID, true, "1.2.3.4").size,
        )
    }
}
