package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ProxyGroupTest {

    @Test
    fun `defaults are select with generate 204 url and 300 second interval`() {
        val group = ProxyGroup(name = "taptap")
        assertEquals(ProxyGroupType.SELECT, group.type)
        assertEquals("http://www.gstatic.com/generate_204", group.urlTestUrl)
        assertEquals(300, group.urlTestIntervalSec)
        assertEquals(emptyList<String>(), group.members)
        assertNull(group.selectedMemberGuid)
    }

    @Test
    fun `effective selected is the stored member when it is still a member`() {
        val group = ProxyGroup(
            members = listOf("a", "b", "c"),
            selectedMemberGuid = "b",
        )
        assertEquals("b", group.effectiveSelectedMemberGuid())
    }

    @Test
    fun `effective selected falls back to first member when stored is null`() {
        val group = ProxyGroup(members = listOf("a", "b"))
        assertEquals("a", group.effectiveSelectedMemberGuid())
    }

    @Test
    fun `effective selected falls back to first member when stored left the group`() {
        val group = ProxyGroup(
            members = listOf("a", "b"),
            selectedMemberGuid = "gone",
        )
        assertEquals("a", group.effectiveSelectedMemberGuid())
    }

    @Test
    fun `effective selected is null for an empty group`() {
        assertNull(ProxyGroup(members = emptyList()).effectiveSelectedMemberGuid())
    }

    @Test
    fun `interval below 60 clamps to 60`() {
        assertEquals(60, ProxyGroup(urlTestIntervalSec = 5).effectiveUrlTestIntervalSec)
        assertEquals(60, ProxyGroup(urlTestIntervalSec = 0).effectiveUrlTestIntervalSec)
    }

    @Test
    fun `interval above 3600 clamps to 3600`() {
        assertEquals(3600, ProxyGroup(urlTestIntervalSec = 5000).effectiveUrlTestIntervalSec)
    }

    @Test
    fun `interval inside range is unchanged`() {
        assertEquals(300, ProxyGroup(urlTestIntervalSec = 300).effectiveUrlTestIntervalSec)
        assertEquals(60, ProxyGroup(urlTestIntervalSec = 60).effectiveUrlTestIntervalSec)
        assertEquals(3600, ProxyGroup(urlTestIntervalSec = 3600).effectiveUrlTestIntervalSec)
    }

    // ---- Nested groups (v1.0.27) ----

    @Test
    fun `no nested groups by default and a missing key reads as none`() {
        val group = ProxyGroup(name = "taptap")
        assertEquals(emptyList<String>(), group.nestedGroupIds)
        assertNull(group.groupMembers)
    }

    @Test
    fun `effective selected accepts a nested group id`() {
        val group = ProxyGroup(
            members = listOf("a", "b"),
            selectedMemberGuid = "g-tes",
            groupMembers = listOf("g-tes"),
        )
        assertEquals("g-tes", group.effectiveSelectedMemberRef())
    }

    @Test
    fun `effective selected falls back to first server member before nested groups`() {
        val group = ProxyGroup(
            members = listOf("a", "b"),
            selectedMemberGuid = "gone",
            groupMembers = listOf("g-tes"),
        )
        assertEquals("a", group.effectiveSelectedMemberRef())
    }

    @Test
    fun `effective selected falls back to first nested group when there are no servers`() {
        val group = ProxyGroup(
            members = emptyList(),
            groupMembers = listOf("g-tes", "g-lain"),
        )
        assertEquals("g-tes", group.effectiveSelectedMemberRef())
    }

    @Test
    fun `effective selected guid still ignores a nested group id`() {
        // The server-only accessor keeps its old meaning: a
        // selection naming a nested group is not a server, so it
        // falls back to the first server member.
        val group = ProxyGroup(
            members = listOf("a", "b"),
            selectedMemberGuid = "g-tes",
            groupMembers = listOf("g-tes"),
        )
        assertEquals("a", group.effectiveSelectedMemberGuid())
    }
}
