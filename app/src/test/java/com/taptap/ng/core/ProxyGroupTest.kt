package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ProxyGroupTest {

    @Test
    fun `defaults are select with generate 204 url and 300 second interval`() {
        val group = ProxyGroup(name = "Proxy")
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
}
