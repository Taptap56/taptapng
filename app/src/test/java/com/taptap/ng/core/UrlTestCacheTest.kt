package com.taptap.ng.core

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Url-test delay cache + loop tests (M7, W2). The loop thread
 * itself is not started here — [UrlTestLoop.probeGroup] /
 * [UrlTestLoop.dueGroups] are the testable core, driven directly
 * with a stub tester.
 */
class UrlTestCacheTest {

    @AfterEach
    fun clearObservatory() {
        Observatory.clear()
    }

    private fun item(guid: String) = ProfileItem(
        guid = guid,
        remarks = guid,
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
    )

    private fun urlTestGroup(
        id: String = "g1",
        members: List<String> = listOf("a", "b"),
        intervalSec: Int = 300,
    ) = ProxyGroup(
        id = id,
        name = "UrlTest",
        type = ProxyGroupType.URL_TEST,
        members = members,
        urlTestIntervalSec = intervalSec,
    )

    @Test
    fun recordAndReadDelay() {
        val cache = UrlTestCache()
        assertNull(cache.delay("a"))
        cache.record("a", 123L, atMs = 1000L)
        assertEquals(123L, cache.delay("a"))
        assertEquals(1000L, cache.measuredAtMs("a"))
    }

    @Test
    fun failedProbeRecordsUnknownDelay() {
        val cache = UrlTestCache()
        cache.record("a", null, atMs = 1000L)
        assertNull(cache.delay("a"))
        assertEquals(mapOf<String, Long?>("a" to null), cache.delays())
    }

    @Test
    fun delaysSnapshotReturnsAllEntries() {
        val cache = UrlTestCache()
        cache.record("a", 100L)
        cache.record("b", null)
        assertEquals(mapOf<String, Long?>("a" to 100L, "b" to null), cache.delays())
    }

    @Test
    fun freshEntryIsFreshAndStaleEntryIsNot() {
        val cache = UrlTestCache()
        cache.record("a", 100L, atMs = 1000L)
        assertTrue(cache.isFresh("a", maxAgeMs = 5000L, nowMs = 5000L))
        assertFalse(cache.isFresh("a", maxAgeMs = 5000L, nowMs = 7000L))
        assertFalse(cache.isFresh("missing", maxAgeMs = 5000L, nowMs = 1000L))
    }

    @Test
    fun failedEntryIsNeverFresh() {
        val cache = UrlTestCache()
        cache.record("a", null, atMs = 1000L)
        assertFalse(cache.isFresh("a", maxAgeMs = 60_000L, nowMs = 1000L))
    }

    @Test
    fun clearEmptiesCache() {
        val cache = UrlTestCache()
        cache.record("a", 100L)
        cache.clear()
        assertNull(cache.delay("a"))
        assertTrue(cache.delays().isEmpty())
    }

    @Test
    fun seedFromObservatoryTakesFreshSuccessesOnly() {
        val cache = UrlTestCache()
        Observatory.record(Observatory.ProbeResult("a", 150L, 9000L, "GET", 1, null))
        Observatory.record(Observatory.ProbeResult("b", -1L, 9000L, "GET", 1, "timeout"))
        Observatory.record(Observatory.ProbeResult("c", 200L, 1000L, "GET", 1, null))
        val seeded = cache.seedFromObservatory(maxAgeMs = 5000L, nowMs = 10_000L)
        assertEquals(1, seeded)
        assertEquals(150L, cache.delay("a"))
        assertNull(cache.delay("b"))
        assertNull(cache.delay("c"))
    }

    @Test
    fun probeGroupRecordsDelaysForMembers() {
        val cache = UrlTestCache()
        val loop = UrlTestLoop(
            cache = cache,
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
            tester = { item, _ -> ServerTester.TestResult(if (item.guid == "a") 100L else 250L, null) },
        )
        val result = loop.probeGroup(urlTestGroup(), listOf(item("a"), item("b")))
        assertEquals(mapOf<String, Long?>("a" to 100L, "b" to 250L), result)
        assertEquals(100L, cache.delay("a"))
        assertEquals(250L, cache.delay("b"))
    }

    @Test
    fun probeGroupRecordsNullOnFailure() {
        val cache = UrlTestCache()
        val loop = UrlTestLoop(
            cache = cache,
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
            tester = { _, _ -> ServerTester.TestResult(-1, "timeout") },
        )
        val result = loop.probeGroup(urlTestGroup(), listOf(item("a")))
        assertEquals(mapOf<String, Long?>("a" to null), result)
        assertNull(cache.delay("a"))
    }

    @Test
    fun probeGroupSkipsMembersWithoutProfile() {
        val cache = UrlTestCache()
        val loop = UrlTestLoop(
            cache = cache,
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
            tester = { _, _ -> ServerTester.TestResult(100L, null) },
        )
        val result = loop.probeGroup(urlTestGroup(members = listOf("a", "gone")), listOf(item("a")))
        assertEquals(mapOf<String, Long?>("a" to 100L), result)
        assertNull(cache.delay("gone"))
    }

    @Test
    fun probeGroupIsNoopForNonUrlTestGroups() {
        val cache = UrlTestCache()
        val loop = UrlTestLoop(
            cache = cache,
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
            tester = { _, _ -> ServerTester.TestResult(100L, null) },
        )
        val select = ProxyGroup(id = "g1", type = ProxyGroupType.SELECT, members = listOf("a"))
        assertTrue(loop.probeGroup(select, listOf(item("a"))).isEmpty())
        assertNull(cache.delay("a"))
    }

    @Test
    fun dueGroupsRespectsInterval() {
        val cache = UrlTestCache()
        val loop = UrlTestLoop(
            cache = cache,
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
            tester = { _, _ -> ServerTester.TestResult(100L, null) },
        )
        val group = urlTestGroup(intervalSec = 300)
        // Never probed: due at once (last probe defaults to 0).
        assertEquals(listOf(group), loop.dueGroups(listOf(group), nowMs = 1000L))
        loop.probeDue(listOf(group), listOf(item("a"), item("b")), nowMs = 1000L)
        // Just probed: not due again until the interval elapses.
        assertTrue(loop.dueGroups(listOf(group), nowMs = 2000L).isEmpty())
        assertEquals(listOf(group), loop.dueGroups(listOf(group), nowMs = 301_000L))
    }

    @Test
    fun nextDueInMsIsZeroWhenAGroupIsDue() {
        val loop = UrlTestLoop(
            cache = UrlTestCache(),
            groupsProvider = { emptyList() },
            profilesProvider = { emptyList() },
        )
        assertEquals(0L, loop.nextDueInMs(listOf(urlTestGroup()), nowMs = 1000L))
        assertEquals(30L * 60_000, loop.nextDueInMs(emptyList(), nowMs = 1000L))
    }
}
