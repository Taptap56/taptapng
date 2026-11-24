package com.taptap.ng.core

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.31 (battery, H2): Observatory hanya mem-probe server yang
 * benar-benar bisa terpilih — anggota grup yang dirujuk aturan
 * yang aktif (+ grup utama sebagai fallback), grup bersarang
 * di-expand. Tes-tes ini GAGAL pada kode lama (itemsProvider
 * mengembalikan semua profil): dengan 8 profil tapi hanya 2 di
 * grup aktif, ronde lama mem-probe 8 server.
 */
class ObservatorySelectableTest {

    private fun item(guid: String) = ProfileItem(
        guid = guid,
        remarks = guid,
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
    )

    private fun tinyConfig() = Observatory.Config(
        leastPingIntervalMs = 100L,
        leastLoadIntervalMs = 200L,
        leastLoadMethod = "HEAD",
        sampling = 1,
        timeoutMs = 5_000,
        delayTestUrl = "",
    )

    private fun waitFor(
        timeoutMs: Long = 12_000,
        what: String,
        condition: () -> Boolean,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(100)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    @Test
    fun `hanya anggota grup aktif yang selectable`() {
        val groups = listOf(
            ProxyGroup(
                id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
                members = listOf("g1", "g2"), selectedMemberGuid = "g1",
            ),
            ProxyGroup(
                id = "g-lain", name = "lain", type = ProxyGroupType.URL_TEST,
                members = listOf("g3", "g4", "g5", "g6", "g7", "g8"),
            ),
        )
        val rules = listOf(
            // Aturan nonaktif ke grup lain: grupnya tidak selectable.
            RouteRule(
                id = "r-off", type = RouteRuleType.DOMAIN_SUFFIX,
                pattern = "example.com", target = "g-lain", enabled = false,
            ),
            // Target DIRECT tidak menyumbang server.
            RouteRule(
                id = "r-direct", type = RouteRuleType.DOMAIN_SUFFIX,
                pattern = "direct.example", target = RouteRule.TARGET_DIRECT,
            ),
            RouteRule(id = "r-final", type = RouteRuleType.FINAL, target = "g-main"),
        )
        assertEquals(
            setOf("g1", "g2"),
            Observatory.selectableGuids(groups, rules, "g-main"),
        )
    }

    @Test
    fun `grup bersarang di-expand, siklus tidak menggantung`() {
        val groups = listOf(
            ProxyGroup(
                id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
                members = listOf("g1"), selectedMemberGuid = "g1",
                groupMembers = listOf("g-tes"),
            ),
            ProxyGroup(
                id = "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
                members = listOf("g2", "g3"),
                groupMembers = listOf("g-main"),
            ),
        )
        val rules = listOf(
            RouteRule(id = "r-final", type = RouteRuleType.FINAL, target = "g-main"),
        )
        assertEquals(
            setOf("g1", "g2", "g3"),
            Observatory.selectableGuids(groups, rules, "g-main"),
        )
    }

    @Test
    fun `tanpa FINAL pun grup utama tetap selectable sebagai fallback`() {
        val groups = listOf(
            ProxyGroup(
                id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
                members = listOf("g1", "g2"), selectedMemberGuid = "g1",
            ),
        )
        assertEquals(
            setOf("g1", "g2"),
            Observatory.selectableGuids(groups, emptyList(), "g-main"),
        )
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun `ronde hanya mem-probe server di grup aktif`() {
        Observatory.clear()
        try {
            val profiles = (1..8).map { item("g$it") }
            val groups = listOf(
                ProxyGroup(
                    id = "g-main", name = "taptap", type = ProxyGroupType.SELECT,
                    members = listOf("g1", "g2"), selectedMemberGuid = "g1",
                ),
                ProxyGroup(
                    id = "g-lain", name = "lain", type = ProxyGroupType.URL_TEST,
                    members = listOf("g3", "g4", "g5", "g6", "g7", "g8"),
                ),
            )
            val rules = listOf(
                RouteRule(id = "r-final", type = RouteRuleType.FINAL, target = "g-main"),
            )
            val probed = java.util.Collections.synchronizedSet(HashSet<String>())
            val prober = ObservatoryProber(
                tinyConfig(),
                tester = { item, _, _ ->
                    probed.add(item.guid)
                    ServerTester.TestResult(100, null)
                },
            )
            // itemsProvider seperti di TaptapVpnService: profil
            // disaring ke yang selectable sebelum diserahkan.
            val runner = ObservatoryRunner(
                config = tinyConfig(),
                itemsProvider = {
                    val selectable = Observatory.selectableGuids(groups, rules, "g-main")
                    profiles.filter { it.guid in selectable }
                },
                prober = prober,
                onBestChanged = { _, _ -> },
                isActive = { true },
            )
            runner.start()
            try {
                assertTrue(
                    waitFor(what = "ronde pertama mem-probe") { probed.isNotEmpty() },
                    "runner tidak pernah mem-probe",
                )
                assertEquals(
                    setOf("g1", "g2"), probed.toSet(),
                    "ronde mem-probe server di luar grup aktif: $probed",
                )
            } finally {
                runner.stop()
            }
        } finally {
            Observatory.clear()
        }
    }
}
