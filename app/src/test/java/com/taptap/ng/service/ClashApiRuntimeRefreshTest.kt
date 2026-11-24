package com.taptap.ng.service

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.ServerTester
import com.taptap.ng.core.UrlTestCache
import com.taptap.ng.core.UrlTestLoop
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.31 (battery, H5b): refreshGroups() hanya membangunkan
 * (kick) loop url-test bila grup benar-benar berubah. Kode lama
 * kick tanpa syarat di tiap panggilan API — tiap poll dashboard
 * (1/dtk) membangunkan worker yang sedang tidur. Tes ini GAGAL
 * pada kode lama (refreshGroups kedua yang tidak berubah tetap
 * menambah hitungan pemanggilan provider loop).
 *
 * Pengamatan: kick membangunkan worker, dan worker membaca ulang
 * grup lewat groupsProvider — jadi hitungan pemanggilan provider
 * adalah proksi kick yang bisa diamati.
 */
class ClashApiRuntimeRefreshTest {

    private fun item(remarks: String) = ProfileItem(
        remarks = remarks, configType = ConfigType.VMESS,
        address = "1.2.3.4", port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
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
    fun `fingerprint sama untuk isi sama, beda bila grup berubah`() {
        val dir = Files.createTempDirectory("refresh-test").toFile()
        val items = listOf(item("A"), item("B"))
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(items, items[0].guid)
        val before = ClashApiRuntime.groupsFingerprint(store)
        // Muat ulang dari disk: isi sama -> fingerprint sama.
        val reloaded = GroupsStore(File(dir, "groups.json"))
        reloaded.load(items, items[0].guid)
        assertEquals(before, ClashApiRuntime.groupsFingerprint(reloaded))
        // Rename grup -> fingerprint berubah.
        val renamed = store.groups[0].copy(name = "taptap-baru")
        store.updateGroup(renamed)
        assertNotEquals(before, ClashApiRuntime.groupsFingerprint(store))
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    fun `refreshGroups tidak kick bila grup tidak berubah, kick bila berubah`() {
        val dir = Files.createTempDirectory("refresh-test").toFile()
        val items = listOf(item("A"), item("B"))
        val profileStore = ProfileStore(ProfileStore.defaultFile(dir))
        items.forEach { profileStore.add(it) }
        profileStore.setSelectedGuid(items[0].guid)
        val setup = GroupsStore(GroupsStore.defaultFile(dir))
        setup.load(items, items[0].guid)
        setup.addGroup(
            ProxyGroup(
                id = "g-tes", name = "tes", type = ProxyGroupType.URL_TEST,
                members = listOf(items[0].guid), urlTestIntervalSec = 3600,
            ),
        )

        val providerCalls = AtomicInteger(0)
        val loop = UrlTestLoop(
            cache = UrlTestCache(),
            groupsProvider = {
                providerCalls.incrementAndGet()
                ClashApiRuntime.groupsStore?.groups?.toList() ?: emptyList()
            },
            profilesProvider = { items },
            tester = { _, _ -> ServerTester.TestResult(100, null) },
            isActive = { true },
            log = {},
        )
        ClashApiRuntime.urlTestLoop = loop
        // Buat shared store dulu (baseline fingerprint) sebelum
        // loop start — kalau tidak, provider loop membaca store
        // null (grup kosong) dan worker tidur 30 menit.
        ClashApiRuntime.refreshGroups(dir)
        loop.start()
        try {
            // Loop start: ronde pertama grup URL_TEST langsung
            // jalan (belum pernah di-probe), lalu worker tidur
            // sampai ronde berikut (3600 dtk) — provider terpanggil
            // 2x lalu stabil.
            assertTrue(
                waitFor(what = "loop stabil sesudah ronde pertama") { providerCalls.get() >= 2 },
                "loop url-test tidak pernah jalan",
            )
            Thread.sleep(500)
            val stable = providerCalls.get()

            // Grup tidak berubah: refreshGroups berulang TIDAK kick.
            repeat(3) { ClashApiRuntime.refreshGroups(dir) }
            Thread.sleep(800)
            assertEquals(
                stable, providerCalls.get(),
                "refreshGroups tanpa perubahan membangunkan loop (kick tanpa syarat?)",
            )

            // Grup berubah (rename): refreshGroups HARUS kick.
            val shared = ClashApiRuntime.refreshGroups(dir)
            val tes = shared.groups.first { it.id == "g-tes" }
            shared.updateGroup(tes.copy(name = "tes2"))
            ClashApiRuntime.refreshGroups(dir)
            assertTrue(
                waitFor(what = "kick sesudah grup berubah") { providerCalls.get() > stable },
                "grup berubah tapi loop tidak dibangunkan",
            )
        } finally {
            loop.stop()
            ClashApiRuntime.urlTestLoop = null
        }
    }
}
