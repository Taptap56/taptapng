package com.taptap.ng

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

class ProfileStoreTest {

    @Test
    fun `save and load round trip`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val store = ProfileStore(File(dir, "profiles.json"))
        store.load()
        assertEquals(0, store.profiles.size)

        val item = ProfileItem(
            remarks = "SSH Edukasi",
            configType = ConfigType.SSH,
            address = "example.com",
            port = 22,
            username = "user",
            pemicuEnabled = true,
            pemicuDomain = "chat.sociomile.com",
            pemicuPort = 443,
        )
        store.add(item)

        val store2 = ProfileStore(File(dir, "profiles.json"))
        store2.load()
        assertEquals(1, store2.profiles.size)
        val loaded = store2.profiles[0]
        assertEquals("SSH Edukasi", loaded.remarks)
        assertEquals(ConfigType.SSH, loaded.configType)
        assertEquals("example.com", loaded.address)
        assertEquals(true, loaded.pemicuEnabled)
        assertEquals("chat.sociomile.com", loaded.pemicuDomain)
        assertEquals(443, loaded.pemicuPort)
    }

    @Test
    fun `old json without new fields reads as null`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val file = File(dir, "profiles.json")
        // Simulate a v1.0.0 file: no pemicu/onering/dnstt fields at all.
        file.writeText(
            """[{"guid":"g1","remarks":"Old","configType":"SSH","address":"h","port":22}]"""
        )
        val store = ProfileStore(file)
        store.load()
        assertEquals(1, store.profiles.size)
        val loaded = store.profiles[0]
        assertEquals("Old", loaded.remarks)
        assertEquals(false, loaded.pemicuEnabled)
        assertNull(loaded.pemicuPort)
        assertNull(loaded.pemicuInterval)
    }

    // v1.0.8, fix A: the selection used to live only in memory —
    // the VpnService's fresh store always read null and fell back
    // to profiles[0] (connect dialled the topmost entry, not the
    // selected one). The selection must survive a fresh store.

    private fun storeWithTwo(dir: File): Pair<ProfileStore, List<ProfileItem>> {
        val store = ProfileStore(File(dir, "profiles.json"))
        val a = ProfileItem(remarks = "A", configType = ConfigType.VMESS, address = "a.example", port = 443)
        val b = ProfileItem(remarks = "B", configType = ConfigType.VMESS, address = "b.example", port = 443)
        store.add(a)
        store.add(b)
        return store to listOf(a, b)
    }

    @Test
    fun `selection survives a fresh store load`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val (store, items) = storeWithTwo(dir)
        store.setSelectedGuid(items[1].guid) // select B, not the first

        val store2 = ProfileStore(File(dir, "profiles.json"))
        store2.load()
        assertEquals(items[1].guid, store2.selectedGuid)
        assertEquals("B", store2.find(store2.selectedGuid!!)?.remarks)
    }

    @Test
    fun `selection of a deleted entry is dropped on load`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val (store, items) = storeWithTwo(dir)
        store.setSelectedGuid(items[1].guid)
        // Simulate the entry being deleted without the store
        // noticing (e.g. an old file): rewrite profiles with only A.
        File(dir, "profiles.json").writeText(
            """[{"guid":"${items[0].guid}","remarks":"A","configType":"VMESS","address":"a.example","port":443}]"""
        )
        val store2 = ProfileStore(File(dir, "profiles.json"))
        store2.load()
        assertNull(store2.selectedGuid)
    }

    @Test
    fun `removing the selected entry clears the persisted selection`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val (store, items) = storeWithTwo(dir)
        store.setSelectedGuid(items[1].guid)
        store.remove(items[1].guid)

        val store2 = ProfileStore(File(dir, "profiles.json"))
        store2.load()
        assertNull(store2.selectedGuid)
    }

    @Test
    fun `removing a group re-points the persisted selection`() {
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val store = ProfileStore(File(dir, "profiles.json"))
        val a = ProfileItem(remarks = "A", configType = ConfigType.VMESS, address = "a.example", port = 443, group = "g1")
        val b = ProfileItem(remarks = "B", configType = ConfigType.VMESS, address = "b.example", port = 443, group = "g2")
        store.add(a)
        store.add(b)
        store.setSelectedGuid(a.guid)
        store.removeGroup("g1")

        val store2 = ProfileStore(File(dir, "profiles.json"))
        store2.load()
        assertEquals(b.guid, store2.selectedGuid)
    }

    @Test
    fun `service resolution picks the selected entry after a fresh load`() {
        // Simulates TaptapVpnService.startTunnel(): a fresh store,
        // load(), then find(selectedGuid) with fallback to first.
        // On v1.0.7 this resolved to profiles[0] (the topmost
        // entry) no matter what the UI had selected.
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val (store, items) = storeWithTwo(dir)
        store.setSelectedGuid(items[1].guid) // select B, not the first

        val serviceStore = ProfileStore(File(dir, "profiles.json"))
        serviceStore.load()
        val item = serviceStore.find(serviceStore.selectedGuid ?: "")
            ?: serviceStore.profiles.firstOrNull()
        assertEquals(items[1].guid, item?.guid)
        assertEquals("B", item?.remarks)
        assertEquals("b.example", item?.address)
    }

    @Test
    fun `profiles file format is unchanged by selection persistence`() {
        // The selection lives in a separate file; the profiles file
        // must stay a plain JSON array (old readers keep working).
        val dir = Files.createTempDirectory("profiles-test").toFile()
        val (store, items) = storeWithTwo(dir)
        store.setSelectedGuid(items[1].guid)
        val text = File(dir, "profiles.json").readText().trim()
        assertTrue(text.startsWith("["), "profiles file must stay a JSON array, was: $text")
        assertTrue(File(dir, "selected-guid.txt").exists())
        assertEquals(items[1].guid, File(dir, "selected-guid.txt").readText())
    }
}
