package com.taptap.x

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
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
}
