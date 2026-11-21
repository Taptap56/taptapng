package com.taptap.ng

import com.google.gson.Gson
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * v1.0.5: the editor adds many fields to ProfileItem. A profiles.json
 * written by v1.0.4 has none of them — Gson must read it with the
 * declared defaults (never null, never a crash on access).
 */
class ProfileItemDefaultsTest {

    @Test
    fun `fresh profile has v2rayng defaults for new fields`() {
        val item = ProfileItem()
        assertEquals("", item.finalMask)
        assertEquals("", item.browserDialerMode)
        assertEquals("", item.echConfigList)
        assertEquals("", item.verifyPeerCertByName)
        assertEquals("", item.pinnedCA256)
        assertEquals("", item.realityPublicKey)
        assertEquals("", item.realityShortId)
        assertEquals("", item.realitySpiderX)
        assertEquals("", item.realityMldsa65Verify)
        assertEquals("none", item.headerType)
        assertEquals("", item.mode)
        assertEquals("", item.xhttpMode)
        assertEquals("", item.authority)
        assertEquals("", item.serviceName)
        assertEquals("", item.xhttpExtra)
        assertEquals("", item.seed)
        assertEquals("", item.kcpMtu)
        assertEquals("", item.kcpTti)
        assertEquals("", item.flow)
        assertEquals("none", item.encryption)
        assertEquals("default", item.sshSniVersion)
        assertEquals("", item.streamSecurity)
        assertFalse(item.tls)
    }

    @Test
    fun `old json without new fields loads with defaults`() {
        val dir = Files.createTempDirectory("profiles-defaults-test").toFile()
        val file = File(dir, "profiles.json")
        // v1.0.4 file: no v1.0.5 fields at all.
        file.writeText(
            """[{"guid":"g1","remarks":"Old","configType":"VMESS","address":"h","port":443,"uuid":"u1"}]"""
        )
        val store = ProfileStore(file)
        store.load()
        assertEquals(1, store.profiles.size)
        val loaded = store.profiles[0]
        assertEquals("Old", loaded.remarks)
        assertEquals(ConfigType.VMESS, loaded.configType)
        assertEquals("", loaded.finalMask)
        assertEquals("", loaded.browserDialerMode)
        assertEquals("", loaded.echConfigList)
        assertEquals("", loaded.verifyPeerCertByName)
        assertEquals("", loaded.pinnedCA256)
        assertEquals("", loaded.realityPublicKey)
        assertEquals("", loaded.realityShortId)
        assertEquals("", loaded.realitySpiderX)
        assertEquals("", loaded.realityMldsa65Verify)
        assertEquals("none", loaded.headerType)
        assertEquals("", loaded.mode)
        assertEquals("", loaded.xhttpMode)
        assertEquals("", loaded.authority)
        assertEquals("", loaded.serviceName)
        assertEquals("", loaded.xhttpExtra)
        assertEquals("", loaded.seed)
        assertEquals("", loaded.kcpMtu)
        assertEquals("", loaded.kcpTti)
        assertEquals("", loaded.flow)
        assertEquals("none", loaded.encryption)
        assertEquals("default", loaded.sshSniVersion)
        assertEquals("", loaded.streamSecurity)
        assertFalse(loaded.tls)
        // Gson round trip keeps the new values once saved.
        val gson = Gson()
        val saved = gson.fromJson(gson.toJson(loaded), ProfileItem::class.java)
        assertEquals("none", saved.headerType)
        assertEquals("default", saved.sshSniVersion)
    }

    @Test
    fun `v101 json with goHelloEnabled loads fine, field removed in v102`() {
        // v1.0.2 deletes ProfileItem.goHelloEnabled (Hello Go is
        // gone). A profiles.json written by v1.0.1 still contains
        // the field — Gson must ignore the unknown key and load the
        // profile with everything else intact, never crash.
        val dir = Files.createTempDirectory("profiles-migration-test").toFile()
        val file = File(dir, "profiles.json")
        file.writeText(
            """[{"guid":"g3","remarks":"Iflix","configType":"VMESS","address":"front.wetv.vip","port":443,"uuid":"u1","tls":true,"network":"ws","goHelloEnabled":true,"pemicuEnabled":true,"pemicuDomain":"front.wetv.vip"}]"""
        )
        val store = ProfileStore(file)
        store.load()
        assertEquals(1, store.profiles.size)
        val loaded = store.profiles[0]
        assertEquals("Iflix", loaded.remarks)
        assertEquals(ConfigType.VMESS, loaded.configType)
        assertEquals("front.wetv.vip", loaded.address)
        assertEquals(443, loaded.port)
        assertEquals("u1", loaded.uuid)
        org.junit.jupiter.api.Assertions.assertTrue(loaded.tls)
        org.junit.jupiter.api.Assertions.assertTrue(loaded.pemicuEnabled)
        assertEquals("front.wetv.vip", loaded.pemicuDomain)
        // Saving drops the dead field: the next load is clean.
        val gson = Gson()
        val resaved = gson.toJson(loaded)
        org.junit.jupiter.api.Assertions.assertFalse(
            resaved.contains("goHelloEnabled"),
            "saved json must not contain goHelloEnabled: $resaved",
        )
    }

    @Test
    fun `old ssh json without new fields loads with defaults`() {
        val dir = Files.createTempDirectory("profiles-defaults-test").toFile()
        val file = File(dir, "profiles.json")
        file.writeText(
            """[{"guid":"g2","remarks":"OldSSH","configType":"SSH","address":"h","port":22,"username":"u"}]"""
        )
        val store = ProfileStore(file)
        store.load()
        val loaded = store.profiles[0]
        assertEquals("default", loaded.sshSniVersion)
        assertNull(loaded.pemicuPort)
        assertEquals("", loaded.streamSecurity)
    }
}
