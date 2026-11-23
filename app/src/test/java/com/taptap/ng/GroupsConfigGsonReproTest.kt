package com.taptap.ng

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.GroupsConfig
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.lang.reflect.ParameterizedType
import java.nio.file.Files

/**
 * Repro + contract tests for the v1.0.17 (M7) phone crash
 * "START GAGAL: ClassCastException" — toast "n20 cannot be cast to ec0".
 *
 * Root cause (proven from the shipped APK's classes.dex, not from source
 * reading alone):
 * - In the release APK, GroupsConfig is obfuscated (field names become
 *   `a`/`b`, the write-only `version` field is removed) and — decisively —
 *   it carries NO generic Signature at all (its class_def has
 *   annotations_off=0). Its `groups`/`rules` fields therefore look like
 *   raw lists to Gson, so each JSON object in `groups` deserialises as a
 *   `com.google.gson.internal.LinkedTreeMap` (obfuscated to `n20`)
 *   instead of a `ProxyGroup` (obfuscated to `ec0`).
 * - `GroupsStore.load()` swallows the deserialisation itself inside
 *   runCatching, but the poisoned list only explodes at the FIRST typed
 *   element access — `pruneMissingProfiles()`'s `groups[i]` — which runs
 *   OUTSIDE the runCatching, so the ClassCastException escapes load()
 *   and is caught by runStart as "START GAGAL".
 *
 * These tests run on the JVM (no R8), so the R8 half is simulated:
 * [RawGroupsConfig] is the same shape with the element type erased,
 * which is exactly what Gson sees in the release build.
 */
class GroupsConfigGsonReproTest {

    /**
     * Mirror of [GroupsConfig] with the generic element type erased —
     * exactly what Gson sees in the release APK, where R8 stripped the
     * Signature from GroupsConfig's list fields.
     */
    private data class RawGroupsConfig(
        val version: Int = 1,
        val groups: List<Any?> = emptyList(),
        val rules: List<Any?> = emptyList(),
    )

    @Test
    fun `release-shaped Gson output - LinkedTreeMap elements - explodes in pruneMissingProfiles`() {
        val dir = Files.createTempDirectory("groups-r8-repro").toFile()
        val item = ProfileItem(
            remarks = "81", configType = ConfigType.VMESS,
            address = "104.17.3.81", port = 443,
        )
        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(item), item.guid)

        // Read the file back the way the release build's Gson does:
        // element type Object, so every group object becomes LinkedTreeMap.
        val text = File(dir, "groups.json").readText()
        val raw = Gson().fromJson(text, RawGroupsConfig::class.java)
        assertTrue(raw.groups.isNotEmpty(), "expected the default group in groups.json")
        assertEquals(
            "com.google.gson.internal.LinkedTreeMap",
            raw.groups[0].javaClass.name,
            "release Gson must produce LinkedTreeMap elements (no generic Signature)",
        )

        // Inject the poisoned list into a real store. This is the same
        // unchecked erasure production code relies on
        // (`cfg.groups.toMutableList()` never checks an element).
        val groupsField = GroupsStore::class.java
            .getDeclaredField("groups").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        groupsField.set(store, raw.groups as MutableList<ProxyGroup>)

        // The exact production throw site: GroupsStore.pruneMissingProfiles
        // reads `groups[i]` (GroupsStore.kt, outside load()'s runCatching).
        // On the phone the class names are obfuscated to
        // "n20 cannot be cast to ec0"; on the JVM they are spelled out.
        val e = assertThrows(ClassCastException::class.java) {
            store.pruneMissingProfiles(setOf(item.guid))
        }
        assertTrue(e.message!!.contains("LinkedTreeMap"), "thrown: ${e.message}")
        assertTrue(e.message!!.contains("ProxyGroup"), "thrown: ${e.message}")
    }

    @Test
    fun `GroupsConfig fields carry SerializedName so R8 cannot rename the JSON keys`() {
        // GroupsConfig's fields have no @SerializedName today, so the
        // release build writes groups.json with obfuscated keys ("a"/"b")
        // instead of "version"/"groups"/"rules". That alone makes the
        // file unreadable by any other build's mapping; together with
        // the missing -keep rules it is half of the M7 crash. Every
        // field must name its JSON key explicitly (like ProxyGroup and
        // RouteRule already do).
        val fields = GroupsConfig::class.java.declaredFields.filterNot { it.isSynthetic }
        assertTrue(fields.isNotEmpty(), "GroupsConfig has no fields?")
        for (f in fields) {
            assertNotNull(
                f.getAnnotation(SerializedName::class.java),
                "GroupsConfig.${f.name} needs @SerializedName (R8 renames it otherwise)",
            )
        }
    }

    @Test
    fun `GroupsConfig list fields keep their generic element types`() {
        // Contract the release build must preserve (via -keep rules for
        // the Gson model): without the ParameterizedType, Gson falls
        // back to Object and every group becomes a LinkedTreeMap.
        // Passes on the JVM (kotlinc emits the Signature); the shipped
        // APK's classes.dex is the authority for the release build.
        val groupsType = GroupsConfig::class.java
            .getDeclaredField("groups").genericType as ParameterizedType
        assertEquals(ProxyGroup::class.java, groupsType.actualTypeArguments.single())
    }

    @Test
    fun `load reads a v1_0_17 obfuscated-key groups json and keeps the group`() {
        // v1.0.17 wrote groups.json with R8-obfuscated keys
        // ("a" = groups, "b" = rules — verified from the shipped
        // classes.dex, see GroupsConfig's KDoc) and no version key.
        // v1.0.18 must read that file back as-is (alternate keys),
        // not fall back to the default and not throw.
        val dir = Files.createTempDirectory("groups-v1017-migration").toFile()
        val item = ProfileItem(
            remarks = "81", configType = ConfigType.VMESS,
            address = "104.17.3.81", port = 443,
        )
        val group = ProxyGroup(
            id = "group-1", name = "Proxy",
            members = listOf(item.guid), selectedMemberGuid = item.guid,
        )
        val rule = com.taptap.ng.core.RouteRule(
            id = "rule-1",
            type = com.taptap.ng.core.RouteRuleType.FINAL,
            target = "group-1",
        )
        val gson = Gson()
        File(dir, "groups.json").writeText(
            """{"a":[${gson.toJson(group)}],"b":[${gson.toJson(rule)}]}""",
        )

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(item), item.guid)

        assertEquals(1, store.groups.size)
        assertEquals("group-1", store.groups[0].id)
        assertEquals("Proxy", store.groups[0].name)
        assertEquals(listOf(item.guid), store.groups[0].members)
        assertEquals(item.guid, store.groups[0].selectedMemberGuid)
        assertEquals(1, store.rules.size)
        assertEquals("rule-1", store.rules[0].id)
        assertEquals("group-1", store.rules[0].target)

        // A second load reads the same group back (no silent
        // fallback to a rebuilt default with a new id).
        val second = GroupsStore(File(dir, "groups.json"))
        second.load(listOf(item), item.guid)
        assertEquals("group-1", second.groups[0].id)
    }

    @Test
    fun `load with wrong-typed group elements falls back to default instead of throwing`() {
        // The closest JVM analogue of the v1.0.17 poison
        // (LinkedTreeMap elements, which Gson only produces when
        // the generic Signature is gone — i.e. in the release dex,
        // never on the JVM): elements of the wrong JSON shape.
        // load() must treat it as a corrupt file — default group,
        // no throw, no START GAGAL.
        val dir = Files.createTempDirectory("groups-wrong-type").toFile()
        val item = ProfileItem(
            remarks = "81", configType = ConfigType.VMESS,
            address = "104.17.3.81", port = 443,
        )
        File(dir, "groups.json").writeText("""{"groups":["oops"],"rules":[]}""")

        val store = GroupsStore(File(dir, "groups.json"))
        store.load(listOf(item), item.guid) // must not throw

        assertEquals(1, store.groups.size)
        assertEquals(GroupsStore.DEFAULT_GROUP_NAME, store.groups[0].name)
        assertEquals(listOf(item.guid), store.groups[0].members)
        assertEquals(1, store.rules.size)
    }
}
