package com.taptap.ng.data

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.taptap.ng.AppConfig
import java.io.File

/**
 * Profile storage: one Gson JSON file in the app's private files dir.
 * Phase 1 keeps it simple (no MMKV); the file format is a JSON array of
 * [ProfileItem], so it stays human-readable and forward-compatible
 * (new nullable fields read as null on old files).
 */
class ProfileStore(private val file: File) {

    private val gson = Gson()

    @Volatile
    var profiles: MutableList<ProfileItem> = mutableListOf()
        private set

    /**
     * The selected entry's guid. v1.0.8, fix A: this used to live only
     * in memory — [save] serialises [profiles] only, so the
     * VpnService's fresh store always read null and fell back to
     * `profiles.firstOrNull()`, i.e. connect dialled the TOPMOST
     * entry while the UI showed another one selected (phone proof:
     * taptapng-4.txt probed leaseweb4 with row 2 selected). The
     * selection now persists in a separate tiny file next to the
     * profiles file, so every store instance agrees. The profiles
     * file format itself is untouched (old files still load).
     */
    @Volatile
    var selectedGuid: String? = null
        private set

    /** File holding the persisted selection (guid text, or absent). */
    private val selectionFile: File
        get() = File(file.parentFile, "selected-guid.txt")

    /** Set the selection AND persist it. Use this everywhere instead
     *  of assigning [selectedGuid] directly. */
    fun setSelectedGuid(guid: String?) {
        selectedGuid = guid
        runCatching {
            if (guid.isNullOrBlank()) {
                selectionFile.delete()
            } else {
                selectionFile.parentFile?.mkdirs()
                selectionFile.writeText(guid)
            }
        }
    }

    fun load() {
        if (!file.exists()) {
            profiles = mutableListOf()
            selectedGuid = null
            return
        }
        runCatching {
            val text = file.readText()
            if (text.isBlank()) {
                profiles = mutableListOf()
            } else {
                val type = object : TypeToken<MutableList<ProfileItem>>() {}.type
                profiles = gson.fromJson<MutableList<ProfileItem>>(text, type) ?: mutableListOf()
            }
        }.onFailure {
            profiles = mutableListOf()
        }
        // Restore the persisted selection, but only if the entry
        // still exists — a deleted entry must not stay selected.
        val saved = runCatching {
            selectionFile.takeIf { it.exists() }?.readText()?.trim()
        }.getOrNull()
        selectedGuid = saved?.takeIf { it.isNotEmpty() && find(it) != null }
    }

    fun save() {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(gson.toJson(profiles))
        if (!tmp.renameTo(file)) {
            file.writeText(gson.toJson(profiles))
        }
    }

    /**
     * v1.0.28: ganti seluruh daftar profil (drag-reorder) lalu
     * simpan. Isi tiap profil tidak berubah — hanya urutannya.
     */
    fun replaceAll(newOrder: List<ProfileItem>) {
        profiles = newOrder.toMutableList()
        save()
    }

    fun add(item: ProfileItem) {
        profiles.add(item)
        save()
    }

    fun update(item: ProfileItem) {
        val idx = profiles.indexOfFirst { it.guid == item.guid }
        if (idx >= 0) {
            profiles[idx] = item
            save()
        }
    }

    fun remove(guid: String) {
        profiles.removeAll { it.guid == guid }
        if (selectedGuid == guid) setSelectedGuid(null)
        save()
    }

    /** Delete a whole group (and every server in it). */
    fun removeGroup(group: String) {
        profiles.removeAll { it.group == group }
        if (selectedGuid != null && find(selectedGuid!!) == null) {
            setSelectedGuid(profiles.firstOrNull()?.guid)
        }
        save()
    }

    /** Distinct group names in first-use order ("" = Default). */
    fun groups(): List<String> {
        val seen = linkedSetOf<String>()
        profiles.forEach { seen += it.group }
        return seen.toList()
    }

    fun find(guid: String): ProfileItem? = profiles.firstOrNull { it.guid == guid }

    companion object {
        fun defaultFile(filesDir: File): File = File(filesDir, AppConfig.PROFILES_FILE)
    }
}
