package com.taptap.x.data

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.taptap.x.AppConfig
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

    @Volatile
    var selectedGuid: String? = null

    fun load() {
        if (!file.exists()) {
            profiles = mutableListOf()
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
    }

    fun save() {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(gson.toJson(profiles))
        if (!tmp.renameTo(file)) {
            file.writeText(gson.toJson(profiles))
        }
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
        if (selectedGuid == guid) selectedGuid = null
        save()
    }

    fun find(guid: String): ProfileItem? = profiles.firstOrNull { it.guid == guid }

    companion object {
        fun defaultFile(filesDir: File): File = File(filesDir, AppConfig.PROFILES_FILE)
    }
}
