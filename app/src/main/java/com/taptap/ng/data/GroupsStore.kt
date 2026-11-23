package com.taptap.ng.data

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.taptap.ng.AppConfig
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import java.io.File

/**
 * On-disk shape of groups.json (M7). `version` is 1; a future
 * format bump reads the old version here and migrates.
 *
 * v1.0.18: every key is explicit ([SerializedName]) so R8 can
 * never rename it again. The v1.0.17 release wrote obfuscated
 * keys — `"a"` = groups, `"b"` = rules (verified from the
 * shipped classes.dex: GroupsConfig's ctor (ArrayList, ArrayList)
 * stores its 1st arg in field `a` and its 2nd in `b`, and save()
 * passes (groups, rules) in that order; `version` was folded
 * away entirely, so a v1.0.17 file has no version key and reads
 * back as the default 1). Those keys stay readable as
 * [SerializedName.alternate]s, so a v1.0.17 file migrates instead
 * of falling back to the default.
 */
internal data class GroupsConfig(
    @SerializedName("version")
    val version: Int = 1,
    @SerializedName(value = "groups", alternate = ["a"])
    val groups: List<ProxyGroup> = emptyList(),
    @SerializedName(value = "rules", alternate = ["b"])
    val rules: List<RouteRule> = emptyList(),
)

/**
 * Proxy-group + route-rule storage (M7): one Gson JSON file in the
 * app's private files dir, mirroring [ProfileStore] — atomic save
 * via a .tmp file, tolerant load (missing or corrupt file falls
 * back to the default configuration).
 *
 * Default configuration (old installs without groups.json):
 * one SELECT group [DEFAULT_GROUP_NAME] holding EVERY profile guid
 * that exists at load time, with `selectedMemberGuid` = the server
 * currently selected in [ProfileStore] (or the first profile), plus
 * one FINAL rule pointing at that group — so an install that never
 * touched groups behaves exactly like before (one selected server).
 *
 * Pruning: [load] drops group members whose guid no longer exists
 * in the profiles passed in — but ONLY when profiles are supplied
 * (null = "unknown", never prune). That single place covers
 * remove / removeGroup / replaceAll, so [ProfileStore] needs no
 * coupling to this store. A SELECT group that loses its selected
 * member re-points at its first remaining member; a group that
 * loses every member stays empty (the route engine decides what
 * an empty group means).
 *
 * [ProfileItem] / profiles.json are untouched by this store.
 */
class GroupsStore(private val file: File) {

    private val gson = Gson()

    @Volatile
    var groups: MutableList<ProxyGroup> = mutableListOf()
        private set

    @Volatile
    var rules: MutableList<RouteRule> = mutableListOf()
        private set

    /**
     * Load groups.json. [profiles] + [selectedGuid] come from a
     * loaded [ProfileStore] and are only used when the file is
     * missing/corrupt (build the default) or to prune stale members.
     * Pass null for [profiles] when the profiles are not loaded —
     * no pruning happens then.
     */
    fun load(profiles: List<ProfileItem>? = null, selectedGuid: String? = null) {
        if (!file.exists()) {
            createDefault(profiles ?: emptyList(), selectedGuid)
            save()
            return
        }
        var corrupt = false
        runCatching {
            val text = file.readText()
            val cfg = gson.fromJson(text, GroupsConfig::class.java)
                ?: throw IllegalStateException("empty groups.json")
            // v1.0.18 (layer 3): a poisoned file parses "fine" but
            // its elements are LinkedTreeMap, not ProxyGroup /
            // RouteRule — that is exactly what the v1.0.17 release
            // produced (R8 stripped the generic Signature), and
            // `toMutableList()` never checks an element (erasure),
            // so the ClassCastException only exploded later, at
            // pruneMissingProfiles() OUTSIDE this runCatching, and
            // killed the start. Validate here, INSIDE the
            // runCatching: a wrong-typed element falls back to the
            // default like any other corrupt file. The `as List<Any?>`
            // is deliberate — checking `it is ProxyGroup` on the
            // typed list would be a no-op the compiler warns about.
            @Suppress("UNCHECKED_CAST")
            val rawGroups = cfg.groups as List<Any?>
            @Suppress("UNCHECKED_CAST")
            val rawRules = cfg.rules as List<Any?>
            if (rawGroups.any { it !is ProxyGroup } || rawRules.any { it !is RouteRule }) {
                throw IllegalStateException("groups.json has wrong element types")
            }
            groups = cfg.groups.toMutableList()
            rules = cfg.rules.toMutableList()
        }.onFailure {
            corrupt = true
        }
        if (corrupt) {
            // Unreadable file: fall back to the default, and persist
            // it so the next load sees a valid file.
            createDefault(profiles ?: emptyList(), selectedGuid)
            save()
            return
        }
        if (profiles != null) {
            pruneMissingProfiles(profiles.map { it.guid }.toSet())
        }
    }

    fun save() {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(gson.toJson(GroupsConfig(CURRENT_VERSION, groups, rules)))
        if (!tmp.renameTo(file)) {
            file.writeText(gson.toJson(GroupsConfig(CURRENT_VERSION, groups, rules)))
        }
    }

    /** Build the default configuration (see class doc). */
    private fun createDefault(profiles: List<ProfileItem>, selectedGuid: String?) {
        val guids = profiles.map { it.guid }
        val group = ProxyGroup(
            name = DEFAULT_GROUP_NAME,
            type = ProxyGroupType.SELECT,
            members = guids,
            selectedMemberGuid = selectedGuid?.takeIf { it in guids } ?: guids.firstOrNull(),
        )
        groups = mutableListOf(group)
        rules = mutableListOf(
            RouteRule(type = RouteRuleType.FINAL, target = group.id),
        )
    }

    /**
     * Drop members whose guid is gone; SELECT groups that lost
     * their selected member re-point at the first remaining member.
     * Returns true when anything changed (and saves then).
     */
    fun pruneMissingProfiles(existingGuids: Set<String>): Boolean {
        var changed = false
        for (i in groups.indices) {
            val g = groups[i]
            val kept = g.members.filter { it in existingGuids }
            if (kept.size != g.members.size) {
                val selected = if (g.type == ProxyGroupType.SELECT) {
                    g.selectedMemberGuid?.takeIf { it in kept } ?: kept.firstOrNull()
                } else {
                    g.selectedMemberGuid?.takeIf { it in kept }
                }
                groups[i] = g.copy(members = kept, selectedMemberGuid = selected)
                changed = true
            }
        }
        if (changed) save()
        return changed
    }

    fun findGroup(id: String): ProxyGroup? = groups.firstOrNull { it.id == id }

    fun findRule(id: String): RouteRule? = rules.firstOrNull { it.id == id }

    fun addGroup(group: ProxyGroup) {
        groups.add(group)
        save()
    }

    fun updateGroup(group: ProxyGroup) {
        val idx = groups.indexOfFirst { it.id == group.id }
        if (idx >= 0) {
            groups[idx] = group
            save()
        }
    }

    fun removeGroup(id: String) {
        groups.removeAll { it.id == id }
        save()
    }

    fun addRule(rule: RouteRule) {
        rules.add(rule)
        save()
    }

    fun updateRule(rule: RouteRule) {
        val idx = rules.indexOfFirst { it.id == rule.id }
        if (idx >= 0) {
            rules[idx] = rule
            save()
        }
    }

    fun removeRule(id: String) {
        rules.removeAll { it.id == id }
        save()
    }

    companion object {
        const val CURRENT_VERSION = 1

        /** Name of the default group (matches the Clash default). */
        const val DEFAULT_GROUP_NAME = "Proxy"

        fun defaultFile(filesDir: File): File = File(filesDir, AppConfig.GROUPS_FILE)
    }
}
