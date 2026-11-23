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
    /**
     * v1.0.23: id of the main group. Null in files written by
     * older builds — [GroupsStore.load] migrates it (see
     * [GroupsStore.migrateMainGroupId]) and persists the result.
     * The main group is identified BY THIS ID, never by name, so
     * renaming it never breaks the route engine, the live switch,
     * or the Clash API's GLOBAL alias.
     */
    @SerializedName("mainGroupId")
    val mainGroupId: String? = null,
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
     * v1.0.23: id of the main group (persisted as
     * [GroupsConfig.mainGroupId]). Null while the file has no
     * groups at all; [load] (and [removeGroup]) always resolve it
     * to an existing group when one exists, so callers can rely
     * on [mainGroup] instead of matching the group by name.
     */
    @Volatile
    var mainGroupId: String? = null
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
            mainGroupId = cfg.mainGroupId
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
        // v1.0.21: the default group was renamed "Proxy" ->
        // "taptap" — migrate a file written by an older build (see
        // [migrateDefaultGroupName]) before pruning, and persist
        // the migration so the next load is a no-op.
        // v1.0.23: resolve the main-group id AFTER that rename, so
        // a pre-v1.0.23 file (no mainGroupId) picks up the renamed
        // group, not the stale "Proxy" name.
        val renamed = migrateDefaultGroupName()
        val mainResolved = migrateMainGroupId()
        if (renamed || mainResolved) save()
        if (profiles != null) {
            pruneMissingProfiles(profiles.map { it.guid }.toSet())
        }
    }

    fun save() {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(gson.toJson(GroupsConfig(CURRENT_VERSION, groups, rules, mainGroupId)))
        if (!tmp.renameTo(file)) {
            file.writeText(gson.toJson(GroupsConfig(CURRENT_VERSION, groups, rules, mainGroupId)))
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
        mainGroupId = group.id
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

    /**
     * v1.0.21: rename the default group "Proxy" -> [DEFAULT_GROUP_NAME].
     * A groups.json written by v1.0.18–v1.0.20 still stores a group
     * named "Proxy" — rename it in place (same id, so rules that
     * target it by id, e.g. FINAL, keep working untouched).
     *
     * Conflict: when a group named "taptap" already exists (created
     * by hand, or written by a newer build), the "Proxy" group is
     * MERGED into it instead — members appended (deduped, order
     * kept), the surviving group's stored selection wins, rules
     * targeting a dropped group's id are re-pointed at the
     * survivor, and the duplicate is removed. After load there is
     * never a "Proxy" and a "taptap" side by side.
     *
     * Rules are also repaired when they target the literal name
     * "Proxy" (a hand-edited file — production code always stores
     * the group id): they are re-pointed at the surviving default
     * group's id. Returns true when anything changed (the caller
     * persists it, so a second load finds no "Proxy" group and no
     * literal-"Proxy" target left and is a no-op).
     */
    private fun migrateDefaultGroupName(): Boolean {
        val legacy = groups.filter { it.name == LEGACY_DEFAULT_GROUP_NAME }
        if (legacy.isEmpty() && rules.none { it.target == LEGACY_DEFAULT_GROUP_NAME }) {
            return false
        }
        var changed = false
        // Surviving default group: an existing "taptap" group wins;
        // otherwise the first legacy group is renamed in place.
        val base = groups.firstOrNull { it.name == DEFAULT_GROUP_NAME }
            ?: legacy.firstOrNull()
        if (base != null) {
            val others = legacy.filter { it.id != base.id }
            val mergedMembers = (base.members + others.flatMap { it.members }).distinct()
            val selected = base.selectedMemberGuid?.takeIf { it in mergedMembers }
                ?: others.firstNotNullOfOrNull { it.selectedMemberGuid?.takeIf { g -> g in mergedMembers } }
                ?: mergedMembers.firstOrNull()
            val merged = base.copy(
                name = DEFAULT_GROUP_NAME,
                members = mergedMembers,
                selectedMemberGuid = selected,
            )
            val droppedIds = others.map { it.id }.toSet()
            groups = groups.mapNotNull { g ->
                when {
                    g.id == base.id -> merged
                    g.id in droppedIds -> null
                    else -> g
                }
            }.toMutableList()
            changed = true
        }
        // Re-point rules at the surviving default group: rules that
        // targeted a dropped legacy id, or the literal name "Proxy".
        // (A rule already targeting the survivor's id is untouched.)
        val targetId = groups.firstOrNull { it.name == DEFAULT_GROUP_NAME }?.id
        if (targetId != null) {
            val droppedIds = legacy.map { it.id }.toSet()
            var rulesChanged = false
            rules = rules.map { r ->
                if (r.target == LEGACY_DEFAULT_GROUP_NAME ||
                    (r.target in droppedIds && r.target != targetId)
                ) {
                    rulesChanged = true
                    r.copy(target = targetId)
                } else {
                    r
                }
            }.toMutableList()
            changed = changed || rulesChanged
        }
        return changed
    }

    /**
     * v1.0.23: the main group, resolved BY ID — never by name.
     * Resolution order (the stored id wins when it still exists):
     * stored [mainGroupId] → the group the FINAL rule targets →
     * the group named [DEFAULT_GROUP_NAME] → the first group →
     * null (no groups at all). The FINAL-target step is why the
     * v1.0.21 migration order matters: a pre-v1.0.23 file whose
     * default group was already renamed by hand still resolves
     * through its FINAL rule. The FINAL target is NOT the
     * identity itself — the user can re-point or delete the FINAL
     * rule, so the stored id is what survives a rename; the
     * fallbacks only cover files / states that have no stored id
     * (or a stale one, e.g. the main group was just deleted).
     */
    fun mainGroup(): ProxyGroup? {
        mainGroupId?.let { id -> findGroup(id)?.let { return it } }
        rules.firstOrNull { it.type == RouteRuleType.FINAL }
            ?.target?.let { target -> findGroup(target)?.let { return it } }
        groups.firstOrNull { it.name == DEFAULT_GROUP_NAME }?.let { return it }
        return groups.firstOrNull()
    }

    /**
     * v1.0.23: persist the main-group id when the loaded file has
     * none (pre-v1.0.23) or a stale one (the group is gone).
     * Runs AFTER [migrateDefaultGroupName], so the "taptap"
     * group it finds is the already-renamed one. Returns true
     * when the stored id changed (the caller persists it).
     */
    private fun migrateMainGroupId(): Boolean {
        val stored = mainGroupId
        if (stored != null && groups.any { it.id == stored }) return false
        val resolved = mainGroup()
        if (resolved?.id == stored) return false
        mainGroupId = resolved?.id
        return true
    }

    /** Outcome of [renameMainGroup] — the card shows the message. */
    sealed interface RenameMainGroupResult {
        /** Renamed (and saved); [group] is the renamed group. */
        data class Renamed(val group: ProxyGroup) : RenameMainGroupResult

        /** The new name was blank. */
        object Blank : RenameMainGroupResult

        /** Another group already uses the name. */
        object Duplicate : RenameMainGroupResult

        /** There is no group to rename (empty group list). */
        object NoMainGroup : RenameMainGroupResult
    }

    /**
     * v1.0.23: rename the main group (the "Grup utama" card).
     * Identity is the stored [mainGroupId], so the rename only
     * changes the name — rules, the route engine, the live
     * switch and the Clash API keep working untouched. The name
     * is trimmed; blank and duplicate names are rejected (the
     * store is left unchanged). Same validation as the group
     * edit dialog's blank check, plus the duplicate check the
     * dialog lacks.
     */
    fun renameMainGroup(newName: String): RenameMainGroupResult {
        val name = newName.trim()
        if (name.isBlank()) return RenameMainGroupResult.Blank
        val main = mainGroup() ?: return RenameMainGroupResult.NoMainGroup
        if (groups.any { it.id != main.id && it.name == name }) {
            return RenameMainGroupResult.Duplicate
        }
        val renamed = main.copy(name = name)
        updateGroup(renamed)
        return RenameMainGroupResult.Renamed(renamed)
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
        val wasMain = id == mainGroupId
        groups.removeAll { it.id == id }
        if (wasMain) {
            // The main group is gone: re-resolve (FINAL target /
            // first group) so mainGroupId never points at a deleted
            // group. The FINAL rule itself keeps its stale target —
            // the engine already skips stale targets.
            mainGroupId = null
            migrateMainGroupId()
        }
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

    /**
     * Move a rule one step up (towards the head of the list, i.e.
     * earlier in the top-down match order) or down. The swap is
     * adjacent-only, so every other rule keeps its relative order.
     * Returns false — and saves nothing — when the rule does not
     * exist or is already at the requested edge. No FINAL guard:
     * moving a rule below FINAL leaves it unreachable, which is
     * the user's choice (same as TB).
     */
    fun moveRuleUp(id: String): Boolean = moveRule(id, -1)

    fun moveRuleDown(id: String): Boolean = moveRule(id, +1)

    private fun moveRule(id: String, delta: Int): Boolean {
        val idx = rules.indexOfFirst { it.id == id }
        val target = idx + delta
        if (idx < 0 || target < 0 || target >= rules.size) return false
        val rule = rules[idx]
        rules[idx] = rules[target]
        rules[target] = rule
        save()
        return true
    }

    companion object {
        const val CURRENT_VERSION = 1

        /** Name of the default group (v1.0.21: renamed from "Proxy"). */
        const val DEFAULT_GROUP_NAME = "taptap"

        /**
         * Pre-v1.0.21 name of the default group. Only used by
         * [migrateDefaultGroupName] to recognise (and rename/merge)
         * a group stored under the old name — never written anymore.
         */
        const val LEGACY_DEFAULT_GROUP_NAME = "Proxy"

        fun defaultFile(filesDir: File): File = File(filesDir, AppConfig.GROUPS_FILE)
    }
}
