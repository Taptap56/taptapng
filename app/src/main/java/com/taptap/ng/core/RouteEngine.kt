package com.taptap.ng.core

import java.net.InetAddress

/**
 * Routing decision for one connection (M7, W2).
 *
 * [Proxy] carries the [ProfileItem.guid][com.taptap.ng.data.ProfileItem.guid]
 * the forwarder must dial; [Direct] dials the target straight from the
 * phone (protected socket, no proxy); [Reject] closes the connection
 * at once (TCP RST / UDP drop).
 */
sealed interface RouteDecision {
    data class Proxy(val profileGuid: String) : RouteDecision
    object Direct : RouteDecision
    object Reject : RouteDecision
}

/**
 * Pure route engine (M7, W2): matches one connection against the
 * ordered [RouteRule] list and picks a member from the target
 * [ProxyGroup]. No Android, no I/O — safe to call from the JVM
 * tests, the forwarder, and the Clash API (W3).
 *
 * Semantics (locked by RouteEngineTest):
 * - Rules are evaluated top-down; the first rule that matches AND
 *   resolves to a usable target wins.
 * - A rule that is switched off ([RouteRule.isEnabled] == false)
 *   is skipped entirely, as if it were not in the list (v1.0.23).
 *   FINAL is the exception: it has no toggle and is always
 *   evaluated, so a hand-edited file can never switch the last
 *   resort off.
 * - A rule whose target is a group with NO usable member (empty
 *   group, or a SELECT group with no members) does NOT match: the
 *   engine falls through to the next rule instead of killing the
 *   connection. A group that lost every member must never blackhole
 *   traffic — the next rule (usually FINAL) decides instead.
 * - A rule whose target names a group id that does not exist is
 *   likewise skipped (stale target, e.g. the group was deleted
 *   after the rule was written).
 * - [RouteRule.TARGET_DIRECT] / [RouteRule.TARGET_REJECT] decide
 *   immediately when their rule matches.
 * - When NO rule matches at all (e.g. the list has no FINAL rule),
 *   the engine falls back to the main group (see [RouteEngine.mainGroup]):
 *   the stored main-group id first, then the group named
 *   [FALLBACK_GROUP_NAME] ("taptap" — the default group
 *   [com.taptap.ng.data.GroupsStore] creates) for configs that
 *   predate the stored id, when it exists and has a usable member;
 *   otherwise [RouteDecision.Direct] — fail-open, so traffic still
 *   flows rather than being silently dropped. A default
 *   configuration always has FINAL → main group, so this path only
 *   runs for a hand-edited config without FINAL.
 *
 * Member selection ([selectMember]):
 * - SELECT → the group's [ProxyGroup.effectiveSelectedMemberGuid].
 * - URL_TEST → the member with the lowest last-known delay
 *   ([delays]); an unknown delay (null = never probed / failed)
 *   counts as infinite, so a member with any known delay always
 *   beats one without; ties keep member order; when every member
 *   is unknown the first member is used (same as "no data yet").
 * - FALLBACK → the first member with a known delay; when none is
 *   known the first member is used (better to try the first entry
 *   than to drop the connection).
 *
 * Nested groups (v1.0.27): a group's member may be another group
 * ([ProxyGroup.nestedGroupIds] — in practice only the main group
 * nests others). [selectMemberRef] picks the member the same way
 * as [selectMember] but across server members AND nested groups;
 * [resolveToServer] follows a nested member down to a real server
 * guid, and [groupDelay] is that server's delay. A cycle (A nests
 * B, B nests A — only possible in a hand-edited file, the store
 * never writes one) is cut by a visited set: the cyclic member is
 * skipped, the event is logged, and resolution returns null
 * instead of looping — never a crash, never a hang. Plain
 * server-only groups resolve exactly as before.
 *
 * [port] is part of the signature for future port-based rules; the
 * current rule types ignore it.
 *
 * Clash mode (M7, W3 — [SettingsStore.clashMode], PATCH /configs):
 * - "rule" (default) = the rule loop below.
 * - "global" = always the selected/effective member of the main
 *   group (see [RouteEngine.mainGroup]), or the first group when there is
 *   no main group; an unusable group falls back to
 *   [RouteDecision.Direct] (fail-open).
 * - "direct" = always [RouteDecision.Direct].
 * An unknown mode value behaves like "rule".
 *
 * v1.0.29: [RouteEngine.resolveDetailed] returns the same decision as
 * [RouteEngine.resolve] plus the [RouteRecord] the forwarder stores per
 * session (rule / rulePayload / chains) for GET /connections —
 * [RouteEngine.resolve] delegates to it, so the matching/selection logic
 * lives in exactly one place and cannot drift between the two.
 */
data class RouteRecord(
    val rule: String,
    val rulePayload: String,
    val chains: List<String>,
)

/**
 * A [RouteEngine] decision WITH its record (v1.0.29): the dial
 * target ([decision]) plus the [RouteRecord] the session stores.
 * [RouteRecord] on its own is what a live session carries:
 *
 * - [RouteRecord.rule]: the matched rule's type name ("FINAL",
 *   "DOMAIN-SUFFIX", ...); "GLOBAL" / "DIRECT" for those Clash
 *   modes; "FINAL" for the no-rule fallback (see
 *   [RouteEngine.resolveDetailed]).
 * - [RouteRecord.rulePayload]: the matched rule's pattern
 *   ("" for FINAL).
 * - [RouteRecord.chains]: the proxy chain as display names —
 *   the nested group names on the path plus the final server
 *   name (["taptap", "tes", "81"]); just the server name
 *   (["81"]) when the server is a direct member; ["DIRECT"]
 *   for a bypass, ["REJECT"] for a block.
 */
data class ResolvedRoute(
    val decision: RouteDecision,
    val record: RouteRecord,
)

object RouteEngine {

    /**
     * Name of the fallback group used when no rule matches. Kept
     * for configs that predate the stored main-group id (see
     * [mainGroup]): [com.taptap.ng.data.GroupsStore] still
     * creates the default group under this name, and the name is
     * the fallback when no stored id is available. Must stay
     * equal to
     * [com.taptap.ng.data.GroupsStore.DEFAULT_GROUP_NAME].
     */
    const val FALLBACK_GROUP_NAME = "taptap"

    /** Clash modes (see class doc). Stored in SettingsStore.clashMode. */
    const val MODE_RULE = "rule"
    const val MODE_GLOBAL = "global"
    const val MODE_DIRECT = "direct"

    /**
     * The main group for [groups]: the group with id
     * [mainGroupId] first (v1.0.23 — the id
     * [com.taptap.ng.data.GroupsStore] persists, so a rename
     * never moves it), then the group named [FALLBACK_GROUP_NAME]
     * for callers / configs without a stored id. Null when
     * neither exists.
     */
    fun mainGroup(groups: List<ProxyGroup>, mainGroupId: String?): ProxyGroup? =
        mainGroupId?.let { id -> groups.firstOrNull { it.id == id } }
            ?: groups.firstOrNull { it.name == FALLBACK_GROUP_NAME }

    fun resolve(
        host: String?,
        ip: InetAddress,
        port: Int,
        groups: List<ProxyGroup>,
        rules: List<RouteRule>,
        /** guid -> last-known delay ms; null = unknown / failed. */
        delays: Map<String, Long?>,
        /** Clash mode: "rule" (default), "global", or "direct". */
        mode: String = MODE_RULE,
        /**
         * v1.0.23: id of the main group (from
         * [com.taptap.ng.data.GroupsStore.mainGroupId]) — the
         * fallback / global group is picked BY THIS ID, not by
         * name, so it follows the group through a rename. Null
         * keeps the legacy name lookup (hand-built callers, old
         * tests).
         */
        mainGroupId: String? = null,
    ): RouteDecision = resolveDetailed(
        host, ip, port, groups, rules, delays, mode, mainGroupId,
    ).decision

    /**
     * v1.0.29: [resolve] WITH its record — the same decision,
     * plus the rule that matched and the proxy chain it resolves
     * to, for the per-connection record (GET /connections).
     * The matching/selection logic is identical to [resolve]
     * (which delegates here); only the returned metadata is new.
     *
     * Record rules:
     * - A matched rule reports its type name ([RouteRuleType])
     *   and its normalised pattern ("" for FINAL).
     * - A matched group reports its chain ([resolveChainNames]):
     *   nested group names + the server display name, or just
     *   the server name for a direct member.
     * - DIRECT / REJECT targets report chains ["DIRECT"] /
     *   ["REJECT"].
     * - Clash modes report rule "GLOBAL" / "DIRECT" (the
     *   mode itself decided, no rule matched).
     * - No rule matched at all: the safe default — rule "FINAL",
     *   payload "", chains [server] when the main group
     *   resolves, ["DIRECT"] when nothing does. Never null,
     *   never a crash.
     */
    fun resolveDetailed(
        host: String?,
        ip: InetAddress,
        port: Int,
        groups: List<ProxyGroup>,
        rules: List<RouteRule>,
        /** guid -> last-known delay ms; null = unknown / failed. */
        delays: Map<String, Long?>,
        /** Clash mode: "rule" (default), "global", or "direct". */
        mode: String = MODE_RULE,
        /**
         * v1.0.23: id of the main group (from
         * [com.taptap.ng.data.GroupsStore.mainGroupId]) — the
         * fallback / global group is picked BY THIS ID, not by
         * name, so it follows the group through a rename. Null
         * keeps the legacy name lookup (hand-built callers, old
         * tests).
         */
        mainGroupId: String? = null,
        /**
         * v1.0.29: server guid -> display name
         * ([com.taptap.ng.data.ProfileItem.displayName],
         * de-duplicated by the caller, as in
         * [com.taptap.ng.service.ClashApiHandler.displayNames]).
         * Only the chain names read it — the decision never
         * does. A guid missing here falls back to the guid
         * itself, never null.
         */
        serverNames: Map<String, String> = emptyMap(),
    ): ResolvedRoute {
        when (mode.trim().lowercase()) {
            MODE_DIRECT -> return ResolvedRoute(
                RouteDecision.Direct,
                RouteRecord("DIRECT", "", listOf("DIRECT")),
            )
            MODE_GLOBAL -> {
                val group = mainGroup(groups, mainGroupId)
                    ?: groups.firstOrNull()
                if (group != null) {
                    val guid = resolveToServer(group, groups, delays)
                    if (guid != null) {
                        return ResolvedRoute(
                            RouteDecision.Proxy(guid),
                            RouteRecord(
                                "GLOBAL", "",
                                resolveChainNames(group, groups, delays, serverNames)
                                    ?: listOf(serverNames[guid] ?: guid),
                            ),
                        )
                    }
                }
                return ResolvedRoute(
                    RouteDecision.Direct,
                    RouteRecord("GLOBAL", "", listOf("DIRECT")),
                )
            }
        }
        for (rule in rules) {
            // v1.0.23: a switched-off rule is skipped; FINAL has no
            // toggle and is always evaluated.
            if (rule.type != RouteRuleType.FINAL && !rule.isEnabled) continue
            if (!rule.matches(host, ip)) continue
            val payload = rule.normalizedPattern
            when (rule.target) {
                RouteRule.TARGET_DIRECT -> return ResolvedRoute(
                    RouteDecision.Direct,
                    RouteRecord(rule.type.name, payload, listOf("DIRECT")),
                )
                RouteRule.TARGET_REJECT -> return ResolvedRoute(
                    RouteDecision.Reject,
                    RouteRecord(rule.type.name, payload, listOf("REJECT")),
                )
                else -> {
                    val group = groups.firstOrNull { it.id == rule.target }
                        ?: continue // Stale target: fall through.
                    val member = resolveToServer(group, groups, delays)
                        ?: continue // Empty group: fall through.
                    return ResolvedRoute(
                        RouteDecision.Proxy(member),
                        RouteRecord(
                            rule.type.name, payload,
                            resolveChainNames(group, groups, delays, serverNames)
                                ?: listOf(serverNames[member] ?: member),
                        ),
                    )
                }
            }
        }
        // No rule matched: fall back to the main group, else Direct.
        val fallback = mainGroup(groups, mainGroupId)
        if (fallback != null) {
            val guid = resolveToServer(fallback, groups, delays)
            if (guid != null) {
                return ResolvedRoute(
                    RouteDecision.Proxy(guid),
                    RouteRecord(
                        "FINAL", "",
                        resolveChainNames(fallback, groups, delays, serverNames)
                            ?: listOf(serverNames[guid] ?: guid),
                    ),
                )
            }
        }
        return ResolvedRoute(
            RouteDecision.Direct,
            RouteRecord("FINAL", "", listOf("DIRECT")),
        )
    }

    /**
     * v1.0.29: the proxy chain a connection through [group]
     * takes, as display names — the nested group names on the
     * path plus the final server's display name, e.g.
     * ["taptap", "tes", "81"] when the main group selects nested
     * group "tes" which selects server "81". When the server is
     * a DIRECT member of [group] (no nesting on the path) the
     * chain is just the server name, e.g. ["81"] — the group
     * itself is implied, like the Clash API's `now` for a plain
     * selection. Null when nothing resolves (empty group, or a
     * cycle — the same guard as [resolveToServer]). The walk
     * mirrors [resolveToServer] exactly (same
     * [selectMemberRef] + visited set), so a chain never
     * disagrees with the decision it annotates. [serverNames]
     * maps server guid -> display name; an unknown guid falls
     * back to the guid itself, never null.
     */
    fun resolveChainNames(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
        serverNames: Map<String, String> = emptyMap(),
    ): List<String>? {
        val visited = HashSet<String>()
        val path = ArrayList<String>()
        var current: ProxyGroup? = group
        while (current != null) {
            if (!visited.add(current.id)) {
                DialLog.log(
                    "ROUTE",
                    "grup bersarang siklus di '${current.name}' — dilewati",
                )
                return null
            }
            val ref = selectMemberRef(current, groups, delays, visited) ?: return null
            val nested = groups.firstOrNull { it.id == ref }
            if (nested == null) {
                // A server guid: the chain ends here.
                val server = serverNames[ref] ?: ref
                return if (path.isEmpty()) listOf(server) else path + server
            }
            path.add(current.name.ifBlank { current.id })
            current = nested
        }
        return null
    }

    /**
     * The member [group] would use for a connection, or null when
     * the group has no member at all. See the class doc for the
     * per-type semantics.
     */
    fun selectMember(group: ProxyGroup, delays: Map<String, Long?>): String? {
        if (group.members.isEmpty()) return null
        return when (group.type) {
            ProxyGroupType.SELECT -> group.effectiveSelectedMemberGuid()
            ProxyGroupType.URL_TEST -> {
                // Lowest known delay wins; unknown = infinite; the
                // first member wins ties (minByOrNull keeps the
                // first minimal element in member order), and when
                // every member is unknown that is the first member.
                group.members.minByOrNull { delays[it] ?: Long.MAX_VALUE }
            }
            ProxyGroupType.FALLBACK -> {
                group.members.firstOrNull { delays[it] != null }
                    ?: group.members.firstOrNull()
            }
        }
    }

    /**
     * v1.0.27: the member [group] would use — a server guid OR a
     * nested group id — picked the same way [selectMember] picks
     * a server, but across server members AND nested groups:
     * SELECT → the stored selection (server or nested group),
     * else the first server member, else the first nested group;
     * URL_TEST → the member with the lowest effective delay (a
     * nested group's delay is its own [groupDelay]; unknown =
     * infinite; ties keep member order, servers before nested
     * groups); FALLBACK → the first member with a known delay.
     * Null when the group has no member at all. A group with only
     * server members returns exactly what [selectMember] returns.
     *
     * The [visited] set is the cycle guard shared with
     * [resolveToServer] / [groupDelay]: it holds the groups on
     * the current resolution path. Delay probes of nested groups
     * ([probeDelay]) snapshot and restore it, so probing never
     * pollutes the path — without that, a probed group would look
     * like a cycle when the walk reaches it for real.
     */
    fun selectMemberRef(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
    ): String? = selectMemberRef(group, groups, delays, HashSet())

    private fun selectMemberRef(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
        visited: MutableSet<String>,
    ): String? {
        if (group.members.isEmpty() && group.nestedGroupIds.isEmpty()) return null
        return when (group.type) {
            ProxyGroupType.SELECT -> group.effectiveSelectedMemberRef()
            ProxyGroupType.URL_TEST -> {
                val serverBest = group.members.minByOrNull { delays[it] ?: Long.MAX_VALUE }
                val nestedBest = group.nestedGroupIds
                    .mapNotNull { id -> groups.firstOrNull { it.id == id } }
                    .map { it to probeDelay(it, groups, delays, visited) }
                    .minByOrNull { it.second ?: Long.MAX_VALUE }
                val serverDelay = serverBest?.let { delays[it] } ?: Long.MAX_VALUE
                val nestedDelay = nestedBest?.second ?: Long.MAX_VALUE
                // Ties keep member order: servers come first, so a
                // server wins a tie against a nested group.
                if (serverDelay <= nestedDelay) serverBest ?: nestedBest?.first?.id
                else nestedBest?.first?.id
            }
            ProxyGroupType.FALLBACK -> {
                group.members.firstOrNull { delays[it] != null }
                    ?: group.nestedGroupIds
                        .mapNotNull { id -> groups.firstOrNull { it.id == id } }
                        .firstOrNull { probeDelay(it, groups, delays, visited) != null }?.id
                    ?: group.members.firstOrNull()
                    ?: group.nestedGroupIds.firstOrNull()
            }
        }
    }

    /**
     * v1.0.27: the real server guid [group] would use for a
     * connection, following nested groups down. A member that is
     * a group id resolves through that group's own selection
     * (SELECT) or best member (URL_TEST / FALLBACK). The walk is
     * guarded by a visited set: a group already on the path — a
     * cycle, or a group nesting itself — is skipped, the event is
     * logged, and null is returned instead of looping. Null also
     * when the group (or every group on the path) has no member.
     */
    fun resolveToServer(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
    ): String? = resolveToServer(group, groups, delays, HashSet())

    private fun resolveToServer(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
        visited: MutableSet<String>,
    ): String? {
        var current: ProxyGroup? = group
        while (current != null) {
            if (!visited.add(current.id)) {
                DialLog.log(
                    "ROUTE",
                    "grup bersarang siklus di '${current.name}' — dilewati",
                )
                return null
            }
            val ref = selectMemberRef(current, groups, delays, visited) ?: return null
            val nested = groups.firstOrNull { it.id == ref }
            if (nested == null) return ref // A server guid.
            current = nested
        }
        return null
    }

    /**
     * v1.0.27: the effective delay of [group] — the last-known
     * delay of the server its selection resolves to (following
     * nested groups, cycle-guarded, see [resolveToServer]).
     * Null when nothing resolves or the resolved server was
     * never probed. This is the delay the Clash API shows for a
     * nested group node, and the delay [selectMemberRef] compares
     * for URL_TEST groups that nest other groups.
     */
    fun groupDelay(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
    ): Long? = groupDelay(group, groups, delays, HashSet())

    private fun groupDelay(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
        visited: MutableSet<String>,
    ): Long? {
        val guid = resolveToServer(group, groups, delays, visited) ?: return null
        return delays[guid]
    }

    /**
     * Delay probe of a nested group while comparing members: the
     * probe shares the caller's [visited] path set (so a cycle
     * through the probed group is still cut), but whatever the
     * probe added is restored afterwards — the probe is not part
     * of the resolution path, and a probed group must not look
     * like a cycle when the walk reaches it for real.
     */
    private fun probeDelay(
        group: ProxyGroup,
        groups: List<ProxyGroup>,
        delays: Map<String, Long?>,
        visited: MutableSet<String>,
    ): Long? {
        val snapshot = visited.toSet()
        try {
            return groupDelay(group, groups, delays, visited)
        } finally {
            visited.retainAll(snapshot)
        }
    }
}
