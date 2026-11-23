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
 *   the engine falls back to the group named [FALLBACK_GROUP_NAME]
 *   ("Proxy" — the default group [com.taptap.ng.data.GroupsStore]
 *   creates) when it exists and has a usable member; otherwise
 *   [RouteDecision.Direct] — fail-open, so traffic still flows
 *   rather than being silently dropped. A default configuration
 *   always has FINAL → Proxy, so this path only runs for a
 *   hand-edited config without FINAL.
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
 * [port] is part of the signature for future port-based rules; the
 * current rule types ignore it.
 *
 * Clash mode (M7, W3 — [SettingsStore.clashMode], PATCH /configs):
 * - "rule" (default) = the rule loop below.
 * - "global" = always the selected/effective member of the group
 *   named [FALLBACK_GROUP_NAME] ("Proxy"), or the first group when
 *   there is no such group; an unusable group falls back to
 *   [RouteDecision.Direct] (fail-open).
 * - "direct" = always [RouteDecision.Direct].
 * An unknown mode value behaves like "rule".
 */
object RouteEngine {

    /**
     * Name of the fallback group used when no rule matches. Must
     * stay equal to
     * [com.taptap.ng.data.GroupsStore.DEFAULT_GROUP_NAME].
     */
    const val FALLBACK_GROUP_NAME = "Proxy"

    /** Clash modes (see class doc). Stored in SettingsStore.clashMode. */
    const val MODE_RULE = "rule"
    const val MODE_GLOBAL = "global"
    const val MODE_DIRECT = "direct"

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
    ): RouteDecision {
        when (mode.trim().lowercase()) {
            MODE_DIRECT -> return RouteDecision.Direct
            MODE_GLOBAL -> {
                val group = groups.firstOrNull { it.name == FALLBACK_GROUP_NAME }
                    ?: groups.firstOrNull()
                if (group != null) {
                    selectMember(group, delays)?.let { return RouteDecision.Proxy(it) }
                }
                return RouteDecision.Direct
            }
        }
        for (rule in rules) {
            if (!rule.matches(host, ip)) continue
            when (rule.target) {
                RouteRule.TARGET_DIRECT -> return RouteDecision.Direct
                RouteRule.TARGET_REJECT -> return RouteDecision.Reject
                else -> {
                    val group = groups.firstOrNull { it.id == rule.target }
                        ?: continue // Stale target: fall through.
                    val member = selectMember(group, delays)
                        ?: continue // Empty group: fall through.
                    return RouteDecision.Proxy(member)
                }
            }
        }
        // No rule matched: fall back to the "Proxy" group, else Direct.
        val fallback = groups.firstOrNull { it.name == FALLBACK_GROUP_NAME }
        if (fallback != null) {
            selectMember(fallback, delays)?.let { return RouteDecision.Proxy(it) }
        }
        return RouteDecision.Direct
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
}
