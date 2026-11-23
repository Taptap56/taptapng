package com.taptap.ng.service

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.data.GroupsStore

/**
 * Live server switch (v1.0.19, Issue 2): tapping another server
 * while the VPN runs must move traffic to it WITHOUT stopping and
 * restarting the tunnel — Clash-style. The tunnel, the forwarder
 * and the TUN stay up; only the routing selection changes.
 *
 * Why the group selection is the switch (verified from code, not
 * assumed): [com.taptap.ng.service.TunForwarder] resolves EVERY
 * new connection through `routeResolver` — which reads
 * `groupsStore.groups` / `.rules` LIVE from the shared
 * [ClashApiRuntime] store — and dials it through `clientProvider`,
 * which creates the guid's client on demand via
 * [com.taptap.ng.core.proto.ProxyClientFactory]. So pointing the
 * default SELECT group's selected member at the new guid is
 * enough: the very next connection is routed through the new
 * server's client. There is no shortcut that keeps new
 * connections on the old tunnel client — the `proxy` fallback in
 * the forwarder only fires when the client provider returns null
 * (unknown guid / factory failure).
 *
 * The same helper also repairs a stale selection found while
 * verifying this path: nothing ever synced the "taptap" group's
 * selected member from [com.taptap.ng.data.ProfileStore]
 * .selectedGuid after the default group was created — only the
 * default-creation path in [GroupsStore.load] reads it. So on
 * v1.0.18 a tap + restart changed the probe client and the
 * "Connected:" label, but the route engine kept routing new
 * connections to the OLD selected member. The service therefore
 * applies [applyLiveSwitchSelection] at start too, so "pilih +
 * start" really routes through the tapped server.
 *
 * All functions here are pure (lists in, lists out) so the JVM
 * tests drive them without Android.
 */
enum class LiveSwitchDecision {
    /** Same server tapped while running: touch nothing. */
    NO_OP,
    /** Different server tapped while running: switch live. */
    SWITCH_LIVE,
    /** VPN stopped: plain select, the next start uses it. */
    SELECT_ONLY,
}

/**
 * What a tap on [newGuid] must do. [currentGuid] is the
 * currently selected server (the running one while the VPN is
 * up — the UI keeps ProfileStore.selectedGuid in sync with it).
 */
fun decideLiveSwitch(isRunning: Boolean, currentGuid: String?, newGuid: String): LiveSwitchDecision =
    when {
        !isRunning -> LiveSwitchDecision.SELECT_ONLY
        newGuid == currentGuid -> LiveSwitchDecision.NO_OP
        else -> LiveSwitchDecision.SWITCH_LIVE
    }

/**
 * Point the default SELECT group ("taptap" — the group the FINAL
 * rule targets) at [newGuid], returning the updated group list,
 * or null when there is nothing to change:
 * - no main group exists;
 * - the main group is not SELECT (URL_TEST / FALLBACK pick
 *   their member by probe / order, not by stored selection);
 * - the group already selects [newGuid] (effective selection,
 *   i.e. stored selection when still a member, else first member).
 *
 * v1.0.23: the group is found BY ID ([mainGroupId], from
 * [com.taptap.ng.data.GroupsStore.mainGroupId]) when one is
 * given, so a renamed main group still switches. Without an id
 * the legacy name lookup applies (hand-built callers, old
 * tests).
 *
 * A guid that is not a member yet is APPENDED first: the default
 * group is defined as holding every profile guid (see
 * [GroupsStore]), but profiles added after groups.json was
 * created never joined it — without the append a freshly added
 * server could never become the routed member. Other groups are
 * returned untouched.
 */
fun applyLiveSwitchSelection(
    groups: List<ProxyGroup>,
    newGuid: String,
    mainGroupId: String? = null,
): List<ProxyGroup>? {
    val idx = mainGroupId?.let { id -> groups.indexOfFirst { it.id == id } }
        ?.takeIf { it >= 0 }
        ?: groups.indexOfFirst { it.name == GroupsStore.DEFAULT_GROUP_NAME }
    if (idx < 0) return null
    val group = groups[idx]
    if (group.type != ProxyGroupType.SELECT) return null
    if (group.effectiveSelectedMemberGuid() == newGuid) return null
    val members = if (newGuid in group.members) group.members else group.members + newGuid
    val updated = group.copy(members = members, selectedMemberGuid = newGuid)
    return groups.toMutableList().also { it[idx] = updated }
}
