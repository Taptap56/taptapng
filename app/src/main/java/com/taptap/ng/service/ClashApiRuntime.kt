package com.taptap.ng.service

import com.taptap.ng.core.UrlTestCache
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileStore
import java.io.File

/**
 * Live state shared between [TaptapVpnService] and the Clash API
 * server (M7, W3).
 *
 * The API server lives as long as the app process (started from
 * [com.taptap.ng.TaptapNGApp]), while the tunnel — and with it the
 * [UrlTestCache] and the [TunForwarder] — only lives while the VPN
 * is up. The handler reads through here and gets empty data when
 * the tunnel is down, instead of crashing or inventing numbers.
 *
 * [groupsStore] is the ONE [GroupsStore] instance both sides use:
 * the service loads it when the tunnel comes up and the API
 * handler refreshes it from disk on every read, so a PUT select
 * from the dashboard is visible to the forwarder's resolver on the
 * very next connection — no VPN restart (live reload). The resolver
 * reads `groupsStore.groups` / `.rules` live per connection, and
 * the Clash mode live from SettingsStore, for the same reason.
 */
object ClashApiRuntime {

    /** Single shared groups store (created lazily, see below). */
    @Volatile
    var groupsStore: GroupsStore? = null
        private set

    /** Delay cache of the running tunnel; null when the VPN is down. */
    @Volatile
    var urlTestCache: UrlTestCache? = null

    /** Live forwarder of the running tunnel; null when the VPN is down. */
    @Volatile
    var forwarder: TunForwarder? = null

    /**
     * The shared [GroupsStore], created once from [filesDir] and
     * loaded with the profiles currently on disk. The service calls
     * this when the tunnel comes up; the API handler calls it on
     * every read (cheap — one small JSON file) so disk edits made
     * elsewhere (profile add/remove) are picked up too.
     */
    @Synchronized
    fun ensureGroupsStore(filesDir: File): GroupsStore {
        val existing = groupsStore
        if (existing != null) return existing
        val profiles = ProfileStore(ProfileStore.defaultFile(filesDir))
            .apply { load() }
        val store = GroupsStore(GroupsStore.defaultFile(filesDir))
        store.load(profiles.profiles, profiles.selectedGuid)
        groupsStore = store
        return store
    }

    /** Re-read groups.json from disk into the shared store (prunes stale members). */
    fun refreshGroups(filesDir: File): GroupsStore {
        val store = ensureGroupsStore(filesDir)
        val profiles = ProfileStore(ProfileStore.defaultFile(filesDir))
            .apply { load() }
        store.load(profiles.profiles, profiles.selectedGuid)
        return store
    }
}
