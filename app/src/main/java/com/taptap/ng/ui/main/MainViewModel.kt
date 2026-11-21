package com.taptap.ng.ui.main

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.taptap.ng.core.LinkParser
import com.taptap.ng.core.ServerTester
import com.taptap.ng.core.proto.MuxConfig
import com.taptap.ng.core.proto.ProxyClientFactory
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import com.taptap.ng.data.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * Main screen state. Durable state lives here and is exposed as
 * immutable StateFlow; the activity only renders it and sends actions
 * back (same pattern as v2rayNG's MainViewModel, minus Compose).
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val store = ProfileStore(ProfileStore.defaultFile(application.filesDir))
    private val gson = Gson()

    private val _profiles = MutableStateFlow<List<ProfileItem>>(emptyList())
    val profiles: StateFlow<List<ProfileItem>> = _profiles.asStateFlow()

    /** Profiles after group + search filtering (what the list shows). */
    private val _visibleProfiles = MutableStateFlow<List<ProfileItem>>(emptyList())
    val visibleProfiles: StateFlow<List<ProfileItem>> = _visibleProfiles.asStateFlow()

    private val _groups = MutableStateFlow<List<String>>(emptyList())
    val groups: StateFlow<List<String>> = _groups.asStateFlow()

    private val _selectedGroup = MutableStateFlow("")
    val selectedGroup: StateFlow<String> = _selectedGroup.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _selectedGuid = MutableStateFlow<String?>(null)
    val selectedGuid: StateFlow<String?> = _selectedGuid.asStateFlow()

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    private val _statusText = MutableStateFlow("")
    val statusText: StateFlow<String> = _statusText.asStateFlow()

    /** guid -> delay ms (-1 = failed). */
    private val _delays = MutableStateFlow<Map<String, Long>>(emptyMap())
    val delays: StateFlow<Map<String, Long>> = _delays.asStateFlow()

    /**
     * guid -> failure stage for failed delay tests ("DNS gagal",
     * "TCP timeout", "protect gagal", ...). v1.0.6, fix C: the row
     * label shows the stage instead of a bare "Timeout".
     */
    private val _delayStages = MutableStateFlow<Map<String, String>>(emptyMap())
    val delayStages: StateFlow<Map<String, String>> = _delayStages.asStateFlow()

    /**
     * guid -> delay kind ("real" or "tcp") for the row label
     * (v1.0.13, fix B): a real ping shows "48ms", a TCP fallback
     * shows "48ms (TCP)" — see [formatDelayLabel].
     */
    private val _delayKinds = MutableStateFlow<Map<String, String>>(emptyMap())
    val delayKinds: StateFlow<Map<String, String>> = _delayKinds.asStateFlow()

    /** Settings (delayTestUrl, realPingConcurrency) — lazy so the
     * ViewModel stays constructible without touching disk. */
    private val settings by lazy { SettingsStore(getApplication()) }

    init {
        store.load()
        _profiles.value = store.profiles.toList()
        _groups.value = store.groups()
        _selectedGroup.value = _groups.value.firstOrNull() ?: ""
        _selectedGuid.value = store.selectedGuid ?: store.profiles.firstOrNull()?.guid
        refreshVisible()
    }

    fun reload() {
        store.load()
        _profiles.value = store.profiles.toList()
        _groups.value = store.groups()
        if (_selectedGroup.value !in _groups.value) {
            _selectedGroup.value = _groups.value.firstOrNull() ?: ""
        }
        refreshVisible()
    }

    fun selectGroup(group: String) {
        _selectedGroup.value = group
        refreshVisible()
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
        refreshVisible()
    }

    private fun refreshVisible() {
        val q = _searchQuery.value.trim().lowercase()
        _visibleProfiles.value = _profiles.value.filter { item ->
            (item.group == _selectedGroup.value) &&
                (q.isEmpty() || item.displayName().lowercase().contains(q) ||
                    item.address.lowercase().contains(q))
        }
    }

    fun select(guid: String) {
        _selectedGuid.value = guid
        store.setSelectedGuid(guid)
    }

    fun selectedItem(): ProfileItem? =
        _selectedGuid.value?.let { store.find(it) }

    fun remove(guid: String) {
        store.remove(guid)
        afterStoreChange()
        if (_selectedGuid.value == guid) {
            _selectedGuid.value = store.profiles.firstOrNull()?.guid
            store.setSelectedGuid(_selectedGuid.value)
        }
    }

    fun removeGroup(group: String) {
        store.removeGroup(group)
        afterStoreChange()
        _selectedGuid.value = store.profiles.firstOrNull()?.guid
        store.setSelectedGuid(_selectedGuid.value)
    }

    /** Returns how many servers were removed. */
    fun removeDuplicates(): Int {
        val seen = HashSet<String>()
        var removed = 0
        val it = store.profiles.iterator()
        while (it.hasNext()) {
            val item = it.next()
            val key = "${item.configType}|${item.address}|${item.port}|${item.uuid}|${item.username}"
            if (!seen.add(key)) {
                it.remove()
                removed++
            }
        }
        if (removed > 0) {
            store.save()
            afterStoreChange()
        }
        return removed
    }

    /** Returns how many servers were removed. */
    fun removeInvalid(): Int {
        val before = store.profiles.size
        store.profiles.removeAll { it.address.isBlank() }
        val removed = before - store.profiles.size
        if (removed > 0) {
            store.save()
            afterStoreChange()
        }
        return removed
    }

    fun removeAll() {
        store.profiles.clear()
        store.setSelectedGuid(null)
        store.save()
        _selectedGuid.value = null
        afterStoreChange()
    }

    /** Import share-link text (clipboard / file / QR). Returns count. */
    fun importLinks(text: String): Int {
        val items = LinkParser.parseBatch(text)
        items.forEach { store.add(it) }
        if (items.isNotEmpty()) afterStoreChange()
        return items.size
    }

    /** Import a profiles.json export (JSON array of ProfileItem). */
    fun importProfilesJson(text: String): Int {
        return try {
            val type = object : TypeToken<MutableList<ProfileItem>>() {}.type
            val items: MutableList<ProfileItem> =
                gson.fromJson(text, type) ?: return 0
            items.forEach { store.add(it) }
            if (items.isNotEmpty()) afterStoreChange()
            items.size
        } catch (_: Exception) {
            0
        }
    }

    /** Share links for all profiles (export to clipboard / file). */
    fun exportLinks(): List<String> =
        store.profiles.mapNotNull { LinkParser.toUri(it) }

    /**
     * v1.0.28: simpan urutan hasil drag-reorder (v2rayNG moveServer).
     * [orderedGuids] = guid baris yang tampil, sesudah digeser.
     * Hanya grup yang tampil yang diurutkan ulang; profil grup lain
     * tetap di tempatnya. Tidak ada perubahan bila urutannya sama.
     */
    fun applyReorderedVisible(orderedGuids: List<String>) {
        val reordered = reorderGroupProfiles(store.profiles, _selectedGroup.value, orderedGuids)
        if (reordered == store.profiles) return
        store.replaceAll(reordered)
        afterStoreChange()
    }

    fun sortByDelay() {
        val order = _delays.value
        store.profiles.sortWith(
            compareBy<ProfileItem> { order[it.guid] == null }
                .thenBy { order[it.guid]?.let { d -> if (d < 0) Long.MAX_VALUE else d } ?: Long.MAX_VALUE }
        )
        store.save()
        afterStoreChange()
    }

    fun testAll(realPing: Boolean = false) {
        val items = store.profiles.toList()
        if (items.isEmpty()) return
        _statusText.value = "Testing…"
        viewModelScope.launch(Dispatchers.IO) {
            if (realPing) {
                // v1.0.13, fix B: real ping = full round-trip
                // through the proxy (HTTP GET to delayTestUrl).
                // Run with the user's realPingConcurrency
                // (default 16, clamp 1..32). v1.0.30: SSH entries
                // ride the proxy now (SshProxyClient), so they take
                // the same real-ping path — no TCP-only branch
                // anymore. A proxy dial that FAILS is a real failure
                // — its stage is shown, never hidden behind a TCP
                // number (the TCP fallback applies only when the
                // real ping cannot run at all).
                val concurrency =
                    settings.realPingConcurrency.toIntOrNull()?.coerceIn(1, 32) ?: 16
                val semaphore = Semaphore(concurrency)
                val results = java.util.concurrent.ConcurrentHashMap<String, Long>()
                val stages = java.util.concurrent.ConcurrentHashMap<String, String>()
                val kinds = java.util.concurrent.ConcurrentHashMap<String, String>()
                val jobs = items.map { item ->
                    async {
                        semaphore.withPermit {
                            val r = ServerTester.testRealPingThroughProxy(
                                item, settings.delayTestUrl,
                                // v1.0.5 (kelompok D): tes delay memakai
                                // jalur yang sama dengan relay — mux ON
                                // berarti delay diukur lewat mux.
                                clientFactory = {
                                    ProxyClientFactory.create(
                                        it, MuxConfig.fromSettings(settings),
                                    )
                                },
                            )
                            if (r.failureStage == ServerTester.CANNOT_RUN_STAGE) {
                                val t = ServerTester.testTcpDetailed(item.address, item.port)
                                results[item.guid] = t.ms
                                kinds[item.guid] = DELAY_KIND_TCP
                                if (t.failureStage != null) stages[item.guid] = t.failureStage
                            } else {
                                results[item.guid] = r.ms
                                kinds[item.guid] = DELAY_KIND_REAL
                                if (r.failureStage != null) stages[item.guid] = r.failureStage
                            }
                        }
                    }
                }
                jobs.awaitAll()
                val okGuids = results.filterValues { it >= 0 }.keys
                _delays.value = _delays.value + results
                _delayStages.value = (_delayStages.value + stages) - okGuids
                _delayKinds.value = _delayKinds.value + kinds
            } else {
                for (item in items) {
                    val r = ServerTester.testTcpDetailed(item.address, item.port)
                    applyDelayResult(item, r.ms, r.failureStage, DELAY_KIND_TCP)
                }
            }
            _statusText.value = "Tested ${items.size} server(s)"
        }
    }

    /** Apply one delay-test result to the row flows. */
    private fun applyDelayResult(item: ProfileItem, ms: Long, stage: String?, kind: String) {
        _delays.value = _delays.value + (item.guid to ms)
        _delayKinds.value = _delayKinds.value + (item.guid to kind)
        _delayStages.value = if (stage != null) {
            _delayStages.value + (item.guid to stage)
        } else {
            _delayStages.value - item.guid
        }
    }

    /**
     * Test the selected server (bottom-bar tap, like v2rayNG).
     * v1.0.9: the result goes to the ROW label only (delay +
     * failure stage) — it must never overwrite the bottom status,
     * which reflects the CONNECTION state. v1.0.8 wrote
     * "<remark>: protect gagal" into the status bar, so a
     * delay-test failure looked like the VPN itself had failed
     * (taptapng-6.txt 04:18), and the 2 s service poll then fought
     * it — the bar flickered between the two.
     */
    fun testCurrent() {
        val item = selectedItem() ?: run {
            _statusText.value = "No server selected"
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            // v1.0.13, fix B + v1.0.30: the selected server is tested
            // with the real ping (full round-trip through the proxy);
            // SSH entries take the same path now (SshProxyClient) —
            // the old SSH exec round-trip would fail on a payload
            // entry (it dialled direct, without the payload chain).
            // The TCP connect is only a fallback when the real ping
            // cannot run at all.
            // v1.0.5 (kelompok D): tes delay memakai jalur yang sama
            // dengan relay — mux ON berarti delay diukur lewat mux.
            val r = ServerTester.testRealPingThroughProxy(
                item, settings.delayTestUrl,
                clientFactory = {
                    ProxyClientFactory.create(it, MuxConfig.fromSettings(settings))
                },
            )
            if (r.failureStage == ServerTester.CANNOT_RUN_STAGE) {
                val t = ServerTester.testTcpDetailed(item.address, item.port)
                applyDelayResult(item, t.ms, t.failureStage, DELAY_KIND_TCP)
            } else {
                applyDelayResult(item, r.ms, r.failureStage, DELAY_KIND_REAL)
            }
        }
    }

    fun setRunning(running: Boolean, status: String = "") {
        _isRunning.value = running
        _statusText.value = status
    }

    private fun afterStoreChange() {
        _profiles.value = store.profiles.toList()
        _groups.value = store.groups()
        if (_selectedGroup.value !in _groups.value) {
            _selectedGroup.value = _groups.value.firstOrNull() ?: ""
        }
        refreshVisible()
    }
}

/**
 * Whether tapping [newGuid] must restart the running VPN with the
 * newly selected server — v2rayNG's MainActivity.setSelectServer:
 * a tap on a DIFFERENT server while the VPN runs restarts the
 * service with it; tapping the already-selected server, or tapping
 * while stopped, only changes the selection. Pure, so it is unit
 * testable without an Application (v1.0.10).
 */
fun shouldRestartOnSelect(isRunning: Boolean, currentGuid: String?, newGuid: String): Boolean =
    isRunning && newGuid != currentGuid

/**
 * Drag-reorder dalam satu grup (v1.0.28 — v2rayNG moveServer):
 * slot-slot grup di daftar penuh dipertahankan posisinya, diisi
 * ulang mengikuti [orderedGuids]; profil grup lain tidak bergerak.
 * Anggota grup yang tidak disebut di [orderedGuids] (mis. disaring
 * pencarian) menempel sesudah yang disebut, dalam urutan semula.
 * Pure, jadi bisa dites tanpa Application.
 */
fun reorderGroupProfiles(
    full: List<ProfileItem>,
    group: String,
    orderedGuids: List<String>,
): List<ProfileItem> {
    val groupItems = full.filter { it.group == group }
    if (groupItems.isEmpty()) return full
    val byGuid = groupItems.associateBy { it.guid }
    val listed = orderedGuids.distinct().mapNotNull { byGuid[it] }
    val listedSet = listed.map { it.guid }.toSet()
    val ordered = listed + groupItems.filter { it.guid !in listedSet }
    val queue = ArrayDeque(ordered)
    return full.map { if (it.group == group) queue.removeFirst() else it }
}

/**
 * Teks "Export configs to clipboard" (v1.0.28 — v2rayNG
 * exportAllAsync): share link tiap profil yang tampil, satu per
 * baris; profil yang tidak bisa diserialisasi dilewati. Pure.
 */
fun buildExportClipboardText(items: List<ProfileItem>): String =
    items.mapNotNull { LinkParser.toUri(it) }.joinToString("\n")
