package com.taptap.x.ui.main

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.taptap.x.core.LinkParser
import com.taptap.x.core.ServerTester
import com.taptap.x.core.SshClient
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

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
        store.selectedGuid = guid
    }

    fun selectedItem(): ProfileItem? =
        _selectedGuid.value?.let { store.find(it) }

    fun remove(guid: String) {
        store.remove(guid)
        afterStoreChange()
        if (_selectedGuid.value == guid) {
            _selectedGuid.value = store.profiles.firstOrNull()?.guid
        }
    }

    fun removeGroup(group: String) {
        store.removeGroup(group)
        afterStoreChange()
        _selectedGuid.value = store.profiles.firstOrNull()?.guid
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
        store.selectedGuid = null
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

    fun exportProfilesJson(): String = gson.toJson(store.profiles)

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
            val results = LinkedHashMap<String, Long>()
            for (item in items) {
                val ms = if (realPing) {
                    // v1.0.5: the (host, port) overload falls back to a
                    // TCP connect on the entry's own port — the
                    // host-only isReachable never answers on a
                    // non-root phone (ICMP needs raw sockets).
                    ServerTester.testRealPing(item.address, item.port)
                } else {
                    ServerTester.testTcp(item.address, item.port)
                }
                results[item.guid] = ms
                _delays.value = _delays.value + (item.guid to ms)
            }
            _statusText.value = "Tested ${results.size} server(s)"
        }
    }

    /** Test the selected server (bottom-bar tap, like v2rayNG). */
    fun testCurrent() {
        val item = selectedItem() ?: run {
            _statusText.value = "No server selected"
            return
        }
        _statusText.value = "Testing ${item.displayName()}..."
        viewModelScope.launch(Dispatchers.IO) {
            val ms: Long
            val label: String
            if (item.configType == ConfigType.SSH) {
                val start = System.nanoTime()
                val outcome = runCatching {
                    SshClient.runCommand(
                        host = item.address,
                        port = item.port,
                        username = item.username,
                        password = item.password,
                        privateKey = item.privateKey,
                        command = "echo ok",
                    )
                }
                ms = (System.nanoTime() - start) / 1_000_000
                label = outcome.fold(
                    onSuccess = { "SSH ${item.displayName()}: ${it.output.trim()} (${ms}ms)" },
                    onFailure = { "SSH ${item.displayName()} gagal: ${it.message}" },
                )
                _delays.value = _delays.value + (item.guid to if (outcome.isSuccess) ms else -1)
            } else {
                ms = ServerTester.testTcp(item.address, item.port)
                _delays.value = _delays.value + (item.guid to ms)
                label = if (ms >= 0) {
                    "${item.displayName()}: ${ms}ms"
                } else {
                    "${item.displayName()}: timeout"
                }
            }
            _statusText.value = label
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
