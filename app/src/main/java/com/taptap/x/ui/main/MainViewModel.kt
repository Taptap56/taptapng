package com.taptap.x.ui.main

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Main screen state, mirroring v2rayNG's MainViewModel pattern:
 * durable state lives in the ViewModel and is exposed as immutable
 * StateFlow; the composable only renders it and sends actions back.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val store = ProfileStore(ProfileStore.defaultFile(application.filesDir))

    private val _profiles = MutableStateFlow<List<ProfileItem>>(emptyList())
    val profiles: StateFlow<List<ProfileItem>> = _profiles.asStateFlow()

    private val _selectedGuid = MutableStateFlow<String?>(null)
    val selectedGuid: StateFlow<String?> = _selectedGuid.asStateFlow()

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    private val _statusText = MutableStateFlow("")
    val statusText: StateFlow<String> = _statusText.asStateFlow()

    init {
        store.load()
        _profiles.value = store.profiles.toList()
        _selectedGuid.value = store.selectedGuid ?: store.profiles.firstOrNull()?.guid
    }

    fun reload() {
        store.load()
        _profiles.value = store.profiles.toList()
    }

    fun select(guid: String) {
        _selectedGuid.value = guid
        store.selectedGuid = guid
    }

    fun remove(guid: String) {
        store.remove(guid)
        _profiles.value = store.profiles.toList()
        if (_selectedGuid.value == guid) {
            _selectedGuid.value = store.profiles.firstOrNull()?.guid
        }
    }

    fun setRunning(running: Boolean, status: String = "") {
        _isRunning.value = running
        _statusText.value = status
    }

    fun testSsh(guid: String) {
        val item = store.find(guid) ?: return
        if (item.configType != com.taptap.x.data.ConfigType.SSH) {
            _statusText.value = "Test SSH hanya untuk entry SSH (Phase 1)"
            return
        }
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            _statusText.value = "Testing ${item.displayName()}..."
            val outcome = runCatching {
                com.taptap.x.core.SshClient.runCommand(
                    host = item.address,
                    port = item.port,
                    username = item.username,
                    password = item.password,
                    privateKey = item.privateKey,
                    command = "echo ok",
                )
            }
            _statusText.value = outcome.fold(
                onSuccess = { "SSH ${item.displayName()}: ${it.output.trim()} (exit ${it.exitStatus})" },
                onFailure = { "SSH ${item.displayName()} gagal: ${it.message}" },
            )
        }
    }
}
