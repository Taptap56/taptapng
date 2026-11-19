package com.taptap.x.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.appcompat.widget.Toolbar
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.navigation.NavigationView
import com.google.android.material.tabs.TabLayout
import com.google.zxing.BarcodeFormat
import com.google.zxing.WriterException
import com.google.zxing.qrcode.QRCodeWriter
import com.taptap.x.AppConfig
import com.taptap.x.R
import com.taptap.x.TaptapXApp
import com.taptap.x.core.LinkParser
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.SettingsStore
import com.taptap.x.service.TaptapVpnService
import com.taptap.x.ui.log.LogActivity
import com.taptap.x.ui.main.MainViewModel
import com.taptap.x.ui.main.ServerAdapter
import com.taptap.x.ui.scanner.ScannerActivity
import com.taptap.x.ui.server.ServerEditorActivity
import com.taptap.x.ui.settings.SettingsActivity
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Main activity, mirroring v2rayNG's MainActivity/MainScreen with
 * Views: DrawerLayout + NavigationView, MaterialToolbar (title,
 * search, + import menu, more menu), group tabs, RecyclerView server
 * list, bottom status bar with the overlapping orange FAB.
 */
class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()
    private lateinit var settings: SettingsStore
    private lateinit var drawerLayout: DrawerLayout
    private lateinit var tabLayout: TabLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: View
    private lateinit var fab: FloatingActionButton
    private lateinit var adapter: ServerAdapter

    private var rebuildingTabs = false
    private var lastDoubleColumn: Boolean? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn()
        } else {
            viewModel.setRunning(false, getString(R.string.toast_vpn_denied))
        }
    }

    private val fileImportLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        val text = runCatching {
            contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
        }.getOrNull() ?: return@registerForActivityResult
        val count = if (text.trimStart().startsWith("[")) {
            viewModel.importProfilesJson(text)
        } else {
            viewModel.importLinks(text)
        }
        toastImportResult(count)
    }

    private val fileExportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use {
                it.write(viewModel.exportProfilesJson())
            }
            Toast.makeText(this, R.string.toast_exported, Toast.LENGTH_SHORT).show()
        }.onFailure {
            Toast.makeText(this, getString(R.string.toast_import_failed, it.message), Toast.LENGTH_SHORT).show()
        }
    }

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
        val text = result.data?.getStringExtra(ScannerActivity.EXTRA_TEXT) ?: return@registerForActivityResult
        val count = viewModel.importLinks(text)
        if (count == 0) {
            Toast.makeText(this, R.string.toast_qr_invalid, Toast.LENGTH_SHORT).show()
        } else {
            toastImportResult(count)
        }
    }

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapXApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = SettingsStore(this)
        setContentView(R.layout.activity_main)

        drawerLayout = findViewById(R.id.drawer_layout)
        tabLayout = findViewById(R.id.group_tabs)
        recyclerView = findViewById(R.id.server_list)
        emptyView = findViewById(R.id.empty_servers)
        fab = findViewById(R.id.fab_toggle)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener {
            drawerLayout.openDrawer(GravityCompat.START)
        }

        findViewById<NavigationView>(R.id.nav_view).setNavigationItemSelectedListener { item ->
            drawerLayout.closeDrawer(GravityCompat.START)
            onDrawerItem(item.itemId)
            true
        }

        adapter = ServerAdapter(object : ServerAdapter.Callbacks {
            override fun onSelect(guid: String) = viewModel.select(guid)
            override fun onShare(item: ProfileItem) = showShareDialog(item)
            override fun onEdit(item: ProfileItem) = openEditor(item.guid, null)
            override fun onDelete(item: ProfileItem) = deleteServer(item)
            override fun onLongPress(item: ProfileItem) = showServerMenu(item)
        })
        recyclerView.adapter = adapter
        applyLayoutManager()

        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                if (rebuildingTabs) return
                viewModel.selectGroup(tab.tag as? String ?: "")
            }
            override fun onTabUnselected(tab: TabLayout.Tab) = Unit
            override fun onTabReselected(tab: TabLayout.Tab) = Unit
        })

        fab.setOnClickListener { toggleRunning() }
        findViewById<View>(R.id.bottom_bar).setOnClickListener { viewModel.testCurrent() }

        observeViewModel()
    }

    override fun onResume() {
        super.onResume()
        viewModel.reload()
        syncServiceState()
        if (lastDoubleColumn != settings.doubleColumnDisplay) applyLayoutManager()
    }

    /** Read the real service state (it may have failed to start, e.g.
     *  SSH profile selected) instead of trusting the optimistic UI. */
    private fun syncServiceState() {
        val running = TaptapVpnService.isRunning
        val status = TaptapVpnService.statusMessage.ifBlank {
            if (running) getString(R.string.status_running)
            else getString(R.string.status_stopped)
        }
        viewModel.setRunning(running, status)
    }

    private fun applyLayoutManager() {
        lastDoubleColumn = settings.doubleColumnDisplay
        adapter.gridMode = settings.doubleColumnDisplay
        recyclerView.layoutManager = if (settings.doubleColumnDisplay) {
            GridLayoutManager(this, 2)
        } else {
            LinearLayoutManager(this)
        }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.visibleProfiles.collect { items ->
                        adapter.items = items
                        emptyView.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
                    }
                }
                launch {
                    viewModel.selectedGuid.collect { adapter.selectedGuid = it }
                }
                launch {
                    viewModel.delays.collect { adapter.delays = it }
                }
                launch {
                    viewModel.delayStages.collect { adapter.delayStages = it }
                }
                launch {
                    viewModel.isRunning.collect { running ->
                        fab.setImageResource(
                            if (running) R.drawable.ic_stop_24dp else R.drawable.ic_play_24dp
                        )
                        fab.backgroundTintList = ColorStateList.valueOf(
                            if (running) getColor(R.color.colorFabActive)
                            else getColor(R.color.colorFabInactive)
                        )
                        fab.contentDescription = getString(
                            if (running) R.string.action_stop else R.string.action_start
                        )
                    }
                }
                launch {
                    viewModel.statusText.collect { text ->
                        val statusView = findViewById<android.widget.TextView>(R.id.status_text)
                        statusView.text = text.ifBlank {
                            if (viewModel.isRunning.value) getString(R.string.status_running)
                            else getString(R.string.status_stopped)
                        }
                    }
                }
                launch {
                    viewModel.groups.collect { groups -> rebuildTabs(groups) }
                }
                launch {
                    viewModel.selectedGroup.collect { group -> selectTab(group) }
                }
                // v1.0.4: the service status changes AFTER the 1.5 s
                // post-start sync (dial failures surface ~10 s in,
                // "Connected" on first successful dial) — poll it so
                // the bottom bar shows "Konek gagal (...)" instead of
                // "Connecting..." forever. Cheap: two volatile reads.
                launch {
                    while (true) {
                        delay(2000)
                        syncServiceState()
                    }
                }
            }
        }
    }

    // ---- Tabs (groups) ----

    private fun rebuildTabs(groups: List<String>) {
        rebuildingTabs = true
        tabLayout.removeAllTabs()
        if (groups.size > 1) {
            tabLayout.visibility = View.VISIBLE
            val counts = viewModel.profiles.value.groupingBy { it.group }.eachCount()
            for (group in groups) {
                val label = if (group.isBlank()) "Default"
                else "$group (${counts[group] ?: 0})"
                val tab = tabLayout.newTab().setText(label)
                tab.tag = group
                tabLayout.addTab(tab)
            }
            // Long-press a tab = delete that group (v2rayNG parity).
            tabLayout.post {
                val strip = tabLayout.getChildAt(0) as? ViewGroup ?: return@post
                for (i in 0 until strip.childCount) {
                    val tabView = strip.getChildAt(i)
                    val group = tabLayout.getTabAt(i)?.tag as? String ?: continue
                    if (group.isBlank()) continue
                    tabView.setOnLongClickListener {
                        confirmDeleteGroup(group)
                        true
                    }
                }
            }
        } else {
            tabLayout.visibility = View.GONE
        }
        rebuildingTabs = false
        selectTab(viewModel.selectedGroup.value)
    }

    private fun selectTab(group: String) {
        if (tabLayout.visibility != View.VISIBLE) return
        for (i in 0 until tabLayout.tabCount) {
            val tab = tabLayout.getTabAt(i) ?: continue
            if ((tab.tag as? String ?: "") == group && !tab.isSelected) {
                tab.select()
                return
            }
        }
    }

    // ---- Toolbar / menus ----
    // The menu MUST be inflated here: once the Toolbar is the support
    // ActionBar, AppCompat owns its menu and the `app:menu` XML
    // attribute alone does not survive — v1.0.2 shipped with an empty
    // right side (no search / + / more) for exactly this reason. Clicks
    // likewise arrive via onOptionsItemSelected, not via the Toolbar's
    // own setOnMenuItemClickListener (the ActionBar wrapper replaces it).
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_toolbar, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (onToolbarMenu(item)) return true
        return super.onOptionsItemSelected(item)
    }

    private fun onToolbarMenu(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_search -> {
                val searchView = item.actionView as? SearchView ?: return true
                searchView.queryHint = getString(R.string.menu_search)
                searchView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
                    override fun onQueryTextSubmit(query: String?): Boolean = false
                    override fun onQueryTextChange(newText: String?): Boolean {
                        viewModel.setSearchQuery(newText ?: "")
                        return true
                    }
                })
                searchView.setOnCloseListener {
                    viewModel.setSearchQuery("")
                    false
                }
                return true
            }
            R.id.action_add -> {
                showImportMenu()
                return true
            }
            R.id.action_more -> {
                showMoreMenu()
                return true
            }
        }
        return false
    }

    private fun showImportMenu() {
        val popup = android.widget.PopupMenu(this, findViewById(R.id.toolbar), Gravity.END)
        popup.menuInflater.inflate(R.menu.import_menu, popup.menu)
        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.import_qrcode -> qrScanLauncher.launch(
                    Intent(this, ScannerActivity::class.java)
                )
                R.id.import_clipboard -> importClipboard()
                R.id.import_file -> fileImportLauncher.launch("*/*")
                R.id.import_vmess -> openEditor(null, ConfigType.VMESS)
                R.id.import_vless -> openEditor(null, ConfigType.VLESS)
                R.id.import_ss -> openEditor(null, ConfigType.SHADOWSOCKS)
                R.id.import_ssh -> openEditor(null, ConfigType.SSH)
                R.id.import_trojan -> openEditor(null, ConfigType.TROJAN)
            }
            true
        }
        popup.show()
    }

    private fun showMoreMenu() {
        val popup = android.widget.PopupMenu(this, findViewById(R.id.toolbar), Gravity.END)
        popup.menuInflater.inflate(R.menu.more_menu, popup.menu)
        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.more_restart -> restartService()
                R.id.more_delete_all -> confirm(
                    getString(R.string.confirm_delete_all)
                ) { viewModel.removeAll() }
                R.id.more_delete_duplicate -> confirm(
                    getString(R.string.confirm_delete_duplicate)
                ) {
                    val n = viewModel.removeDuplicates()
                    Toast.makeText(this, getString(R.string.toast_deleted) + " ($n)", Toast.LENGTH_SHORT).show()
                }
                R.id.more_delete_invalid -> confirm(
                    getString(R.string.confirm_delete_invalid)
                ) {
                    val n = viewModel.removeInvalid()
                    Toast.makeText(this, getString(R.string.toast_deleted) + " ($n)", Toast.LENGTH_SHORT).show()
                }
                R.id.more_export_all -> fileExportLauncher.launch("taptapx-profiles.json")
                R.id.more_locate_selected -> locateSelected()
                R.id.more_sort_by_test -> viewModel.sortByDelay()
                R.id.more_test_all -> viewModel.testAll(false)
                R.id.more_test_all_real -> viewModel.testAll(true)
                R.id.more_update_sub -> Toast.makeText(
                    this, R.string.toast_not_available, Toast.LENGTH_SHORT
                ).show()
            }
            true
        }
        popup.show()
    }

    private fun onDrawerItem(itemId: Int) {
        when (itemId) {
            R.id.nav_settings -> startActivity(Intent(this, SettingsActivity::class.java))
            R.id.nav_logcat -> startActivity(Intent(this, LogActivity::class.java))
            R.id.nav_about -> AlertDialog.Builder(this)
                .setTitle(R.string.about_title)
                .setMessage(getString(R.string.about_text, AppConfig.VERSION_NAME))
                .setPositiveButton(android.R.string.ok, null)
                .show()
            else -> Toast.makeText(this, R.string.toast_not_available, Toast.LENGTH_SHORT).show()
        }
    }

    // ---- Server actions ----

    private fun openEditor(guid: String?, type: ConfigType?) {
        val intent = Intent(this, ServerEditorActivity::class.java)
        if (guid != null) intent.putExtra(ServerEditorActivity.EXTRA_GUID, guid)
        if (type != null) intent.putExtra(ServerEditorActivity.EXTRA_TYPE, type.name)
        startActivity(intent)
    }

    private fun deleteServer(item: ProfileItem) {
        if (settings.confirmRemove) {
            confirm(getString(R.string.confirm_delete_server)) { viewModel.remove(item.guid) }
        } else {
            viewModel.remove(item.guid)
        }
    }

    private fun confirmDeleteGroup(group: String) {
        confirm(getString(R.string.confirm_delete_group, group)) {
            viewModel.removeGroup(group)
        }
    }

    private fun showServerMenu(item: ProfileItem) {
        AlertDialog.Builder(this)
            .setTitle(item.displayName())
            .setItems(
                arrayOf(
                    getString(R.string.action_edit),
                    getString(R.string.action_test),
                    getString(R.string.action_share),
                    getString(R.string.action_delete),
                )
            ) { _, which ->
                when (which) {
                    0 -> openEditor(item.guid, null)
                    1 -> {
                        viewModel.select(item.guid)
                        viewModel.testCurrent()
                    }
                    2 -> showShareDialog(item)
                    3 -> deleteServer(item)
                }
            }
            .show()
    }

    private fun showShareDialog(item: ProfileItem) {
        val link = LinkParser.toUri(item) ?: return
        AlertDialog.Builder(this)
            .setTitle(item.displayName())
            .setItems(
                arrayOf(
                    getString(R.string.share_qrcode),
                    getString(R.string.share_clipboard),
                    getString(R.string.share_full_content),
                )
            ) { _, which ->
                when (which) {
                    0 -> showQrDialog(item, link)
                    1 -> copyToClipboard(link)
                    2 -> {
                        val intent = Intent(Intent.ACTION_SEND)
                            .setType("text/plain")
                            .putExtra(Intent.EXTRA_TEXT, link)
                        startActivity(Intent.createChooser(intent, getString(R.string.action_share)))
                    }
                }
            }
            .show()
    }

    private fun showQrDialog(item: ProfileItem, link: String) {
        val bitmap = qrBitmap(link) ?: run {
            Toast.makeText(this, R.string.toast_import_failed, Toast.LENGTH_SHORT).show()
            return
        }
        val imageView = ImageView(this).apply {
            setImageBitmap(bitmap)
            setPadding(32, 32, 32, 32)
        }
        AlertDialog.Builder(this)
            .setTitle(item.displayName())
            .setView(imageView)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun qrBitmap(text: String): Bitmap? {
        return try {
            val size = 512
            val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
            val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
            for (x in 0 until size) {
                for (y in 0 until size) {
                    bitmap.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }
            bitmap
        } catch (_: WriterException) {
            null
        }
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("TaptapX", text))
        Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show()
    }

    private fun locateSelected() {
        val guid = viewModel.selectedGuid.value ?: run {
            Toast.makeText(this, R.string.toast_no_server_selected, Toast.LENGTH_SHORT).show()
            return
        }
        val index = viewModel.visibleProfiles.value.indexOfFirst { it.guid == guid }
        if (index >= 0) recyclerView.scrollToPosition(index)
    }

    // ---- Import ----

    private fun importClipboard() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString() ?: ""
        if (text.isBlank()) {
            Toast.makeText(this, R.string.toast_import_none, Toast.LENGTH_SHORT).show()
            return
        }
        val count = viewModel.importLinks(text)
        toastImportResult(count)
    }

    private fun toastImportResult(count: Int) {
        if (count > 0) {
            Toast.makeText(this, getString(R.string.toast_imported, count), Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, R.string.toast_import_none, Toast.LENGTH_SHORT).show()
        }
    }

    // ---- VPN ----

    private fun toggleRunning() {
        if (TaptapVpnService.isRunning) {
            stopVpn()
        } else {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnPermissionLauncher.launch(intent)
            } else {
                startVpn()
            }
        }
    }

    private fun startVpn() {
        val intent = Intent(this, TaptapVpnService::class.java)
            .setAction(TaptapVpnService.ACTION_START)
        startService(intent)
        // v1.0.6, fix B: name the entry being dialled right away —
        // the old generic "Running" left the user guessing which
        // entry the status belonged to, and the 2 s poll then
        // restored the service's (possibly stale) text.
        val item = viewModel.selectedItem()
        val optimistic = if (item != null) {
            "Connecting: ${com.taptap.x.service.dialLabel(item)}…"
        } else {
            getString(R.string.status_running)
        }
        viewModel.setRunning(true, optimistic)
        // The service may refuse to start (no server / SSH profile /
        // bad profile): re-read its real state shortly after.
        fab.postDelayed({ syncServiceState() }, 1500)
    }

    private fun stopVpn() {
        val intent = Intent(this, TaptapVpnService::class.java)
            .setAction(TaptapVpnService.ACTION_STOP)
        startService(intent)
        viewModel.setRunning(false, getString(R.string.status_stopped))
    }

    private fun restartService() {
        stopVpn()
        // Small delay so the old TUN is released before the new start.
        fab.postDelayed({ toggleRunning() }, 500)
    }

    private fun confirm(message: String, onConfirm: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> onConfirm() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
