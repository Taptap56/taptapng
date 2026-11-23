package com.taptap.ng.ui

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.Animatable
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.ImageView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
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
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.navigation.NavigationView
import com.google.android.material.tabs.TabLayout
import com.google.zxing.BarcodeFormat
import com.google.zxing.WriterException
import com.google.zxing.qrcode.QRCodeWriter
import com.taptap.ng.BuildConfig
import com.taptap.ng.R
import com.taptap.ng.TaptapNGApp
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.LinkParser
import com.taptap.ng.core.PemicuManager
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.SettingsStore
import com.taptap.ng.service.ClashApiServer
import com.taptap.ng.service.LiveSwitchDecision
import com.taptap.ng.service.TaptapVpnService
import com.taptap.ng.service.decideLiveSwitch
import com.taptap.ng.ui.groups.GroupsActivity
import com.taptap.ng.ui.log.LogActivity
import com.taptap.ng.ui.main.DashboardUrl
import com.taptap.ng.ui.main.GROUP_ALL_ID
import com.taptap.ng.ui.main.MainViewModel
import com.taptap.ng.ui.main.ServerAdapter
import com.taptap.ng.ui.main.SpeedDisplay
import com.taptap.ng.ui.main.buildExportClipboardText
import com.taptap.ng.ui.scanner.ScannerActivity
import com.taptap.ng.ui.server.ServerEditorActivity
import com.taptap.ng.ui.settings.SettingsActivity
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

    // M7 (W5): Server | Dashboard toggle in the top bar (same
    // position as TB/TC). The Dashboard WebView is created lazily
    // on first selection, never at Activity creation.
    private lateinit var mainTabs: TabLayout
    private lateinit var dashboardContainer: View
    private lateinit var dashboardDisabled: View
    private lateinit var dashboardError: View
    private var dashboardWebView: WebView? = null
    private var dashboardMode = false
    /** Full dashboard URL currently loaded (may hold the secret — never log it). */
    private var dashboardUrlLoaded: String? = null

    /** Back goes through WebView history while in Dashboard mode. */
    private val dashboardBackCallback = object : OnBackPressedCallback(false) {
        override fun handleOnBackPressed() {
            val webView = dashboardWebView
            if (webView != null && webView.canGoBack()) {
                webView.goBack()
                return
            }
            // No history left: fall through to normal back.
            isEnabled = false
            onBackPressedDispatcher.onBackPressed()
        }
    }

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
        super.attachBaseContext(TaptapNGApp.wrapLocale(newBase))
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
        mainTabs = findViewById(R.id.main_tabs)
        dashboardContainer = findViewById(R.id.dashboard_container)
        dashboardDisabled = findViewById(R.id.dashboard_disabled)
        dashboardError = findViewById(R.id.dashboard_error)
        dashboardMode = savedInstanceState?.getBoolean(KEY_DASHBOARD_MODE, false) ?: false
        onBackPressedDispatcher.addCallback(this, dashboardBackCallback)
        setupMainTabs()
        findViewById<Button>(R.id.dashboard_enable_button).setOnClickListener {
            enableClashApiAndLoad()
        }
        findViewById<Button>(R.id.dashboard_retry_button).setOnClickListener {
            reloadDashboard()
        }

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

        // v1.0.28: logo kue TB/TC bergerak hanya saat drawer terbuka
        // (persis CSS TB/TC: animasi jalan hanya bila drawer open).
        val navHeader = findViewById<NavigationView>(R.id.nav_view).getHeaderView(0)
        val drawerLogo = navHeader.findViewById<ImageView>(R.id.drawer_logo).drawable as? Animatable
        drawerLayout.addDrawerListener(object : DrawerLayout.DrawerListener {
            override fun onDrawerOpened(drawerView: View) {
                drawerLogo?.start()
            }
            override fun onDrawerClosed(drawerView: View) {
                drawerLogo?.stop()
            }
            override fun onDrawerSlide(drawerView: View, slideOffset: Float) = Unit
            override fun onDrawerStateChanged(newState: Int) = Unit
        })

        adapter = ServerAdapter(object : ServerAdapter.Callbacks {
            override fun onSelect(guid: String) {
                // v1.0.19 (Issue 2): Clash-style live switch — ketuk
                // server lain saat VPN jalan PINDAH TANPA restart
                // (tunnel + forwarder tetap hidup; hanya seleksi
                // grup "taptap" yang pindah — lihat LiveSwitch).
                // Ketuk server yang sama = no-op; saat VPN mati
                // ketuk tetap pilih saja, start berikutnya memakai
                // entry itu (perilaku lama, tidak berubah).
                when (decideLiveSwitch(
                    viewModel.isRunning.value, viewModel.selectedGuid.value, guid,
                )) {
                    LiveSwitchDecision.NO_OP -> Unit
                    LiveSwitchDecision.SELECT_ONLY -> viewModel.select(guid)
                    LiveSwitchDecision.SWITCH_LIVE -> {
                        viewModel.select(guid)
                        switchService(guid)
                    }
                }
            }
            override fun onShare(item: ProfileItem) = showShareDialog(item)
            override fun onEdit(item: ProfileItem) = openEditor(item.guid, null)
            override fun onDelete(item: ProfileItem) = deleteServer(item)
            override fun onLongPress(item: ProfileItem) = showServerMenu(item)
        })
        recyclerView.adapter = adapter
        applyLayoutManager()

        // v1.0.28: tekan lama = drag untuk mengurutkan (v2rayNG).
        // Drag hanya di mode list dan bila tidak ada pencarian aktif
        // (mirip v2rayNG: canReorder = groupId tidak kosong dan
        // searchQuery kosong). Urutan disimpan sekali saat drag
        // selesai (clearView), bukan tiap langkah.
        val touchHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            ItemTouchHelper.UP or ItemTouchHelper.DOWN or
                ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT,
            0
        ) {
            override fun isLongPressDragEnabled(): Boolean =
                !settings.doubleColumnDisplay && viewModel.searchQuery.value.isEmpty()

            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder,
            ): Boolean {
                val from = viewHolder.bindingAdapterPosition
                val to = target.bindingAdapterPosition
                if (from == RecyclerView.NO_POSITION || to == RecyclerView.NO_POSITION) {
                    return false
                }
                adapter.moveItem(from, to)
                return true
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) = Unit

            override fun clearView(recyclerView: RecyclerView, viewHolder: RecyclerView.ViewHolder) {
                super.clearView(recyclerView, viewHolder)
                viewModel.applyReorderedVisible(adapter.items.map { it.guid })
            }
        })
        touchHelper.attachToRecyclerView(recyclerView)

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
        dashboardWebView?.onResume()
        dashboardWebView?.resumeTimers()
        // Port/secret may have changed in Settings while this tab
        // was open — showDashboard() reloads only if the URL changed.
        if (dashboardMode) showDashboard()
        viewModel.reload()
        // The groupAllDisplay setting may have changed in Settings —
        // rebuild the tabs (the All tab appears / disappears).
        rebuildTabs(viewModel.groups.value)
        syncServiceState()
        updateSpeedDisplay()
        if (lastDoubleColumn != settings.doubleColumnDisplay) applyLayoutManager()
    }

    override fun onPause() {
        dashboardWebView?.onPause()
        dashboardWebView?.pauseTimers()
        super.onPause()
    }

    override fun onDestroy() {
        dashboardWebView?.let { webView ->
            (webView.parent as? ViewGroup)?.removeView(webView)
            webView.destroy()
        }
        dashboardWebView = null
        super.onDestroy()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_DASHBOARD_MODE, dashboardMode)
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

    /**
     * v1.0.5, group A (v2rayNG "Enable speed display"): the small
     * download-rate line under the status text. OFF = hidden;
     * ON = the rate of the newest SPEED line in DialLog (logged by
     * the forwarder while transferring). Refreshed by the 2 s poll
     * and on resume (the setting may have changed in Settings).
     */
    private fun updateSpeedDisplay() {
        val view = findViewById<android.widget.TextView>(R.id.speed_text)
        val text = SpeedDisplay.formatSpeedText(
            settings.speedEnabled,
            SpeedDisplay.latestSpeedSummary(DialLog.lines()),
        )
        if (text == null) {
            view.visibility = View.GONE
        } else {
            view.visibility = View.VISIBLE
            view.text = text
        }
    }

    private fun applyLayoutManager() {
        lastDoubleColumn = settings.doubleColumnDisplay
        adapter.gridMode = settings.doubleColumnDisplay
        // v1.0.28: drag-reorder hanya di mode list (di grid tombol
        // aksi disembunyikan dan tekan lama membuka menu).
        adapter.dragReorderEnabled = !settings.doubleColumnDisplay
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
                        if (!dashboardMode) {
                            emptyView.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
                        }
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
                    viewModel.delayKinds.collect { adapter.delayKinds = it }
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
                launch {
                    viewModel.ipResult.collect { result ->
                        if (result != null) {
                            Toast.makeText(this@MainActivity, result, Toast.LENGTH_LONG).show()
                            viewModel.consumeIpResult()
                        }
                    }
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
                        updateSpeedDisplay()
                    }
                }
            }
        }
    }

    // ---- Tabs (groups) ----

    private fun rebuildTabs(groups: List<String>) {
        rebuildingTabs = true
        tabLayout.removeAllTabs()
        // v1.0.5, group A (v2rayNG "Show an All group tab"): with
        // groupAllDisplay on, an "All" tab leads — selecting it
        // shows every server regardless of group.
        val tabGroups = if (settings.groupAllDisplay) {
            listOf(GROUP_ALL_ID) + groups
        } else {
            groups
        }
        if (tabGroups.size > 1 && !dashboardMode) {
            tabLayout.visibility = View.VISIBLE
            val counts = viewModel.profiles.value.groupingBy { it.group }.eachCount()
            for (group in tabGroups) {
                val label = when {
                    group == GROUP_ALL_ID ->
                        "${getString(R.string.group_all_tab)} (${viewModel.profiles.value.size})"
                    group.isBlank() -> "Default"
                    else -> "$group (${counts[group] ?: 0})"
                }
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
                    if (group.isBlank() || group == GROUP_ALL_ID) continue
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

    // ---- Dashboard tab (M7, W5) ----
    // Toggle Server | Dashboard in the top bar, same position as
    // TB/TC (TabLayout above the group tabs, not a drawer item, not
    // a menu, not a separate Activity). Server mode is exactly the
    // old screen; Dashboard mode swaps the server list area for a
    // WebView onto the bundled yacd served by the local Clash API.

    private fun setupMainTabs() {
        mainTabs.addTab(mainTabs.newTab().setText(R.string.tab_server).setTag(false))
        mainTabs.addTab(mainTabs.newTab().setText(R.string.tab_dashboard).setTag(true))
        mainTabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                setDashboardMode(tab.tag as? Boolean ?: false)
            }
            override fun onTabUnselected(tab: TabLayout.Tab) = Unit
            override fun onTabReselected(tab: TabLayout.Tab) = Unit
        })
        mainTabs.getTabAt(if (dashboardMode) 1 else 0)?.select()
        // Selecting the already-selected Server tab fires nothing,
        // so apply the restored mode explicitly.
        setDashboardMode(dashboardMode)
    }

    private fun setDashboardMode(dashboard: Boolean) {
        dashboardMode = dashboard
        if (dashboard) {
            tabLayout.visibility = View.GONE
            recyclerView.visibility = View.GONE
            emptyView.visibility = View.GONE
            fab.visibility = View.GONE
            dashboardContainer.visibility = View.VISIBLE
            showDashboard()
        } else {
            dashboardContainer.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
            fab.visibility = View.VISIBLE
            // group_tabs visibility is owned by rebuildTabs; re-run
            // it so the tabs come back exactly as before, and
            // restore the empty view the collector owns.
            rebuildTabs(viewModel.groups.value)
            emptyView.visibility =
                if (viewModel.visibleProfiles.value.isEmpty()) View.VISIBLE else View.GONE
        }
        updateBackCallback()
    }

    /**
     * Show the dashboard, or the disabled panel when the Clash API
     * is off. The WebView is created lazily here, on first
     * selection — never at Activity creation. The loaded URL is
     * re-checked on every show so a port/secret change in Settings
     * is picked up without a restart.
     */
    private fun showDashboard() {
        if (!settings.clashApiEnabled) {
            dashboardDisabled.visibility = View.VISIBLE
            dashboardError.visibility = View.GONE
            dashboardWebView?.visibility = View.GONE
            return
        }
        dashboardDisabled.visibility = View.GONE
        val webView = dashboardWebView ?: createDashboardWebView().also { dashboardWebView = it }
        webView.visibility = View.VISIBLE
        val url = currentDashboardUrl()
        if (dashboardUrlLoaded != url) {
            dashboardError.visibility = View.GONE
            dashboardUrlLoaded = url
            // Never log `url`: it may carry ?secret=.
            webView.loadUrl(url)
        }
    }

    /**
     * "Aktifkan": the simplest safe enable path — flip the same
     * setting the Settings screen flips and restart the server the
     * same way it does, then load the dashboard. No app restart.
     */
    private fun enableClashApiAndLoad() {
        settings.clashApiEnabled = true
        ClashApiServer.restart(this)
        showDashboard()
    }

    private fun reloadDashboard() {
        dashboardError.visibility = View.GONE
        val webView = dashboardWebView ?: run { showDashboard(); return }
        dashboardUrlLoaded = currentDashboardUrl()
        // Never log the URL: it may carry ?secret=.
        webView.loadUrl(dashboardUrlLoaded!!)
    }

    private fun currentDashboardUrl(): String = DashboardUrl.build(
        SettingsStore.clashApiPortInt(settings.clashApiPort),
        settings.clashApiSecret,
    )

    /** Origin the WebView is allowed to stay inside (loopback + API port). */
    private fun dashboardOrigin(): String =
        "http://127.0.0.1:${SettingsStore.clashApiPortInt(settings.clashApiPort)}/"

    @SuppressLint("SetJavaScriptEnabled")
    private fun createDashboardWebView(): WebView {
        val webView = WebView(this)
        webView.layoutParams = ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        )
        webView.settings.apply {
            // yacd needs JS + DOM storage + localStorage (it keeps
            // its API config and preferences there).
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowFileAccess = false
            allowContentAccess = false
        }
        webView.webViewClient = object : WebViewClient() {
            /**
             * Navigation decision: same-origin links (the dashboard
             * itself, including its in-app routes) stay in the
             * WebView; anything leaving the local origin opens in
             * the system browser instead of navigating the
             * dashboard away.
             */
            override fun shouldOverrideUrlLoading(
                view: WebView,
                request: WebResourceRequest,
            ): Boolean {
                val url = request.url.toString()
                if (url.startsWith(dashboardOrigin())) return false
                runCatching {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                }
                return true
            }

            override fun onPageFinished(view: WebView, url: String) {
                dashboardError.visibility = View.GONE
                updateBackCallback()
            }

            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: WebResourceError,
            ) {
                // Main frame only: a failed sub-resource (icon,
                // chunk) must not blank the whole dashboard.
                if (request.isForMainFrame) showDashboardError()
            }

            override fun onReceivedHttpError(
                view: WebView,
                request: WebResourceRequest,
                errorResponse: WebResourceResponse,
            ) {
                if (request.isForMainFrame) showDashboardError()
            }
        }
        (dashboardContainer as ViewGroup).addView(webView, 0)
        return webView
    }

    private fun showDashboardError() {
        dashboardError.visibility = View.VISIBLE
        updateBackCallback()
    }

    private fun updateBackCallback() {
        dashboardBackCallback.isEnabled =
            dashboardMode && (dashboardWebView?.canGoBack() == true)
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
                R.id.more_export_all -> exportVisibleToClipboard()
                R.id.more_locate_selected -> locateSelected()
                R.id.more_sort_by_test -> viewModel.sortByDelay()
                R.id.more_test_all -> viewModel.testAll(false)
                R.id.more_test_all_real -> viewModel.testAll(true)
                R.id.more_prime_now -> primeNow()
                R.id.more_groups_routes -> startActivity(Intent(this, GroupsActivity::class.java))
                R.id.more_check_ip -> viewModel.checkIp()
                R.id.more_update_sub -> Toast.makeText(
                    this, R.string.toast_not_available, Toast.LENGTH_SHORT
                ).show()
            }
            true
        }
        popup.show()
    }

    /**
     * Manual "Prime sekarang" (v1.0.24, M5): prime the selected
     * entry's Pemicu target once, right now — works whether the VPN
     * is up or down (the dial goes direct when there is no TUN).
     * The result lands in DialLog (PRIME OK / PRIME GAGAL); the
     * toast only confirms the prime was sent.
     */
    private fun primeNow() {
        val item = viewModel.selectedItem() ?: run {
            Toast.makeText(this, R.string.toast_no_server_selected, Toast.LENGTH_SHORT).show()
            return
        }
        if (PemicuManager.targetFromProfile(item) == null) {
            Toast.makeText(this, R.string.toast_prime_no_domain, Toast.LENGTH_SHORT).show()
            return
        }
        PemicuManager.primeNow(item)
        Toast.makeText(this, R.string.toast_prime_sent, Toast.LENGTH_SHORT).show()
    }

    private fun onDrawerItem(itemId: Int) {
        when (itemId) {
            R.id.nav_groups -> startActivity(
                GroupsActivity.newIntent(this, GroupsActivity.SECTION_GROUPS)
            )
            R.id.nav_routes -> startActivity(
                GroupsActivity.newIntent(this, GroupsActivity.SECTION_ROUTES)
            )
            R.id.nav_settings -> startActivity(Intent(this, SettingsActivity::class.java))
            R.id.nav_logcat -> startActivity(Intent(this, LogActivity::class.java))
            R.id.nav_about -> AlertDialog.Builder(this)
                .setTitle(R.string.about_title)
                .setMessage(formatAboutText(getString(R.string.about_text), BuildConfig.VERSION_NAME))
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

    /**
     * v1.0.28: "Export configs to clipboard" (v2rayNG
     * exportAllAsync) — salin share link semua config yang tampil
     * ke clipboard, tanpa file. Kosong = toast, bukan clipboard
     * kosong.
     */
    private fun exportVisibleToClipboard() {
        val text = buildExportClipboardText(viewModel.visibleProfiles.value)
        if (text.isBlank()) {
            Toast.makeText(this, R.string.toast_nothing_to_export, Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("TaptapNG", text))
        Toast.makeText(this, R.string.toast_exported, Toast.LENGTH_SHORT).show()
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("TaptapNG", text))
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
        } else if (com.taptap.ng.data.SettingsStore(this).enableRootMode) {
            // v1.0.15 (Root mode): tanpa TUN, izin VPN tidak
            // diperlukan — langsung start, tanpa dialog izin.
            startVpn()
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
            "Connecting: ${com.taptap.ng.service.dialLabel(item)}…"
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

    /**
     * v1.0.19 (Issue 2): minta service pindah live ke [guid]
     * tanpa stop/start (ACTION_SWITCH). Service yang memvalidasi
     * entry, memindah seleksi grup + label + loop Pemicu — bila
     * ditolak, tunnel tetap jalan di entry lama (lihat
     * TaptapVpnService.switchTunnel).
     */
    private fun switchService(guid: String) {
        val intent = Intent(this, TaptapVpnService::class.java)
            .setAction(TaptapVpnService.ACTION_SWITCH)
            .putExtra(TaptapVpnService.EXTRA_GUID, guid)
        startService(intent)
        // The service moves the "Connected:" label itself; the 2 s
        // poll picks it up. No optimistic text here — a rejected
        // switch must not flash the new entry's name.
    }

    private fun confirm(message: String, onConfirm: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> onConfirm() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    companion object {
        private const val KEY_DASHBOARD_MODE = "dashboard_mode"
    }
}
