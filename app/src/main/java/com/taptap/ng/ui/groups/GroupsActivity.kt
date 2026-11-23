package com.taptap.ng.ui.groups

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.ContextThemeWrapper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputLayout
import com.taptap.ng.R
import com.taptap.ng.TaptapNGApp
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileStore

/**
 * M7 editor for proxy groups + route rules (Views, mirroring
 * ServerEditorActivity's dialogs and the flat rows of item_server).
 * The route engine (W2) and the Clash API (W3) read the same
 * [GroupsStore]; this activity only edits it — it never dials.
 *
 * Entry point: MainActivity overflow menu "Grup proxy & rute".
 */
class GroupsActivity : AppCompatActivity() {

    private lateinit var profileStore: ProfileStore
    private lateinit var groupsStore: GroupsStore
    private lateinit var groupAdapter: GroupAdapter
    private lateinit var ruleAdapter: RuleAdapter

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapNGApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_groups)

        profileStore = ProfileStore(ProfileStore.defaultFile(filesDir))
        profileStore.load()
        groupsStore = GroupsStore(GroupsStore.defaultFile(filesDir))
        groupsStore.load(profileStore.profiles, profileStore.selectedGuid)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        // v1.0.21: drawer "Grup"/"Rute" opens this same activity
        // straight at the requested section (title follows the
        // section); no extra = the old full title (overflow menu).
        val section = resolveSection(intent.getStringExtra(EXTRA_SECTION))
        toolbar.title = getString(sectionTitleRes(section))
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        // v1.0.22: show only the requested section (the v1.0.21
        // posted scroll hack never moved — see sectionsVisibleFor).
        // No extra = the old full view (overflow menu).
        val visibility = sectionsVisibleFor(section)
        findViewById<View>(R.id.groups_section).visibility =
            if (visibility.groupsVisible) View.VISIBLE else View.GONE
        findViewById<View>(R.id.rules_section).visibility =
            if (visibility.rulesVisible) View.VISIBLE else View.GONE

        groupAdapter = GroupAdapter(
            onEdit = { showGroupDialog(it) },
            onDelete = { confirmDeleteGroup(it) },
        )
        ruleAdapter = RuleAdapter(
            onEdit = { showRuleDialog(it) },
            onDelete = { confirmDeleteRule(it) },
            onMoveUp = { if (groupsStore.moveRuleUp(it.id)) refresh() },
            onMoveDown = { if (groupsStore.moveRuleDown(it.id)) refresh() },
        )
        findViewById<RecyclerView>(R.id.groups_list).apply {
            layoutManager = LinearLayoutManager(this@GroupsActivity)
            adapter = groupAdapter
        }
        findViewById<RecyclerView>(R.id.rules_list).apply {
            layoutManager = LinearLayoutManager(this@GroupsActivity)
            adapter = ruleAdapter
        }
        findViewById<View>(R.id.add_group).setOnClickListener { showGroupDialog(null) }
        findViewById<View>(R.id.add_rule).setOnClickListener { showRuleDialog(null) }
        findViewById<View>(R.id.save_main_group).setOnClickListener { saveMainGroupName() }
        refresh()
    }

    private fun refresh() {
        groupAdapter.submit(groupsStore.groups.toList())
        ruleAdapter.submit(groupsStore.rules.toList())
        // v1.0.23: kartu "Grup utama" — nama saat ini (by id,
        // jadi rename lewat dialog edit grup ikut tampil di sini).
        findViewById<EditText>(R.id.main_group_name)
            .setText(groupsStore.mainGroup()?.name ?: "")
        findViewById<View>(R.id.empty_groups).visibility =
            if (groupsStore.groups.isEmpty()) View.VISIBLE else View.GONE
        findViewById<View>(R.id.empty_rules).visibility =
            if (groupsStore.rules.isEmpty()) View.VISIBLE else View.GONE
    }

    /**
     * v1.0.23: simpan nama baru grup utama dari kartu di atas
     * seksi grup. Validasi di [GroupsStore.renameMainGroup]:
     * kosong dan duplikat ditolak dengan Toast, tanpa crash.
     * Berlaku langsung — rute dibaca per koneksi, tanpa restart.
     */
    private fun saveMainGroupName() {
        val name = findViewById<EditText>(R.id.main_group_name).text.toString()
        when (groupsStore.renameMainGroup(name)) {
            is GroupsStore.RenameMainGroupResult.Renamed -> {
                Toast.makeText(this, R.string.groups_main_group_saved, Toast.LENGTH_SHORT).show()
                refresh()
            }
            GroupsStore.RenameMainGroupResult.Blank ->
                Toast.makeText(this, R.string.groups_name_required, Toast.LENGTH_SHORT).show()
            GroupsStore.RenameMainGroupResult.Duplicate ->
                Toast.makeText(this, R.string.groups_main_group_name_taken, Toast.LENGTH_SHORT).show()
            GroupsStore.RenameMainGroupResult.NoMainGroup ->
                Toast.makeText(this, R.string.groups_empty_groups, Toast.LENGTH_SHORT).show()
        }
    }

    // ---- Group dialog ----

    private fun showGroupDialog(existing: ProxyGroup?) {
        val servers = profileStore.profiles.toList()
        val ctx = this
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, pad / 2)
        }
        // v1.0.26: label "Nama grup" pakai labeled() seperti URL tes /
        // Interval tes (v1.0.25) — pola hint yang SAMA: saat Ubah grup
        // field terisi ("taptap") sehingga hint menimpa nilai, persis
        // seperti URL/Interval di v1.0.24 (screenshot 2026-11-24 05:04,
        // dilingkari merah). Saat Tambah grup field kosong, hint tampil
        // sendiri jadi rusaknya tidak kelihatan. Hint di EditText
        // dihapus; TextView label nyata di atas field, berlaku untuk
        // tambah maupun ubah (satu kode dialog untuk keduanya).
        val nameInput = EditText(ctx).apply {
            setText(existing?.name ?: "")
        }
        root.addView(
            labeled(
                ctx, getString(R.string.groups_group_name),
                TextInputLayout(ctx).apply { addView(nameInput) },
            ),
        )

        val typeSpinner = Spinner(ctx).apply {
            adapter = ArrayAdapter(
                ctx, android.R.layout.simple_spinner_dropdown_item,
                ProxyGroupType.values().map { typeLabel(it) },
            )
            setSelection(existing?.type?.ordinal ?: 0)
        }
        root.addView(labeled(ctx, getString(R.string.groups_group_type), typeSpinner))

        // Label di ATAS nilai, pakai labeled() seperti spinner
        // "Tipe grup" / "Anggota terpilih" di dialog ini. v1.0.24:
        // label kedua field ini cuma EditText.hint di dalam
        // TextInputLayout(ctx) polos (tanpa hint di layout, tanpa
        // style OutlinedBox) — hint tidak mengambang ke atas, jadi
        // saat nilai sudah terisi (default URL tes / interval) label
        // menimpa nilai dan keduanya tidak terbaca. labeled() menaruh
        // TextView label di atas field, jadi tumpukan itu tidak
        // mungkin terjadi lagi; hint di EditText dihapus.
        val urlInput = EditText(ctx).apply {
            setText(existing?.urlTestUrl ?: ProxyGroup.DEFAULT_URL_TEST_URL)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        root.addView(
            labeled(
                ctx, getString(R.string.groups_url_test_url),
                TextInputLayout(ctx).apply { addView(urlInput) },
            ),
        )

        val intervalInput = EditText(ctx).apply {
            setText((existing?.urlTestIntervalSec ?: ProxyGroup.DEFAULT_URL_TEST_INTERVAL_SEC).toString())
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        root.addView(
            labeled(
                ctx, getString(R.string.groups_url_test_interval),
                TextInputLayout(ctx).apply { addView(intervalInput) },
            ),
        )

        // Member picking: multi-choice dialog over the server list.
        // The SELECT "terpilih" spinner below is rebuilt whenever
        // the member set changes, so declare it first.
        val chosen = (existing?.members ?: emptyList()).toMutableSet()
        var selectedGuid: String? = existing?.selectedMemberGuid
        var selectedRow: View? = null
        fun rebuildSelectedSpinner() {
            val picked = servers.filter { it.guid in chosen }
            val labels = picked.map { it.displayName() }
            val spinner = Spinner(ctx).apply {
                adapter = ArrayAdapter(
                    ctx, android.R.layout.simple_spinner_dropdown_item, labels,
                )
                val idx = picked.indexOfFirst { it.guid == selectedGuid }.takeIf { it >= 0 } ?: 0
                if (labels.isNotEmpty()) setSelection(idx)
                setOnItemSelectedListener(object : android.widget.AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(
                        parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long,
                    ) {
                        selectedGuid = picked.getOrNull(position)?.guid
                    }

                    override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
                })
            }
            val row = labeled(ctx, getString(R.string.groups_selected), spinner)
            val old = selectedRow
            if (old != null) {
                val idx = root.indexOfChild(old)
                root.removeView(old)
                root.addView(row, idx)
            } else {
                root.addView(row)
            }
            selectedRow = row
        }

        // v1.0.25: tombol isi hijau yang sama dengan ketiga tombol
        // header Grup/Rute (Widget.TaptapNG.Button.FilledAccent).
        // Sebelumnya `Button(ctx)` polos — style isi default M2 yang
        // latarnya `colorPrimary` (hitam di tema terang), jadi tombol
        // ini hitam seperti ketiganya. MaterialButton TIDAK punya
        // konstruktor 4-argumen (ctx, attrs, defStyleAttr, defStyleRes)
        // — style diterapkan lewat ContextThemeWrapper; teks 15sp
        // seperti ketiganya. Teks, klik (dialog multi-pilih server),
        // dan posisi tidak berubah.
        val membersButton = MaterialButton(ContextThemeWrapper(ctx, R.style.Widget_TaptapNG_Button_FilledAccent)).apply {
            text = membersButtonText(chosen.size)
            textSize = 15f
            setOnClickListener {
                val names = servers.map { it.displayName() }.toTypedArray()
                val checked = servers.map { it.guid in chosen }.toBooleanArray()
                AlertDialog.Builder(ctx)
                    .setTitle(R.string.groups_members)
                    .setMultiChoiceItems(names, checked) { _, which, isChecked ->
                        val guid = servers[which].guid
                        if (isChecked) chosen += guid else chosen -= guid
                    }
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        text = membersButtonText(chosen.size)
                        rebuildSelectedSpinner()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
        root.addView(membersButton)
        rebuildSelectedSpinner()

        AlertDialog.Builder(ctx)
            .setTitle(if (existing == null) R.string.groups_add_group else R.string.groups_edit)
            .setView(root)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val name = nameInput.text.toString().trim()
                if (name.isBlank()) {
                    Toast.makeText(ctx, R.string.groups_name_required, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (chosen.isEmpty()) {
                    Toast.makeText(ctx, R.string.groups_need_member, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val type = ProxyGroupType.values()[typeSpinner.selectedItemPosition]
                val url = urlInput.text.toString().trim()
                    .ifBlank { ProxyGroup.DEFAULT_URL_TEST_URL }
                val interval = intervalInput.text.toString().toIntOrNull()
                    ?: ProxyGroup.DEFAULT_URL_TEST_INTERVAL_SEC
                val group = (existing ?: ProxyGroup()).copy(
                    name = name,
                    type = type,
                    // Keep the server-list order for members.
                    members = servers.filter { it.guid in chosen }.map { it.guid },
                    selectedMemberGuid = if (type == ProxyGroupType.SELECT) {
                        selectedGuid?.takeIf { it in chosen }
                            ?: servers.firstOrNull { it.guid in chosen }?.guid
                    } else {
                        null
                    },
                    urlTestUrl = url,
                    urlTestIntervalSec = interval,
                )
                if (existing == null) groupsStore.addGroup(group) else groupsStore.updateGroup(group)
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun membersButtonText(count: Int): String =
        "${getString(R.string.groups_members)} ($count)"

    private fun confirmDeleteGroup(group: ProxyGroup) {
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.groups_delete_group, group.name))
            .setPositiveButton(android.R.string.ok) { _, _ ->
                groupsStore.removeGroup(group.id)
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ---- Rule dialog ----

    private fun showRuleDialog(existing: RouteRule?) {
        val ctx = this
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, pad / 2)
        }
        val typeSpinner = Spinner(ctx).apply {
            adapter = ArrayAdapter(
                ctx, android.R.layout.simple_spinner_dropdown_item,
                RouteRuleType.values().map { it.name },
            )
            setSelection(existing?.type?.ordinal ?: 0)
        }
        root.addView(labeled(ctx, getString(R.string.groups_rule_type), typeSpinner))

        val patternInput = EditText(ctx).apply {
            hint = getString(R.string.groups_rule_pattern)
            setText(existing?.pattern ?: "")
        }
        root.addView(TextInputLayout(ctx).apply { addView(patternInput) })

        // Target: every group + DIRECT + REJECT.
        val targetOptions = groupsStore.groups.map { it.name to it.id } +
            listOf(
                getString(R.string.groups_target_direct) to RouteRule.TARGET_DIRECT,
                getString(R.string.groups_target_reject) to RouteRule.TARGET_REJECT,
            )
        val targetSpinner = Spinner(ctx).apply {
            adapter = ArrayAdapter(
                ctx, android.R.layout.simple_spinner_dropdown_item,
                targetOptions.map { it.first },
            )
            val idx = targetOptions.indexOfFirst { it.second == existing?.target }
                .takeIf { it >= 0 } ?: 0
            setSelection(idx)
        }
        root.addView(labeled(ctx, getString(R.string.groups_rule_target), targetSpinner))

        AlertDialog.Builder(ctx)
            .setTitle(if (existing == null) R.string.groups_add_rule else R.string.groups_edit)
            .setView(root)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val type = RouteRuleType.values()[typeSpinner.selectedItemPosition]
                val pattern = patternInput.text.toString().trim()
                if (type != RouteRuleType.FINAL && pattern.isEmpty()) {
                    Toast.makeText(ctx, R.string.groups_pattern_required, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (type == RouteRuleType.IP_CIDR && !RouteRule.isValidCidr(pattern)) {
                    Toast.makeText(ctx, R.string.groups_cidr_invalid, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val target = targetOptions[targetSpinner.selectedItemPosition].second
                val rule = (existing ?: RouteRule()).copy(
                    type = type,
                    pattern = if (type == RouteRuleType.FINAL) "" else pattern,
                    target = target,
                )
                if (existing == null) groupsStore.addRule(rule) else groupsStore.updateRule(rule)
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteRule(rule: RouteRule) {
        AlertDialog.Builder(this)
            .setMessage(R.string.groups_delete_rule)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                groupsStore.removeRule(rule.id)
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun labeled(ctx: Context, label: String, view: View): View =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (4 * resources.displayMetrics.density).toInt()
            setPadding(0, pad, 0, pad)
            addView(TextView(ctx).apply {
                text = label
                setTextAppearance(android.R.style.TextAppearance_Small)
            })
            addView(view)
        }

    // ---- Adapters ----

    private inner class GroupAdapter(
        private val onEdit: (ProxyGroup) -> Unit,
        private val onDelete: (ProxyGroup) -> Unit,
    ) : RecyclerView.Adapter<GroupAdapter.Holder>() {
        private var items: List<ProxyGroup> = emptyList()

        fun submit(list: List<ProxyGroup>) {
            items = list
            notifyDataSetChanged()
        }

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val name: TextView = view.findViewById(R.id.group_name)
            val type: TextView = view.findViewById(R.id.group_type)
            val detail: TextView = view.findViewById(R.id.group_detail)
            val edit: ImageButton = view.findViewById(R.id.group_edit)
            val delete: ImageButton = view.findViewById(R.id.group_delete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_proxy_group, parent, false))

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val group = items[position]
            holder.name.text = group.name
            holder.type.text = typeLabel(group.type)
            val selectedName = group.effectiveSelectedMemberGuid()
                ?.let { profileStore.find(it)?.displayName() }
            holder.detail.text = buildString {
                append(getString(R.string.groups_members_count, group.members.size))
                if (group.type == ProxyGroupType.SELECT && selectedName != null) {
                    append(" · ")
                    append(getString(R.string.groups_selected_member, selectedName))
                }
                if (group.members.isEmpty()) {
                    append(" · ")
                    append(getString(R.string.groups_no_member))
                }
            }
            holder.edit.setOnClickListener { onEdit(group) }
            holder.delete.setOnClickListener { onDelete(group) }
        }
    }

    private inner class RuleAdapter(
        private val onEdit: (RouteRule) -> Unit,
        private val onDelete: (RouteRule) -> Unit,
        private val onMoveUp: (RouteRule) -> Unit,
        private val onMoveDown: (RouteRule) -> Unit,
    ) : RecyclerView.Adapter<RuleAdapter.Holder>() {
        private var items: List<RouteRule> = emptyList()

        fun submit(list: List<RouteRule>) {
            items = list
            notifyDataSetChanged()
        }

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val type: TextView = view.findViewById(R.id.rule_type)
            val pattern: TextView = view.findViewById(R.id.rule_pattern)
            val target: TextView = view.findViewById(R.id.rule_target)
            val moveUp: ImageButton = view.findViewById(R.id.rule_move_up)
            val moveDown: ImageButton = view.findViewById(R.id.rule_move_down)
            val enabled: SwitchMaterial = view.findViewById(R.id.rule_enabled)
            val edit: ImageButton = view.findViewById(R.id.rule_edit)
            val delete: ImageButton = view.findViewById(R.id.rule_delete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_route_rule, parent, false))

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val rule = items[position]
            holder.type.text = rule.type.name
            holder.pattern.text = rule.pattern.ifBlank { "—" }
            holder.target.text = when (rule.target) {
                RouteRule.TARGET_DIRECT -> getString(R.string.groups_target_direct)
                RouteRule.TARGET_REJECT -> getString(R.string.groups_target_reject)
                else -> getString(
                    R.string.groups_target_group,
                    groupsStore.findGroup(rule.target)?.name ?: rule.target,
                )
            }
            // Edges cannot move further that way: disable (dimmed),
            // never hide — the row layout stays stable.
            holder.moveUp.isEnabled = position > 0
            holder.moveUp.alpha = if (position > 0) 1.0f else 0.3f
            holder.moveDown.isEnabled = position < items.size - 1
            holder.moveDown.alpha = if (position < items.size - 1) 1.0f else 0.3f
            holder.moveUp.setOnClickListener { onMoveUp(rule) }
            holder.moveDown.setOnClickListener { onMoveDown(rule) }
            // v1.0.23: per-rule on/off toggle, persisted via
            // updateRule. FINAL ("Rute akhir") has no toggle — it
            // is always active, like TaptapBox/TaptapClash.
            // Clear the listener before setting the state, or
            // recycling a row would fire a stale toggle.
            holder.enabled.setOnCheckedChangeListener(null)
            if (rule.type == RouteRuleType.FINAL) {
                holder.enabled.visibility = View.GONE
            } else {
                holder.enabled.visibility = View.VISIBLE
                holder.enabled.isChecked = rule.isEnabled
                holder.enabled.setOnCheckedChangeListener { _, checked ->
                    val updated = rule.copy(enabled = checked)
                    groupsStore.updateRule(updated)
                    items = items.map { if (it.id == rule.id) updated else it }
                }
            }
            // Edit reads the CURRENT row object, not the one
            // captured at bind time: a toggle updates `items`
            // in place, and editing a stale copy would write
            // the old `enabled` value back over it.
            holder.edit.setOnClickListener {
                onEdit(items.firstOrNull { it.id == rule.id } ?: rule)
            }
            holder.delete.setOnClickListener { onDelete(rule) }
        }
    }

    companion object {
        /** Intent extra selecting which section to show on open. */
        const val EXTRA_SECTION = "com.taptap.ng.ui.groups.EXTRA_SECTION"

        /** Full view, old title ("Grup proxy & rute") — overflow menu. */
        const val SECTION_DEFAULT = "default"

        /** Proxy-groups section (drawer "Grup"). */
        const val SECTION_GROUPS = "groups"

        /** Route-rules section (drawer "Rute"). */
        const val SECTION_ROUTES = "routes"

        fun newIntent(context: Context, section: String): Intent =
            Intent(context, GroupsActivity::class.java)
                .putExtra(EXTRA_SECTION, section)

        /**
         * Resolve a raw extra value to a section. Unknown or missing
         * values fall back to the full view — never crash on a bad
         * extra. Pure, JVM-tested.
         */
        fun resolveSection(extra: String?): String = when (extra) {
            SECTION_GROUPS -> SECTION_GROUPS
            SECTION_ROUTES -> SECTION_ROUTES
            else -> SECTION_DEFAULT
        }

        /** Toolbar title for a resolved section. */
        fun sectionTitleRes(section: String): Int = when (section) {
            SECTION_GROUPS -> R.string.drawer_groups
            SECTION_ROUTES -> R.string.drawer_routes
            else -> R.string.groups_title
        }

        /** Which sections are visible for a resolved section. Pure, JVM-tested. */
        data class SectionVisibility(val groupsVisible: Boolean, val rulesVisible: Boolean)

        fun sectionsVisibleFor(section: String): SectionVisibility = when (section) {
            SECTION_GROUPS -> SectionVisibility(groupsVisible = true, rulesVisible = false)
            SECTION_ROUTES -> SectionVisibility(groupsVisible = false, rulesVisible = true)
            else -> SectionVisibility(groupsVisible = true, rulesVisible = true)
        }

        /** Display label for a group type (URL_TEST shows as URL-TEST). */
        fun typeLabel(type: ProxyGroupType): String = when (type) {
            ProxyGroupType.SELECT -> "SELECT"
            ProxyGroupType.URL_TEST -> "URL-TEST"
            ProxyGroupType.FALLBACK -> "FALLBACK"
        }
    }
}
