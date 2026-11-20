package com.taptap.ng.ui.main

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.taptap.ng.R
import com.taptap.ng.data.ProfileItem

/**
 * Server list adapter, mirroring v2rayNG's MainServerPager row:
 * accent bar + remarks + share/edit/delete, statistics, type + delay.
 * In double-column (grid) mode the row buttons are hidden and the
 * row is managed via long-press instead.
 */
class ServerAdapter(
    private val callbacks: Callbacks,
) : RecyclerView.Adapter<ServerAdapter.ViewHolder>() {

    interface Callbacks {
        fun onSelect(guid: String)
        fun onShare(item: ProfileItem)
        fun onEdit(item: ProfileItem)
        fun onDelete(item: ProfileItem)
        fun onLongPress(item: ProfileItem)
    }

    /**
     * v1.0.28: daftar disimpan di backing list privat supaya
     * [moveItem] bisa menggeser satu baris tanpa memicu setter
     * (setter = notifyDataSetChanged penuh, yang membatalkan drag
     * ItemTouchHelper di tengah jalan).
     */
    private val mutableItems = mutableListOf<ProfileItem>()
    var items: List<ProfileItem>
        get() = mutableItems
        set(value) {
            mutableItems.clear()
            mutableItems.addAll(value)
            notifyDataSetChanged()
        }

    var selectedGuid: String? = null
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    var delays: Map<String, Long> = emptyMap()
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    /** guid -> failure stage for failed delay tests (v1.0.6, fix C). */
    var delayStages: Map<String, String> = emptyMap()
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    /** guid -> delay kind ("real" or "tcp", v1.0.13, fix B). */
    var delayKinds: Map<String, String> = emptyMap()
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    var gridMode: Boolean = false
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    /**
     * v1.0.28: true di mode list — tekan lama = drag reorder
     * (ItemTouchHelper), jadi long-click menu dimatikan; false di
     * mode grid — tekan lama tetap buka menu (tombol aksi
     * disembunyikan di grid, menu satu-satunya jalan edit/share/
     * hapus di sana).
     */
    var dragReorderEnabled: Boolean = false

    /**
     * v1.0.28: geser satu baris (drag reorder). Hanya ubah backing
     * list + notifyItemMoved — persistensi dilakukan pemanggil saat
     * drag selesai (clearView), bukan di sini.
     */
    fun moveItem(from: Int, to: Int) {
        if (from == to) return
        if (from !in mutableItems.indices || to !in mutableItems.indices) return
        mutableItems.add(to, mutableItems.removeAt(from))
        notifyItemMoved(from, to)
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val accentBar: View = view.findViewById(R.id.accent_bar)
        val remarks: TextView = view.findViewById(R.id.remarks)
        val statistics: TextView = view.findViewById(R.id.statistics)
        val typeDesc: TextView = view.findViewById(R.id.type_desc)
        val delay: TextView = view.findViewById(R.id.delay)
        val btnShare: ImageButton = view.findViewById(R.id.btn_share)
        val btnEdit: ImageButton = view.findViewById(R.id.btn_edit)
        val btnDelete: ImageButton = view.findViewById(R.id.btn_delete)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_server, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val selected = item.guid == selectedGuid
        val context = holder.itemView.context

        holder.remarks.text = item.displayName()
        // v1.0.4: v2rayNG bolds EVERY row's remarks, not only the
        // selected one — the old selected-only bold left unselected
        // rows thin and hard to read.
        holder.remarks.setTypeface(null, Typeface.BOLD)
        holder.accentBar.visibility = if (selected) View.VISIBLE else View.INVISIBLE
        holder.statistics.text = "${item.address}:${item.port}"
        holder.typeDesc.text = item.typeDescription()

        val delayMs = delays[item.guid]
        if (delayMs == null) {
            holder.delay.text = ""
        } else if (delayMs < 0) {
            // v1.0.6: show WHERE the test died instead of a bare
            // "Timeout" ("TCP timeout", "DNS gagal", "protect gagal").
            holder.delay.text = formatDelayFailure(delayStages[item.guid])
            holder.delay.setTextColor(ContextCompat.getColor(context, R.color.colorPingRed))
        } else {
            // v1.0.13, fix B: the label says which ping it is — a
            // real ping shows "48ms", a TCP fallback "48ms (TCP)",
            // so a TCP number is never mistaken for a real ping.
            holder.delay.text = formatDelayLabel(delayMs, delayKinds[item.guid])
            holder.delay.setTextColor(ContextCompat.getColor(context, R.color.colorPing))
        }

        val buttonsVisible = if (gridMode) View.GONE else View.VISIBLE
        holder.btnShare.visibility = buttonsVisible
        holder.btnEdit.visibility = buttonsVisible
        holder.btnDelete.visibility = buttonsVisible

        holder.itemView.setOnClickListener { callbacks.onSelect(item.guid) }
        // v1.0.28: tekan lama = drag reorder bila aktif; kalau tidak,
        // tekan lama buka menu (mode grid).
        if (dragReorderEnabled) {
            holder.itemView.setOnLongClickListener(null)
        } else {
            holder.itemView.setOnLongClickListener {
                callbacks.onLongPress(item)
                true
            }
        }
        holder.btnShare.setOnClickListener { callbacks.onShare(item) }
        holder.btnEdit.setOnClickListener { callbacks.onEdit(item) }
        holder.btnDelete.setOnClickListener { callbacks.onDelete(item) }
    }
}

/** Delay kind: full round-trip through the proxy (v1.0.13, fix B). */
const val DELAY_KIND_REAL = "real"

/** Delay kind: plain TCP connect fallback (only when the real ping
 * cannot run at all). */
const val DELAY_KIND_TCP = "tcp"

/**
 * Row delay label (v1.0.13, fix B): a real ping shows "48ms"; a
 * TCP fallback shows "48ms (TCP)". Pure, so it is unit testable.
 */
fun formatDelayLabel(ms: Long, kind: String?): String =
    if (kind == DELAY_KIND_TCP) "${ms}ms (TCP)" else "${ms}ms"

/**
 * Row label for a failed delay test (v1.0.22): the stage text can be a
 * long diagnostic ("TCP gagal: connect timed out after ...") that
 * squeezed the protocol label. Keep only the part before the first
 * colon, capped at 22 characters; blank = "Timeout" like v2rayNG.
 */
fun formatDelayFailure(stage: String?): String {
    val head = stage?.substringBefore(':')?.trim().orEmpty()
    if (head.isEmpty()) return "Timeout"
    return if (head.length > 22) head.take(21) + "…" else head
}
