package com.taptap.x.ui.main

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.taptap.x.R
import com.taptap.x.data.ProfileItem

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

    var items: List<ProfileItem> = emptyList()
        set(value) {
            field = value
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
            holder.delay.text = delayStages[item.guid]?.takeIf { it.isNotBlank() } ?: "Timeout"
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
        holder.itemView.setOnLongClickListener {
            callbacks.onLongPress(item)
            true
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
