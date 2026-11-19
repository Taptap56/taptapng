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
        holder.remarks.setTypeface(null, if (selected) Typeface.BOLD else Typeface.NORMAL)
        holder.accentBar.visibility = if (selected) View.VISIBLE else View.INVISIBLE
        holder.statistics.text = "${item.address}:${item.port}"
        holder.typeDesc.text = item.typeDescription()

        val delayMs = delays[item.guid]
        if (delayMs == null) {
            holder.delay.text = ""
        } else if (delayMs < 0) {
            holder.delay.text = "Timeout"
            holder.delay.setTextColor(ContextCompat.getColor(context, R.color.colorPingRed))
        } else {
            holder.delay.text = "${delayMs}ms"
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
