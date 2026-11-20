package com.taptap.x.service

import com.taptap.x.data.ProfileItem

/**
 * Human-readable label for the entry being dialled: remark plus
 * address, so two entries that share a remark ("Zoom onering" on
 * both leaseweb4 and support.zoom.us) are never confused in the
 * status bar. A blank remark falls back to the bare address.
 */
fun dialLabel(item: ProfileItem): String {
    val remarks = item.displayName()
    return if (remarks == item.address) item.address else "$remarks (${item.address})"
}

/**
 * Connection state machine (v1.0.6, fix B). Pure Kotlin, no Android
 * — the service owns one instance and the UI reads [status] /
 * [isRunning] through the service's statics.
 *
 * Phone evidence (2026-11-20 02:49–02:53): the user ran entry B
 * ("Taptap WS (CDN) TLS", 104.17.3.81) but the status stayed
 * "Connecting: Zoom onering..." — the v1.0.5 service silently
 * ignored a second ACTION_START while already running (its
 * `started` flag), so the old entry's connection and status kept
 * running. A new start must now RESTART with the new entry, and
 * the status must name the entry being dialled from the first
 * moment — never another entry's remark.
 */
class VpnConnection {

    enum class State { IDLE, STARTING, RUNNING, FAILED }

    enum class Decision { START_FRESH, RESTART, ALREADY_RUNNING }

    @Volatile
    var state: State = State.IDLE
        private set

    /** Last human-readable status for the main screen. */
    @Volatile
    var status: String = "Stopped"
        private set

    /** Label of the entry being dialled / running, or null when idle. */
    @Volatile
    var runningEntry: String? = null
        private set

    val isRunning: Boolean
        get() = state == State.STARTING || state == State.RUNNING

    /**
     * A (re)start was requested for [label]. Returns what the caller
     * must do — and the status already names [label], so the UI poll
     * picks the new entry up within one cycle.
     */
    @Synchronized
    fun requestStart(label: String): Decision {
        return when {
            state == State.IDLE || state == State.FAILED -> {
                state = State.STARTING
                runningEntry = label
                status = "Connecting: $label…"
                Decision.START_FRESH
            }
            runningEntry == label -> Decision.ALREADY_RUNNING
            else -> {
                state = State.STARTING
                runningEntry = label
                status = "Connecting: $label…"
                Decision.RESTART
            }
        }
    }

    /** The probe dial succeeded and the TUN is up. */
    @Synchronized
    fun reportConnected(label: String) {
        state = State.RUNNING
        runningEntry = label
        status = "Connected: $label"
    }

    /**
     * A start/probe failed. [message] is the full status text — the
     * caller names the entry in it (e.g. "Konek gagal (TLS gagal):
     * Zoom onering (support.zoom.us)"), because a rejection can name
     * a different entry than the running one.
     */
    @Synchronized
    fun reportFailure(message: String) {
        state = State.FAILED
        status = message
    }

    /**
     * Forwarder callback: "Connected" on the first successful app
     * dial, "Konek gagal (<reason>)" on a dial failure. The status
     * always carries the RUNNING entry's label.
     *
     * v1.0.13, fix C: a dial failure while RUNNING must NOT
     * overwrite the status. The forwarder reports EVERY failed app
     * dial (first failure at once, then once per 10 s); once the
     * VPN is up, one background app hitting a closed window wrote
     * "Konek gagal (WS gagal: ...)" over the good "Connected: ..."
     * status while the VPN icon was up and video played (phone
     * screenshot 2026-11-20 08:57:42). Failures belong in DialLog
     * once connected. While STARTING (no dial has succeeded yet)
     * the failure still shows, so a dead start is never silent
     * (v1.0.4).
     */
    @Synchronized
    fun reportDialStatus(msg: String) {
        val entry = runningEntry
        if (msg == "Connected") {
            state = State.RUNNING
            if (entry != null) status = "Connected: $entry"
        } else if (state != State.RUNNING) {
            status = if (entry != null) "$msg: $entry" else msg
        }
    }

    @Synchronized
    fun requestStop() {
        state = State.IDLE
        runningEntry = null
        status = "Stopped"
    }
}
