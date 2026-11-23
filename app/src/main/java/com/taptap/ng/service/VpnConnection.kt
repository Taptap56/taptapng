package com.taptap.ng.service

import com.taptap.ng.data.ProfileItem

/**
 * Human-readable label for the entry being dialled: remark plus
 * address, so two entries that share a remark ("Zoom onering" on
 * both leaseweb4 and support.zoom.us) are never confused in the
 * "Connecting:" text or a failure message. A blank remark falls
 * back to the bare address.
 */
fun dialLabel(item: ProfileItem): String {
    val remarks = item.displayName()
    return if (remarks == item.address) item.address else "$remarks (${item.address})"
}

/**
 * Short label for the "Connected:" status bar (v1.0.7): the remark
 * only, without the " (address)" suffix [dialLabel] appends. The
 * full label stays in [VpnConnection.runningEntry] — the
 * "Connecting:" text, failure messages and DialLog keep the
 * address, so two entries sharing a remark are still told apart
 * there. Only the Connected status drops it (user order
 * 2026-11-21: "Connected: iflix cloudfront", not "... (front.wetv.vip)").
 *
 * [dialLabel] appends the address as the FINAL parenthesised group,
 * so only the last group is stripped — a remark like "Taptap WS
 * (CDN) TLS" keeps its own parentheses, and a bare address (no
 * remark) is returned unchanged.
 */
fun connectedLabel(label: String): String {
    return if (label.endsWith(")") && label.contains(" (")) {
        label.substringBeforeLast(" (")
    } else {
        label
    }
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
        // v1.0.7: the status bar shows the remark only, without the
        // " (address)" suffix — "Connected: iflix cloudfront".
        status = "Connected: ${connectedLabel(label)}"
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
            // v1.0.7: remark only, like reportConnected.
            if (entry != null) status = "Connected: ${connectedLabel(entry)}"
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

    /**
     * Live switch (v1.0.19, Issue 2): move the RUNNING tunnel to
     * [label] WITHOUT a restart. The state stays RUNNING and only
     * the entry label + "Connected:" status change — the tunnel,
     * the forwarder and the route to existing connections are
     * untouched (existing connections keep flowing through the
     * old server until they close, like Clash). Returns false
     * when the tunnel is not RUNNING (IDLE / STARTING / FAILED):
     * a switch mid-start would race the start worker, whose
     * reportConnected would overwrite the new label with the
     * old entry's — the caller must not change the routing
     * selection then either.
     */
    @Synchronized
    fun switchEntry(label: String): Boolean {
        if (state != State.RUNNING) return false
        runningEntry = label
        status = "Connected: ${connectedLabel(label)}"
        return true
    }
}
