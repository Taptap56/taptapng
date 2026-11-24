package com.taptap.ng.ui.main

/**
 * v1.0.32: pure gate for the dashboard tab — the yacd WebView only
 * runs while the VPN tunnel is actually up.
 *
 * Priority (first match wins):
 * 1. Clash API off -> [State.API_DISABLED] (the panel that already
 *    existed — the user can enable the API from there).
 * 2. API on but VPN not connected -> [State.VPN_OFF] (new static
 *    placeholder; no WebView is created or loaded).
 * 3. Both on -> [State.WEBVIEW] (dashboard as in v1.0.30).
 *
 * "VPN connected" means the tunnel state is RUNNING — NOT merely
 * STARTING. `VpnConnection.isRunning` is true from the moment a
 * start is requested, so it cannot be the predicate here; use
 * `VpnConnection.isConnected` / `TaptapVpnService.isConnected`
 * (state == RUNNING, i.e. the probe dial succeeded and the TUN is
 * up). A start that never completes, a failed start and a stopped
 * VPN all stay on the placeholder.
 *
 * Pure functions only, so this is unit-testable on the JVM (see
 * DashboardGateTest). The Activity owns the WebView lifecycle
 * (create / destroy); this object only decides which panel shows.
 */
object DashboardGate {

    enum class State { WEBVIEW, VPN_OFF, API_DISABLED }

    fun decide(vpnConnected: Boolean, clashApiEnabled: Boolean): State =
        when {
            !clashApiEnabled -> State.API_DISABLED
            !vpnConnected -> State.VPN_OFF
            else -> State.WEBVIEW
        }
}
