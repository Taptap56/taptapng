package com.taptap.ng.service

/**
 * LAN bypass for the TUN (v1.0.5, group A — v2rayNG "Bypass LAN").
 *
 * v2rayNG implements this in xray routing rules; TaptapNG has no
 * core, so it is implemented at the TUN layer instead: when bypass
 * is on, the Builder does NOT get the catch-all 0.0.0.0/0 route —
 * it gets the complement of the LAN ranges instead, so traffic to
 * a LAN address never enters the TUN and goes out the physical
 * interface directly. When bypass is off the single 0.0.0.0/0
 * route is used, exactly like v1.0.4.
 *
 * LAN ranges excluded (RFC 1918 + link-local): 10.0.0.0/8,
 * 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16. "Bypass mainland
 * China" (stored value "2") is NOT implemented — it needs a
 * geoip database TaptapNG does not bundle; it behaves like off
 * (full tunnel) and is documented as such in the Settings UI.
 * Pure IPv4 math, no Android APIs — unit-testable on the JVM.
 */
object LanBypass {

    data class Route(val address: String, val prefixLength: Int) {
        override fun toString(): String = "$address/$prefixLength"
    }

    /** Stored vpnBypassLan value "1" = bypass LAN (v2rayNG default). */
    fun bypassEnabled(value: String): Boolean = value.trim() == "1"

    /**
     * Routes the TUN Builder should add: the public-space
     * complement of the LAN ranges when bypass is on, otherwise
     * the single catch-all route (v1.0.4 behaviour).
     */
    fun tunnelRoutes(bypassLan: String): List<Route> =
        if (bypassEnabled(bypassLan)) PUBLIC_ROUTES else listOf(Route("0.0.0.0", 0))

    /** True when [ip] is a LAN/link-local address (never tunnelled when bypass is on). */
    fun isLanAddress(ip: String): Boolean {
        val n = parseIpv4(ip) ?: return false
        return isIn(n, "10.0.0.0", 8) ||
            isIn(n, "172.16.0.0", 12) ||
            isIn(n, "192.168.0.0", 16) ||
            isIn(n, "169.254.0.0", 16)
    }

    /** True when [ip] is covered by [routes] (used by tests; the Builder does this at establish). */
    fun isCoveredBy(routes: List<Route>, ip: String): Boolean {
        val n = parseIpv4(ip) ?: return false
        return routes.any { isIn(n, it.address, it.prefixLength) }
    }

    private fun isIn(ip: Long, network: String, prefix: Int): Boolean {
        val net = parseIpv4(network) ?: return false
        if (prefix == 0) return true
        val mask = -1L shl (32 - prefix)
        return (ip and mask) == (net and mask)
    }

    /** "a.b.c.d" -> unsigned 32-bit value, or null when not an IPv4 literal. */
    fun parseIpv4(ip: String): Long? {
        val parts = ip.trim().split(".")
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255 || part != n.toString()) return null
            value = (value shl 8) or n.toLong()
        }
        return value
    }

    /**
     * 0.0.0.0/0 minus 10/8, 172.16/12, 192.168/16, 169.254/16 —
     * the exact complement, verified by LanBypassTest (every LAN
     * address uncovered, sampled public addresses covered, no two
     * routes overlap).
     */
    val PUBLIC_ROUTES: List<Route> = listOf(
        Route("0.0.0.0", 7),
        Route("2.0.0.0", 7),
        Route("4.0.0.0", 6),
        Route("8.0.0.0", 7),
        Route("11.0.0.0", 8),
        Route("12.0.0.0", 6),
        Route("16.0.0.0", 4),
        Route("32.0.0.0", 3),
        Route("64.0.0.0", 2),
        Route("128.0.0.0", 3),
        Route("160.0.0.0", 5),
        Route("168.0.0.0", 8),
        Route("169.0.0.0", 9),
        Route("169.128.0.0", 10),
        Route("169.192.0.0", 11),
        Route("169.224.0.0", 12),
        Route("169.240.0.0", 13),
        Route("169.248.0.0", 14),
        Route("169.252.0.0", 15),
        Route("169.255.0.0", 16),
        Route("170.0.0.0", 7),
        Route("172.0.0.0", 12),
        Route("172.32.0.0", 11),
        Route("172.64.0.0", 10),
        Route("172.128.0.0", 9),
        Route("173.0.0.0", 8),
        Route("174.0.0.0", 7),
        Route("176.0.0.0", 4),
        Route("192.0.0.0", 9),
        Route("192.128.0.0", 11),
        Route("192.160.0.0", 13),
        Route("192.169.0.0", 16),
        Route("192.170.0.0", 15),
        Route("192.172.0.0", 14),
        Route("192.176.0.0", 12),
        Route("192.192.0.0", 10),
        Route("193.0.0.0", 8),
        Route("194.0.0.0", 7),
        Route("196.0.0.0", 6),
        Route("200.0.0.0", 5),
        Route("208.0.0.0", 4),
        Route("224.0.0.0", 3),
    )
}
