package com.taptap.x.core

/**
 * Whether OUR TUN interface is currently up (v1.0.7).
 *
 * Single source of truth for "is there a VPN to bypass". The service
 * sets it true only after Builder.establish() succeeds and false in
 * teardownTunnel(). Dial / DNS / delay-test code consults it before
 * enforcing VpnService.protect():
 *
 * - Before establish() there is no VPN yet, and protect() returns
 *   false on this phone (nothing to bypass) — enforcing it made
 *   every v1.0.6 probe dial fail instantly with "protect() gagal"
 *   before any network I/O (DialLog taptapx-4.txt, 2026-11-20
 *   03:19). Pre-TUN dials therefore go direct.
 * - Once the TUN is up, protect MUST still be enforced — an
 *   unprotected dial would loop into the tunnel forever.
 * - v1.0.9: protect() ALSO returns false once the TUN is up on this
 *   phone (delay test "protect gagal", taptapx-6.txt 04:18; the
 *   forwarder then never dials at all, so no app traffic flows —
 *   "Vpn naik internet ga jalan", 2026-11-20 04:21). v2rayNG
 *   anticipates exactly this: its CoreVpnService disallows its own
 *   package from the VPN, and its PemicuManager notes the dial
 *   "bypasses even if protect() returns false". [appBypass] records
 *   whether our TUN was established with that disallow: while it is
 *   true, a refused protect is non-fatal (the socket bypasses at
 *   the routing level anyway); while false, a refused protect still
 *   fails fast as before.
 */
object TunnelState {
    @Volatile
    var up: Boolean = false

    /**
     * True only while the TUN is up AND our own package was
     * disallowed from the VPN at establish() time (see
     * TaptapVpnService.establishTunnel). Set false in
     * teardownTunnel(). Dial / DNS / delay-test code treats a
     * refused protect as non-fatal only while this is true.
     */
    @Volatile
    var appBypass: Boolean = false
}
