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
 */
object TunnelState {
    @Volatile
    var up: Boolean = false
}
