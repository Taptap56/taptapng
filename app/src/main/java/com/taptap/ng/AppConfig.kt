package com.taptap.ng

/** App-wide constants (Phase 1). */
object AppConfig {
    const val APP_NAME = "TaptapNG"
    const val VERSION_NAME = "1.0.2"

    /** Profiles are stored as one JSON file in the app's private files dir. */
    const val PROFILES_FILE = "profiles.json"

    /** SSH defaults (proof-of-concept protocol, Phase 1). */
    const val SSH_DEFAULT_PORT = 22
    const val SSH_CONNECT_TIMEOUT_MS = 10_000
    const val SSH_CHANNEL_TIMEOUT_MS = 10_000
    /** v1.0.30: server-alive interval for a long-lived SSH tunnel
     *  session (one session per VPN start, shared by all dials). */
    const val SSH_KEEPALIVE_MS = 30_000

    /** Pemicu (built-in primer, M5 v1.0.24): engine in-app
     *  (PemicuManager) — dial SSLSocket + protect(), prime segera
     *  saat konek + auto-prime tiap interval selama VPN jalan. */
    const val PEMICU_DEFAULT_PORT = 443
    const val PEMICU_DEFAULT_INTERVAL = 15
    const val PEMICU_MIN_INTERVAL = 5
    const val PEMICU_MAX_INTERVAL = 300
}
