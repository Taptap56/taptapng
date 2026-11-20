package com.taptap.x

/** App-wide constants (Phase 1). */
object AppConfig {
    const val APP_NAME = "TaptapX"
    const val VERSION_NAME = "1.0.18"

    /** Profiles are stored as one JSON file in the app's private files dir. */
    const val PROFILES_FILE = "profiles.json"

    /** SSH defaults (proof-of-concept protocol, Phase 1). */
    const val SSH_DEFAULT_PORT = 22
    const val SSH_CONNECT_TIMEOUT_MS = 10_000
    const val SSH_CHANNEL_TIMEOUT_MS = 10_000

    /** Pemicu (built-in primer) defaults — engine lands in a later milestone. */
    const val PEMICU_DEFAULT_PORT = 443
    const val PEMICU_DEFAULT_INTERVAL = 15
    const val PEMICU_MIN_INTERVAL = 5
    const val PEMICU_MAX_INTERVAL = 300
}
