package com.taptap.x.data

import java.util.UUID

/** Supported proxy protocols (Phase 1: SSH is the working proof-of-concept;
 *  VMess/VLESS/Trojan/Shadowsocks land in later milestones). */
enum class ConfigType {
    SSH, VMESS, VLESS, TROJAN, SHADOWSOCKS
}

/**
 * One server profile. Field names mirror v2rayNG's ProfileItem so import
 * links (vmess://, vless://, ssh://, trojan://, ss://) map 1:1 later.
 * Nullable = inactive/absent (Gson reads old JSON as null).
 */
data class ProfileItem(
    val guid: String = UUID.randomUUID().toString(),
    var remarks: String = "",
    var configType: ConfigType = ConfigType.SSH,
    var address: String = "",
    var port: Int = 22,
    // SSH
    var username: String = "",
    var password: String = "",
    var privateKey: String = "",
    var sshUsePayload: Boolean = false,
    var sshPayload: String = "",
    var sshUseSlowdns: Boolean = false,
    // VMess / VLESS / Trojan / Shadowsocks
    var uuid: String = "",
    var alterId: Int = 0,
    var security: String = "auto",
    var network: String = "tcp",
    var host: String = "",
    var path: String = "",
    var tls: Boolean = false,
    var sni: String = "",
    var fingerprint: String = "",
    var alpn: String = "",
    var insecure: Boolean = false,
    // SlowDNS / DNSTT (Xray method)
    var dnsttEnabled: Boolean = false,
    var dnsttNS: String = "",
    var dnsttPubkey: String = "",
    var dnsttResolver: String = "",
    var dnsttRecordType: String = "null",
    // Onering (Xray method): bug domain hidden in TLS extension 0xff00,
    // standard SNI stays the real domain.
    var oneringEnabled: Boolean = false,
    var oneringBug: String = "",
    // Pemicu (built-in primer, Xray method): per-entry primer.
    // Empty domain = entry is NOT primed (no fallback to address).
    var pemicuEnabled: Boolean = false,
    var pemicuDomain: String = "",
    var pemicuPort: Int? = null, // null/empty = 443
    var pemicuInterval: Int? = null, // null = 15
) {
    /** Display name for the server list row. */
    fun displayName(): String = remarks.ifBlank { address }

    /** Protocol label for the server list row (orange, like v2rayNG). */
    fun typeLabel(): String = when (configType) {
        ConfigType.SSH -> "SSH"
        ConfigType.VMESS -> "VMess"
        ConfigType.VLESS -> "VLESS"
        ConfigType.TROJAN -> "Trojan"
        ConfigType.SHADOWSOCKS -> "SS"
    }
}
