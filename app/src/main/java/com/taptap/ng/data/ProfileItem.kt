package com.taptap.ng.data

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
    var group: String = "",
    var configType: ConfigType = ConfigType.SSH,
    var address: String = "",
    var port: Int = 22,
    // SSH
    var username: String = "",
    var password: String = "",
    var privateKey: String = "",
    var sshUsePayload: Boolean = false,
    var sshPayload: String = "",
    var sshRemoteProxy: String = "",
    var sshUseEnhanced: Boolean = false,
    var sshUseTls: Boolean = false,
    var sshSni: String = "",
    var sshInsecure: Boolean = false,
    var sshUseSlowdns: Boolean = false,
    // VMess / VLESS / Trojan / Shadowsocks
    var uuid: String = "",
    var alterId: Int = 0,
    var security: String = "auto",
    var method: String = "", // SS cipher / VLESS encryption ("none")
    var network: String = "tcp",
    var host: String = "",
    var path: String = "",
    var tls: Boolean = false,
    // Stream security (v2rayNG "TLS" dropdown): "", "tls" or "reality".
    // `tls` above stays synced (true when tls/reality) for the M2 engine.
    var streamSecurity: String = "",
    var sni: String = "",
    var fingerprint: String = "",
    var alpn: String = "",
    var insecure: Boolean = false,
    // v2rayNG extras (M2 engine may ignore them; they are stored so
    // v2rayNG <-> TaptapNG copy round-trips). Missing in old JSON ->
    // Gson uses the defaults below (see ProfileItemDefaultsTest).
    var finalMask: String = "",
    var browserDialerMode: String = "", // "", "OkHttp", "WebView" (WS/XHTTP only)
    var echConfigList: String = "",
    var verifyPeerCertByName: String = "",
    var pinnedCA256: String = "", // certificate fingerprint (SHA-256)
    var realityPublicKey: String = "",
    var realityShortId: String = "",
    var realitySpiderX: String = "",
    var realityMldsa65Verify: String = "",
    var headerType: String = "none", // TCP/KCP "head type"
    var mode: String = "", // gRPC mode: "gun" / "multi"
    var xhttpMode: String = "", // "auto" / "packet-up" / "stream-up" / "stream-one"
    var authority: String = "", // gRPC authority (host field for gRPC)
    var serviceName: String = "", // gRPC serviceName (path field for gRPC)
    var xhttpExtra: String = "", // raw JSON { XHTTPObject }
    var seed: String = "", // KCP seed (path field for KCP)
    var kcpMtu: String = "",
    var kcpTti: String = "",
    var flow: String = "", // VLESS flow
    var encryption: String = "none", // VLESS encryption ("none"); SS uses `method`
    // SSH extras
    var sshSniVersion: String = "default", // default/tls1/tls1.1/tls1.2/tls1.3
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
    // Payload + Proxy ala XVEON 6.1 (Xray method, v1.0.10):
    // HTTP CONNECT proxy (proxyHost = domain bug, dukung
    // [rotate=bug1;bug2]) + template payload custom yang dikirim
    // ke proxy sebelum CONNECT dan dipakai lagi sebagai WS
    // handshake. Semua default mati/kosong — entry lama tanpa
    // field ini (Gson) jalan persis seperti v1.0.9.
    var xrayUsePayload: Boolean = false,
    var xrayPayload: String = "",
    var proxyEnabled: Boolean = false,
    var proxyHost: String = "",
    var proxyPort: Int? = null, // null/empty = 80
) {
    /** Display name for the server list row. */
    fun displayName(): String = remarks.ifBlank { address }

    /** Group display name; the empty group is "Default" (v2rayNG). */
    fun groupName(): String = group.ifBlank { "Default" }

    /** Type + transport description for the server list row. */
    fun typeDescription(): String {
        val base = typeLabel()
        if (configType == ConfigType.SSH) return base
        val parts = mutableListOf(base)
        if (network.isNotBlank() && network != "tcp") parts += network
        if (tls) parts += "TLS"
        if (dnsttEnabled) parts += "SlowDNS"
        if (oneringEnabled) parts += "Onering"
        if (proxyEnabled) parts += "Proxy"
        return parts.joinToString(" · ")
    }

    /** Protocol label for the server list row (orange, like v2rayNG). */
    fun typeLabel(): String = when (configType) {
        ConfigType.SSH -> "SSH"
        ConfigType.VMESS -> "VMess"
        ConfigType.VLESS -> "VLESS"
        ConfigType.TROJAN -> "Trojan"
        ConfigType.SHADOWSOCKS -> "SS"
    }
}
