package com.taptap.ng.core.proto

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem

/**
 * Factory for the M2 in-app protocol clients (VMess/VLESS/Trojan/
 * Shadowsocks). v1.0.30: SSH is built here too — [SshProxyClient]
 * (one shared JSch session, one direct-tcpip channel per dial).
 *
 * Rules:
 * - network must be tcp or ws (blank = tcp). Anything else throws.
 * - Shadowsocks only runs over raw TCP: network ws (or tls) on an SS
 *   profile throws instead of being silently ignored.
 * - Unknown configType / SS method / VMess security throw
 *   IllegalArgumentException with a clear message.
 */
object ProxyClientFactory {

    /**
     * v1.0.5 (kelompok D): [muxConfig] diteruskan ke VmessClient /
     * VlessClient (default OFF — perilaku lama). Trojan/SS/SSH
     * mengabaikannya (mux hanya untuk VMess/VLESS).
     */
    fun create(item: ProfileItem, muxConfig: MuxConfig = MuxConfig.DISABLED): ProxyClient {
        val network = item.network.ifBlank { "tcp" }.lowercase()
        if (network != "tcp" && network != "ws") {
            throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws)")
        }
        return when (item.configType) {
            ConfigType.VMESS -> VmessClient(item, muxConfig = muxConfig)
            ConfigType.VLESS -> VlessClient(item, muxConfig = muxConfig)
            ConfigType.TROJAN -> TrojanClient(item)
            ConfigType.SHADOWSOCKS -> {
                if (network != "tcp") {
                    throw IllegalArgumentException(
                        "Shadowsocks hanya jalan di TCP (network ws tidak didukung)",
                    )
                }
                // Validate the method eagerly so a bad profile fails
                // at creation time, not on first dial.
                SsCrypto.resolveCipher(item.method)
                SsClient(item)
            }
            ConfigType.SSH -> SshProxyClient(item)
        }
    }
}
