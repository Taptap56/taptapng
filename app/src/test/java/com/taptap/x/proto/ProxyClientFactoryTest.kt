package com.taptap.x.proto
import com.taptap.x.core.proto.*

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Factory mapping + rejection rules (no network).
 */
class ProxyClientFactoryTest {

    private fun item(type: ConfigType, network: String = "tcp", method: String = "") =
        ProfileItem(
            configType = type,
            address = "127.0.0.1", port = 1,
            uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            password = "secret", method = method, network = network,
        )

    @Test
    fun `factory maps each config type`() {
        assertTrue(ProxyClientFactory.create(item(ConfigType.VMESS)) is VmessClient)
        assertTrue(ProxyClientFactory.create(item(ConfigType.VLESS)) is VlessClient)
        assertTrue(ProxyClientFactory.create(item(ConfigType.TROJAN)) is TrojanClient)
        assertTrue(
            ProxyClientFactory.create(
                item(ConfigType.SHADOWSOCKS, method = "aes-256-gcm"),
            ) is SsClient,
        )
    }

    @Test
    fun `factory accepts blank network as tcp`() {
        assertTrue(ProxyClientFactory.create(item(ConfigType.VMESS, network = "")) is VmessClient)
    }

    @Test
    fun `factory accepts ws for vmess vless trojan`() {
        assertTrue(ProxyClientFactory.create(item(ConfigType.VMESS, network = "ws")) is VmessClient)
        assertTrue(ProxyClientFactory.create(item(ConfigType.VLESS, network = "ws")) is VlessClient)
        assertTrue(ProxyClientFactory.create(item(ConfigType.TROJAN, network = "ws")) is TrojanClient)
    }

    @Test
    fun `factory rejects unknown network`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(item(ConfigType.VMESS, network = "kcp"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(item(ConfigType.VLESS, network = "grpc"))
        }
    }

    @Test
    fun `factory rejects ws for shadowsocks`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(
                item(ConfigType.SHADOWSOCKS, network = "ws", method = "aes-256-gcm"),
            )
        }
    }

    @Test
    fun `factory rejects unknown ss method eagerly`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(
                item(ConfigType.SHADOWSOCKS, method = "2022-blake3-aes-128-gcm"),
            )
        }
    }

    @Test
    fun `factory rejects ssh`() {
        assertThrows(IllegalArgumentException::class.java) {
            ProxyClientFactory.create(item(ConfigType.SSH))
        }
    }
}
