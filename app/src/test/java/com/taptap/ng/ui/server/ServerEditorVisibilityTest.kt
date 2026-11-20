package com.taptap.ng.ui.server

import com.taptap.ng.data.ConfigType
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.31: the Xray method section (SlowDNS / Onering / Pemicu) is
 * hidden while an SSH entry is being edited — SSH gets its Pemicu
 * chip in the SSH method row instead. The rule is a pure function
 * (ServerEditorActivity.isXrayMethodVisible) so it can be asserted
 * on the JVM; the chip mirroring itself is Views code and is covered
 * by :app:assembleRelease + the phone check.
 */
class ServerEditorVisibilityTest {

    @Test
    fun `xray method hidden for ssh`() {
        assertFalse(ServerEditorActivity.isXrayMethodVisible(ConfigType.SSH))
    }

    @Test
    fun `xray method shown for vmess`() {
        assertTrue(ServerEditorActivity.isXrayMethodVisible(ConfigType.VMESS))
    }

    @Test
    fun `xray method shown for vless`() {
        assertTrue(ServerEditorActivity.isXrayMethodVisible(ConfigType.VLESS))
    }

    @Test
    fun `xray method shown for trojan`() {
        assertTrue(ServerEditorActivity.isXrayMethodVisible(ConfigType.TROJAN))
    }

    @Test
    fun `xray method shown for shadowsocks`() {
        assertTrue(ServerEditorActivity.isXrayMethodVisible(ConfigType.SHADOWSOCKS))
    }
}
