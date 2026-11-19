package com.taptap.x

import com.taptap.x.core.Base64Util
import com.taptap.x.core.LinkParser
import com.taptap.x.data.ConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LinkParserTest {

    @Test
    fun `base64 round trip incl url-safe without padding`() {
        val original = "hello world: vmess test ✓".toByteArray(Charsets.UTF_8)
        val encoded = Base64Util.encodeUrlSafe(original)
        assertFalse(encoded.contains('='))
        assertEquals(String(original, Charsets.UTF_8), Base64Util.decodeToString(encoded))
        // Standard alphabet + padding also decodes.
        assertEquals(
            String(original, Charsets.UTF_8),
            Base64Util.decodeToString(Base64Util.encode(original))
        )
        assertNull(Base64Util.decode("!!!not-base64!!!"))
    }

    @Test
    fun `vmess json link parses`() {
        val json = """{"v":"2","ps":"Zoom wc","add":"support.zoom.us","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","type":"none","host":"support.zoom.us.leaseweb4.svrkencang.web.id","path":"/","tls":"tls","sni":"support.zoom.us.leaseweb4.svrkencang.web.id","fp":"chrome","alpn":"h2"}"""
        val b64 = Base64Util.encodeUrlSafe(json.toByteArray(Charsets.UTF_8))
        val item = LinkParser.parse("vmess://$b64")
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.VMESS, item.configType)
        assertEquals("Zoom wc", item.remarks)
        assertEquals("support.zoom.us", item.address)
        assertEquals(443, item.port)
        assertEquals("11111111-2222-3333-4444-555555555555", item.uuid)
        assertEquals("ws", item.network)
        assertTrue(item.tls)
        assertEquals("chrome", item.fingerprint)
        assertEquals("h2", item.alpn)
    }

    @Test
    fun `vmess std query link parses`() {
        val item = LinkParser.parse(
            "vmess://11111111-2222-3333-4444-555555555555@1.2.3.4:443" +
                "?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fws#Test"
        )
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.VMESS, item.configType)
        assertEquals("1.2.3.4", item.address)
        assertEquals("Test", item.remarks)
        assertTrue(item.tls)
        assertEquals("example.com", item.sni)
        assertEquals("ws", item.network)
    }

    @Test
    fun `vmess with onering sni splits real and bug`() {
        val item = LinkParser.parse(
            "vmess://11111111-2222-3333-4444-555555555555@1.2.3.4:443" +
                "?security=tls&sni=onering%3Aexample.com%3Alive.iflix.com&type=ws#Onering"
        )
        assertNotNull(item)
        item!!
        assertTrue(item.oneringEnabled)
        assertEquals("example.com", item.sni)
        assertEquals("live.iflix.com", item.oneringBug)
    }

    @Test
    fun `vless link parses`() {
        val item = LinkParser.parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@leaseweb4.svrkencang.web.id:443" +
                "?encryption=none&security=tls&sni=live.iflix.com&type=ws&host=leaseweb4.svrkencang.web.id&path=%2F#VLESS-Test"
        )
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.VLESS, item.configType)
        assertEquals("leaseweb4.svrkencang.web.id", item.address)
        assertEquals("none", item.method)
        assertTrue(item.tls)
        assertEquals("live.iflix.com", item.sni)
        assertEquals("VLESS-Test", item.remarks)
    }

    @Test
    fun `vless without query is invalid`() {
        assertNull(LinkParser.parse("vless://uuid@host.example:443#NoQuery"))
    }

    @Test
    fun `trojan link parses`() {
        val item = LinkParser.parse(
            "trojan://secretpass@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftrojan#Trojan1"
        )
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.TROJAN, item.configType)
        assertEquals("secretpass", item.password)
        assertEquals("trojan.example.com", item.address)
        assertTrue(item.tls)
        assertEquals("ws", item.network)
    }

    @Test
    fun `ss sip002 link parses`() {
        val userInfo = Base64Util.encodeUrlSafe("aes-256-gcm:pass123".toByteArray(Charsets.UTF_8))
        val item = LinkParser.parse("ss://$userInfo@ss.example.com:8388#SS-Test")
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.SHADOWSOCKS, item.configType)
        assertEquals("aes-256-gcm", item.method)
        assertEquals("pass123", item.password)
        assertEquals("ss.example.com", item.address)
        assertEquals(8388, item.port)
    }

    @Test
    fun `ss legacy link parses`() {
        val encoded = Base64Util.encodeUrlSafe(
            "aes-128-cfb:mypassword@10.0.0.1:8388".toByteArray(Charsets.UTF_8)
        )
        val item = LinkParser.parse("ss://$encoded#Legacy")
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.SHADOWSOCKS, item.configType)
        assertEquals("aes-128-cfb", item.method)
        assertEquals("mypassword", item.password)
        assertEquals("10.0.0.1", item.address)
    }

    @Test
    fun `ssh link parses incl dnstt and methods`() {
        val item = LinkParser.parse(
            "ssh://user:pass%40123@ssh.example.com:22" +
                "?methods=payload%2Cslowdns&payload=GET%20%2F%20HTTP%2F1.1&dnstt_ns=ns.example.com&dnstt_pubkey=ABCDEF1234#SSH-Test"
        )
        assertNotNull(item)
        item!!
        assertEquals(ConfigType.SSH, item.configType)
        assertEquals("user", item.username)
        assertEquals("pass@123", item.password)
        assertEquals("ssh.example.com", item.address)
        assertEquals(22, item.port)
        assertTrue(item.sshUsePayload)
        assertTrue(item.sshUseSlowdns)
        assertFalse(item.sshUseTls)
        assertTrue(item.dnsttEnabled)
        assertEquals("ns.example.com", item.dnsttNS)
    }

    @Test
    fun `ssh link without port defaults to 22`() {
        val item = LinkParser.parse("ssh://user@ssh.example.com#NoPort")
        assertNotNull(item)
        assertEquals(22, item!!.port)
    }

    @Test
    fun `batch parses multiple lines and ignores junk`() {
        val text = """
            not a link
            vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@a.example:443?encryption=none&security=tls#One
            trojan://pw@b.example:443#Two
        """.trimIndent()
        val items = LinkParser.parseBatch(text)
        assertEquals(2, items.size)
        assertEquals("One", items[0].remarks)
        assertEquals("Two", items[1].remarks)
    }

    @Test
    fun `batch decodes base64 subscription blob`() {
        val blob = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@a.example:443?encryption=none&security=tls#Sub\n"
        val encoded = Base64Util.encode(blob.toByteArray(Charsets.UTF_8))
        val items = LinkParser.parseBatch(encoded)
        assertEquals(1, items.size)
        assertEquals("Sub", items[0].remarks)
    }

    @Test
    fun `toUri round trips vless and ssh`() {
        val vless = LinkParser.parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@a.example:443" +
                "?encryption=none&security=tls&sni=s.example&type=ws&host=h.example&path=%2Fp#RT"
        )!!
        val back = LinkParser.parse(LinkParser.toUri(vless)!!)
        assertNotNull(back)
        assertEquals(vless.address, back!!.address)
        assertEquals(vless.uuid, back.uuid)
        assertEquals(vless.sni, back.sni)
        assertEquals(vless.remarks, back.remarks)

        val ssh = LinkParser.parse("ssh://u:p@ssh.example:2222?methods=payload&payload=HELLO#S")!!
        val sshBack = LinkParser.parse(LinkParser.toUri(ssh)!!)
        assertNotNull(sshBack)
        assertEquals("u", sshBack!!.username)
        assertEquals(2222, sshBack.port)
        assertTrue(sshBack.sshUsePayload)
        assertEquals("HELLO", sshBack.sshPayload)
    }

    @Test
    fun `unknown scheme returns null`() {
        assertNull(LinkParser.parse("https://example.com"))
        assertNull(LinkParser.parse(""))
    }
}
