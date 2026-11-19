package com.taptap.x.core

import com.google.gson.JsonParser
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.net.URI

/**
 * Share-link parser, mirroring v2rayNG's fmt/ parsers (VmessFmt,
 * VlessFmt, TrojanFmt, ShadowsocksFmt, SshFmt) but written from
 * scratch for TaptapX's [ProfileItem]. Pure Kotlin (no Android APIs)
 * so it is covered by JVM unit tests ([LinkParserTest]).
 *
 * Supported: vmess:// (base64-JSON + std query form), vless://,
 * trojan://, ss:// (SIP002 + legacy), ssh:// (with the DNSTT /
 * methods query parameters).
 *
 * TaptapX extensions carried in the query string (round-tripped by
 * [toUri]): dnstt_ns / dnstt_pubkey / dnstt_resolver /
 * dnstt_record_type, onering via sni=onering:<real>:<bug>.
 * Pemicu is NOT carried in links (v2rayNG has no pemicu_* keys).
 */
object LinkParser {

    fun parse(text: String): ProfileItem? {
        val str = text.trim()
        return when {
            str.startsWith("vmess://", ignoreCase = true) -> parseVmess(str)
            str.startsWith("vless://", ignoreCase = true) -> parseVless(str)
            str.startsWith("trojan://", ignoreCase = true) -> parseTrojan(str)
            str.startsWith("ss://", ignoreCase = true) -> parseSs(str)
            str.startsWith("ssh://", ignoreCase = true) -> parseSsh(str)
            str.startsWith("{") -> parseVmessJson(str)
            else -> null
        }
    }

    /**
     * Parse a blob of text (clipboard / file / QR content) into profiles.
     * Lines are tried one by one; if no link is found, the whole blob is
     * tried as one base64 document (subscription-style) and re-parsed.
     */
    fun parseBatch(text: String): List<ProfileItem> {
        val out = mutableListOf<ProfileItem>()
        for (line in text.lines()) {
            parse(line)?.let { out += it }
        }
        if (out.isEmpty()) {
            val decoded = Base64Util.decodeToString(text.trim())
            if (decoded != null && decoded.contains("://")) {
                for (line in decoded.lines()) {
                    parse(line)?.let { out += it }
                }
            }
        }
        return out
    }

    // ---- VMess ----

    private fun parseVmess(str: String): ProfileItem? {
        val body = str.substring("vmess://".length)
        // Std form: vmess://uuid@host:port?query (a '?' before any '#'
        // fragment; v2rayNG std links can have a single query param).
        if (body.contains('@') && body.substringBefore('#').contains('?')) {
            return parseVmessStd(str)
        }
        val json = Base64Util.decodeToString(body) ?: return null
        return parseVmessJson(json)
    }

    private fun parseVmessStd(str: String): ProfileItem? {
        val uri = safeUri(str) ?: return null
        val q = queryParams(uri)
        val item = ProfileItem(configType = ConfigType.VMESS)
        item.uuid = percentDecode(uri.rawUserInfo ?: "")
        item.address = uri.host ?: return null
        item.port = if (uri.port > 0) uri.port else 443
        item.remarks = percentDecode(uri.rawFragment ?: "").ifEmpty { "none" }
        applyCommonQuery(item, q)
        // std-form "security" is the stream security (tls/reality/none);
        // the VMess cipher only comes from a cipher value.
        val cipher = q["security"]
        item.security = if (cipher != null && cipher in VMESS_CIPHERS) cipher else "auto"
        return item
    }

    internal fun parseVmessJson(json: String): ProfileItem? {
        val obj = runCatching { JsonParser.parseString(json).asJsonObject }.getOrNull()
            ?: return null
        val add = obj.str("add") ?: return null
        val port = obj.str("port") ?: return null
        val id = obj.str("id") ?: return null
        val net = obj.str("net") ?: return null
        val item = ProfileItem(configType = ConfigType.VMESS)
        item.remarks = obj.str("ps") ?: ""
        item.address = add
        item.port = port.toIntOrNull() ?: return null
        item.uuid = id
        item.alterId = obj.str("aid")?.toIntOrNull() ?: 0
        item.security = obj.str("scy")?.ifBlank { "auto" } ?: "auto"
        item.network = net.ifBlank { "tcp" }
        item.host = obj.str("host") ?: ""
        item.path = obj.str("path") ?: ""
        item.headerType = obj.str("type")?.ifBlank { "none" } ?: "none"
        // v2rayNG JSON mapping: KCP carries the seed in "path",
        // gRPC carries mode in "type", serviceName in "path",
        // authority in "host".
        if (item.network == "kcp") {
            item.seed = item.path
        }
        if (item.network == "grpc") {
            item.mode = item.headerType
            item.serviceName = item.path
            item.authority = item.host
        }
        when (obj.str("tls")) {
            "tls" -> {
                item.tls = true
                item.streamSecurity = "tls"
            }
            "reality" -> {
                item.tls = true
                item.streamSecurity = "reality"
            }
            else -> {
                item.tls = false
                item.streamSecurity = ""
            }
        }
        val sni = obj.str("sni") ?: ""
        applyOneringSni(item, sni)
        item.fingerprint = obj.str("fp") ?: ""
        item.alpn = obj.str("alpn") ?: ""
        item.finalMask = obj.str("fm") ?: ""
        item.verifyPeerCertByName = obj.str("vcn") ?: ""
        item.pinnedCA256 = obj.str("pcs") ?: ""
        item.echConfigList = obj.str("ech") ?: ""
        item.realityPublicKey = obj.str("pbk") ?: ""
        item.realityShortId = obj.str("sid") ?: ""
        item.realitySpiderX = obj.str("spx") ?: ""
        item.realityMldsa65Verify = obj.str("pqv") ?: ""
        applyExtensionJson(item, obj)
        return item
    }

    /** TaptapX extensions carried as extra keys in the vmess JSON
     *  (v2rayNG ignores unknown JSON keys, so the link still imports
     *  there — the extensions are just dropped in that direction). */
    private fun applyExtensionJson(item: ProfileItem, obj: com.google.gson.JsonObject) {
        item.dnsttNS = obj.str("dnstt_ns") ?: ""
        item.dnsttPubkey = obj.str("dnstt_pubkey") ?: ""
        item.dnsttResolver = obj.str("dnstt_resolver") ?: ""
        item.dnsttRecordType = obj.str("dnstt_record_type") ?: "null"
        if (item.dnsttNS.isNotBlank() && item.dnsttPubkey.isNotBlank()) {
            item.dnsttEnabled = true
        }
        // Pemicu deliberately NOT carried in links: v2rayNG has no
        // pemicu_* keys, so a shared link must never contain them.
    }

    // ---- VLESS / Trojan ----

    private fun parseVless(str: String): ProfileItem? {
        val uri = safeUri(str) ?: return null
        if (uri.rawQuery.isNullOrEmpty()) return null
        val q = queryParams(uri)
        val item = ProfileItem(configType = ConfigType.VLESS)
        item.uuid = percentDecode(uri.rawUserInfo ?: "")
        item.address = uri.host ?: return null
        item.port = if (uri.port > 0) uri.port else 443
        item.remarks = percentDecode(uri.rawFragment ?: "").ifEmpty { "none" }
        item.encryption = q["encryption"] ?: "none"
        item.method = item.encryption // legacy mirror (older builds read method)
        applyCommonQuery(item, q)
        return item
    }

    private fun parseTrojan(str: String): ProfileItem {
        val uri = safeUri(str) ?: return ProfileItem(configType = ConfigType.TROJAN)
        val q = queryParams(uri)
        val item = ProfileItem(configType = ConfigType.TROJAN)
        item.password = percentDecode(uri.rawUserInfo ?: "")
        item.address = uri.host ?: ""
        item.port = if (uri.port > 0) uri.port else 443
        item.remarks = percentDecode(uri.rawFragment ?: "").ifEmpty { "none" }
        if (uri.rawQuery.isNullOrEmpty()) {
            item.network = "tcp"
            item.tls = true
            item.streamSecurity = "tls"
        } else {
            applyCommonQuery(item, q)
            // Trojan defaults to TLS when the link carries no security.
            if (!q.containsKey("security")) {
                item.tls = true
                item.streamSecurity = "tls"
            }
        }
        return item
    }

    // ---- Shadowsocks ----

    private fun parseSs(str: String): ProfileItem? =
        parseSsSip002(str) ?: parseSsLegacy(str)

    private fun parseSsSip002(str: String): ProfileItem? {
        val uri = safeUri(str) ?: return null
        if (uri.host.isNullOrEmpty() || uri.port <= 0) return null
        if (uri.rawUserInfo.isNullOrEmpty()) return null
        val item = ProfileItem(configType = ConfigType.SHADOWSOCKS)
        item.remarks = percentDecode(uri.rawFragment ?: "").ifEmpty { "none" }
        item.address = uri.host
        item.port = uri.port
        val userInfo = if (uri.rawUserInfo.contains(":")) {
            uri.rawUserInfo
        } else {
            Base64Util.decodeToString(uri.rawUserInfo) ?: return null
        }
        val parts = userInfo.split(":", limit = 2)
        if (parts.size != 2) return null
        item.method = percentDecode(parts[0])
        item.password = percentDecode(parts[1])
        val q = queryParams(uri)
        q["plugin"]?.let { plugin ->
            if (plugin.contains("obfs=http")) {
                val kv = plugin.split(";").mapNotNull {
                    val kvParts = it.split("=", limit = 2)
                    if (kvParts.size == 2) kvParts[0] to kvParts[1] else null
                }.toMap()
                item.network = "tcp"
                item.host = kv["obfs-host"] ?: ""
                item.path = kv["path"] ?: ""
            }
        }
        applyExtensionQuery(item, q)
        return item
    }

    private fun parseSsLegacy(str: String): ProfileItem? {
        var body = str.substring("ss://".length)
        val item = ProfileItem(configType = ConfigType.SHADOWSOCKS)
        val hash = body.indexOf('#')
        if (hash > 0) {
            item.remarks = runCatching {
                percentDecode(body.substring(hash + 1))
            }.getOrDefault("")
            body = body.substring(0, hash)
        }
        val at = body.indexOf('@')
        if (at > 0) {
            body = (Base64Util.decodeToString(body.substring(0, at)) ?: return null) +
                body.substring(at)
        } else {
            body = Base64Util.decodeToString(body) ?: return null
        }
        val m = Regex("^(.+?):(.*)@(.+?):(\\d+)/?$").matchEntire(body) ?: return null
        item.method = m.groupValues[1].lowercase()
        item.password = m.groupValues[2]
        item.address = m.groupValues[3].removeSurrounding("[", "]")
        item.port = m.groupValues[4].toIntOrNull() ?: return null
        return item
    }

    // ---- SSH ----

    private fun parseSsh(str: String): ProfileItem? {
        val uri = safeUri(str) ?: return null
        if (uri.host.isNullOrBlank()) return null
        val item = ProfileItem(configType = ConfigType.SSH)
        val userInfo = uri.rawUserInfo
        if (!userInfo.isNullOrEmpty()) {
            val idx = userInfo.indexOf(':')
            if (idx >= 0) {
                item.username = percentDecode(userInfo.substring(0, idx))
                item.password = percentDecode(userInfo.substring(idx + 1))
            } else {
                item.username = percentDecode(userInfo)
            }
        }
        item.address = uri.host
        item.port = if (uri.port > 0) uri.port else 22
        item.remarks = percentDecode(uri.rawFragment ?: "").ifEmpty { "none" }
        val q = queryParams(uri)
        applyExtensionQuery(item, q)
        if (item.dnsttEnabled) item.sshUseSlowdns = true
        item.privateKey = q["private_key"] ?: ""
        item.sshSniVersion = q["sni_version"] ?: "default"
        item.sshPayload = q["payload"] ?: ""
        item.sshRemoteProxy = q["remote_proxy"] ?: ""
        item.sshSni = q["sni"] ?: ""
        item.sshInsecure = q["insecure"] == "1"
        val methods = q["methods"]?.split(",")?.map { it.trim().lowercase() }
            ?.filter { it.isNotEmpty() }?.toSet().orEmpty()
        if (methods.isNotEmpty()) {
            item.sshUsePayload = methods.contains("payload")
            item.sshUseEnhanced = methods.contains("enhanced")
            item.sshUseTls = methods.contains("tls")
            item.sshUseSlowdns = methods.contains("slowdns")
        } else {
            when (q["method"]?.trim()?.lowercase()) {
                "payload" -> item.sshUsePayload = true
                "enhanced" -> item.sshUseEnhanced = true
                "tls" -> item.sshUseTls = true
                "slowdns" -> item.sshUseSlowdns = true
            }
        }
        return item
    }

    // ---- Shared query handling (v2rayNG FmtBase.getItemFormQuery) ----

    private fun applyCommonQuery(item: ProfileItem, q: Map<String, String>) {
        item.network = q["type"] ?: "tcp"
        item.host = q["host"] ?: ""
        item.path = q["path"] ?: ""
        // Stream security: only "tls"/"reality" survive, anything else
        // (incl. "none" or a missing key) means no stream security.
        val security = q["security"]
        item.streamSecurity = if (security == "tls" || security == "reality") security else ""
        item.tls = item.streamSecurity.isNotBlank()
        item.insecure = q["insecure"] == "1" || q["allowInsecure"] == "1" ||
            q["allow_insecure"] == "1"
        applyOneringSni(item, q["sni"] ?: "")
        item.fingerprint = q["fp"] ?: ""
        item.alpn = q["alpn"] ?: ""
        item.echConfigList = q["ech"] ?: ""
        item.verifyPeerCertByName = q["vcn"] ?: ""
        item.pinnedCA256 = q["pcs"] ?: ""
        item.realityPublicKey = q["pbk"] ?: ""
        item.realityShortId = q["sid"] ?: ""
        item.realitySpiderX = q["spx"] ?: ""
        item.realityMldsa65Verify = q["pqv"] ?: ""
        item.finalMask = q["fm"] ?: ""
        item.flow = q["flow"] ?: ""
        item.headerType = q["headerType"]?.ifBlank { "none" } ?: "none"
        item.mode = q["mode"] ?: ""
        item.xhttpExtra = q["extra"] ?: ""
        item.seed = q["seed"] ?: ""
        item.authority = q["authority"] ?: ""
        item.serviceName = q["serviceName"] ?: ""
        item.kcpMtu = q["mtu"] ?: ""
        item.kcpTti = q["tti"] ?: ""
        applyExtensionQuery(item, q)
    }

    /** TaptapX extensions carried in the query string (round-tripped
     *  by [toUri]). v2rayNG ignores unknown query params, so a link
     *  carrying them still imports there — the extensions are just
     *  dropped in that direction. */
    private fun applyExtensionQuery(item: ProfileItem, q: Map<String, String>) {
        item.dnsttNS = q["dnstt_ns"] ?: ""
        item.dnsttPubkey = q["dnstt_pubkey"] ?: ""
        item.dnsttResolver = q["dnstt_resolver"] ?: ""
        item.dnsttRecordType = q["dnstt_record_type"] ?: "null"
        if (item.dnsttNS.isNotBlank() && item.dnsttPubkey.isNotBlank()) {
            item.dnsttEnabled = true
        }
        // Pemicu deliberately NOT carried in links: v2rayNG has no
        // pemicu_* keys, so a shared link must never contain them.
    }

    /** sni=onering:<real>:<bug> splits into real SNI + Onering on. */
    fun applyOneringSni(item: ProfileItem, sni: String) {
        val parsed = parseOneringSni(sni)
        if (parsed != null) {
            item.sni = parsed.first
            item.oneringEnabled = true
            item.oneringBug = parsed.second
        } else {
            item.sni = sni
        }
    }

    fun parseOneringSni(sni: String?): Pair<String, String>? {
        if (sni.isNullOrBlank() || !sni.startsWith("onering:")) return null
        val rest = sni.removePrefix("onering:")
        val idx = rest.indexOf(':')
        if (idx <= 0 || idx == rest.length - 1) return null
        return rest.substring(0, idx) to rest.substring(idx + 1)
    }

    // ---- toUri (share / export) ----

    fun toUri(item: ProfileItem): String? = when (item.configType) {
        ConfigType.VMESS -> toVmessUri(item)
        ConfigType.VLESS -> toVlessUri(item)
        ConfigType.TROJAN -> toTrojanUri(item)
        ConfigType.SHADOWSOCKS -> toSsUri(item)
        ConfigType.SSH -> toSshUri(item)
    }

    /** VMess cipher values (the editor's Security dropdown). */
    private val VMESS_CIPHERS = setOf("chacha20-poly1305", "aes-128-gcm", "auto", "none", "zero")

    private fun commonQuery(item: ProfileItem): LinkedHashMap<String, String> {
        val q = LinkedHashMap<String, String>()
        if (item.network.isNotBlank()) q["type"] = item.network
        // Stream security is always written; empty means "none".
        q["security"] = item.streamSecurity.ifBlank { "none" }
        if (item.sni.isNotBlank()) {
            q["sni"] = if (item.oneringEnabled && item.oneringBug.isNotBlank()) {
                "onering:${item.sni}:${item.oneringBug}"
            } else {
                item.sni
            }
        }
        if (item.fingerprint.isNotBlank()) q["fp"] = item.fingerprint
        if (item.alpn.isNotBlank()) q["alpn"] = item.alpn
        if (item.echConfigList.isNotBlank()) q["ech"] = item.echConfigList
        if (item.verifyPeerCertByName.isNotBlank()) q["vcn"] = item.verifyPeerCertByName
        if (item.pinnedCA256.isNotBlank()) q["pcs"] = item.pinnedCA256
        if (item.realityPublicKey.isNotBlank()) q["pbk"] = item.realityPublicKey
        if (item.realityShortId.isNotBlank()) q["sid"] = item.realityShortId
        if (item.realitySpiderX.isNotBlank()) q["spx"] = item.realitySpiderX
        if (item.realityMldsa65Verify.isNotBlank()) q["pqv"] = item.realityMldsa65Verify
        if (item.host.isNotBlank()) q["host"] = item.host
        if (item.path.isNotBlank()) q["path"] = item.path
        if (item.network == "grpc") {
            if (item.mode.isNotBlank()) q["mode"] = item.mode
            if (item.authority.isNotBlank()) q["authority"] = item.authority
            if (item.serviceName.isNotBlank()) q["serviceName"] = item.serviceName
        }
        if (item.network == "xhttp" && item.xhttpExtra.isNotBlank()) q["extra"] = item.xhttpExtra
        if (item.network == "kcp") {
            if (item.seed.isNotBlank()) q["seed"] = item.seed
            if (item.kcpMtu.isNotBlank()) q["mtu"] = item.kcpMtu
            if (item.kcpTti.isNotBlank()) q["tti"] = item.kcpTti
        }
        q["headerType"] = item.headerType.ifBlank { "none" }
        if (item.finalMask.isNotBlank()) q["fm"] = item.finalMask
        if (item.streamSecurity == "tls") {
            // Both keys, same value (v2rayNG reads either).
            q["insecure"] = if (item.insecure) "1" else "0"
            q["allowInsecure"] = if (item.insecure) "1" else "0"
        }
        if (item.dnsttEnabled) {
            if (item.dnsttNS.isNotBlank()) q["dnstt_ns"] = item.dnsttNS
            if (item.dnsttPubkey.isNotBlank()) q["dnstt_pubkey"] = item.dnsttPubkey
            if (item.dnsttResolver.isNotBlank()) q["dnstt_resolver"] = item.dnsttResolver
            q["dnstt_record_type"] = item.dnsttRecordType.ifBlank { "null" }
        }
        return q
    }

    private fun encodeQuery(q: Map<String, String>): String =
        q.entries.joinToString("&") { "${it.key}=${encodeURIComponent(it.value)}" }

    private fun toVmessUri(item: ProfileItem): String {
        // v2rayNG JSON mapping (inverse of parseVmessJson): KCP carries
        // the seed in "path", gRPC carries mode in "type", serviceName
        // in "path", authority in "host". aid is always "0" (alterId is
        // deprecated in v2rayNG exports). New keys are only written when
        // set, so an empty field stays out of the link entirely.
        val net = item.network.ifBlank { "tcp" }
        val jsonType = when (net) {
            "grpc" -> item.mode.ifBlank { "none" }
            "tcp", "kcp" -> item.headerType.ifBlank { "none" }
            else -> "none"
        }
        val jsonHost = if (net == "grpc") item.authority.ifBlank { item.host } else item.host
        val jsonPath = when (net) {
            "kcp" -> item.seed
            "grpc" -> item.serviceName.ifBlank { item.path }
            else -> item.path
        }
        val json = buildString {
            append("{")
            append("\"v\":\"2\",")
            append("\"ps\":${jsonStr(item.remarks)},")
            append("\"add\":${jsonStr(item.address)},")
            append("\"port\":${jsonStr(item.port.toString())},")
            append("\"id\":${jsonStr(item.uuid)},")
            append("\"aid\":\"0\",")
            append("\"scy\":${jsonStr(item.security.ifBlank { "auto" })},")
            append("\"net\":${jsonStr(net)},")
            append("\"type\":${jsonStr(jsonType)},")
            append("\"host\":${jsonStr(jsonHost)},")
            append("\"path\":${jsonStr(jsonPath)},")
            append("\"tls\":${jsonStr(item.streamSecurity)},")
            val sni = if (item.oneringEnabled && item.oneringBug.isNotBlank()) {
                "onering:${item.sni}:${item.oneringBug}"
            } else {
                item.sni
            }
            append("\"sni\":${jsonStr(sni)},")
            append("\"fp\":${jsonStr(item.fingerprint)},")
            append("\"alpn\":${jsonStr(item.alpn)}")
            if (item.finalMask.isNotBlank()) append(",\"fm\":${jsonStr(item.finalMask)}")
            if (item.verifyPeerCertByName.isNotBlank()) append(",\"vcn\":${jsonStr(item.verifyPeerCertByName)}")
            if (item.pinnedCA256.isNotBlank()) append(",\"pcs\":${jsonStr(item.pinnedCA256)}")
            if (item.echConfigList.isNotBlank()) append(",\"ech\":${jsonStr(item.echConfigList)}")
            if (item.realityPublicKey.isNotBlank()) append(",\"pbk\":${jsonStr(item.realityPublicKey)}")
            if (item.realityShortId.isNotBlank()) append(",\"sid\":${jsonStr(item.realityShortId)}")
            if (item.realitySpiderX.isNotBlank()) append(",\"spx\":${jsonStr(item.realitySpiderX)}")
            if (item.realityMldsa65Verify.isNotBlank()) append(",\"pqv\":${jsonStr(item.realityMldsa65Verify)}")
            if (item.dnsttEnabled) {
                if (item.dnsttNS.isNotBlank()) append(",\"dnstt_ns\":${jsonStr(item.dnsttNS)}")
                if (item.dnsttPubkey.isNotBlank()) append(",\"dnstt_pubkey\":${jsonStr(item.dnsttPubkey)}")
                if (item.dnsttResolver.isNotBlank()) append(",\"dnstt_resolver\":${jsonStr(item.dnsttResolver)}")
                append(",\"dnstt_record_type\":${jsonStr(item.dnsttRecordType.ifBlank { "null" })}")
            }
            append("}")
        }
        return "vmess://" + Base64Util.encodeUrlSafe(json.toByteArray(Charsets.UTF_8))
    }

    private fun toVlessUri(item: ProfileItem): String {
        val q = commonQuery(item)
        q["encryption"] = item.encryption.ifBlank { item.method.ifBlank { "none" } }
        if (item.flow.isNotBlank()) q["flow"] = item.flow
        return "vless://${encodeURIComponent(item.uuid)}@${item.address}:${item.port}" +
            "?${encodeQuery(q)}#${encodeURIComponent(item.remarks)}"
    }

    private fun toTrojanUri(item: ProfileItem): String {
        val q = commonQuery(item)
        return "trojan://${encodeURIComponent(item.password)}@${item.address}:${item.port}" +
            "?${encodeQuery(q)}#${encodeURIComponent(item.remarks)}"
    }

    private fun toSsUri(item: ProfileItem): String {
        val userInfo = Base64Util.encodeUrlSafe(
            "${item.method}:${item.password}".toByteArray(Charsets.UTF_8)
        )
        // No query string: v2rayNG does not read any SS query params,
        // so extensions here would be silently dropped on import
        // (a copy trap) — the plain SIP002 form is the whole link.
        return "ss://$userInfo@${item.address}:${item.port}#${encodeURIComponent(item.remarks)}"
    }

    private fun toSshUri(item: ProfileItem): String {
        val q = LinkedHashMap<String, String>()
        val methods = mutableListOf<String>()
        if (item.sshUsePayload) methods += "payload"
        if (item.sshUseEnhanced) methods += "enhanced"
        if (item.sshUseTls) methods += "tls"
        if (item.sshUseSlowdns) methods += "slowdns"
        if (methods.isNotEmpty()) q["methods"] = methods.joinToString(",")
        if (item.sshPayload.isNotBlank()) q["payload"] = item.sshPayload
        if (item.sshRemoteProxy.isNotBlank()) q["remote_proxy"] = item.sshRemoteProxy
        if (item.sshSni.isNotBlank()) q["sni"] = item.sshSni
        if (item.sshSniVersion.isNotBlank() && item.sshSniVersion != "default") {
            q["sni_version"] = item.sshSniVersion
        }
        if (item.sshInsecure) q["insecure"] = "1"
        if (item.privateKey.isNotBlank()) q["private_key"] = item.privateKey
        if (item.dnsttNS.isNotBlank()) q["dnstt_ns"] = item.dnsttNS
        if (item.dnsttPubkey.isNotBlank()) q["dnstt_pubkey"] = item.dnsttPubkey
        if (item.dnsttResolver.isNotBlank()) q["dnstt_resolver"] = item.dnsttResolver
        if (item.dnsttNS.isNotBlank()) q["dnstt_record_type"] = item.dnsttRecordType
        val userInfo = buildString {
            append(encodeURIComponent(item.username))
            if (item.password.isNotEmpty()) append(":${encodeURIComponent(item.password)}")
        }
        val query = if (q.isEmpty()) "" else "?${encodeQuery(q)}"
        return "ssh://$userInfo@${item.address}:${item.port}$query#${encodeURIComponent(item.remarks)}"
    }

    // ---- helpers ----

    private fun safeUri(str: String): URI? {
        // java.net.URI rejects spaces and other illegal chars; v2rayNG
        // fixes the URL first (Utils.fixIllegalUrl).
        var fixed = str.replace(" ", "%20")
        return runCatching { URI(fixed) }.getOrNull()
            ?: runCatching { URI(fixed.replace("|", "%7C")) }.getOrNull()
    }

    private fun queryParams(uri: URI): Map<String, String> {
        val raw = uri.rawQuery ?: return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in raw.split("&")) {
            val idx = pair.indexOf('=')
            if (idx < 0) continue
            val key = percentDecode(pair.substring(0, idx))
            val value = percentDecode(pair.substring(idx + 1))
            out[key] = value
        }
        return out
    }

    /** decodeURIComponent semantics: %XX decoded, '+' stays '+'. */
    fun percentDecode(s: String): String {
        if (!s.contains('%')) return s
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = ByteArray(bytes.size)
        var o = 0
        var i = 0
        while (i < bytes.size) {
            if (bytes[i] == '%'.code.toByte() && i + 2 < bytes.size) {
                val hex = String(bytes, i + 1, 2, Charsets.US_ASCII)
                val v = hex.toIntOrNull(16)
                if (v != null) {
                    out[o++] = v.toByte()
                    i += 3
                    continue
                }
            }
            out[o++] = bytes[i]
            i++
        }
        return String(out, 0, o, Charsets.UTF_8)
    }

    fun encodeURIComponent(s: String): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            if (ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' ||
                ch == '-' || ch == '_' || ch == '.' || ch == '!' ||
                ch == '~' || ch == '*' || ch == '\'' || ch == '(' || ch == ')'
            ) {
                sb.append(ch)
            } else {
                sb.append('%')
                sb.append(String.format("%02X", c))
            }
        }
        return sb.toString()
    }

    private fun jsonStr(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun com.google.gson.JsonObject.str(key: String): String? {
        if (!has(key)) return null
        val el = get(key) ?: return null
        if (el.isJsonNull) return null
        return if (el.isJsonPrimitive) el.asString else null
    }
}
