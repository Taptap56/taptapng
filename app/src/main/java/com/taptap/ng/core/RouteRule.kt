package com.taptap.ng.core

import com.google.gson.annotations.SerializedName
import java.net.InetAddress
import java.util.UUID

/** Route rule type (M7). Rules are matched top-down; the first match wins. */
enum class RouteRuleType {
    DOMAIN, DOMAIN_SUFFIX, DOMAIN_KEYWORD, IP_CIDR, FINAL
}

/**
 * One routing rule (M7): when [matches] is true, traffic goes to
 * [target] — a [ProxyGroup.id], [TARGET_DIRECT], or [TARGET_REJECT].
 *
 * Pure logic, no Android: safe to call from the JVM tests, the
 * route engine (W2), and the Clash API (W3).
 *
 * The pattern is normalised to lowercase (trimmed) when read, so
 * JSON written by an older build or by hand still matches the same
 * way; Gson bypasses the constructor, so normalisation lives in
 * [normalizedPattern], never in an init block. JSON field names are
 * stable (see [SerializedName]); never rename them without a
 * migration + regression test.
 *
 * v1.0.23: [enabled] is nullable on purpose (see the field doc).
 * A plain `Boolean = true` default would be safe ONLY while
 * Gson instantiates this class through its no-arg constructor
 * (kotlinc emits one while every parameter has a default); if
 * the class ever loses that constructor, Gson falls back to
 * Unsafe allocation and the field would read the JVM default
 * `false` — every old rule silently switched off. `null`
 * (missing key) means active on EITHER path, so read the flag
 * only through [isEnabled]. Verified 2026-11-24: Gson 2.13.1
 * on the no-arg constructor applies the declared defaults
 * (a `{"type":"FINAL"}` document reads back with a fresh UUID
 * id, empty pattern and DIRECT target), and the old-file test
 * in RouteRuleEnabledTest pins the active-by-default behaviour.
 */
data class RouteRule(
    @SerializedName("id")
    val id: String = UUID.randomUUID().toString(),
    @SerializedName("type")
    val type: RouteRuleType = RouteRuleType.FINAL,
    @SerializedName("pattern")
    val pattern: String = "",
    @SerializedName("target")
    val target: String = TARGET_DIRECT,
    /**
     * Stored on/off flag (v1.0.23). Nullable on purpose: a file
     * written before v1.0.23 has no "enabled" key, and the field
     * reads `null` on either Gson instantiation path (no-arg
     * constructor, or Unsafe allocation if this class ever loses
     * it) — `null` means the rule is active. Never read this field
     * directly; use [isEnabled]. Gson omits nulls when writing, so
     * a rule that was never toggled stays key-less on disk,
     * exactly like a v1.0.22 file.
     */
    @SerializedName("enabled")
    val enabled: Boolean? = null,
) {
    /**
     * Whether this rule takes part in matching. Missing (null) =
     * active, so every rule written by v1.0.17–v1.0.22 keeps
     * working after the update. FINAL has no UI toggle; a FINAL
     * rule is always evaluated by the engine regardless of this
     * flag (see [RouteEngine]).
     */
    val isEnabled: Boolean
        get() = enabled ?: true

    /** Pattern trimmed + lowercased; empty for FINAL. */
    val normalizedPattern: String
        get() = pattern.trim().lowercase()

    /**
     * Pure match: DOMAIN = exact host (case-insensitive);
     * DOMAIN_SUFFIX = host == pattern or ends with ".pattern";
     * DOMAIN_KEYWORD = host contains pattern; IP_CIDR = [ip] inside
     * the CIDR (IPv4 and IPv6); FINAL = always true. An empty
     * pattern never matches for the DOMAIN* types (it would match
     * everything); an unparseable CIDR never matches.
     */
    fun matches(host: String?, ip: InetAddress?): Boolean {
        return when (type) {
            RouteRuleType.FINAL -> true
            RouteRuleType.DOMAIN -> {
                val p = normalizedPattern
                p.isNotEmpty() && host?.lowercase() == p
            }
            RouteRuleType.DOMAIN_SUFFIX -> {
                val p = normalizedPattern
                val h = host?.lowercase() ?: return false
                p.isNotEmpty() && (h == p || h.endsWith(".$p"))
            }
            RouteRuleType.DOMAIN_KEYWORD -> {
                val p = normalizedPattern
                p.isNotEmpty() && (host?.lowercase()?.contains(p) == true)
            }
            RouteRuleType.IP_CIDR -> ip != null && matchesCidr(ip, normalizedPattern)
        }
    }

    companion object {
        /** Target: bypass the proxy, dial direct. */
        const val TARGET_DIRECT = "DIRECT"

        /** Target: drop the connection. */
        const val TARGET_REJECT = "REJECT"

        /**
         * True when [cidr] parses as an IPv4/IPv6 CIDR with an
         * in-range prefix length. Pure — used by the editor to
         * reject bad input before it is stored.
         */
        fun isValidCidr(cidr: String): Boolean {
            val slash = cidr.indexOf('/')
            if (slash <= 0) return false
            val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return false
            val addr = parseIpLiteral(cidr.substring(0, slash)) ?: return false
            return prefix in 0..(addr.address.size * 8)
        }

        /**
         * Strict IP-literal parse with NO DNS lookup. [InetAddress.getByName]
         * falls back to hostname resolution for strings like
         * "999.999.0.0" (a resolver may even answer), so IPv4 is
         * checked part by part here; a ':' means an IPv6 literal,
         * which getByName parses without touching DNS.
         */
        private fun parseIpLiteral(text: String): InetAddress? {
            if (text.contains(':')) {
                return runCatching { InetAddress.getByName(text) }.getOrNull()
            }
            val parts = text.split('.')
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for (i in parts.indices) {
                val p = parts[i]
                if (p.isEmpty() || p.length > 3 || !p.all { it.isDigit() }) return null
                val v = p.toInt()
                if (v > 255) return null
                bytes[i] = v.toByte()
            }
            return runCatching { InetAddress.getByAddress(bytes) }.getOrNull()
        }

        /**
         * Pure IPv4/IPv6 CIDR match ("192.168.0.0/24", "2001:db8::/32").
         * Returns false for an unparseable pattern, a family mismatch,
         * or an out-of-range prefix length.
         */
        fun matchesCidr(ip: InetAddress, cidr: String): Boolean {
            val slash = cidr.indexOf('/')
            if (slash <= 0) return false
            val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return false
            val network = parseIpLiteral(cidr.substring(0, slash)) ?: return false
            val ipBytes = ip.address
            val netBytes = network.address
            if (ipBytes.size != netBytes.size) return false
            if (prefix < 0 || prefix > ipBytes.size * 8) return false
            var bitsLeft = prefix
            for (i in ipBytes.indices) {
                if (bitsLeft <= 0) break
                val mask = when {
                    bitsLeft >= 8 -> 0xFF
                    else -> (0xFF shl (8 - bitsLeft)) and 0xFF
                }
                if ((ipBytes[i].toInt() and mask) != (netBytes[i].toInt() and mask)) return false
                bitsLeft -= 8
            }
            return true
        }
    }
}
