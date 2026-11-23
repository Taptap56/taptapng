package com.taptap.ng.core

import com.google.gson.annotations.SerializedName
import java.util.UUID

/**
 * Proxy group type (M7). Load-balance is deliberately NOT offered:
 * the in-app engine has no load metric yet, and Clash's
 * load-balance needs a strategy the M7 scope does not include.
 * SELECT / URL_TEST / FALLBACK cover what the route engine (W2)
 * and the Clash API (W3) need.
 */
enum class ProxyGroupType {
    SELECT, URL_TEST, FALLBACK
}

/**
 * One proxy group (M7): a named set of servers ([members] are
 * [com.taptap.ng.data.ProfileItem.guid] values) that the route
 * engine (W2) picks from, and the Clash API (W3) exposes as a
 * Clash proxy group.
 *
 * JSON field names are stable (see [SerializedName]); never rename
 * them without a migration + regression test. Gson bypasses the
 * constructor, so derived behaviour lives in the `effective*`
 * accessors below, never in an init block.
 *
 * `selectedMemberGuid` is only meaningful for SELECT (null = first
 * member). `urlTestUrl` / `urlTestIntervalSec` are only meaningful
 * for URL_TEST, but are always stored so a type change keeps them.
 */
data class ProxyGroup(
    @SerializedName("id")
    val id: String = UUID.randomUUID().toString(),
    @SerializedName("name")
    val name: String = "",
    @SerializedName("type")
    val type: ProxyGroupType = ProxyGroupType.SELECT,
    @SerializedName("members")
    val members: List<String> = emptyList(),
    @SerializedName("selectedMemberGuid")
    val selectedMemberGuid: String? = null,
    @SerializedName("urlTestUrl")
    val urlTestUrl: String = DEFAULT_URL_TEST_URL,
    @SerializedName("urlTestIntervalSec")
    val urlTestIntervalSec: Int = DEFAULT_URL_TEST_INTERVAL_SEC,
) {
    /**
     * The member a SELECT group actually uses: the stored selection
     * when it is still a member, otherwise the first member (or
     * null when the group is empty). For URL_TEST / FALLBACK the
     * engine picks by probe / order, so this returns the first
     * member as a stable fallback.
     */
    fun effectiveSelectedMemberGuid(): String? =
        selectedMemberGuid?.takeIf { it in members } ?: members.firstOrNull()

    /** Stored interval clamped to [MIN_URL_TEST_INTERVAL_SEC]..[MAX_URL_TEST_INTERVAL_SEC]. */
    val effectiveUrlTestIntervalSec: Int
        get() = urlTestIntervalSec.coerceIn(MIN_URL_TEST_INTERVAL_SEC, MAX_URL_TEST_INTERVAL_SEC)

    companion object {
        const val DEFAULT_URL_TEST_URL = "http://www.gstatic.com/generate_204"
        const val DEFAULT_URL_TEST_INTERVAL_SEC = 300
        const val MIN_URL_TEST_INTERVAL_SEC = 60
        const val MAX_URL_TEST_INTERVAL_SEC = 3600
    }
}
