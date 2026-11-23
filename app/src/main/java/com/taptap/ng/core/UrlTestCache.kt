package com.taptap.ng.core

import com.taptap.ng.data.ProfileItem
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * In-memory delay cache for URL_TEST / FALLBACK groups (M7, W2).
 *
 * One entry per profile guid: the last measured delay in ms
 * (null = the last probe failed, or the entry was never probed)
 * plus when it was measured. The forwarder reads it from many
 * dial threads at once, so every access goes through a
 * [ConcurrentHashMap]; [delays] returns a snapshot for
 * [RouteEngine.resolve]. Nothing here is persisted — a fresh
 * start re-probes (seeded once from [Observatory], see below).
 *
 * Delays come from [UrlTestLoop], which probes each member of a
 * URL_TEST group with [ServerTester.testRealPingThroughProxy] —
 * the same full dial + HTTP GET the manual delay test uses, so a
 * number here means the entry really answered through the proxy.
 * The loop never touches [PemicuManager]: probing must not prime.
 */
class UrlTestCache {

    /** One cached measurement. [delayMs] null = unknown / failed. */
    data class Entry(val delayMs: Long?, val atMs: Long)

    private val entries = ConcurrentHashMap<String, Entry>()

    /** Record a measurement (a probe result, or null on failure). */
    fun record(guid: String, delayMs: Long?, atMs: Long = System.currentTimeMillis()) {
        entries[guid] = Entry(delayMs, atMs)
    }

    /** Last-known delay for [guid], or null when unknown / failed. */
    fun delay(guid: String): Long? = entries[guid]?.delayMs

    /** When [guid] was last measured, or null when never. */
    fun measuredAtMs(guid: String): Long? = entries[guid]?.atMs

    /** Snapshot of guid -> last-known delay (for [RouteEngine]). */
    fun delays(): Map<String, Long?> = entries.mapValues { it.value.delayMs }

    /**
     * True when [guid] was measured within [maxAgeMs] of [nowMs].
     * A failed measurement (null delay) is never fresh — it only
     * says "unknown", never "fast".
     */
    fun isFresh(guid: String, maxAgeMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        val e = entries[guid] ?: return false
        if (e.delayMs == null) return false
        return nowMs - e.atMs <= maxAgeMs
    }

    fun clear() = entries.clear()

    /**
     * Seed the cache from [Observatory] results (which the
     * observatory runner already collects while the tunnel is up).
     * Only fresh successes are taken (ms >= 0 and within
     * [maxAgeMs]); failed probes leave existing entries alone, so
     * one bad observatory round never wipes a good url-test
     * measurement. Returns how many entries were seeded.
     */
    fun seedFromObservatory(
        maxAgeMs: Long = DEFAULT_SEED_MAX_AGE_MS,
        nowMs: Long = System.currentTimeMillis(),
    ): Int {
        var seeded = 0
        for ((guid, result) in Observatory.results()) {
            if (result.ms < 0) continue
            if (nowMs - result.atMs > maxAgeMs) continue
            record(guid, result.ms, result.atMs)
            seeded++
        }
        return seeded
    }

    companion object {
        /** Observatory results older than this are not seeded. */
        const val DEFAULT_SEED_MAX_AGE_MS = 15L * 60_000
    }
}

/**
 * Periodic url-test loop for URL_TEST groups (M7, W2).
 *
 * One daemon thread: each round probes the members of every
 * URL_TEST group whose [ProxyGroup.effectiveUrlTestIntervalSec]
 * has elapsed since its last round, and records the results in
 * [UrlTestCache]. The loop itself is started by the service when
 * the tunnel comes up and stopped on teardown — it never runs
 * without a tunnel, because a probe dials through the proxy.
 *
 * Probing is sequential per group (one member at a time) and uses
 * the group's own [ProxyGroup.urlTestUrl]; each probe is the
 * manual delay test ([ServerTester.testRealPingThroughProxy]) with
 * its default 10 s timeout, so a round over a 5-member group can
 * take up to ~50 s when every member is dead — the next round is
 * simply due later, never overlapping. The loop never triggers
 * [PemicuManager] (probing is not priming).
 *
 * [probeGroup] / [dueGroups] / [probeDue] are the testable core:
 * the thread only sleeps until the next group is due and calls
 * them. [tester] is injectable so tests can stub the probe.
 *
 * v1.0.28: every round is visible in the Log — [probeGroup]
 * writes one start line per URL_TEST group (the first time it is
 * probed) and one round line per round (member delays + the
 * picked member) through [log], which defaults to
 * [DialLog.log] at INFO (shown at the default log level; the
 * loop never logged anything before, so rounds ran invisibly).
 * [kick] wakes the sleeping worker at once, so a URL_TEST group
 * created / edited / selected after the tunnel came up gets its
 * first round immediately instead of up to [MAX_SLEEP_MS] later.
 */
class UrlTestLoop(
    private val cache: UrlTestCache,
    private val groupsProvider: () -> List<ProxyGroup>,
    private val profilesProvider: () -> List<ProfileItem>,
    private val tester: (ProfileItem, String) -> ServerTester.TestResult = { item, url ->
        ServerTester.testRealPingThroughProxy(item, url)
    },
    /** False = rounds are postponed (e.g. screen off), like Observatory. */
    private val isActive: () -> Boolean = { true },
    /** Log sink; defaults to DialLog INFO (visible in the Log page). */
    private val log: (String) -> Unit = { DialLog.log("URL-TEST", it) },
) {
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    /** Group ids whose start line was already written (once per loop). */
    private val loggedStartIds =
        Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    /** The worker waits on this; [kick] notifies it. */
    private val sleepLock = Object()

    /** Wake the worker at once (e.g. a URL_TEST group just appeared). */
    fun kick() {
        synchronized(sleepLock) { sleepLock.notifyAll() }
    }

    /** guid-group last round start, keyed by group id. */
    private val lastProbeMs = ConcurrentHashMap<String, Long>()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        worker = thread(name = "url-test", isDaemon = true) {
            while (running.get()) {
                val now = System.currentTimeMillis()
                var groups = runCatching { groupsProvider() }.getOrElse { emptyList() }
                val nextDueIn = nextDueInMs(groups, now)
                // A due group probes at once — no minimum sleep
                // first (a never-probed group is due at tunnel
                // start). Otherwise wait until the next group is
                // due; [kick] notifies early when a URL_TEST group
                // appears / changes while the tunnel is up.
                if (nextDueIn > 0) {
                    try {
                        synchronized(sleepLock) {
                            sleepLock.wait(nextDueIn.coerceIn(MIN_SLEEP_MS, MAX_SLEEP_MS))
                        }
                    } catch (_: InterruptedException) {
                        break
                    }
                    if (!running.get()) break
                    // Re-read after the wait: a kick means the
                    // groups may have changed while asleep, and
                    // the pre-sleep snapshot would miss the new
                    // group entirely for one more round.
                    groups = runCatching { groupsProvider() }.getOrElse { emptyList() }
                }
                if (!running.get()) break
                if (!isActive()) {
                    // Screen off: wait a full minute before
                    // checking again — the nextDue sleep above
                    // would otherwise wake us every 5 s.
                    try {
                        Thread.sleep(INACTIVE_RETRY_MS)
                    } catch (_: InterruptedException) {
                        break
                    }
                    continue
                }
                val t = System.currentTimeMillis()
                val profiles = runCatching { profilesProvider() }.getOrElse { emptyList() }
                try {
                    probeDue(groups, profiles, t)
                } catch (_: Exception) {
                    // One round failing must not kill the loop.
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        worker?.interrupt()
        worker = null
    }

    /**
     * URL_TEST groups whose interval has elapsed at [nowMs]. A
     * group that was never probed is due at once (its first round
     * runs right after the tunnel comes up).
     */
    fun dueGroups(groups: List<ProxyGroup>, nowMs: Long): List<ProxyGroup> =
        groups.filter { group ->
            if (group.type != ProxyGroupType.URL_TEST) return@filter false
            val last = lastProbeMs[group.id] ?: return@filter true
            nowMs - last >= group.effectiveUrlTestIntervalSec * 1000L
        }

    /** Probe every due group; returns guid -> delay ms for probed members. */
    fun probeDue(
        groups: List<ProxyGroup>,
        profiles: List<ProfileItem>,
        nowMs: Long = System.currentTimeMillis(),
    ): Map<String, Long?> {
        val out = LinkedHashMap<String, Long?>()
        for (group in dueGroups(groups, nowMs)) {
            lastProbeMs[group.id] = nowMs
            out += probeGroup(group, profiles)
        }
        return out
    }

    /**
     * Probe one URL_TEST group's members and record the results.
     * Non-URL_TEST groups are a no-op (their members are picked by
     * selection / order, never by probe). A member with no profile
     * is skipped; a probe failure records null (unknown), never a
     * stale number. Returns guid -> delay ms for probed members.
     *
     * v1.0.28: writes the Log lines for the group — one start line
     * the first time it is probed (name + test URL + interval +
     * members) and one round line per round (each member's delay
     * + the picked member, i.e. the lowest delay — the same pick
     * the route engine makes). Only member display names and
     * delays are logged, never credentials or proxy URLs.
     */
    fun probeGroup(group: ProxyGroup, profiles: List<ProfileItem>): Map<String, Long?> {
        if (group.type != ProxyGroupType.URL_TEST) return emptyMap()
        val out = LinkedHashMap<String, Long?>()
        val url = group.urlTestUrl.ifBlank { ProxyGroup.DEFAULT_URL_TEST_URL }
        if (loggedStartIds.add(group.id)) {
            val names = group.members.map { guid ->
                profiles.firstOrNull { it.guid == guid }?.displayName() ?: guid
            }
            log(
                "url-test mulai: grup '${group.name}' — URL tes $url, " +
                    "interval ${group.effectiveUrlTestIntervalSec} dtk, " +
                    "anggota: ${names.joinToString(", ").ifEmpty { "-" }}",
            )
        }
        for (guid in group.members) {
            val item = profiles.firstOrNull { it.guid == guid } ?: continue
            val result = runCatching { tester(item, url) }
                .getOrElse { e ->
                    val stage = if (e is Exception) ServerTester.stageOf(e) else "gagal"
                    ServerTester.TestResult(-1, stage)
                }
            val delay = result.ms.takeIf { it >= 0 }
            cache.record(guid, delay)
            out[guid] = delay
        }
        if (out.isNotEmpty()) {
            val parts = out.entries.joinToString(", ") { (guid, ms) ->
                val name = profiles.firstOrNull { it.guid == guid }?.displayName() ?: guid
                "$name=${ms?.let { "${it}ms" } ?: "gagal"}"
            }
            val best = out.entries.filter { it.value != null }.minByOrNull { it.value!! }
            val picked = best?.let { (guid, ms) ->
                val name = profiles.firstOrNull { it.guid == guid }?.displayName() ?: guid
                "$name (${ms}ms)"
            } ?: "- (tidak ada yang menjawab)"
            log("url-test '${group.name}': $parts — terpilih: $picked")
        }
        return out
    }

    /** Ms until the next URL_TEST group is due (0 when one is due now). */
    fun nextDueInMs(groups: List<ProxyGroup>, nowMs: Long): Long {
        var next = Long.MAX_VALUE
        for (group in groups) {
            if (group.type != ProxyGroupType.URL_TEST) continue
            // Never probed: due now.
            val last = lastProbeMs[group.id] ?: return 0L
            val dueAt = last + group.effectiveUrlTestIntervalSec * 1000L
            next = minOf(next, dueAt - nowMs)
        }
        return if (next == Long.MAX_VALUE) MAX_SLEEP_MS else next.coerceAtLeast(0L)
    }

    private companion object {
        const val MIN_SLEEP_MS = 5_000L
        const val MAX_SLEEP_MS = 30L * 60_000
        const val INACTIVE_RETRY_MS = 60_000L
    }
}
