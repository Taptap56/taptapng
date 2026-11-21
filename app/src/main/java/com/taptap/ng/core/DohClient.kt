package com.taptap.ng.core

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom

/**
 * Klien DNS-over-HTTPS (RFC 8484), v1.0.5 (kelompok C) — untuk query
 * in-tunnel yang dirutekan ke remote ([DnsSettings.remoteDohUrl]).
 *
 * Wire format: pesan DNS standar ([DnsResolver.buildQuery] /
 * [DnsResolver.parseAnswers]) di dalam body HTTP dengan
 * `Content-Type: application/dns-message`. Dua cara kirim:
 * - POST (dipakai [query]): body = pesan DNS, header
 *   `Content-Type` + `Accept: application/dns-message`.
 * - GET (dipakai [queryViaGet]): `?dns=<base64url tanpa padding
 *   dari pesan DNS>`, header `Accept: application/dns-message`.
 *
 * Transport HTTP-nya bisa di-inject ([Exchange]) — tes memakai stub
 * in-memory, tanpa jaringan. Transport default ([HttpExchange])
 * adalah [HttpURLConnection] biasa: aplikasi ini di-disallow dari
 * VPN sendiri (addDisallowedApplication), jadi koneksi HTTPS-nya
 * bypass TUN di level routing; bila disallow itu pernah gagal,
 * soketnya masuk TUN dan dial lewat proxy (semantik "remote DNS"
 * v2rayNG — lewat proxy), dan host DoH sendiri tidak pernah
 * dirutekan ke DoH oleh relay ([DnsRelayPolicy.route] mengecualikan
 * host DoH dari rute DoH), jadi tidak ada loop.
 *
 * Tidak ada logging di sini: URL DoH membawa query DNS yang
 * di-encode (nama domain yang ditanya) — tidak boleh masuk log.
 */
class DohClient(
    /** URL DoH lengkap, mis. https://cloudflare-dns.com/dns-query. */
    val url: String,
    private val exchange: Exchange = HttpExchange(),
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MS,
) {
    init {
        require(isValidDohUrl(url)) { "URL DoH tidak valid: $url" }
    }

    /** Satu pertukaran HTTP DoH: kirim [query], kembalikan body jawaban. */
    fun interface Exchange {
        @Throws(IOException::class)
        fun exchange(url: String, query: ByteArray, useGet: Boolean, timeoutMs: Int): ByteArray
    }

    /**
     * Tanya [host] ([qtype], default A) lewat DoH POST.
     * @throws IOException bila HTTP gagal / bukan 200 / jawaban
     * kosong / tanpa record yang cocok.
     */
    @Throws(IOException::class)
    fun query(host: String, qtype: Int = DnsResolver.TYPE_A): List<InetAddress> {
        val id = ThreadLocalRandom.current().nextInt(0, 65536)
        val wire = DnsResolver.buildQuery(host, id, qtype)
        val resp = exchange(url, wire, false, timeoutMs)
        val addrs = DnsResolver.parseAnswers(resp, id)
        if (addrs.isEmpty()) throw IOException("DoH tanpa jawaban A/AAAA untuk $host")
        return addrs
    }

    /** Seperti [query], tapi lewat GET (`?dns=...`). */
    @Throws(IOException::class)
    fun queryViaGet(host: String, qtype: Int = DnsResolver.TYPE_A): List<InetAddress> {
        val id = ThreadLocalRandom.current().nextInt(0, 65536)
        val wire = DnsResolver.buildQuery(host, id, qtype)
        val resp = exchange(url, wire, true, timeoutMs)
        val addrs = DnsResolver.parseAnswers(resp, id)
        if (addrs.isEmpty()) throw IOException("DoH tanpa jawaban A/AAAA untuk $host")
        return addrs
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 5000
        const val CONTENT_TYPE_DNS_MESSAGE = "application/dns-message"

        /** URL DoH valid = https:// + host tak kosong. */
        fun isValidDohUrl(url: String): Boolean {
            val u = url.trim()
            if (!u.startsWith("https://")) return false
            val afterScheme = u.removePrefix("https://")
            val host = afterScheme.substringBefore('/').substringBefore(':')
            return host.isNotEmpty() && !host.contains(' ')
        }

        /** Host dari URL DoH (untuk pengecualian loop relay), atau null. */
        fun hostOf(url: String): String? {
            if (!isValidDohUrl(url)) return null
            val afterScheme = url.trim().removePrefix("https://")
            return afterScheme.substringBefore('/').substringBefore(':').lowercase()
                .takeIf { it.isNotEmpty() }
        }

        /**
         * URL GET DoH: basis + `?dns=<base64url tanpa padding>`
         * (pakai '&' bila basis sudah punya query).
         */
        fun buildGetUrl(baseUrl: String, query: ByteArray): String {
            val sep = if (baseUrl.contains('?')) "&" else "?"
            return "$baseUrl${sep}dns=${Base64Util.encodeUrlSafe(query)}"
        }
    }

    /**
     * Transport default: [HttpURLConnection]. POST menulis pesan DNS
     * sebagai body; GET memakai [buildGetUrl]. Status bukan 200 =
     * IOException. Timeout connect + read = [timeoutMs].
     */
    class HttpExchange : Exchange {
        override fun exchange(
            url: String,
            query: ByteArray,
            useGet: Boolean,
            timeoutMs: Int,
        ): ByteArray {
            val target = if (useGet) buildGetUrl(url, query) else url
            val conn = URL(target).openConnection() as HttpURLConnection
            try {
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.setRequestProperty("Accept", CONTENT_TYPE_DNS_MESSAGE)
                if (useGet) {
                    conn.requestMethod = "GET"
                } else {
                    conn.requestMethod = "POST"
                    conn.doOutput = true
                    conn.setRequestProperty("Content-Type", CONTENT_TYPE_DNS_MESSAGE)
                    conn.setRequestProperty(
                        "Content-Length", query.size.toString(),
                    )
                    conn.outputStream.use { it.write(query) }
                }
                val code = conn.responseCode
                if (code != HttpURLConnection.HTTP_OK) {
                    throw IOException("DoH HTTP $code")
                }
                return conn.inputStream.use { it.readBytes() }
            } finally {
                conn.disconnect()
            }
        }
    }
}
