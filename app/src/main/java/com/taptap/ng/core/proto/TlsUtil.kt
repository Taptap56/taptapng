package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.data.ProfileItem
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * TLS for the proxy transports (VMess/VLESS/Trojan over TLS, M2).
 *
 * - SNI = item.sni, or the proxy address when empty. An IP-literal SNI is
 *   skipped (SNIHostName rejects IPs).
 * - ALPN = item.alpn (comma-separated) when set. `SSLParameters
 *   .applicationProtocols` needs API 29+; on older runtimes the call
 *   throws NoSuchMethodError and is silently ignored. v1.0.4: NO
 *   default ALPN — the planned "http/1.1 default for ws" was DROPPED
 *   after the dex check (d9.txt has no setApplicationProtocols call,
 *   so XVEON does not always set ALPN; entry iflix already sets
 *   http/1.1 itself).
 * - insecure = trust-all certificates (user option, same meaning as
 *   v2rayNG "allowInsecure"). No hostname verification is done on a raw
 *   SSLSocket either way — verification only exists in HttpsURLConnection.
 * - The plain socket's SO_TIMEOUT is carried over as the handshake
 *   timeout; callers clear it after dial().
 */
object TlsUtil {

    /** TLS 1.3 + 1.2 — the protocols XVEON offers (dex d9.txt:678
     *  calls setEnabledProtocols). The platform default on modern
     *  Android is the same pair, so this only narrows old runtimes
     *  that still offer TLS 1.0/1.1. */
    val DEFAULT_TLS_PROTOCOLS = arrayOf("TLSv1.3", "TLSv1.2")

    /** Trust-all SSLContext (v1.0.4: also used by the prime dial,
     *  which only needs a ClientHello — see PemicuManager). */
    internal val trustAllContext: SSLContext by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }
    }

    fun wrap(
        plain: Socket,
        item: ProfileItem,
        enabledProtocols: Array<String>? = null,
        /**
         * v1.0.5: fragment the ClientHello (Fragment settings).
         * Null = v1.0.4 path untouched. Non-null wraps [plain]
         * in a [FragmentSocket] so the SSLSocket writes its
         * records through a [FragmentingOutputStream] — the
         * SSLSocket itself is unchanged (see TlsFragment).
         */
        fragmentConfig: FragmentConfig? = null,
    ): SSLSocket {
        val socketForTls: Socket =
            if (fragmentConfig != null) FragmentSocket(plain, fragmentConfig) else plain
        val factory: SSLSocketFactory = if (item.insecure) {
            trustAllContext.socketFactory
        } else {
            SSLSocketFactory.getDefault() as SSLSocketFactory
        }
        val tls = factory.createSocket(socketForTls, item.address, item.port, true) as SSLSocket
        applyTlsSettings(tls, item, enabledProtocols)
        tls.soTimeout = Transport.HANDSHAKE_TIMEOUT_MS
        tls.startHandshake()
        // v1.0.2 (XVEON order): name the negotiated version —
        // "TLS established: TLSv1.3" — not just "TLS ok".
        DialLog.log("TLS", "TLS established: ${tls.session.protocol}")
        return tls
    }

    /**
     * Apply SNI / ALPN / protocol settings to an SSLSocket without
     * handshaking — testable on an unconnected socket. ALPN comes
     * ONLY from the entry's alpn field (see the header note: no
     * default ALPN in v1.0.4). Protocols default to
     * [DEFAULT_TLS_PROTOCOLS]; a non-null [enabledProtocols] is the
     * SSH TLS version forcing (v1.0.30) and wins. An unsupported
     * name must never kill the dial — fall back to negotiation and
     * say so in the log.
     */
    internal fun applyTlsSettings(
        tls: SSLSocket,
        item: ProfileItem,
        enabledProtocols: Array<String>? = null,
    ) {
        val params: SSLParameters = tls.sslParameters
        val sni = item.sni.ifBlank { item.address }
        if (!AddrCodec.isIpLiteral(sni)) {
            runCatching { params.serverNames = listOf(SNIHostName(sni)) }
        }
        if (item.alpn.isNotBlank()) {
            val protocols = item.alpn.split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toTypedArray()
            if (protocols.isNotEmpty()) {
                // API 29+ only; older runtimes ignore ALPN.
                runCatching { params.applicationProtocols = protocols }
            }
        }
        tls.sslParameters = params
        val protocols = enabledProtocols ?: DEFAULT_TLS_PROTOCOLS
        runCatching { tls.enabledProtocols = protocols }
            .onFailure {
                DialLog.log(
                    "TLS",
                    "versi TLS ${protocols.joinToString(",")} tidak didukung — lanjut negosiasi",
                )
            }
    }
}
