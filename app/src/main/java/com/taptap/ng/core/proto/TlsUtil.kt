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
 *   throws NoSuchMethodError and is silently ignored.
 * - insecure = trust-all certificates (user option, same meaning as
 *   v2rayNG "allowInsecure"). No hostname verification is done on a raw
 *   SSLSocket either way — verification only exists in HttpsURLConnection.
 * - The plain socket's SO_TIMEOUT is carried over as the handshake
 *   timeout; callers clear it after dial().
 */
object TlsUtil {

    private val trustAllContext: SSLContext by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }
    }

    fun wrap(plain: Socket, item: ProfileItem, enabledProtocols: Array<String>? = null): SSLSocket {
        val factory: SSLSocketFactory = if (item.insecure) {
            trustAllContext.socketFactory
        } else {
            SSLSocketFactory.getDefault() as SSLSocketFactory
        }
        val tls = factory.createSocket(plain, item.address, item.port, true) as SSLSocket
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
        if (enabledProtocols != null) {
            // v1.0.30: SSH TLS version forcing (sshSniVersion).
            // An unsupported name must never kill the dial — fall
            // back to negotiation and say so in the log.
            runCatching { tls.enabledProtocols = enabledProtocols }
                .onFailure {
                    DialLog.log(
                        "TLS",
                        "versi TLS ${enabledProtocols.joinToString(",")} tidak didukung — lanjut negosiasi",
                    )
                }
        }
        tls.soTimeout = Transport.HANDSHAKE_TIMEOUT_MS
        tls.startHandshake()
        // v1.0.2 (XVEON order): name the negotiated version —
        // "TLS established: TLSv1.3" — not just "TLS ok".
        DialLog.log("TLS", "TLS established: ${tls.session.protocol}")
        return tls
    }
}
