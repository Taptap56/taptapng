package com.taptap.x.core

import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Fetches a server's leaf certificate SHA-256 fingerprint with a plain
 * TLS dial (no xray-core): SSLSocket to address:port, SNI from the
 * editor's SNI field (skipped for IP literals), trust-all (the point
 * is to read whatever certificate the server presents, not to validate
 * the chain). Runs on its own thread; the result arrives on [callback]
 * (null = failure, the pcs field is left untouched then).
 * Never logs certificates or credentials.
 */
object CertFingerprintFetcher {

    private const val TIMEOUT_MS = 5000

    fun fetch(host: String, port: Int, sni: String?, callback: (String?) -> Unit) {
        Thread {
            val result = runCatching { fetchSync(host, port, sni) }.getOrNull()
            callback(result)
        }.start()
    }

    private fun fetchSync(host: String, port: Int, sni: String?): String? {
        val trustAll = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            }
        )
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        val socket = ctx.socketFactory.createSocket() as SSLSocket
        try {
            socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            socket.soTimeout = TIMEOUT_MS
            val sniName = sni?.trim().orEmpty()
            if (sniName.isNotBlank() && !isIpLiteral(sniName)) {
                val params = SSLParameters()
                params.serverNames = listOf(javax.net.ssl.SNIHostName(sniName))
                socket.sslParameters = params
            }
            socket.startHandshake()
            val cert: Certificate = socket.session.peerCertificates.firstOrNull() ?: return null
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            return digest.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        } finally {
            runCatching { socket.close() }
        }
    }

    /** True for IPv4 / bracketed-or-bare IPv6 literals (SNI must be a DNS name). */
    internal fun isIpLiteral(value: String): Boolean {
        val v = value.trim().removeSurrounding("[", "]")
        if (v.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))) return true
        return v.contains(':') && v.matches(Regex("[0-9a-fA-F:]+"))
    }
}
