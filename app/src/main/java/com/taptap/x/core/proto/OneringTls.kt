package com.taptap.x.core.proto

import com.taptap.x.core.DialLog
import com.taptap.x.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.Enumeration
import java.util.Hashtable
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.NameType
import org.bouncycastle.tls.ProtocolName
import org.bouncycastle.tls.ServerName
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto

/**
 * Onering (M4, v1.0.23): the bug domain rides in TLS extension 0xff00,
 * FIRST in the ClientHello; the standard SNI stays the real domain.
 * Format: SNI `onering:<real>:<bug>` (same as the TC mihomo fork,
 * v2rayNG Onering and TaptapPing v1.6.3 — so servers copy both ways).
 *
 * WHY Bouncy Castle, and why NOT the other two options:
 * - SSLSocket/SSLEngine (platform TLS) expose NO custom-extension API:
 *   there is no way to add 0xff00 through javax.net.ssl at all.
 * - Patching the ClientHello bytes AFTER SSLEngine generates them
 *   breaks the TLS transcript hash: the engine computes Finished
 *   over the ORIGINAL ClientHello while the server sees the MODIFIED
 *   one, so the handshake fails on both TLS 1.2 and 1.3. Any code
 *   that claims to do this is faking it.
 * - Bouncy Castle's TLS client builds the ClientHello itself from
 *   getClientExtensions(), so the 0xff00 extension is part of the
 *   transcript from the start — the handshake stays consistent.
 *   BC serializes extensions by iterating Hashtable.keys(), so the
 *   ordering is forced with [OrderedExtensions] (0xff00 first);
 *   TlsExtensionsUtils.ensureExtensionsInitialised does NOT copy the
 *   table, so the ordering survives into sendClientHello.
 *   Crypto is BC's own implementation ([BcTlsCrypto]), NOT the
 *   platform JCA ([JcaTlsCryptoProvider]): the JCA path delegates
 *   the TLS 1.3 CertificateVerify signature to the platform under
 *   BC's algorithm name "SHA256WITHRSAANDMGF1" (rsa_pss_rsae_sha256),
 *   which no platform provider registers, so the handshake dies
 *   with NoSuchAlgorithmException -> TlsFatalAlert internal_error(80)
 *   against any RSA server (proven by the 44722503904 CI failure +
 *   a local JVM repro, 2026-11-20). BcTlsCrypto verifies natively
 *   inside BC — no provider registration, no reflection. bcprov
 *   is still on the classpath (transitive dep of bctls via bcutil)
 *   because BcTlsCrypto's algorithm implementations live there; R8 keeps
 *   only what is reachable. Certificate validation itself still
 *   uses the platform TrustManager (see getAuthentication).
 *   (APK size is checked on every release build.)
 *
 * The 0xff00 extension DATA is byte-identical to the TC fork
 * (`oneringBugExtensionData`, port of dharak36/xray-onering,
 * DeemXray-proven 2026-11-17): a server_name_list holding the bug
 * domain — list_len (2B) + name_type 0 (1B) + host_len (2B) + bug.
 * The DPI reads the bug from the first extension; the proxy server
 * reads the real domain from the standard SNI (type 0x0000).
 *
 * Onering still needs priming when the operator window is closed —
 * it is a bug carrier, not a primer (see the M4 milestone notes).
 */
object OneringHello {

    /** Custom TLS extension type carrying the bug domain. */
    const val EXTENSION_TYPE = 0xff00

    /**
     * Build the 0xff00 extension data for [bug], byte-identical to
     * the TC fork's oneringBugExtensionData: list_len (2B BE) +
     * name_type 0 (1B) + host_len (2B BE) + bug (ASCII).
     */
    fun bugExtensionData(bug: String): ByteArray {
        require(bug.isNotBlank()) { "Bug domain Onering kosong" }
        require(bug.all { it.code < 128 }) { "Bug domain harus ASCII: $bug" }
        require(!bug.contains(':')) { "Bug domain tidak boleh mengandung ':': $bug" }
        val bytes = bug.toByteArray(Charsets.US_ASCII)
        require(bytes.size <= 253) { "Bug domain terlalu panjang: ${bytes.size} byte" }
        val listLen = 3 + bytes.size
        val out = ByteArray(5 + bytes.size)
        out[0] = (listLen shr 8).toByte()
        out[1] = listLen.toByte()
        out[2] = 0 // name_type host_name
        out[3] = (bytes.size shr 8).toByte()
        out[4] = bytes.size.toByte()
        bytes.copyInto(out, 5)
        return out
    }

    /**
     * Decode the bug domain back out of 0xff00 extension data, or
     * null when the bytes are not a well-formed bug list. Used by
     * tests (and the log) to prove what actually went on the wire.
     */
    fun parseBugExtensionData(data: ByteArray): String? {
        if (data.size < 5) return null
        val listLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (listLen != data.size - 2) return null
        if (data[2] != 0.toByte()) return null
        val hostLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        if (hostLen != data.size - 5) return null
        return data.copyOfRange(5, data.size).toString(Charsets.US_ASCII)
    }
}

/**
 * A Hashtable whose keys() enumeration puts the Onering extension
 * FIRST, then the rest in natural Hashtable order. Bouncy Castle
 * writes ClientHello extensions by iterating keys() (twice: empty
 * extensions first, then non-empty — see TlsProtocol
 * .writeSelectedExtensions), so this is what decides the wire order.
 * get()/put()/remove() behave like a plain Hashtable; the order is
 * computed live on every keys() call, so extensions BC adds later
 * (supported_versions, key_share) are picked up too, after 0xff00.
 */
internal class OrderedExtensions : Hashtable<Int, ByteArray>() {

    @Synchronized
    override fun keys(): Enumeration<Int> {
        val rest = super.keys().toList().filter { it != OneringHello.EXTENSION_TYPE }
        val ordered = if (containsKey(OneringHello.EXTENSION_TYPE)) {
            listOf(OneringHello.EXTENSION_TYPE) + rest
        } else {
            rest
        }
        return Collections.enumeration(ordered)
    }
}

/**
 * Bouncy Castle TLS client for an Onering entry: SNI = real domain,
 * ALPN = item.alpn, and the 0xff00 bug extension first. Certificate
 * validation mirrors TlsUtil: trust-all when insecure, otherwise the
 * platform default TrustManager (no hostname verification — a raw
 * TLS client has none, same as the SSLSocket path).
 */
internal class OneringTlsClient(
    crypto: org.bouncycastle.tls.crypto.TlsCrypto,
    private val sni: String,
    private val alpn: String,
    private val bug: String,
    private val insecure: Boolean,
    private val trustManager: X509TrustManager? = null,
) : DefaultTlsClient(crypto) {

    private fun defaultTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    override fun getSNIServerNames(): java.util.Vector<*> {
        // SNI = real domain only (an IP literal gets no SNI, like TlsUtil).
        if (sni.isBlank() || AddrCodec.isIpLiteral(sni)) return java.util.Vector<ServerName>()
        val names = java.util.Vector<ServerName>()
        names.add(ServerName(NameType.host_name, sni.toByteArray(Charsets.US_ASCII)))
        return names
    }

    override fun getProtocolNames(): java.util.Vector<*> {
        if (alpn.isBlank()) return java.util.Vector<ProtocolName>()
        val names = java.util.Vector<ProtocolName>()
        alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
            names.add(ProtocolName.asUtf8Encoding(it))
        }
        return names
    }

    override fun getClientExtensions(): Hashtable<*, *> {
        @Suppress("UNCHECKED_CAST")
        val base = super.getClientExtensions() as Hashtable<Int, ByteArray>
        val ordered = OrderedExtensions()
        ordered.putAll(base)
        ordered[OneringHello.EXTENSION_TYPE] = OneringHello.bugExtensionData(bug)
        return ordered
    }

    override fun getAuthentication(): TlsAuthentication {
        return object : TlsAuthentication {
            override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                if (insecure) return
                val chain = serverCertificate.certificate.certificateList
                if (chain.isEmpty()) throw IOException("Sertifikat server kosong")
                val cf = CertificateFactory.getInstance("X.509")
                val x509 = chain.map { tlsCert ->
                    cf.generateCertificate(
                        ByteArrayInputStream(
                            (tlsCert as org.bouncycastle.tls.crypto.TlsCertificate).encoded,
                        ),
                    ) as X509Certificate
                }.toTypedArray()
                val authType = when (x509[0].publicKey.algorithm) {
                    "EC" -> "ECDSA"
                    "RSA" -> "RSA"
                    else -> x509[0].publicKey.algorithm
                }
                (trustManager ?: defaultTrustManager()).checkServerTrusted(x509, authType)
            }

            override fun getClientCredentials(
                certificateRequest: CertificateRequest,
            ): TlsCredentials? = null
        }
    }
}

/**
 * Run a Bouncy Castle TLS handshake over (input, output) for an
 * Onering entry and return the encrypted (tlsInput, tlsOutput) pair.
 * The caller owns the underlying streams: closing them closes the
 * TLS session (no separate close_notify is sent on a bare socket
 * close — the connection is ending anyway).
 *
 * Timeouts: the handshake read blocks on [input] — the caller
 * bounds it with the socket SO_TIMEOUT (Transport sets
 * HANDSHAKE_TIMEOUT_MS before TLS) and the DialWatchdog.
 */
object OneringTls {

    /** True when this entry must ride the Onering TLS path. */
    fun isOnering(item: ProfileItem): Boolean =
        item.oneringEnabled && item.oneringBug.isNotBlank()

    fun wrap(
        input: InputStream,
        output: OutputStream,
        item: ProfileItem,
        trustManager: X509TrustManager? = null,
    ): Pair<InputStream, OutputStream> {
        val sni = item.sni.ifBlank { item.address }
        val bug = item.oneringBug.trim()
        require(bug.isNotBlank()) { "Bug domain Onering kosong" }
        val crypto = BcTlsCrypto(SecureRandom())
        val protocol = TlsClientProtocol(input, output)
        val client = OneringTlsClient(crypto, sni, item.alpn, bug, item.insecure, trustManager)
        protocol.connect(client)
        DialLog.log("TLS", "Onering ${item.address} ok (bug $bug, SNI $sni)")
        return protocol.inputStream to protocol.outputStream
    }
}
