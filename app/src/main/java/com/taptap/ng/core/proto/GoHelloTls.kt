package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.data.ProfileItem
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Collections
import java.util.Enumeration
import java.util.Hashtable
import javax.net.ssl.X509TrustManager
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ExtensionType
import org.bouncycastle.tls.NameType
import org.bouncycastle.tls.NamedGroup
import org.bouncycastle.tls.ProtocolName
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.ServerName
import org.bouncycastle.tls.SignatureScheme
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsUtils
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto

/**
 * Hello Go (v1.0.1): a ClientHello shaped like Go's crypto/tls DEFAULT
 * Hello — the dial v2rayNG's xray-core sends when the entry fingerprint
 * is empty. NOT Chrome (uTLS-Chrome already failed in TB v1.0.73/77)
 * and NOT a hand-rolled handshake: Bouncy Castle builds the Hello
 * itself from the overrides below, so the transcript stays consistent
 * (same machinery as OneringTls).
 *
 * REFERENCE (captured 2026-11-21, test resources hello127-*.bin):
 * a local Go 1.27.1 program dialling a raw TCP server with a plain
 * tls.Config (ServerName + optional ALPN). The libv2ray core in the
 * v2rayNG build is go1.27.1 and its main module says `go 1.27`, so
 * the MLKEM hybrids are ON by default (GODEBUG tlsmlkem unset):
 * supported_groups [X25519MLKEM768, SecP256r1MLKEM768,
 * SecP384r1MLKEM1024, X25519, P-256, P-384, P-521], key_share
 * [X25519MLKEM768 (1216 B) + X25519 fallback (32 B)], sigalgs
 * starting MLDSA44/65/87 (0x0904-0x0906), sigalgs_cert the same
 * list PLUS rsa_pkcs1_sha1 + ecdsa_sha1. Cipher suites (13, TLS 1.2
 * suites first, TLS 1.3 last — Go's preference order). Extensions
 * in Go's order: SNI, ec_point_formats, renegotiation_info,
 * extended_master_secret (empty), signed_certificate_timestamp
 * (empty), status_request, supported_groups, signature_algorithms,
 * signature_algorithms_cert, ALPN (when set), supported_versions,
 * key_share. Record version 0x0301, legacy_version 0x0303, random
 * 32-byte session id (compatibility mode).
 *
 * KNOWN DEVIATION (Bouncy Castle, not a bug in this code):
 * TlsProtocol.writeExtensionsData writes zero-length extensions
 * FIRST ("reports of servers that don't accept a zero-length
 * extension as the last one") — so extended_master_secret and
 * signed_certificate_timestamp, which Go writes 4th/5th, go first
 * here instead. Their RELATIVE order (EMS before SCT, as in Go)
 * is kept, the extension SET is identical, and every non-empty
 * extension is in Go's order. The test asserts exactly that.
 * If a DPI fingerprints by JA3 (extension order hashed), this
 * deviation changes the hash; if it checks the set/shape, it
 * matches. The phone test decides — this is an experiment, not a
 * guaranteed fix.
 */
object GoHelloTls {

    /** Go 1.27 crypto/tls default cipher suites, preference order
     *  (TLS 1.2 ECDHE first, TLS 1.3 last — NOT sorted by version). */
    val CIPHER_SUITES: IntArray = intArrayOf(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xc02b
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 0xc02f
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 0xc02c
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 0xc030
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca8
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // 0xc009
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // 0xc013
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // 0xc00a
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // 0xc014
        CipherSuite.TLS_AES_128_GCM_SHA256, // 0x1301
        CipherSuite.TLS_AES_256_GCM_SHA384, // 0x1302
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256, // 0x1303
    )

    /** Go 1.27 default supported groups, preference order
     *  (PQ hybrids first — X25519MLKEM768 is the key-share group). */
    val SUPPORTED_GROUPS: IntArray = intArrayOf(
        NamedGroup.X25519MLKEM768, // 0x11ec
        NamedGroup.SecP256r1MLKEM768, // 0x11eb
        NamedGroup.SecP384r1MLKEM1024, // 0x11ed
        NamedGroup.x25519, // 0x001d
        NamedGroup.secp256r1, // 0x0017
        NamedGroup.secp384r1, // 0x0018
        NamedGroup.secp521r1, // 0x0019
    )

    /** Go sends key shares for the first group plus an X25519
     *  fallback share (the hybrid's second half). */
    val EARLY_KEY_SHARE_GROUPS: IntArray = intArrayOf(
        NamedGroup.X25519MLKEM768,
        NamedGroup.x25519,
    )

    /** Go 1.27 default signature_algorithms (NO SHA-1 here). */
    val SIGNATURE_ALGORITHMS: IntArray = intArrayOf(
        SignatureScheme.mldsa44, // 0x0904
        SignatureScheme.mldsa65, // 0x0905
        SignatureScheme.mldsa87, // 0x0906
        SignatureScheme.rsa_pss_rsae_sha256, // 0x0804
        SignatureScheme.ecdsa_secp256r1_sha256, // 0x0403
        SignatureScheme.ed25519, // 0x0807
        SignatureScheme.rsa_pss_rsae_sha384, // 0x0805
        SignatureScheme.rsa_pss_rsae_sha512, // 0x0806
        SignatureScheme.rsa_pkcs1_sha256, // 0x0401
        SignatureScheme.rsa_pkcs1_sha384, // 0x0501
        SignatureScheme.rsa_pkcs1_sha512, // 0x0601
        SignatureScheme.ecdsa_secp384r1_sha384, // 0x0503
        SignatureScheme.ecdsa_secp521r1_sha512, // 0x0603
    )

    /** Go's signature_algorithms_cert: the same list PLUS the two
     *  SHA-1 schemes (Go advertises them for certificates only). */
    val SIGNATURE_ALGORITHMS_CERT: IntArray = SIGNATURE_ALGORITHMS +
        intArrayOf(SignatureScheme.rsa_pkcs1_sha1, SignatureScheme.ecdsa_sha1)

    /** Go's ClientHello extension order (wire order). Bouncy Castle
     *  reorders the two zero-length extensions (0x0017, 0x0012) to
     *  the front — see the class doc — everything else follows
     *  this list. */
    val EXTENSION_ORDER: IntArray = intArrayOf(
        ExtensionType.server_name, // 0x0000
        ExtensionType.ec_point_formats, // 0x000b
        ExtensionType.renegotiation_info, // 0xff01
        ExtensionType.extended_master_secret, // 0x0017 (empty)
        ExtensionType.signed_certificate_timestamp, // 0x0012 (empty)
        ExtensionType.status_request, // 0x0005
        ExtensionType.supported_groups, // 0x000a
        ExtensionType.signature_algorithms, // 0x000d
        ExtensionType.signature_algorithms_cert, // 0x0032
        ExtensionType.application_layer_protocol_negotiation, // 0x0010
        ExtensionType.supported_versions, // 0x002b
        ExtensionType.key_share, // 0x0033
    )

    /** True when this entry must ride the Go Hello path. */
    fun isGoHello(item: ProfileItem): Boolean = item.goHelloEnabled

    /**
     * Result of a Go Hello handshake: the encrypted streams plus
     * the negotiated TLS version (the prime dial needs it for its
     * PRIME OK line; Transport only needs the streams).
     */
    data class Handshake(
        val input: InputStream,
        val output: OutputStream,
        val protocol: String,
    )

    fun wrap(
        input: InputStream,
        output: OutputStream,
        item: ProfileItem,
        trustManager: X509TrustManager? = null,
    ): Handshake {
        val sni = item.sni.ifBlank { item.address }
        val crypto = BcTlsCrypto(SecureRandom())
        val protocol = TlsClientProtocol(input, output)
        val client = GoHelloTlsClient(crypto, sni, item.alpn, item.insecure, trustManager)
        protocol.connect(client)
        val version = client.negotiatedVersion
        val protocolName = when (version) {
            ProtocolVersion.TLSv13 -> "TLS 1.3"
            ProtocolVersion.TLSv12 -> "TLS 1.2"
            null -> "TLS?"
            else -> version.toString()
        }
        DialLog.log("TLS", "GoHello ${item.address} ok (SNI $sni, $protocolName)")
        return Handshake(protocol.inputStream, protocol.outputStream, protocolName)
    }
}

/**
 * A Hashtable whose keys() enumeration follows Go's extension
 * order (see [GoHelloTls.EXTENSION_ORDER]) for the extensions
 * present, with any unexpected extras appended last (never
 * dropped). Bouncy Castle calls keys() twice — empty extensions
 * first, then non-empty — so the two zero-length extensions
 * (0x0017, 0x0012) still come out first, in Go's relative order;
 * the non-empty ones come out in Go's order (same trick as
 * [OrderedExtensions], which puts 0xff00 first for Onering).
 */
internal class GoOrderedExtensions : Hashtable<Int, ByteArray>() {

    @Synchronized
    override fun keys(): Enumeration<Int> {
        val present = super.keys().toList().toSet()
        val ordered = GoHelloTls.EXTENSION_ORDER.filter { it in present }.toMutableList()
        ordered += present.filter { it !in GoHelloTls.EXTENSION_ORDER }
        return Collections.enumeration(ordered)
    }
}

/**
 * Bouncy Castle TLS client sending Go's default ClientHello:
 * Go's cipher suites/groups/signature algorithms/versions, SNI =
 * the entry's SNI (or address), ALPN = item.alpn. Certificate
 * validation mirrors TlsUtil (see [bcTlsAuthentication]).
 */
internal class GoHelloTlsClient(
    crypto: org.bouncycastle.tls.crypto.TlsCrypto,
    private val sni: String,
    private val alpn: String,
    private val insecure: Boolean,
    private val trustManager: X509TrustManager? = null,
) : DefaultTlsClient(crypto) {

    /** Negotiated TLS version, recorded by [notifyServerVersion]. */
    @Volatile
    var negotiatedVersion: ProtocolVersion? = null
        private set

    override fun notifyServerVersion(serverVersion: ProtocolVersion) {
        negotiatedVersion = serverVersion
    }

    override fun getSupportedVersions(): Array<ProtocolVersion> =
        arrayOf(ProtocolVersion.TLSv13, ProtocolVersion.TLSv12)

    override fun getSupportedCipherSuites(): IntArray =
        TlsUtils.getSupportedCipherSuites(crypto, GoHelloTls.CIPHER_SUITES)

    override fun getSupportedGroups(namedGroupRoles: java.util.Vector<*>?): java.util.Vector<*>? {
        val groups = java.util.Vector<Int>()
        GoHelloTls.SUPPORTED_GROUPS.forEach { groups.add(it) }
        return groups
    }

    override fun getEarlyKeyShareGroups(): java.util.Vector<*>? {
        val groups = java.util.Vector<Int>()
        GoHelloTls.EARLY_KEY_SHARE_GROUPS.forEach { groups.add(it) }
        return groups
    }

    override fun getSupportedSignatureAlgorithms(): java.util.Vector<*>? {
        val algs = java.util.Vector<Int>()
        GoHelloTls.SIGNATURE_ALGORITHMS.forEach { algs.add(it) }
        return algs
    }

    override fun getSupportedSignatureAlgorithmsCert(): java.util.Vector<*>? {
        val algs = java.util.Vector<Int>()
        GoHelloTls.SIGNATURE_ALGORITHMS_CERT.forEach { algs.add(it) }
        return algs
    }

    override fun getSNIServerNames(): java.util.Vector<*>? {
        // null (not an empty Vector) = omit the SNI extension entirely
        // (same contract as OneringTlsClient).
        if (sni.isBlank() || AddrCodec.isIpLiteral(sni)) return null
        val names = java.util.Vector<ServerName>()
        names.add(ServerName(NameType.host_name, sni.toByteArray(Charsets.US_ASCII)))
        return names
    }

    override fun getProtocolNames(): java.util.Vector<*>? {
        // null when ALPN is blank: BC rejects an empty Vector with
        // TlsFatalAlert internal_error (same trap as OneringTlsClient).
        if (alpn.isBlank()) return null
        val names = java.util.Vector<ProtocolName>()
        alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
            names.add(ProtocolName.asUtf8Encoding(it))
        }
        return names
    }

    override fun getClientExtensions(): Hashtable<*, *> {
        @Suppress("UNCHECKED_CAST")
        val base = super.getClientExtensions() as Hashtable<Int, ByteArray>
        // Go does NOT send encrypt_then_mac (0x0016); BC adds it
        // whenever TLS 1.2 is offered — remove it.
        base.remove(ExtensionType.encrypt_then_mac)
        // Go sends an empty renegotiation_info extension (one 0x00
        // byte = empty renegotiated_connection) instead of the
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite — adding
        // it here also stops BC appending the SCSV (see
        // TlsClientProtocol.sendClientHello).
        base[ExtensionType.renegotiation_info] = byteArrayOf(0)
        // Go sends an empty signed_certificate_timestamp extension;
        // BC never adds it — add it here.
        base[ExtensionType.signed_certificate_timestamp] = ByteArray(0)
        // extended_master_secret (0x0017, empty) is added by the
        // protocol itself (shouldUseExtendedMasterSecret) — it is
        // picked up by GoOrderedExtensions.keys() like
        // supported_versions and key_share.
        val ordered = GoOrderedExtensions()
        ordered.putAll(base)
        return ordered
    }

    override fun getAuthentication(): org.bouncycastle.tls.TlsAuthentication =
        bcTlsAuthentication(insecure, trustManager)
}
