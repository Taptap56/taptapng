package com.taptap.x.core.proto

import com.taptap.x.data.ProfileItem
import java.io.ByteArrayOutputStream

/**
 * The probe's first body bytes (v1.0.8, fix B).
 *
 * Why a probe needs a body at all: the xray-core VMess/VLESS server
 * buffers its response header in a `buf.BufferedWriter` and only
 * flushes it (`SetBuffered(false)`) AFTER reading the first data
 * from the dispatch target (`transferResponse` reads
 * `link.Reader` first — proxy/vmess/inbound/inbound.go). The probe
 * targets the entry itself, and the entry's :443 is a TLS server: it
 * sends nothing until spoken to. Probe sends no body + target sends
 * nothing = deadlock, and the client reads the response header until
 * its 10 s timeout (phone proof, taptapx-5.txt: DNS/TCP/TLS/WS all
 * "ok", then "VMess gagal: Read timed out" ~10 s later, on both
 * entries — while the same entries connect in v2rayNG, where real
 * app traffic flows as the body). The VMess header/KDF are proven
 * correct by the same log: a bad header/UUID makes the server close
 * the connection (fast EOF), not a 10 s timeout.
 *
 * So the probe speaks first: a minimal TLS 1.2 ClientHello when the
 * entry uses TLS (the target answers with a ServerHello), a minimal
 * HTTP GET otherwise. The body is only sent on PROBE dials (see
 * [ProxyClient.dial]); relay dials pass null and stay byte-exact.
 */
object ProbeBody {

    /** First body bytes for a probe dial of [item]. */
    fun forEntry(item: ProfileItem): ByteArray =
        if (item.tls) clientHello(sniHost(item)) else httpGet(item.address, item.port)

    /** SNI for the ClientHello: the entry's address when it is a
     *  domain; IP literals carry no SNI. */
    fun sniHost(item: ProfileItem): String? =
        if (AddrCodec.isIpLiteral(item.address)) null else item.address

    /** Minimal HTTP/1.0 GET (for non-TLS probe targets). */
    fun httpGet(host: String, port: Int): ByteArray {
        val hostHeader = if (port == 80) host else "$host:$port"
        return "GET / HTTP/1.0\r\nHost: $hostHeader\r\n\r\n"
            .toByteArray(Charsets.UTF_8)
    }

    /**
     * Minimal but valid TLS 1.2 ClientHello. SNI is included when
     * [sni] is a domain; the cipher list and extensions are the
     * small standard set any TLS server answers with a ServerHello
     * (or an alert — either is data, which is all the probe needs
     * to unblock the server's response-header flush).
     */
    fun clientHello(sni: String?): ByteArray {
        val hs = ByteArrayOutputStream()
        hs.write(0x01) // handshake type: ClientHello
        val body = ByteArrayOutputStream()
        body.write(0x03)
        body.write(0x03) // version TLS 1.2
        body.write(Crypto.randomBytes(32)) // random
        body.write(0x00) // session id length
        val suites = intArrayOf(
            0x1301, 0x1302, 0x1303, // TLS 1.3
            0xC02F, 0xC030, 0xC02B, 0xC02C, // ECDHE + AES-GCM
            0x009E, 0x009F, // DHE + AES-GCM
        )
        body.writeU16(suites.size * 2)
        suites.forEach { body.writeU16(it) }
        body.write(0x01) // compression methods length
        body.write(0x00) // null compression
        val exts = ByteArrayOutputStream()
        if (sni != null) {
            val name = sni.toByteArray(Charsets.UTF_8)
            val entry = ByteArrayOutputStream()
            entry.write(0x00) // host_name
            entry.writeU16(name.size)
            entry.write(name)
            // server_name data = list length (2) + entry; the 2-byte
            // prefix is mandatory (RFC 6066) — without it the hello
            // is malformed and a strict server answers nothing.
            val list = ByteArrayOutputStream()
            list.writeU16(entry.size())
            list.write(entry.toByteArray())
            exts.writeU16(0x0000) // server_name
            exts.writeU16(list.size())
            exts.write(list.toByteArray())
        }
        // supported_groups: x25519, secp256r1
        exts.writeU16(0x000A)
        exts.writeU16(6)
        exts.writeU16(4)
        exts.writeU16(0x001D)
        exts.writeU16(0x0017)
        // signature_algorithms
        exts.writeU16(0x000D)
        exts.writeU16(8)
        exts.writeU16(6)
        exts.writeU16(0x0403)
        exts.writeU16(0x0503)
        exts.writeU16(0x0804)
        // supported_versions: TLS 1.3, TLS 1.2
        exts.writeU16(0x002B)
        exts.writeU16(5)
        exts.write(4)
        exts.writeU16(0x0304)
        exts.writeU16(0x0303)
        body.writeU16(exts.size())
        body.write(exts.toByteArray())
        val bodyBytes = body.toByteArray()
        hs.writeU24(bodyBytes.size)
        hs.write(bodyBytes)
        val hsBytes = hs.toByteArray()
        val rec = ByteArrayOutputStream()
        rec.write(0x16) // record type: handshake
        rec.write(0x03)
        rec.write(0x01) // record version TLS 1.0
        rec.writeU16(hsBytes.size)
        rec.write(hsBytes)
        return rec.toByteArray()
    }

    private fun ByteArrayOutputStream.writeU16(v: Int) {
        write((v ushr 8) and 0xFF)
        write(v and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU24(v: Int) {
        write((v ushr 16) and 0xFF)
        write((v ushr 8) and 0xFF)
        write(v and 0xFF)
    }
}
