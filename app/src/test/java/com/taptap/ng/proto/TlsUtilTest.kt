package com.taptap.ng.proto

import com.taptap.ng.core.proto.TlsUtil
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.4 (review Claude atas v1.0.3): XVEON mempersempit protokol
 * TLS ke 1.3 + 1.2 (dex d9.txt:678 calls setEnabledProtocols), jadi
 * TaptapNG ikut mempersempit — default platform di Android modern
 * sudah pasangan yang sama, jadi ini hanya mempersempit runtime
 * lama yang masih menawarkan TLS 1.0/1.1.
 *
 * Yang TIDAK di-port dari (1d): ALPN default "http/1.1 untuk ws"
 * dan setUseSessionTickets — verifikasi dex (d9.txt) tidak
 * menemukan setApplicationProtocols maupun setUseSessionTickets di
 * XVEON, jadi keduanya tetap inferensi dan tidak diimplementasikan
 * sebagai perbaikan terbukti. Tes di bawah mengunci perilaku itu:
 * entry tanpa alpn TIDAK mengirim ALPN.
 */
class TlsUtilTest {

    private fun item(alpn: String = "", sni: String = "") = ProfileItem(
        configType = ConfigType.VMESS,
        address = "example.com",
        port = 443,
        uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
        network = "ws",
        tls = true,
        sni = sni,
        alpn = alpn,
    )

    private fun unconnectedSocket(): SSLSocket =
        SSLSocketFactory.getDefault().createSocket() as SSLSocket

    @Test
    fun `default protocols are TLS 1 dot 3 and 1 dot 2`() {
        val socket = unconnectedSocket()
        try {
            TlsUtil.applyTlsSettings(socket, item())
            assertArrayEquals(arrayOf("TLSv1.3", "TLSv1.2"), socket.enabledProtocols)
        } finally {
            runCatching { socket.close() }
        }
    }

    @Test
    fun `explicit protocols override the default`() {
        // SSH TLS version forcing (v1.0.30) tetap menang atas default.
        val socket = unconnectedSocket()
        try {
            TlsUtil.applyTlsSettings(socket, item(), arrayOf("TLSv1.2"))
            assertArrayEquals(arrayOf("TLSv1.2"), socket.enabledProtocols)
        } finally {
            runCatching { socket.close() }
        }
    }

    @Test
    fun `no ALPN when the entry leaves alpn blank`() {
        // v1.0.4: tidak ada ALPN default. Entry tanpa alpn tidak
        // mengirim ekstensi ALPN — sama seperti v1.0.3.
        val socket = unconnectedSocket()
        try {
            TlsUtil.applyTlsSettings(socket, item())
            assertTrue(
                socket.sslParameters.applicationProtocols.isEmpty(),
                "tanpa alpn, applicationProtocols harus kosong",
            )
        } finally {
            runCatching { socket.close() }
        }
    }

    @Test
    fun `alpn from the entry is applied`() {
        val socket = unconnectedSocket()
        try {
            TlsUtil.applyTlsSettings(socket, item(alpn = "http/1.1"))
            assertArrayEquals(
                arrayOf("http/1.1"),
                socket.sslParameters.applicationProtocols,
            )
        } finally {
            runCatching { socket.close() }
        }
    }

    @Test
    fun `sni defaults to the address`() {
        val socket = unconnectedSocket()
        try {
            TlsUtil.applyTlsSettings(socket, item())
            val names = socket.sslParameters.serverNames
            assertEquals(1, names.size)
            assertEquals("example.com", (names[0] as SNIHostName).hostName)
        } finally {
            runCatching { socket.close() }
        }
    }
}
