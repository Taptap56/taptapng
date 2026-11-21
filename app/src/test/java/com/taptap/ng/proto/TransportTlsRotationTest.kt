package com.taptap.ng.proto

import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.Transport
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.4 (review Claude atas v1.0.3): setelah TLS timeout, dial
 * berikutnya harus merotasi ke alamat berikutnya di cache — log HP
 * 09:35 menunjukkan dial utama memakai IP yang sama persis dengan
 * yang baru saja gagal TLS di prime (cache hit, tanpa rotasi).
 *
 * Rotasi penuh (dial → timeout → alamat berikutnya) tidak bisa
 * diuji di JVM: handshake SSLSocket ke loopback di-reset di
 * lingkungan tes, jadi timeout 10 dtk sungguhan tidak pernah
 * terjadi. Yang diuji di sini adalah keputusan rotasinya
 * ([Transport.shouldRotateAfterTlsFailure]) + rotasi di
 * DnsResolver (DnsResolverTest); pemakaian predikat di catch TLS
 * [Transport.open] diverifikasi dari kode.
 */
class TransportTlsRotationTest {

    @Test
    fun `read timeout rotates`() {
        assertTrue(
            Transport.shouldRotateAfterTlsFailure(
                SocketTimeoutException("Read timed out"),
            ),
        )
    }

    @Test
    fun `certificate and other TLS failures do not rotate`() {
        // Bukan soal IP: sertifikat salah akan salah juga di IP
        // berikutnya; merotasi hanya membuang satu alamat bagus.
        assertFalse(
            Transport.shouldRotateAfterTlsFailure(
                SSLException("certificate unknown"),
            ),
        )
        assertFalse(
            Transport.shouldRotateAfterTlsFailure(
                IOException("Connection reset"),
            ),
        )
    }

    @Test
    fun `fired watchdog counts as a TLS timeout even for SocketException`() {
        // Watchdog menutup socket saat dial stuck — handshake
        // melempar SocketException ("Socket closed"), bukan timeout.
        // Tanpa watchdog yang meledak, SocketException ini TIDAK
        // merotasi (lihat tes di atas).
        val watchdog = DialWatchdog(timeoutMs = 50)
        Transport.setThreadWatchdog(watchdog)
        try {
            watchdog.start()
            val deadline = System.currentTimeMillis() + 2000
            while (!watchdog.fired && System.currentTimeMillis() < deadline) {
                Thread.sleep(10)
            }
            assertTrue(watchdog.fired, "watchdog harus meledak dalam 2 dtk")
            assertTrue(
                Transport.shouldRotateAfterTlsFailure(
                    SocketException("Socket closed"),
                ),
            )
        } finally {
            watchdog.stop()
            Transport.setThreadWatchdog(null)
        }
    }
}
