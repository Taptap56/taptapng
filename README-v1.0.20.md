# TaptapNG v1.0.20 (entry Onering konek lagi — perbaikan regresi v1.0.19)

Rilis 24 November 2026. APK `taptapng-v1.0.20.apk` (vc21, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
3 tes unit baru `OneringTlsTest` ditambahkan (dijalankan CI, Gradle
diblokir di VM), plus seluruh regresi yang sudah ada.

## Yang diperbaiki

### Regresi — Entry Onering gagal TLS di v1.0.19: SELESAI

Di v1.0.19, semua entry Onering (mis. iflix: VMess · ws · TLS ·
Onering) gagal konek: log HP 2026-11-24 01:20 mencatat 4x
`TLS gagal: Domain specific configurations require that hostname
aware checkServerTrusted(X509Certificate[], String, String) is
used`. Di v1.0.18 entry yang sama konek normal — ini regresi
v1.0.19, bukan masalah server atau jendela prime.

- **Akar penyebab:** `network_security_config.xml` v1.0.19
  menambahkan `<domain-config>` (untuk cleartext dashboard lokal).
  Sejak ada domain-config, `NetworkSecurityTrustManager` Android
  MENOLAK pemanggilan 2-arg
  `checkServerTrusted(chain, authType)` dan menuntut versi
  hostname-aware 3-arg. Satu-satunya pemanggil 2-arg ke platform
  TrustManager di codebase adalah `OneringTls.kt` di
  `bcTlsAuthentication` — dipakai semua entry Onering. Jalur plain
  selamat karena Conscrypt memanggil versi 3-arg sendiri dengan
  peer host; prime dial pakai trustAllContext sendiri.
- **Perbaikan:** `bcTlsAuthentication` kini menerima hostname
  (SNI / domain asli, sudah ada di `OneringTlsClient`) dan memanggil
  `checkServerTrusted(chain, authType, hostname)` pada
  `X509ExtendedTrustManager` — dengan `as?` + fallback ke 2-arg
  bila TrustManager-nya bukan extended (test double / trust-all),
  tanpa `as` buta. `network_security_config.xml` TIDAK diubah.
- **Perilaku verifikasi berubah (disengaja):** sebelumnya sertifikat
  hanya dicek rantainya tanpa verifikasi hostname; kini hostname
  diverifikasi terhadap SNI domain asli. Untuk Onering itu benar —
  SNI adalah domain asli dan sertifikat edge diterbitkan untuk
  domain itu (mis. SNI `d3vaf207v45s96.cloudfront.net`, sertifikat
  `*.cloudfront.net`). Entry Onering yang sertifikatnya TIDAK cocok
  dengan SNI-nya kini ditolak — itu perilaku yang diinginkan,
  bukan bug.
- **Tes:** `OneringTlsTest` — (1) overload 3-arg dipanggil tepat
  1x dengan hostname = SNI (`RecordingExtendedTrustManager`);
  (2) fallback 2-arg saat TrustManager bukan extended
  (`RecordingPlainTrustManager`, handshake tetap jalan);
  (3) sertifikat yang tidak cocok hostname ditolak (SNI
  `support.zoom.us` vs sertifikat tes `localhost`). Tes validasi
  platform yang sudah ada disesuaikan: SNI-nya kini `localhost`
  agar cocok dengan sertifikat tes.

## Catatan

- JVM tidak bisa mereproduksi penolakan 2-arg khas Android
  (TrustManager JDK bukan NetworkSecurityTrustManager) — bukti
  runtime-nya tetap log HP. Tes JVM membuktikan overload yang
  dipanggil dan perilaku verifikasinya, bukan penolakan itu sendiri.
- Tidak ada perubahan UI, rute, grup, atau perilaku non-Onering.
