# TaptapNG v1.0.20 (dashboard kebuka + entry Onering konek lagi — perbaikan 2 regresi v1.0.19)

Rilis 24 November 2026. APK `taptapng-v1.0.20.apk` (vc21, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
4 tes unit baru `OneringTlsTest` + 4 tes `ClashApiServerBindTest`
ditambahkan (dijalankan CI, Gradle diblokir di VM), plus seluruh
regresi yang sudah ada.

## Yang diperbaiki

### Regresi — Dashboard tidak kebuka di v1.0.19: SELESAI

Di v1.0.18 tab Dashboard gagal dengan `ERR_CLEARTEXT_NOT_PERMITTED`;
di v1.0.19 cleartext-nya sudah benar tapi error BERUBAH jadi
`ERR_CONNECTION_REFUSED`. Log HP 2026-11-24 01:19 mencatat
`API Clash jalan di ::1:9091` — server Clash API bind ke `::1`
(IPv6 loopback), sedangkan URL dashboard hardcoded `127.0.0.1`.

- **Akar penyebab:** `ClashApiServer.kt` memakai
  `InetAddress.getLoopbackAddress()` saat `clashApiAllowLan` mati —
  di HP ini resolve ke `::1`, bukan `127.0.0.1`.
- **Perbaikan:** fungsi baru `bindAddress(allowLan)` bind eksplisit
  ke `InetAddress.getByName("127.0.0.1")` saat LAN mati; cabang LAN
  (`0.0.0.0`) tidak diubah. `network_security_config.xml` tidak
  diubah (cleartext loopback-only dari v1.0.19 tetap).
- **Tes:** `ClashApiServerBindTest` — (1) non-LAN = 127.0.0.1,
  (2) hasil bind IPv4 bukan IPv6, (3) LAN = 0.0.0.0,
  (4) host bind cocok dengan host URL dashboard.

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
  hostname-aware. Satu-satunya pemanggil 2-arg ke platform
  TrustManager di codebase adalah `OneringTls.kt` di
  `bcTlsAuthentication` — dipakai semua entry Onering. Jalur plain
  selamat karena Conscrypt memanggil versi hostname-aware sendiri dengan
  peer host; prime dial pakai trustAllContext sendiri.
- **Perbaikan (rework):** `bcTlsAuthentication` kini menerima hostname
  (SNI / domain asli, sudah ada di `OneringTlsClient`) dan memverifikasi
  lewat `android.net.http.X509TrustManagerExtensions` — API publik
  Android (sejak API 17; minSdk app 24) yang memang dibuat untuk kasus
  tanpa SSLEngine/SSLSocket, persis jalur raw-TLS Bouncy Castle ini:
  konstruktornya membungkus TrustManager platform, dan
  `checkServerTrusted(chain, authType, host)`-nya menggerakkan jalur
  hostname-aware TrustManager platform, termasuk penegakan
  domain-config. Bila konstruktor extensions melempar
  `IllegalArgumentException` (TrustManager bukan tipe platform yang
  didukung wrapper) atau hostname kosong, fallback ke 2-arg
  `checkServerTrusted(chain, authType)` — aman untuk TrustManager
  non-platform karena tidak ada domain-config yang ditegakkan.
  `network_security_config.xml` TIDAK diubah.
- **Koreksi premis:** percobaan v1.0.20 pertama memanggil overload
  3-arg `checkServerTrusted(chain, authType, hostname)` pada
  `X509ExtendedTrustManager` — overload itu TIDAK ADA
  (X509ExtendedTrustManager hanya punya overload 3-arg Socket dan
  SSLEngine), sehingga kode tidak compile (CI 45238965988,
  `:app:compileDebugKotlin`). Rework ini menggantinya dengan
  X509TrustManagerExtensions, yang memang API yang benar untuk
  kasus ini. Akar masalahnya tetap sama dan terbukti dari log HP:
  sejak ada `<domain-config>`, pemanggilan 2-arg ditolak platform.
- **Perilaku verifikasi berubah (disengaja):** sebelumnya sertifikat
  hanya dicek rantainya tanpa verifikasi hostname; kini hostname
  diverifikasi terhadap SNI domain asli. Untuk Onering itu benar —
  SNI adalah domain asli dan sertifikat edge diterbitkan untuk
  domain itu (mis. SNI `d3vaf207v45s96.cloudfront.net`, sertifikat
  `*.cloudfront.net`). Entry Onering yang sertifikatnya TIDAK cocok
  dengan SNI-nya kini ditolak — itu perilaku yang diinginkan,
  bukan bug.
- **Tes:** `OneringTlsTest` — (1) seam hostname-aware dipanggil tepat
  1x dengan hostname = SNI (`ValidatingHostnameAwareVerify`, fake yang
  meniru X509TrustManagerExtensions: chain check + verifikasi hostname
  terhadap SAN/CN sertifikat); (2) fallback 2-arg saat hostname kosong;
  (3) sertifikat yang tidak cocok hostname ditolak (SNI
  `support.zoom.us` vs sertifikat tes `localhost`); (4) fallback 2-arg
  saat extensions melempar `IllegalArgumentException` (TrustManager
  bukan tipe platform). Tes validasi platform yang sudah ada
  disesuaikan: SNI-nya kini `localhost` agar cocok dengan sertifikat
  tes, dan memakai fake seam yang sama.

## Catatan

- JVM tidak bisa mereproduksi penolakan 2-arg khas Android
  (TrustManager JDK bukan NetworkSecurityTrustManager) dan tidak bisa
  menjalankan `X509TrustManagerExtensions` yang asli (kelas
  Android-only; android.jar di JVM hanya stub) — bukti runtime-nya
  tetap log HP. Tes JVM membuktikan seam hostname-aware dipanggil
  dengan SNI yang benar, perilaku fallback-nya, dan verifikasi
  hostname-nya lewat fake, bukan penolakan itu sendiri.
- Tidak ada perubahan UI, rute, grup, atau perilaku non-Onering.
