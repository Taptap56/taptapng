# TaptapX v1.0.15

Aplikasi Android BARU dari awal — UI persis v2rayNG 2.3.15 (Android
Views: XML layouts + RecyclerView + Material Components, **tanpa
Compose**), isinya protokol in-app (Kotlin/Java), **tanpa bundel
xray-core**. Arsitektur ala XVEON: protokol ditulis langsung di kode
app, jadi APK kecil (bukan 41 MB).

- **id** `com.taptap.x`, **versi** 1.0.15 (vc16)
- Data: `profiles.json` (Gson) di files dir privat app
- Terowongan: `VpnService` (`TaptapVpnService`, TUN 172.19.0.1/30)

## Arsitektur

```
MainActivity (Views) ──> MainViewModel ──> ProfileStore (profiles.json)
   ├─> ServerEditorActivity (Xray method: SlowDNS / Onering / Pemicu)
   ├─> SettingsActivity (PreferenceFragmentCompat), LogActivity (logcat)
   ├─> ScannerActivity (Camera1 + ZXing, QR import)
   └─> TaptapVpnService (TUN, start/stop)
Core (in-app, tanpa native):
   ├─> SshClient (JSch, pure Java) — Phase 1 proof-of-concept
   ├─> LinkParser (vmess/vless/trojan/ss/ssh share links + toUri)
   ├─> ServerTester (TCP delay / real ping)
   └─> (milestone berikut: VMess/VLESS/Trojan/SS, SlowDNS/DNSTT,
        Onering, PemicuManager)
```

## v1.0.15 — Kecepatan relay

Speedtest 2026-11-20 back-to-back (entry sama, kondisi sama):
v2rayNG 133 Mbps, XVEON ~32 Mbps, TaptapX ~30,9 Mbps. Dua app
tanpa core mentok di ~30 Mbps — batasnya di relay in-app, bukan
di server. Perbaikan (tanpa ubah protokol, tanpa core, APK tetap
~2 MB):

- Chunk VMess 8KB → **16KB** (server xray-core menerima ukuran
  chunk berapa pun — reader-nya baca 2-byte size tanpa batas
  atas; yang 8KB itu cuma ukuran tulis server).
- MSS SYN-ACK 1360 → **1460** (MTU − 40; margin 100B XVEON untuk
  overhead terowongan luar tidak berlaku di link TUN lokal).
- Relay baca TUN: satu `read()` tarik sampai **32KB** (dulu satu
  segmen 1360B per read), segmen dibangun langsung dari buffer
  baca ke buffer paket yang dipakai ulang (tanpa `copyOf`, tanpa
  alokasi per segmen).
- `VmessBodyOutputStream` / `SsBodyOutputStream`: buffer pending
  jadi `ByteArray` (dulu `MutableList<Byte>` yang me-boxing tiap
  byte — 1460 alokasi per segmen).
- Parse TCP satu salinan (dulu `parseIp` + `parseTcp` menyalin
  segmen dua kali).
- Window terima tetap 256 KiB (sudah cukup, bukan bottleneck);
  fd TUN tetap blocking (v1.0.11) jadi sleep 10ms di loop baca
  tidak pernah jalan saat stream sibuk.
- Tes baru `RelayThroughputTest` (in-memory, tanpa socket):
  throughput relay download + round-trip codec chunk VMess,
  print MB/s di log CI (grep THROUGHPUT), floor konservatif.

**Tes HP (yang menentukan — angka lokal tidak membuktikan
kenaikan di HP):** Speedtest back-to-back, entry sama, kondisi
sama, lawan v2rayNG: (1) TaptapX, (2) v2rayNG, (3) TaptapX lagi.
Laporkan download/upload ketiganya. Target: TaptapX naik dari
~31 Mbps (tidak dijamin samakan 133 Mbps v2rayNG — jalur data
native Go tetap lebih cepat dari relay Java tulisan tangan).

## v1.0.1 — UI dibangun ulang dengan Views + fitur v2rayNG

- UI Compose diganti total ke Views (XML + RecyclerView + Material
  Components + AppCompat), meniru susunan v2rayNG 2.3.15: drawer
  (header 180dp + 10 item), top bar (judul Config, search, menu
  import +, menu more ⋮), tab grup, baris server (accent bar,
  tombol share/edit/delete, statistik, label protokol oranye, delay
  hijau), bottom status bar 64dp + FAB oranye yang overlap.
- Settings lengkap ala v2rayNG (UI / VPN / local proxy / DNS /
  advanced): tema (system/light/dark), bahasa (auto/en/id), dynamic
  color, double column, confirm remove, IPv6, local DNS, FakeDNS,
  VPN DNS, MTU, SOCKS, remote/domestic DNS, log level, auto-start.
- Import: from clipboard (parser link vmess/vless/trojan/ss/ssh,
  unit test `LinkParserTest`), from QR code (scan Camera1 + ZXing
  core — tanpa CameraX demi ukuran), from file (daftar link atau
  export profiles.json). Tambah manual per protokol, edit/hapus
  server, hapus grup (long-press tab grup), test/delay server
  (TCPing + real ping, sortir berdasar hasil tes), export ke file.
- Editor: chip protokol, field per protokol, seksi SSH method
  (Payload/Enhanced/TLS/SlowDNS) + seksi Xray method (SlowDNS /
  Onering / Pemicu + Domain/Port/Interval pemicu).
- SSH via JSch (pure Java): connect + exec + disconnect; unit test
  end-to-end melawan server MINA SSHD in-process (`SshClientTest`).
- VpnService kerangka: TUN interface + start/stop; DNS server ikut
  Settings (remote DNS). Auto-start on boot (bila izin VPN sudah
  diberikan).
- Build: Gradle (AGP 9.4.1, Kotlin 2.4.21, compileSdk/targetSdk 37,
  minSdk 24), **release + R8** (minify + shrinkResources, keep rules
  untuk Gson/JSch/ZXing/VpnService), ditandatangani keystore debug
  agar APK CI bisa diinstal. Gradle diblokir di VM, jadi build APK
  lewat GitHub Actions CI (`.github/workflows/build.yml`).

## Milestone berikut

- **M2 — VMess/VLESS/Trojan/SS in-app**: implementasi protokol di
  Kotlin (enkripsi + framing), WS + TLS transport, SNI mode.
  Bukti: unit test melawan server lokal + tes HP.
- **M3 — SlowDNS/DNSTT in-app**: transport DNSTT (DNS tunneling)
  + outbound DNSTT, chip SlowDNS di editor. Bukti: unit test + tes HP.
- **M4 — Onering**: bug domain di ext TLS 0xff00 (SNI = domain asli),
  format `onering:<real>:<bug>`. Bukti: unit test byte-level + tes HP.
- **M5 — Pemicu bawaan**: chip Pemicu + Domain/Port/Interval per entry;
  dial in-app SSLSocket + `VpnService.protect()` (tanpa root),
  tidak ganggu VMess. Bukti: unit test + tes HP (PRIME OK).
- **M6 — Terowongan penuh**: forwarding paket TUN <-> protokol
  (SOCKS5 lokal + routing), tes HP end-to-end (entry konek).

## Build

```sh
./gradlew :app:assembleRelease   # di CI (Gradle diblokir di VM ini)
```

CI: `.github/workflows/build.yml` (release, arm64-v8a).
Repo: https://github.com/Taptap56/taptapx

## Yang belum terverifikasi (butuh HP)

- Tampilan di HP (daftar server, editor, drawer, FAB, Settings, scan QR)
- VpnService: izin VPN + TUN benar-benar jalan di HP
- SSH ke server sungguhan (bukan server tes in-process)
- Import clipboard/QR/file di HP (parser baru, baru lolos unit test JVM)
- Semua protokol M2–M6 (belum dibangun)
