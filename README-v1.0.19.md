# TaptapNG v1.0.19 (dashboard tampil + pindah server live tanpa restart)

Rilis 24 November 2026. APK `taptapng-v1.0.19.apk` (vc20, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
15 tes unit baru `LiveSwitchTest` lolos di CI (0 gagal), plus seluruh
regresi yang sudah ada.

## Yang diperbaiki

### Issue 1 — Tab Dashboard tidak kebuka: SELESAI

Di v1.0.18, tab **Dashboard** menampilkan "Halaman web tidak tersedia"
(`net::ERR_CLEARTEXT_NOT_PERMITTED`) untuk `http://127.0.0.1:9091/ui/`,
padahal status sudah "Connected". Akar penyebabnya: sejak targetSdk 28,
Android menolak cleartext (http://) secara default, dan aplikasi tidak
punya `networkSecurityConfig`.

- **Perbaikan:** file baru `app/src/main/res/xml/network_security_config.xml`
  mengizinkan cleartext **hanya** untuk `127.0.0.1` dan `localhost`
  (domain-config), sementara `base-config` tetap
  `cleartextTrafficPermitted="false"` — semua host lain tetap dilarang
  cleartext. Satu baris `android:networkSecurityConfig` ditambahkan di
  `AndroidManifest.xml`. Tidak ada `usesCleartextTraffic` global.
- Dashboard yacd kini dimuat dari API Clash lokal seperti semula; tidak
  ada perubahan pada API Clash, grup, atau rute.

### Issue 2 — Pindah server me-restart VPN: SELESAI

Di v1.0.18, ketuk server lain saat VPN jalan selalu me-restart tunnel
(PUT select dari dashboard pun begitu). Sekarang ketuk server lain
**memindahkan koneksi baru ke server baru tanpa restart** — TUN,
forwarder, dan label "Connected:" tetap jalan; hanya seleksi rute yang
berpindah, seperti Clash.

- **Mekanisme:** `LiveSwitch.kt` (pure, tanpa Android) memutuskan
  (`decideLiveSwitch`: sama = diam, beda + VPN jalan = pindah live,
  VPN mati = pilih biasa) dan mengarahkan grup SELECT default "Proxy"
  ke guid baru (`applyLiveSwitchSelection` — guid yang belum jadi
  anggota grup ditambahkan dulu). `TaptapVpnService.switchTunnel()`
  (aksi baru `ACTION_SWITCH`) memvalidasi entry baru persis seperti
  start; bila ditolak, seleksi dikembalikan dan tunnel lama tetap
  jalan. `VpnConnection.switchEntry()` memindahkan label "Connected:"
  selagi status tetap RUNNING.
- **Temuan penting saat pengerjaan:** seleksi grup "Proxy" **tidak
  pernah disinkron** dari `ProfileStore.selectedGuid` sesudah grup
  default dibuat — di v1.0.18 ketuk + restart pun hanya mengganti
  probe client dan label, koneksi baru tetap ke anggota SELECT lama.
  Perbaikan start-sync ikut di rilis ini: saat tunnel naik, seleksi
  grup diselaraskan dulu dengan entry yang dipilih, jadi "pilih +
  start" benar-benar merute lewat server yang diketuk.
- **Pemicu (M5) ikut pindah:** loop prime berhenti di target lama dan
  mulai di target entry baru (tanpa target = loop berhenti, bukan
  crash). Pindah tidak menunggu prime — routing sudah pindah duluan,
  prime jalan di latar belakang.
- **Tes:** `LiveSwitchTest.kt` (15 tes baru) + regresi yang sudah ada
  lolos di CI. `SelectionRestartTest.kt` dihapus — ia mengunci
  perilaku restart lama yang kini sengaja diubah.

Tidak ada perubahan lain: protokol, relay, grup/rute, API Clash, dan
UI tetap seperti v1.0.18.

## Cara tes di HP (penentu)

1. **Instal APK ini TIMPA v1.0.18 tanpa hapus data** (jangan uninstall,
   jangan hapus data — entry dan grup harus terbawa).
2. **Tanpa internet pun bisa dites dulu:** buka tab **Dashboard** —
   harus tampil halaman Proxies yacd (bukan "Halaman web tidak
   tersedia"). Inilah tes yang gagal di v1.0.18.
3. Konek satu entry (misal **81 / 104.17.3.81**) sampai status
   "Connected".
4. **Saat VPN jalan, ketuk server lain** (misal Sociomile Edukasi) —
   harus pindah **tanpa restart**: status tetap "Connected" (tidak
   ada putus-sambung), label ikut ganti ke server baru, dan koneksi
   baru (buka halaman/tes delay) lewat server baru. Inilah tes yang
   gagal di v1.0.18.
5. Bila ada yang gagal, export Log dari aplikasi dan kirim — baris
   `SWITCH` di log mencatat pindah live, penolakan, dan alasannya.

## Caveat (jujur)

- **Koneksi lama tetap di server lama sampai putus** — sama seperti
  Clash. Hanya koneksi baru yang lewat server baru; unduhan atau
  panggilan yang sedang jalan tidak dipindahkan paksa.
- **Mode root tidak bisa pindah live:** `switchTunnel` me-restart
  tunnel di mode root (dicatat di Log), karena RootForwarder memegang
  satu client tanpa mesin rute.
- **SOCKS lokal (lanSharing, port 10808) tetap dial lewat client
  tunnel lama** — pindah live hanya mengubah mesin rute TUN.
- **Bila switch ditolak** (entry tidak valid), seleksi dikembalikan
  ke entry lama + dicatat di Log; tunnel lama tidak terganggu.
- **Dashboard PUT select tanpa ubah `ProfileStore.selectedGuid`**
  akan ditimpa seleksi daftar-server pada start berikutnya
  (start-sync) — pindah dari dashboard tetap berlaku selama tunnel
  jalan, tapi start ulang memakai pilihan daftar-server.
- Pindah live saat tunnel masih STARTING dibatalkan (label bisa
  tertimpa worker start) — ketuk lagi sesudah status "Connected".
- GEOIP belum dibangun: aturan berbasis negara (GEOIP/GEOSITE) belum
  ada — yang tersedia hanya DOMAIN/SUFFIX/KEYWORD/IP-CIDR/FINAL.
- Load-balance belum dibangun: grup hanya SELECT, URL-TEST, FALLBACK.
- Mode root tidak di-routing: trafik mode root tetap lewat jalur lama,
  aturan rute hanya berlaku untuk trafik VPN (TUN).
- SOCKS lokal (lanSharing, port 10808) tidak di-routing: koneksi
  lewat SOCKS lokal tidak melewati mesin rute.
- Anggota grup yang baru ditambahkan dan belum pernah di-prime bisa
  gagal konek di percobaan pertama — prime dulu lewat cara biasa
  (ketuk entry-nya sekali) sebelum memakainya di grup.

## Instalasi

Instal APK ini langsung menimpa v1.0.18 (keystore stabil sejak
v1.0.2 — tidak perlu uninstall). Export konfigurasi dulu dari
Pengaturan → Export sebagai cadangan sebelum instalasi.
