# TaptapNG v1.0.32 — Dashboard hanya aktif saat VPN jalan

Satu perubahan saja, dari v1.0.30 (branch `v1032-from-1030`, base
`39132d8`). v1.0.31 (vc32) ditolak user dan tidak dibawa ke sini —
vc32 sudah terpakai di sana, jadi v1.0.32 memakai vc33.

## Kenapa

Dashboard yacd (WebView + WebSocket `/traffic`, `/logs`,
`/connections`) selama ini hidup begitu tab dibuka, walau VPN mati —
padahal tanpa tunnel tidak ada yang bisa ditampilkannya, dan
stream-nya jalan terus. Kini tab Dashboard hanya aktif saat tunnel
benar-benar up.

## Perilaku

- VPN mati → tab Dashboard menampilkan placeholder statis "VPN mati —
  nyalakan VPN untuk membuka dashboard". WebView TIDAK dibuat/dimuat,
  tidak ada polling/stream.
- VPN nyala → dashboard jalan normal seperti v1.0.30 (yacd
  Proxies/Connections/Rules/Overview, delay live, scroll sampai bawah
  dengan bottomMargin 80dp — tidak diubah).
- VPN dimatikan saat dashboard sedang terbuka → WebView dihentikan /
  dihancurkan (stopLoading + lepas dari parent + destroy + null +
  reset penanda URL yang sudah dimuat), tab kembali ke placeholder.
  Transisi paling lambat ~2 dtk sesudah VPN nyala/mati (poll 2 dtk
  yang sudah ada di `syncServiceState()`).
- VPN masih STARTING (belum "Connected") → placeholder sampai
  benar-benar jalan. Predikatnya `VpnConnection.isConnected`
  (state == RUNNING) — `isRunning` sudah true saat STARTING, jadi
  tidak bisa dipakai sebagai predikat.
- Prioritas panel: API Clash mati → panel `dashboardDisabled` yang
  sudah ada; API nyala + VPN mati → placeholder VPN baru; keduanya
  nyala → WebView.
- Server Clash API (127.0.0.1:9091) TETAP jalan mengikuti proses
  aplikasi (tidak diberhentikan saat VPN mati). Alasan dari kode:
  lifecycle-nya terikat proses (`TaptapNGApp.onCreate` →
  `ClashApiServer.start`), dan tidak ada konsumen HTTP in-app selain
  WebView dashboard — daftar server, delay test, Grup/Rute dan live
  switch semuanya memakai `ClashApiRuntime` langsung in-process
  (`TaptapVpnService`, `GroupsActivity`, `LiveClashApiDeps` membaca
  state runtime, bukan lewat socket). Saat idle server hanya satu
  thread accept yang blocking; stream WebSocket hanya ada bila ada
  klien, dan satu-satunya klien (WebView) sudah dihancurkan.

## Yang TIDAK berubah

Server list, Grup/Rute, live switch, grup bersarang, log url-test di
halaman Log aplikasi, detail koneksi (rule/chains leaf-first), scroll
dashboard, kecepatan relay, mux OFF, primer (tetap interval 15 dtk
seperti v1.0.30 — TIDAK ada backoff), Observatory (tetap seperti
v1.0.30).

## File yang diubah

- `app/src/main/java/com/taptap/ng/ui/main/DashboardGate.kt` (baru):
  objek murni `decide(vpnConnected, clashApiEnabled)` → WEBVIEW /
  VPN_OFF / API_DISABLED, prioritas API-mati dulu.
- `app/src/main/java/com/taptap/ng/service/VpnConnection.kt`:
  `isConnected` (state == RUNNING).
- `app/src/main/java/com/taptap/ng/service/TaptapVpnService.kt`:
  `isConnected` di companion, delegasi ke `connection`.
- `app/src/main/java/com/taptap/ng/ui/MainActivity.kt`: field +
  `findViewById` `dashboardVpnOff`; `showDashboard()` lewat gate +
  `destroyDashboardWebView()`; `syncServiceState()` mengevaluasi
  ulang dashboard bila tab-nya terbuka; `reloadDashboard()` tidak
  me-reload saat gate bukan WEBVIEW; `onDestroy()` memakai helper
  yang sama.
- `app/src/main/res/layout/activity_main.xml`: panel
  `dashboard_vpn_off` (gaya `dashboardDisabled`).
- `app/src/main/res/values/strings.xml`: `dashboard_vpn_off`.
- `app/src/test/java/com/taptap/ng/DashboardGateTest.kt` (baru):
  14 @Test — gate murni, predikat RUNNING vs STARTING, dan
  source-assertion untuk wiring Activity + layout + margin 80dp.
- Bump: `app/build.gradle.kts` (vc33, 1.0.32), `README.md`,
  `.github/workflows/build.yml` (nama artifact v1.0.32).

## Tes

- 14 @Test baru lolos lokal (kotlinc standalone + JUnit, Gradle
  diblokir di VM). Di kode lama (v1.0.30, dicek dengan menjalankan
  tes yang sama dari checkout murni `39132d8`): 4 tes source-assertion
  gagal (gate di `showDashboard`, teardown WebView, sync di
  `syncServiceState`, placeholder di layout/strings); 9 tes murni
  tidak bisa dikompilasi terhadap kode lama sama sekali
  (`DashboardGate` dan `VpnConnection.isConnected` tidak ada di
  v1.0.30 — `git grep` 0 hasil); 1 tes margin 80dp lolos di lama,
  sesuai rancangannya sebagai guard. Total tree:
  1027 @Test (1013 di v1.0.30 + 14 baru).
- Tidak ada tes JVM untuk teardown WebView itu sendiri (tanpa
  Robolectric) — bukti visual hanya dari screenshot HP.

## Cara tes di HP

1. VPN mati → buka tab Dashboard → placeholder "VPN mati — nyalakan
   VPN untuk membuka dashboard", bukan halaman yacd.
2. Nyalakan VPN → dalam ~2 dtk dashboard muncul normal (Proxies,
   delay live). Saat masih "Connecting..." tetap placeholder.
3. Matikan VPN saat dashboard terbuka → dalam ~2 dtk tab kembali ke
   placeholder (WebView dihancurkan, bukan disembunyikan).
4. Matikan Clash API di Settings → panel "Clash API is off" (bukan
   placeholder VPN); nyalakan lagi saat VPN mati → placeholder VPN.
5. Dashboard tetap bisa di-scroll sampai bawah; daftar server,
   Grup/Rute, live switch, dan log url-test tidak berubah.

## Batasan (jujur)

- Teardown WebView + transisi tab hanya bisa dibuktikan dari
  screenshot HP — tes JVM membuktikan gate, predikat, dan wiring,
  bukan tampilan di layar.
