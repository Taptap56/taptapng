# TaptapNG v1.0.21 (drawer Grup + Rute, dashboard hanya grup "taptap")

Rilis 24 November 2026. APK `taptapng-v1.0.21.apk` (vc22, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
17 tes unit baru ditambahkan (total 873 @Test, dihitung dari tree;
dijalankan CI, Gradle diblokir di VM), plus seluruh regresi yang sudah ada.

## Yang berubah

### 1. Drawer jadi menu "Grup" + "Rute" (seperti TB/TC)

Dua item drawer v2rayNG lama diganti, posisi tetap (Grup di atas Rute):

- "Per-App Proxy" → **"Grup"** — buka editor grup proxy.
- "Routing settings" → **"Rute"** — buka editor aturan rute.

Editornya tetap SATU activity (`GroupsActivity`, tidak diduplikasi):
drawer "Grup"/"Rute" membuka activity yang sama lewat intent extra
(`EXTRA_SECTION` + judul toolbar ikut "Grup"/"Rute"; "Rute" langsung
scroll ke bagian aturan). Entry overflow lama "Grup proxy & rute" tetap
jalan (tanpa extra → judul lama, tampilan penuh).

- **Per-App Proxy sebagai fitur: TIDAK ADA yang hilang.** Dicek dulu
  sebelum mengubah: kedua item drawer lama itu TIDAK PUNYA handler —
  `onDrawerItem()` hanya menangani Settings/Logcat/About, sisanya
  jatuh ke toast "not available". Tidak ada activity, setting, atau
  logika Per-App Proxy di TaptapNG (fitur itu memang belum pernah
  dibangun di sini).
- **Tes:** `GroupsSectionTest` — 8 tes (`resolveSection` null/groups/
  routes/asing/kosong + assertion urutan Grup di atas Rute, string,
  cabang handler, mapping judul, anchor scroll, string/id lama hilang).

### 2. Grup default "Proxy" jadi "taptap" (rename + migrasi)

- Konstanta di-rename di semua lapisan: `GroupsStore.DEFAULT_GROUP_NAME`
  dan `RouteEngine.FALLBACK_GROUP_NAME` = `"taptap"`. Semua pemakai
  lewat konstanta (start-sync v1.0.19, live-switch, Clash API, dashboard
  yacd) ikut berubah otomatis.
- **Migrasi (wajib, `GroupsStore.migrateDefaultGroupName()`):** file
  groups.json lama yang menyimpan grup "Proxy" di-rename jadi "taptap"
  saat load (id sama, jadi aturan FINAL yang menunjuk via id tidak
  berubah), lalu di-persist — load kedua idempotent. Bentrok: bila grup
  "taptap" sudah ada, grup "Proxy" di-MERGE ke dalamnya (member
  digabung dedup, seleksi survivor menang, aturan yang menunjuk id
  grup yang dibuang di-repoint, duplikat dihapus). Aturan yang
  target-nya literal "Proxy" (file edit-tangan) ikut di-repoint ke id
  grup default. Sesudah load tidak pernah ada "Proxy" + "taptap"
  berdampingan.
- String user-visible yang menyebut nama grup ikut diubah:
  `settings_strings.xml` ("selalu grup Proxy" → "selalu grup taptap").
- **Tes:** `GroupsMigrationTest` — 4 tes baru (rename + FINAL utuh +
  file bersih + idempotent; repoint target literal; bentrok merge;
  file yang sudah "taptap" tidak berubah) + ekspektasi tes lama
  diperbarui (`GroupsConfigGsonReproTest`, `RouteEngineTest`,
  `ClashApiModeTest`, `ClashApiHandlerTest`, `ProxyGroupTest`,
  `LiveSwitchTest`).

### 3. Pseudo-group "GLOBAL" dihapus dari dashboard

- `/proxies` tidak lagi mengemisikan "GLOBAL" — dashboard hanya
  menampilkan grup nyata + server individual. Grup nyata "taptap"
  (selector, semua server) sudah menjalankan peran GLOBAL.
- PUT alias: `PUT /proxies/GLOBAL` (body maupun path form) tetap
  DITERIMA dan dipetakan ke grup fallback (murah, menjaga klik ganti
  server dari tampilan lama tetap jalan); guard: grup nyata yang
  kebetulan bernama "GLOBAL" menang atas alias. GET
  `/proxies/GLOBAL` dan delay GLOBAL kini 404 seperti nama tak dikenal.
- **yacd bundle dibiarkan** (minified upstream): satu-satunya pemakai
  GLOBAL — tanpa GLOBAL, daftar "semua proxy" kosong dan grup tampil
  dalam urutan config; halaman Proxies tetap merender semua grup nyata
  + server individual.
- **Tes:** `ClashApiHandlerTest` — assertion GLOBAL hilang + 4 tes baru
  (alias PUT body/path form, alias 404 tanpa grup fallback, grup nyata
  bernama GLOBAL menang, GET/delay GLOBAL 404).

## Cara tes di HP

1. Instal timpa v1.0.20 tanpa hapus data (entry + grup terbawa).
2. Buka drawer: **"Grup"** buka editor grup (judul "Grup"), **"Rute"**
   buka editor rute (judul "Rute", langsung di bagian aturan).
3. Buka tab **Dashboard** — HANYA satu grup **"taptap"**, isinya semua
   server, selected = entry yang konek. Tidak ada lagi kartu "Proxy"
   maupun "GLOBAL".
4. Konek **iflix** + **81** tetap jalan (regresi dilarang — v1.0.20
   sudah terbukti di HP 02:23).
5. Grup lama "Proxy" di HP bermigrasi jadi "taptap" tanpa duplikat
   (cek di editor Grup: satu grup "taptap" berisi semua server).
6. Buat grup url-test / load-balance dari editor — harus muncul di
   dashboard sebagai grup baru.

## Catatan

- Scroll "Rute" memakai `post { scrollTo(...) }` sesudah layout pass —
  perilaku visual di HP belum teruji (ketuk "Rute" harus langsung
  menampilkan header "Aturan rute" di atas).
- Urutan grup di dashboard tanpa GLOBAL mengikuti urutan config
  (yacd tidak lagi punya daftar "semua proxy" untuk mengurutkan).
- Migrasi mengenali nama lama yang persis `"Proxy"` (case-sensitive).
  Grup kustom pengguna yang kebetulan bernama `"Proxy"` akan ikut
  di-rename/digabung — tidak bisa dibedakan dari grup default lama.
- `SocksServer.kt:606` masih memakai `getLoopbackAddress()` — sengaja
  di luar cakupan (server SOCKS, bukan Clash API/dashboard).
- Tidak ada perubahan dial, TLS, primer, atau rute — hanya drawer,
  nama grup, dan listing dashboard.
