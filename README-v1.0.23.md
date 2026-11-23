# TaptapNG v1.0.23 (halaman Grup/Rute disamakan dengan TB/TC)

Rilis 24 November 2026. APK `taptapng-v1.0.23.apk` (vc24, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
32 tes unit baru (total 909 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.22 — perbaikan pemisah layar Grup/Rute tidak disentuh.

Referensi: screenshot halaman Grup + Rute TB/TC (2026-11-24 03:31).

## Yang berubah

### 1. Aturan bisa diurutkan naik/turun (halaman Rute)

Tiap baris aturan kini punya tombol ↑/↓ (seperti TB/TC). Urutan disimpan
di `groups.json` dan bertahan setelah restart aplikasi — urutan list
adalah urutan pencocokan engine ("dicek dari atas ke bawah", pertama
cocok menang). Di ujung (paling atas tidak bisa naik, paling bawah
tidak bisa turun) tombol di-disable (redup, alpha 0.3), bukan
disembunyikan, supaya layout baris tetap stabil. Tidak ada batasan
otomatis soal FINAL: memindah aturan ke bawah FINAL membuatnya tak
terjangkau — itu pilihan user, sama seperti TB.

### 2. Toggle aktif/nonaktif per aturan (halaman Rute)

Tiap baris aturan (kecuali FINAL) kini punya switch. Aturan yang
dimatikan dilewati mesin rute dan tersimpan di `groups.json`. FINAL
("Rute akhir") tidak punya toggle — selalu aktif, seperti TB/TC.

**Detail penyimpanan.** Field baru `enabled` di `RouteRule` sengaja
nullable (`Boolean? = null`) + accessor `isEnabled` (`enabled ?: true`).
File lama (v1.0.17–v1.0.22) tidak punya key `"enabled"` → terbaca
aktif; Gson menghilangkan null saat save, jadi aturan yang tak pernah
di-toggle tetap tanpa key di disk, persis file v1.0.22. Catatan jujur:
probe empiris membuktikan Gson memakai konstruktor no-arg kotlinc
untuk class ini, jadi default `Boolean = true` biasa pun akan terbaca
benar — pola nullable tetap dipakai karena aman di kedua jalur (bila
kelak konstruktor no-arg hilang, Gson jatuh ke alokasi Unsafe).

### 3. Kartu "Grup utama" (halaman Grup)

Di atas seksi grup: field nama grup utama + tombol Simpan + penjelasan
"Berlaku langsung, tanpa restart — rute dibaca per koneksi." (Teks TB
"Menyimpan me-restart sing-box bila sedang terhubung" sengaja TIDAK
ditiru — rute NG live per koneksi, tidak perlu restart.)

**Detail identitas.** Grup utama kini dikenali BY ID, bukan by nama:
field baru `mainGroupId` (nullable) di `GroupsConfig` + helper
`mainGroup()` di `GroupsStore`. Urutan resolusi: id tersimpan → target
aturan FINAL → grup bernama `"taptap"` → grup pertama → null. Target
aturan FINAL sengaja TIDAK dipakai sebagai identitas (user bisa
mengubah/menghapus aturan FINAL). Migrasi file lama tanpa key jalan
sesudah migrasi v1.0.21 ("Proxy"→"taptap") dan hasilnya dipersist.
Semua lookup berbasis nama diubah mengikuti id tersimpan: fallback
`RouteEngine`, alias PUT `/proxies/GLOBAL` di Clash API, live-switch,
dan start-sync. Nama di "Rute akhir" dan di dashboard ikut nama
tersimpan otomatis (target FINAL by id; yacd baca grup live).
Validasi: nama kosong ditolak, nama yang sudah dipakai grup lain
ditolak (Toast, tanpa crash). Menghapus grup utama me-resolve ulang id
(tidak pernah menunjuk grup yang sudah dihapus).

## Tes

- `GroupsStoreTest` + `RouteEngineTest` — 7 tes baru (naik/turun, ujung,
  id tak dikenal, satu aturan, persistensi urutan, urutan dibalik →
  pemenang pencocokan berubah).
- `RouteRuleEnabledTest` — 11 tes baru (file lama tanpa field → aktif,
  toggle off → engine lewati, toggle on → cocok lagi, FINAL dengan
  `enabled=false` di file tetap dicocokkan, persistensi save→load).
- `MainGroupTest` — 13 tes baru (rename persist, migrasi 4 varian,
  blank/duplikat ditolak, engine fallback + global mode ikut rename,
  live-switch + start-sync ikut rename, hapus grup utama) +
  `ClashApiHandlerTest` (tes GLOBAL-rename).
- Total: 909 @Test (877 v1.0.22 + 32 baru).

## Yang sengaja TIDAK dibangun (tidak portable ke NG)

- **Blokir Iklan + IP Privat → Bypass** (TB): butuh `geosite.dat` /
  `geoip.dat` — file geodata tidak pernah dibangun di NG (M7).
- **Toggle Sniffing di halaman Rute**: sudah ada di Pengaturan
  (v1.0.5, `sniffingEnabled`) — tidak diduplikasi.
- **Kartu Langganan di dalam Grup**: Langganan sudah jadi item drawer
  sendiri (`nav_subscriptions`).
- **Tombol "Terapkan (restart)"**: tidak perlu — rute NG live per
  koneksi; perubahan grup/aturan langsung berlaku.
- **Kartu Rule-set**: butuh file rule-set, belum ada di NG.

## Cara tes di HP

1. Instal timpa v1.0.22 tanpa hapus data (grup "taptap" + aturan lama
   terbawa; file lama tanpa key `enabled` harus terbaca semua aktif).
2. Halaman **Rute**: pindah satu aturan ke atas/bawah (tombol ↑/↓) →
   urutan berubah dan bertahan setelah tutup-buka aplikasi; hasil
   pencocokan ikut urutan baru (aturan yang tumpang-tindih: yang di
   atas menang).
3. Halaman **Rute**: matikan toggle satu aturan → trafik yang tadinya
   cocok aturan itu jatuh ke aturan berikut / FINAL; nyalakan lagi →
   cocok lagi. Baris FINAL tidak punya toggle.
4. Halaman **Grup**: ganti nama grup utama di kartu "Grup utama" →
   Simpan → nama baru tampil di halaman Grup, di "Rute akhir" halaman
   Rute, dan di dashboard (tanpa restart, tanpa putus koneksi).
   Coba nama kosong dan nama duplikat → ditolak dengan Toast.
5. Konek **iflix** + **81** tetap jalan (regresi dilarang).

## Batasan jujur

- Tampilan switch/tombol ↑/↓ dan kartu "Grup utama" tidak bisa dites
  di JVM (tidak ada Robolectric di tree ini); bukti runtime-nya tes di
  HP (di atas).
- `:app:testDebugUnitTest`, `:app:compileDebugKotlin`, dan
  `:app:assembleRelease` dijalankan di CI (Gradle diblokir di VM).
