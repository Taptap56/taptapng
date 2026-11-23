# TaptapNG v1.0.28 (loop url-test jalan + kelihatan di Log)

Rilis 24 November 2026. APK `taptapng-v1.0.28.apk` (vc29, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
4 tes unit baru (total 989 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.27 (HEAD `e20ae2b`).

Referensi: pesan user 2026-11-24 06:21 — url-test yang dipilih ("tes")
tidak kelihatan jalan di Log, tidak ada baris tes berkala grup URL-TEST.

## Masalah

Grup URL-TEST "tes" sudah dipilih di dashboard dan delay-nya tampil
(255ms), tapi halaman Log tidak pernah menampilkan satu baris pun soal
tes berkala. Diagnosis dari kode (HEAD `e20ae2b`, sudah bulat sebelum
build ini): loop `UrlTestLoop` dibuat + distart saat tunnel naik, tapi
`grep -c DialLog` pada `UrlTestCache.kt` = **0** — ronde jalan tiap
interval tanpa menulis apa pun ke Log. Kontras: Observatory menulis
baris tiap perubahan entry terbaik, PemicuManager menulis PRIME
OK/GAGAL.

Dua keterlambatan nyata ikut ditemukan: (1) bila TIDAK ADA grup
URL_TEST saat tunnel naik, loop tidur `MAX_SLEEP_MS` = 30 menit —
grup "tes" yang dibuat sesudah VPN naik baru terlihat paling lambat
30 menit kemudian; (2) `GroupsActivity` memakai instance `GroupsStore`
sendiri dan hanya `save()` ke file — instance bersama baru termuat
ulang lewat `refreshGroups()` saat ada pembacaan API.

## Yang berubah

- `core/UrlTestCache.kt` (`UrlTestLoop`):
  - Setiap ronde kini menulis ke `DialLog` (INFO, tampil di level log
    default): satu baris mulai per grup URL_TEST saat pertama kali
    di-probe, dan satu baris ronde per grup per ronde (tiap anggota +
    delay + yang terpilih = delay terendah, sama seperti pilihan
    route engine). Hanya nama tampilan anggota + delay yang di-log,
    tanpa kredensial / URL proxy.
  - `kick()`: membangunkan worker yang sedang tidur (`wait`/`notify`,
    bukan `interrupt` — interrupt tetap berarti stop). Ronde pertama
    grup yang baru aktif jalan langsung, tanpa menunggu interval dan
    tanpa menunggu tidur 30 menit. Grup dibaca ulang sesudah bangun,
    supaya snapshot sebelum tidur tidak melewatkan grup baru.
  - Bila ada grup yang due saat loop berjalan, ronde pertama jalan
    langsung (tanpa tidur minimum 5 detik dulu); bila belum due,
    tidur tetap dibatasi 5 dtk–30 mnt seperti sebelumnya.
- `service/ClashApiRuntime.kt`: pegang `urlTestLoop` (di-set/dibersihkan
  `TaptapVpnService` bersama `urlTestCache`); `refreshGroups()` memanggil
  `kick()` sesudah memuat ulang — mencakup PUT select dashboard dan
  pembacaan dashboard.
- `service/ClashApiServer.kt` (`selectProxy`): `kick()` sesudah pilihan
  disimpan — memilih node grup bersarang "tes" di grup utama ikut
  membangunkan loop.
- `ui/groups/GroupsActivity.kt`: `onPause()` memuat ulang store bersama
  lewat `refreshGroups()` (sekaligus `kick()`) — grup URL-TEST yang
  dibuat/diubah di editor terlihat loop tanpa harus membuka dashboard
  dulu.
- Tidak diubah: perilaku seleksi/route, delay test manual (tombol ⚡ —
  tetap langsung, tetap tidak ditulis ke cache dan tidak di-log),
  interval default 300 dtk (clamp 60–3600 tetap).

## Baris log persis yang ditulis

Mulai (sekali per grup, saat pertama di-probe):

```text
url-test mulai: grup 'tes' — URL tes http://www.gstatic.com/generate_204, interval 300 dtk, anggota: 81, iflix cloudfront
```

Tiap ronde (per grup):

```text
url-test 'tes': 81=312ms, iflix cloudfront=662ms — terpilih: 81 (312ms)
```

Bila semua anggota gagal menjawab:

```text
url-test 'tes': 81=gagal, iflix cloudfront=gagal — terpilih: - (tidak ada yang menjawab)
```

## Tes baru (4, di `UrlTestCacheTest.kt` — gagal di kode lama, lolos di baru)

- `probeGroupWritesStartLineOncePerGroup` — baris mulai ditulis sekali
  per grup (ronde kedua sesudah interval tidak mengulanginya).
- `probeGroupWritesRoundLineWithMembersAndPicked` — baris ronde berisi
  anggota + delay + terpilih.
- `probeGroupRoundLineWhenAllMembersFail` — semua gagal → `gagal` per
  anggota + `terpilih: - (tidak ada yang menjawab)`.
- `kickWakesLoopForNewGroupAtOnce` — loop distart tanpa grup (tidur
  30 menit), grup baru ditambah + `kick()` → ronde pertama jalan
  <5 detik (regresi tidur 30 menit).

## Cara tes di HP

1. VPN jalan (VpnService, Root mode OFF), grup URL-TEST "tes" sudah ada
   (anggota 81 + iflix cloudfront, interval 300).
2. Buka halaman Log: baris `url-test mulai: grup 'tes' …` tampil, lalu
   langsung baris ronde pertama `url-test 'tes': 81=…ms, iflix
   cloudfront=…ms — terpilih: …`.
3. Tunggu satu interval (300 dtk): baris ronde berikutnya muncul dengan
   delay + terpilih yang baru.
4. Buat grup URL-TEST baru selagi VPN jalan (atau pilih node "tes" di
   dashboard): ronde pertamanya muncul dalam hitungan detik, bukan
   30 menit.
5. Dashboard tetap tampil benar (Groups 2, "tes" URLTest + terpilih);
   konek iflix + 81 tetap jalan seperti v1.0.27.

## Batasan (jujur)

- Visual / baris Log di atas hanya bisa dibuktikan dari HP — tes JVM
  membuktikan baris ditulis + `kick()` membangunkan loop, bukan
  tampilannya di halaman Log.
- Root mode: bila `enableRootMode` ON, `establishTunnel()` tidak pernah
  dipanggil sehingga loop tidak pernah dibuat — loop url-test tetap
  tidak jalan di Root mode. Sengaja di luar cakupan v1.0.28, belum
  di-wire ke Root mode.
