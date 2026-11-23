# TaptapNG v1.0.25 (tombol hijau, label seksi terbaca, label dialog tidak menimpa)

Rilis 24 November 2026. APK `taptapng-v1.0.25.apk` (vc26, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
12 tes unit baru (total 926 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.24 — fungsi Grup/Rute tidak disentuh, UI-only.

Referensi: 2 screenshot HP user (2026-11-24 04:33) + pesan
"Tombol2 hitam dan kayanya masih ada tulisan kecil".

## Masalah (v1.0.24)

1. **Tombol hitam.** Tombol SIMPAN + TAMBAH GRUP di halaman Grup kini
   kelihatan (outlined, huruf kapital — perbaikan v1.0.24 jalan), tapi
   tampil gelap/hitam, bukan seperti tombol lain yang hijau.
2. **Tulisan kecil masih ada.** Label seksi "Grup utama" / "Grup proxy"
   / "Aturan rute" masih kecil-redup, hampir tak terbaca di tema gelap.
3. **Label dialog menimpa nilai (BUG).** Di dialog "Tambah grup", label
   "URL tes (URL-TEST)" menimpa teks "http://www.gstatic.com/generate_204"
   dan label "Interval tes (detik, 60-3600)" menimpa "300".

## Akar penyebab (dari kode)

1. **Tombol:** v1.0.24 memakai M2 `OutlinedButton` — latar transparan +
   garis 1dp + teks `colorPrimary`. Di tema gelap `colorPrimary` adalah
   abu `#FFC0C0C0` di atas latar hampir-hitam, jadi tombol terbaca
   "hitam". Tidak ada satu pun MaterialButton isi hijau di aplikasi
   untuk dicopy — yang hijau hanya FAB `fab_toggle` saat VPN jalan,
   yang tint-nya diganti kode menjadi `colorFabActive` (nilainya persis
   `colorAccent`: `#0FB88A` terang / `#22E6A8` gelap).
2. **Label seksi:** ketiga label memakai `?attr/textAppearanceTitleSmall`
   / `?attr/textAppearanceTitleMedium` — atribut yang **tidak pernah
   didefinisikan** di `Theme.TaptapNG` (hanya BodyLarge/Medium/Small +
   TitleLarge yang ada) maupun di parent M2 → resolve ke resource ID 0
   → label jatuh ke ukuran default kecil tanpa warna tema. Bug sekelas
   v1.0.3 (`ThemeTypographyTest`).
3. **Label dialog:** dialog dibangun programatik di `GroupsActivity.kt`
   (`showGroupDialog`). Label URL tes + Interval tes hanya ada sebagai
   `EditText.hint` — hint dirender di dalam area teks, di tempat nilai —
   di dalam `TextInputLayout(ctx)` polos tanpa style `OutlinedBox`,
   tanpa hint di layout, anaknya `EditText` biasa (bukan
   `TextInputEditText`), jadi tidak ada yang menegakkan float. Kedua
   field ini satu-satunya yang selalu terisi sejak awal (`setText`
   default URL tes / interval), jadi dari frame pertama hint dan nilai
   berbagi area teks yang sama. "Nama grup" memakai pola hint yang sama
   tapi kosong saat tambah grup, jadi hint-nya tampil sendiri sebagai
   placeholder — itulah kenapa hanya dua field ini yang rusak. Pola
   yang benar sudah ada di dialog yang sama: helper `labeled()` menaruh
   TextView label **di atas** kontrol (dipakai spinner "Tipe grup" /
   "Anggota terpilih").

## Yang berubah

| Bagian | Lama (v1.0.24) | Baru (v1.0.25) |
|---|---|---|
| Tombol Simpan / Tambah grup / Tambah aturan | M2 OutlinedButton, 15sp, teks `colorPrimary`, latar transparan + border 1dp | Style baru `Widget.TaptapNG.Button.FilledAccent` (di `themes.xml`): isi penuh `backgroundTint = @color/colorAccent` (`#0FB88A` terang / `#22E6A8` gelap), teks hitam eksplisit (`@android:color/black` — teks putih default tombol isi nyaris tak terbaca di atas mint/hijau) |
| Tombol ANGGOTA (PILIH SERVER) di dialog Tambah grup | `Button(ctx)` polos, isi default M2 = `colorPrimary` hitam — akar masalah yang sama | `MaterialButton(ctx, null, 0, R.style.Widget_TaptapNG_Button_FilledAccent)` + `textSize = 15f` |
| Label "Grup utama" / "Grup proxy" / "Aturan rute" | `?attr/textAppearanceTitleSmall/Medium` — tak terdefinisi → fallback kecil tanpa warna | `?attr/textAppearanceBodyLarge` — terdefinisi: **16sp, `?attr/colorOnSurface`** (`#FFE6E1E5` gelap / `#FF1C1B1F` terang), sama seperti header seksi di editor server ("Protokol", "Metode SSH", "Jaringan", dst.) |
| Label "URL tes (URL-TEST)" / "Interval tes (detik, 60-3600)" di dialog Tambah grup | `hint` di `EditText` di dalam `TextInputLayout` polos → menimpa nilai | Dibungkus `labeled(ctx, ...)` — TextView nyata di atas field, pola yang sama dengan spinner di dialog yang sama; tidak lagi bergantung pada mekanisme float |

Posisi/id/teks/fungsi tidak berubah di mana pun. Warna tema tidak
diubah. Tombol "Ambil fingerprint" di editor server tetap
OutlinedButton (layar lain, di luar scope). Header seksi Pengaturan
(14sp medium `colorSecondary`) sengaja tidak dicopy — 14sp adalah
ukuran "tulisan kecil" yang dikeluhkan user.

## Tes baru

- `GroupsHeaderButtonsTest` (+3, total 8 @Test): definisi style
  `FilledAccent`, `colorAccent` per tema + kesamaan dengan
  `colorFabActive`, tombol anggota memakai style yang sama.
- `GroupsSectionLabelsTest` (5 @Test): ketiga label BodyLarge; tidak
  ada lagi TitleSmall/Medium di layout; BodyLarge tema 16sp +
  onSurface; 5 header editor tetap BodyLarge (guard acuan).
- `GroupDialogLabelsTest` (4 @Test): label di atas field, hint hilang
  dari kedua input, default terisi tetap, `labeled()` menaruh label
  dulu, baris lain tidak berubah.

## Cara tes di HP

1. Instal timpa v1.0.24 tanpa hapus data (grup "taptap" + aturan lama
   terbawa).
2. Halaman **Grup**: tombol SIMPAN + TAMBAH GRUP kini hijau isi (bukan
   hitam), terbaca jelas; label "Grup utama" dan "Grup proxy" terbaca
   jelas — di tema terang maupun gelap.
3. Halaman **Rute**: tombol TAMBAH ATURAN hijau; label "Aturan rute"
   terbaca jelas.
4. Buka **Tambah grup**: label "URL tes (URL-TEST)" tampil DI ATAS
   nilai "http://www.gstatic.com/generate_204" (tidak menimpa);
   label "Interval tes (detik, 60-3600)" tampil DI ATAS "300".
5. Fungsi tetap jalan: ganti nama grup utama → Simpan → nama baru
   tampil tanpa restart; Tambah grup → dialog kebuka, ANGGOTA (PILIH
   SERVER) → dialog multi-pilih server; Tambah aturan → dialog aturan
   kebuka.
6. Konek **iflix** + **81** tetap jalan (regresi dilarang).

## Batasan jujur

- Keterbacaan visual tidak bisa dites di JVM (tidak ada Robolectric
  di tree ini); bukti runtime-nya screenshot HP.
- `:app:testDebugUnitTest`, `:app:compileDebugKotlin`, dan
  `:app:assembleRelease` dijalankan di CI (Gradle diblokir di VM).
