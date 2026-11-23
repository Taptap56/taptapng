# TaptapNG v1.0.24 (tombol aksi Grup/Rute disamakan dengan tombol lain)

Rilis 24 November 2026. APK `taptapng-v1.0.24.apk` (vc25, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
5 tes unit baru (total 914 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.23 — fungsi Grup/Rute tidak disentuh, UI-only.

Referensi: screenshot halaman Grup v1.0.23 (2026-11-24 04:01) + perintah
user "Tulisan kecil tombol gak keliatan sesuaikan seperti yg lain".

## Masalah (v1.0.23)

Tiga tombol aksi kecil di header — **"Simpan"** (kartu Grup utama),
**"Tambah grup"** (seksi Grup proxy), **"Tambah aturan"** (seksi Aturan
rute) — hampir tidak kelihatan di HP, padahal kartu "Grup utama" sendiri
tampil benar (field "taptap", tombol Simpan, hint "Berlaku langsung,
tanpa restart — rute dibaca per koneksi") dan grup "taptap" SELECT
4 anggota, Terpilih: iflix cloudfront.

## Akar penyebab (dari kode)

Ketiga tombol memakai `Widget.Material3.Button.TextButton` (Material
1.13.0): teks 14sp mixed-case medium, warna `?attr/colorPrimary`,
latar TRANSPARAN, tanpa garis tepi (strokeWidth 0dp) — satu-satunya
tombol tanpa latar dan tanpa border di aplikasi. `colorPrimary` =
hitam `#FF000000` di tema terang dan abu terang `#FFC0C0C0` di tema
gelap (`values-night/colors.xml`), jadi di tema gelap tulisannya abu
di atas latar hampir-hitam `#FF1C1B1F` tanpa apa pun yang menandainya
sebagai tombol. Di tema terang pun tampilannya paling tipis/kecil di
aplikasi: tanpa bentuk, tanpa huruf kapital, 14sp, bersebelahan dengan
judul seksi TitleMedium 16sp.

## Yang berubah

Ketiga tombol kini memakai gaya yang sama dengan tombol aksi lain di
aplikasi — `Widget.MaterialComponents.Button.OutlinedButton` (M2),
persis tombol "Ambil fingerprint" di layar Edit server (dan satu
keluarga M2 dengan tombol isi di layar utama) — ditambah
`android:textSize="15sp"` eksplisit, ukuran label yang dipakai status
bar dan alamat baris server di tempat lain. Hasilnya: garis tepi 1dp
+ teks huruf kapital M2 + 15sp, terbaca jelas di tema terang maupun
gelap. Warna teks/latar mengikuti style (colorPrimary, adaptif tema);
tidak ada warna tema yang diubah.

| Tombol | Lama (v1.0.23) | Baru (v1.0.24) |
|---|---|---|
| Simpan (`save_main_group`) | M3 TextButton, 14sp, `colorPrimary`, tanpa latar/border | M2 OutlinedButton, 15sp, `colorPrimary`, border 1dp |
| Tambah grup (`add_group`) | M3 TextButton, 14sp, `colorPrimary`, tanpa latar/border | M2 OutlinedButton, 15sp, `colorPrimary`, border 1dp |
| Tambah aturan (`add_rule`) | M3 TextButton, 14sp, `colorPrimary`, tanpa latar/border | M2 OutlinedButton, 15sp, `colorPrimary`, border 1dp |

Gaya "yang lain" diambil dari tombol **"Ambil fingerprint"**
(`button_fetch_fingerprint`, `activity_server_editor.xml`) — tombol
aksi sekunder di dalam form yang sama-sama M2 OutlinedButton — bukan
dari tombol isi hijau/TB-TC: tombol isi lain di aplikasi juga 14sp
dan juga `colorPrimary`, jadi bukan gaya hijau yang jadi acuan, melainkan
bentuk tombol M2 yang sudah ada (border + huruf kapital). Posisi ketiga
tombol tidak berubah, id/teks/click wiring tidak berubah, layout dan
fungsi lain tidak disentuh.

## Tes baru

`GroupsHeaderButtonsTest` (5 @Test, source-assertion atas
`activity_groups.xml` + `GroupsActivity.kt`): ketiga tombol memakai
OutlinedButton dan bukan lagi M3 TextButton; ketiganya 15sp; id/teks/
posisi/wiring tetap; tombol acuan di editor tetap OutlinedButton;
tidak ada M3 TextButton tersisa di layout Grup.

## Cara tes di HP

1. Instal timpa v1.0.23 tanpa hapus data (grup "taptap" + aturan lama
   terbawa).
2. Buka halaman **Grup**: tulisan "Simpan" di kartu "Grup utama" dan
   "Tambah grup" di seksi Grup proxy terbaca jelas seperti tombol lain
   (kotak bergaris tepi, huruf kapital) — di tema terang maupun gelap.
3. Buka halaman **Rute**: tulisan "Tambah aturan" terbaca jelas sama.
4. Fungsi tetap jalan: ganti nama grup utama → Simpan → nama baru
   tampil tanpa restart; Tambah grup → dialog grup kebuka; Tambah
   aturan → dialog aturan kebuka.
5. Konek **iflix** + **81** tetap jalan (regresi dilarang).

## Batasan jujur

- Keterbacaan visual tidak bisa dites di JVM (tidak ada Robolectric
  di tree ini); bukti runtime-nya screenshot HP (di atas).
- `:app:testDebugUnitTest`, `:app:compileDebugKotlin`, dan
  `:app:assembleRelease` dijalankan di CI (Gradle diblokir di VM).
