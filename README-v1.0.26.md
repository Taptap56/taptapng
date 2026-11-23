# TaptapNG v1.0.26 (nama+tipe baris tidak menimpa, ikon aksi terlihat, label "Nama grup" di atas nilai)

Rilis 24 November 2026. APK `taptapng-v1.0.26.apk` (vc27, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
20 tes unit baru (total 946 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.25 — fungsi Grup/Rute tidak disentuh, UI-only.

Referensi: 3 screenshot HP user (2026-11-24 05:03–05:04, diedit,
dilingkari merah) + pesan "Yg ini lo".

## Masalah (v1.0.25)

1. **Nama + tipe grup menimpa di baris list.** "taptap SELECT" dan
   "tes URL-TEST" bertabrakan — nama grup dan tipe grup digambar
   menumpuk. Di baris aturan (`item_route_rule.xml:37`) pola yang
   sama dipakai judul aturan.
2. **Ikon aksi baris hitam/gelap.** Ikon edit (pensil) + hapus (tong
   sampah) di baris grup, dan naik/turun + edit + hapus di baris
   aturan, nyaris tak terlihat di atas latar gelap.
3. **Label "Nama grup" menimpa nilai di dialog Ubah.** Saat edit grup,
   field nama terisi "taptap" dan label "Nama grup" menimpa nilainya —
   bug hint yang sama seperti URL/Interval di v1.0.25, tapi field ini
   tidak ikut diperbaiki karena saat tambah grup fieldnya kosong.

Yang sudah terbukti jalan di v1.0.25: tombol hijau (SIMPAN, TAMBAH
GRUP, TAMBAH ATURAN terbaca); label dialog URL tes + Interval tes
sudah di atas nilai; user berhasil buat grup baru "tes" (URL-TEST,
2 anggota); Terpilih grup taptap kini "81".

## Akar penyebab (dari kode)

1. **Baris menimpa — dua lapis.** (a) `group_name` memakai
   `?attr/textAppearanceTitleSmall` — atribut yang **tidak pernah
   didefinisikan** di `Theme.TaptapNG` (hanya BodyLarge/Medium/Small
   + TitleLarge yang ada) maupun di parent M2 → resolve ke resource
   ID 0 → fallback kecil tanpa warna (mekanisme yang sama dengan
   label seksi v1.0.25); dibuktikan dari APK kiriman v1.0.25
   (`aapt2 dump resources`: grep seluruh dump hanya menemukan
   definisi attr-nya sendiri, nol assignment). Sementara
   `group_type` render normal di BodySmall 12sp yang terdefinisi,
   sehingga nama kecil-redup dan tipe besar-terang terbaca sebagai
   satu gumpalan bertabrakan. (b) Nama dan tipe dua-duanya
   `wrap_content` tanpa weight/maxLines/ellipsize/maxWidth — beda
   dengan satu-satunya baris dua-label lain di aplikasi,
   `item_server.xml`, yang membatasi nama (`remarks` = 0dp + weight
   1 + ellipsize + maxLines 2). Adapter tidak bisa menyelamatkan
   ini: `GroupAdapter.onBindViewHolder` hanya set `.text`, tidak
   pernah menyentuh lebar/ellipsize.
2. **Ikon hitam.** Keempat drawable vector fill-nya hard-coded hitam
   pekat (`ic_edit_24dp`, `ic_delete_24dp`, `ic_arrow_up_24dp`,
   `ic_arrow_down_24dp` — semuanya `android:fillColor="#FF000000"`),
   dan keenam `ImageButton` baris grup/aturan **tanpa atribut tint**
   → ikon dirender hitam mentah di atas latar gelap. Pembanding yang
   membuktikan: baris server (`item_server.xml`) memakai drawable
   yang sama tapi terlihat, karena `btn_share`/`btn_edit`/`btn_delete`
   di sana semuanya membawa `android:tint="?attr/colorOnSurface"`.
3. **Label dialog.** Sama seperti URL/Interval di v1.0.24: label
   "Nama grup" hanya ada sebagai `EditText.hint` di dalam
   `TextInputLayout(ctx)` polos tanpa style OutlinedBox, anaknya
   `EditText` biasa (bukan `TextInputEditText`), jadi tidak ada yang
   menegakkan float. Saat Tambah grup field kosong → hint tampil
   sendiri, kelihatan normal. Saat Ubah grup field terisi `"taptap"`
   → hint dan nilai berbagi area teks yang sama.

## Yang berubah

| Bagian | Lama (v1.0.25) | Baru (v1.0.26) |
|---|---|---|
| `group_name` di `item_proxy_group.xml` | `wrap_content` + `textAppearanceTitleSmall` (tak terdefinisi → fallback kecil tanpa warna) | `0dp` + `layout_weight="1"` + `ellipsize="end"` + `maxLines="1"` + `textAppearanceBodyLarge` (16sp, `colorOnSurface` — pola v1.0.25, sama seperti nama baris server). Nama yang mengalah, bukan tipe |
| `group_type` | `wrap_content` + BodySmall + `colorPrimary` | tetap, tambah `maxLines="1"` |
| `rule_pattern` di `item_route_rule.xml` (`:37`) | `wrap_content` + `textAppearanceTitleSmall` | `0dp` + weight 1 + ellipsize + maxLines 1 + BodyLarge (baris aturan ruangnya lebih sempit: toggle + 4× tombol 48dp) |
| `rule_type` | BodySmall + `colorPrimary` | tetap, tambah `maxLines="1"` |
| 6 ikon aksi baris (`group_edit`, `group_delete`, `rule_move_up`, `rule_move_down`, `rule_edit`, `rule_delete`) | tanpa tint → drawable hitam `#FF000000` mentah | `android:tint="?attr/colorOnSurface"` per tombol (`#FFE6E1E5` gelap / `#FF1C1B1F` terang — adaptif tema). Drawable **tidak** diubah, karena `ic_edit`/`ic_delete` juga dipakai `editor_toolbar.xml` dan `log_toolbar.xml` (menu toolbar men-tint ikonnya sendiri lewat tema toolbar) |
| Label "Nama grup" di dialog grup (`showGroupDialog`, tambah maupun ubah) | `hint` di `EditText` → menimpa nilai saat edit | Dibungkus `labeled(ctx, ...)` — TextView nyata di atas field, pola yang sama dengan URL tes / Interval tes (v1.0.25) dan spinner "Tipe grup" / "Anggota terpilih"; `hint` dihapus, `setText` pre-fill tetap |

Posisi/id/teks/fungsi tidak berubah di mana pun. Setelah perbaikan,
tidak ada lagi pemakaian `textAppearanceTitleSmall`/`TitleMedium`
sebagai atribut di `res/` (yang tersisa hanya penyebutan di komentar
XML sebagai dokumentasi akar penyebab).

## Tes baru

- `GroupRowLabelsTest` (8 @Test): nama BodyLarge + 0dp/weight/
  ellipsize/maxLines 1; tipe tetap BodySmall + maxLines 1; pola yang
  sama di baris aturan; tidak ada lagi TitleSmall sebagai atribut.
  Di kode lama 6 gagal, sesudah perbaikan 8/8 lolos.
- `GroupsRowIconsTest` (7 @Test): keenam tombol bertint
  `colorOnSurface`; drawable tetap ber-fill hitam (guard — tint
  harus di layout, bukan dengan mengubah drawable). Di kode lama 2
  tes tint gagal; sesudah perbaikan 7/7 lolos.
- `GroupDialogLabelsTest` (+1, total 5 @Test): field nama memakai
  `labeled()` tanpa hint yang menimpa, `setText` pre-fill tetap;
  guard lama yang mengunci pola hint nama dihapus karena justru
  itulah bugnya; baris lain (Tipe grup, Anggota terpilih, ANGGOTA,
  OK/BATAL) tidak berubah. Gagal di kode lama, 5/5 lolos di kode
  baru.

## Cara tes di HP

1. Instal timpa v1.0.25 tanpa hapus data (grup "taptap" + "tes" +
   aturan lama terbawa).
2. Halaman **Grup**: nama tiap baris ("taptap", "tes") besar-terang,
   tipe ("SELECT", "URL-TEST") kecil di kanannya dengan jarak jelas,
   tidak menimpa; ikon pensil + tong sampah terlihat jelas (putih
   keabuan di tema gelap). Uji nama panjang (buat/rename grup dengan
   nama panjang) — nama terpotong "…" dan tipe tetap kelihatan penuh.
3. Halaman **Rute**: pola aturan besar-terang, tipe aturan kecil di
   kirinya, satu baris, tidak bertabrakan; ikon naik/turun + pensil
   + tong sampah terlihat jelas. Ulangi tema terang: ikon tetap
   terlihat (hitam di atas latar terang).
4. Dialog **Ubah** grup "taptap": label "Nama grup" di atas nilai
   "taptap", keduanya terbaca penuh, tidak menimpa. Dialog **Tambah**
   grup: label "Nama grup" di atas field kosong.
5. Fungsi tetap jalan: tambah/ubah grup, pindah aturan naik/turun,
   toggle aturan, konek **iflix** + **81** tetap jalan (regresi
   dilarang).

## Batasan jujur

- Keterbacaan visual tidak bisa dites di JVM (tidak ada Robolectric
  di tree ini); bukti runtime-nya screenshot HP.
- `:app:testDebugUnitTest`, `:app:compileDebugKotlin`, dan
  `:app:assembleRelease` dijalankan di CI (Gradle diblokir di VM).
