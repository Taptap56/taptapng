# TaptapNG v1.0.22 (drawer "Rute" benar-benar hanya aturan)

Rilis 24 November 2026. APK `taptapng-v1.0.22.apk` (vc23, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
4 tes unit baru (total 877 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.

## Bug yang diperbaiki

Menu drawer **"Rute"** di v1.0.21 membuka layar yang SAMA persis dengan
"Grup": kedua seksi ("Grup proxy" + "Aturan rute") kelihatan, layar
terbuka di posisi atas. Scroll ke header aturan (`post { scrollTo }`)
tidak jalan di HP (screenshot 2026-11-24 03:13).

**Akar penyebab (dari kode, bukan tebakan).** Hack v1.0.21
(`scrollView.post { scrollView.scrollTo(0, rulesHeader.top) }`)
dipanggil dari `onCreate`, sesudah `setContentView` tapi sebelum view
ter-attach ke window. `View.post()` saat itu tidak masuk handler queue
melainkan `RunQueue`, yang dieksekusi di `dispatchAttachedToWindow` —
dan itu terjadi SEBELUM `performMeasure`/`performLayout` pertama. Jadi
saat runnable jalan, belum ada satu pun view yang di-layout,
`rulesHeader.top` persis 0, dan `scrollTo(0, 0)` = no-op. Sekunder:
kalaupun timing diperbaiki, scroll sekali tetap kalah lawan layout
RecyclerView (`refresh()` hanya `submit()` → pengukuran konten terjadi
di layout pass berikutnya, tanpa pengulangan scroll).

## Yang berubah

- `GroupsActivity` kini **menyembunyikan seksi yang tidak relevan
  dengan `View.GONE`** sesuai `EXTRA_SECTION`, dan hack scroll
  **dihapus seluruhnya** (termasuk import `NestedScrollView`):
  - Drawer "Grup" → hanya seksi grup yang tampil (seksi aturan GONE).
  - Drawer "Rute" → hanya seksi aturan yang tampil (seksi grup GONE).
  - Tanpa extra (entry overflow lama "Grup proxy & rute") → kedua
    seksi tampil seperti dulu.
  - Judul toolbar tetap ikut seksi ("Grup"/"Rute").
- Keputusan visibilitas dipisah jadi fungsi pure `sectionsVisibleFor`
  di companion (`Grup → (true, false)`, `Rute → (false, true)`,
  default/tak dikenal → `(true, true)`).
- Layout `activity_groups.xml`: tiap seksi dibungkus container ber-id
  (`groups_section`, `rules_section`); isi tiap seksi tidak diubah.
- **Tidak ada yang lain berubah:** migrasi grup "taptap", dashboard
  satu grup, live-switch, start-sync — semuanya disentuh nol.

## Tes

- `GroupsSectionTest` — 12 @Test (sebelumnya 8): **4 baru**
  (`sectionsVisibleFor` untuk Grup / Rute / default / seksi tak
  dikenal) + 8 lama dipertahankan, termasuk assertion bahwa tidak ada
  lagi `scrollTo`/`rulesHeader`/`NestedScrollView` di activity.
- **Batasan jujur:** penerapan `View.GONE` di `onCreate` tidak bisa
  dites di JVM (tidak ada Robolectric di tree ini — hanya JUnit 5 +
  source-assertion); bukti runtime-nya tes di HP (di bawah).

## Cara tes di HP

1. Instal timpa v1.0.21 tanpa hapus data.
2. Buka drawer **"Rute"** — hanya aturan yang tampil (FINAL → taptap),
   tidak ada seksi grup sama sekali.
3. Buka drawer **"Grup"** — hanya grup yang tampil (taptap SELECT,
   4 anggota, Terpilih: iflix cloudfront), tidak ada seksi aturan.
4. Buka overflow **"Grup proxy & rute"** — kedua seksi tampil seperti
   dulu.
5. Konek **iflix** + **81** tetap jalan (regresi dilarang).
