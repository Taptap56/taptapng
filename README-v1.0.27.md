# TaptapNG v1.0.27 (FINAL + grup utama tak bisa diedit, grup bersarang, halaman Rules jalan)

Rilis 24 November 2026. APK `taptapng-v1.0.27.apk` (vc28, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
43 tes unit baru net (10 no-edit + 31 nested + 2 rules; total 985 @Test,
dihitung dari tree; dijalankan CI, Gradle diblokir di VM), plus
seluruh regresi yang sudah ada.
Dibangun di atas v1.0.26 — tiga perubahan di bawah, masing-masing
di branch kerja terpisah lalu di-merge bersih tanpa konflik.

Referensi: 5 screenshot HP user (2026-11-24 05:37–05:38) + pesan
"Harusnya taptap final tidak bisa di edit di grup msupun rute dia
cuma bisa di edit namanya saja di grup, url test baru harusnya masuk
ke taptap grup juga, tombol rule penggaris belum jalan bila ditekan
maka ia akan ke halaman ini".

Yang sudah terbukti jalan di v1.0.26: baris grup + aturan sudah benar
(nama dan tipe terpisah, ikon terlihat); dashboard tampil Groups 2 —
"taptap" Selector (Terpilih: 81, 312ms) + "tes" URLTest (Terpilih:
iflix cloudfront, 662ms), tanpa kartu "Proxy"/"GLOBAL".

## 1. FINAL + grup utama tidak bisa diedit

**Masalah.** Di halaman Rute, baris FINAL masih menampilkan keempat
ikon aksi (naik/turun/edit/hapus) padahal FINAL adalah rute akhir
yang tidak boleh diubah. Di halaman Grup, baris grup utama "taptap"
masih menampilkan pensil + tong sampah padahal grup utama hanya boleh
diubah namanya lewat kartu "Grup utama" (v1.0.23).

**Akar penyebab (dari kode).** Kedua adapter di `GroupsActivity.kt`
mengikat tombol aksi **tanpa syarat**: `GroupAdapter` selalu memasang
edit/hapus dalam keadaan terlihat, `RuleAdapter` selalu memasang
naik/turun/edit/hapus dalam keadaan terlihat. Satu-satunya guard yang
ada adalah toggle FINAL (v1.0.23) — tidak ada pengecekan "apakah ini
grup utama" atau "apakah ini FINAL" di binding baris mana pun.

**Yang berubah.**
- `GroupAdapter`: edit/hapus disembunyikan (`GONE`) pada baris grup
  utama saja, lewat helper murni `groupActionsVisible(group,
  mainGroupId) = group.id != mainGroupId`. Identitas by **id, bukan
  nama** — rename grup utama tidak membuka kembali tombolnya.
  Grup lain ("tes") tetap bisa edit/hapus.
- `RuleAdapter`: keempat ikon disembunyikan pada baris FINAL saja,
  lewat helper murni `ruleActionsVisible(rule) = rule.type !=
  RouteRuleType.FINAL`. Aturan lain tetap punya ikon lengkap; toggle
  FINAL tetap GONE (v1.0.23, tidak berubah).
- Visibilitas diset di **kedua cabang** (RecyclerView mendaur ulang
  baris — baris main yang dipakai ulang tidak boleh mewarisi tombol
  terlihat dari grup lain). Layout XML tidak diubah.
- Lapisan data sengaja tidak diubah: `GroupsStore.removeGroup(main)`
  sudah "dialihkan dengan aman" — menghapus grup utama me-resolve
  ulang `mainGroupId` ke grup berikutnya dan FINAL yang targetnya
  basi dilewati engine (perilaku yang dipin `MainGroupTest`).
  Rename grup utama tetap membuat target FINAL mengikuti (sudah
  jalan sejak v1.0.23).

**Tes baru.** `GroupsNoEditTest` (10 @Test): FINAL tanpa aksi,
grup utama tanpa aksi, rename tidak membuka tombol (identitas id),
grup lain bernama "taptap" tetap bisa edit, `mainGroupId` null =
semua baris bisa edit, toggle FINAL tetap tersembunyi, rename
mengikuti FINAL + engine, hapus grup utama re-resolve aman,
file lama tanpa `mainGroupId` tetap ter-resolve.

**Caveat.** Menu dashboard di `MainActivity.confirmDeleteGroup` →
`MainViewModel.removeGroup` → `GroupsStore.removeGroup` tetap bisa
menghapus grup utama (ditangani aman oleh store, lihat di atas).
Bila penghapusan itu juga harus ditutup di UI dashboard, itu
pekerjaan terpisah. Dialog "Tambah aturan" masih mengizinkan membuat
aturan FINAL kedua — juga di luar cakupan ini.

## 2. Grup bersarang — grup url-test baru masuk ke taptap juga

**Masalah.** Grup "tes" (URL-TEST) yang dibuat lewat dialog Tambah
grup hidup terpisah; di dashboard ia hanya tampil sebagai kartu
sendiri. Harusnya ia juga menjadi anggota grup utama "taptap"
sehingga muncul sebagai node di dalam kartu "taptap" dan bisa
dipilih — panah oranye user di screenshot dashboard menunjuk
"tes" → ke dalam "taptap".

**Akar penyebab (dari kode).** `ProxyGroup.members` hanya bisa
berisi guid server — tidak ada tempat merujuk grup lain.
`GroupsStore` tidak pernah menambahkan grup baru ke grup mana pun,
`RouteEngine.selectMember` hanya mengenal guid server, dan
`ClashApiHandler.proxiesObject()` membangun `all` hanya dari nama
server.

**Yang berubah.**
- **Model:** `ProxyGroup` dapat field baru `groupMembers:
  List<String>?` (id grup bersarang, nullable mengikuti pola
  `RouteRule.enabled` — file v1.0.26 tanpa key terbaca kosong, Gson
  mengomit null saat tulis; tidak ada field lama yang diubah).
  `selectedMemberGuid` kini boleh menyimpan id grup.
- **Store:** `GroupsStore.ensureNestedInMain()` menegakkan invarian
  — semua grup non-utama jadi anggota grup utama; dipanggil saat
  `load` (migrasi file lama, termasuk "tes" yang sudah ada),
  `addGroup` (grup baru otomatis masuk taptap), `removeGroup` (id
  terhapus ikut hilang dari keanggotaan; bila grup utama dihapus,
  grup utama baru mewarisi sisanya). `updateGroup` men-sanitasi:
  id grup utama dan id sendiri tidak pernah tersimpan sebagai
  anggota grup lain.
- **RouteEngine:** `selectMemberRef` (pilih anggota di antara
  server + grup bersarang, per tipe SELECT/URL_TEST/FALLBACK),
  `resolveToServer` (ikut sampai ke server nyata), `groupDelay`.
  Siklus (A↔B, self) dipotong visited-set, dicatat ke DialLog
  (`ROUTE: grup bersarang siklus ...`), lalu fall-through ke
  Direct — tidak crash, tidak hang.
- **Clash API:** `GET /proxies` — `all` grup kini berisi nama
  server + nama grup bersarang; `now` = nama anggota terpilih
  (nama server, atau nama grup bersarang — yacd merender rantai
  `tes › Server A`); `history` = history server hasil resolve.
  `GET /proxies/{nama}/delay` me-resolve grup bersarang ke server
  terbaiknya dulu. `PUT /proxies/{grup}` menerima nama grup
  bersarang. Grup tanpa anggota bersarang mengeluarkan respons
  yang identik dengan sebelumnya. Diverifikasi dari JS yacd yang
  dibundel: member bertipe Selector/URLTest/Fallback dirender
  sebagai node grup, latensinya mengikuti rantai `now` (cap 3
  level) dengan fallback ke `history`.
- Grup utama TIDAK boleh menjadi anggota grup lain. Grup yang
  dihapus hilang dari daftar anggota grup utama juga. Kartu grup
  itu sendiri ("tes") tetap tampil terpisah (dashboard tetap
  Groups 2). Perilaku seleksi grup SELECT biasa tidak berubah.

**Tes baru.** 31 @Test: `ProxyGroupTest` +5, `RouteEngineNestedTest`
10, `NestedGroupsTest` 8, `ClashApiHandlerNestedTest` 8 — migrasi
load file v1.0.26, grup baru otomatis masuk taptap, hapus grup
membersihkan keanggotaan, cegah self + siklus, `/proxies` memuat
node "tes" di dalam "taptap" beserta delay, PUT memilih node
bersarang, RouteEngine me-resolve pilihan bersarang ke server,
hapus grup utama mewariskan nesting.

**Caveat.** Render node bersarang oleh yacd dan routing lewat node
bersarang hanya bisa dibuktikan dari screenshot HP — verifikasi di
sini sebatas membaca JS yacd yang dibundel dan bentuk respons API.
`LiveClashApiDeps.selectProxy` (produksi, butuh Android Context)
tidak bisa diuji JVM — logika intinya dishare sebagai fungsi murni
dan diuji lewat FakeDeps. Bila dua grup punya nama sama, seleksi
PUT memakai yang pertama ditemukan (ambiguitas nama sudah ada
sebelumnya di `/proxies`).

## 3. Tombol penggaris (Rules) di dashboard

**Masalah.** Di dashboard yacd, menekan ikon penggaris (tab Rules
`#/rules`) malah membuka halaman error yacd (logo kucing + teks
Mandarin "出错了! 请尝试清理缓存和Cookie后重试" + "Switch
backend" + "metacubex/yacd"), padahal harusnya membuka halaman
Rules. Halaman Proxies tampil benar.

**Akar penyebab (dari kode).** Frontend yacd yang dibundel
(`assets/yacd/assets/index-tgGzoeh6.js`) menuntut respons `GET
/rules` berupa **objek `{"rules": [...]}`** — normalizer `K$`
melempar invariant `there is no valid rules list in the rules
API response` bila `e.rules` tidak ada, dan throw itu yang
menampilkan halaman error generik yacd. Handler lama
(`ClashApiHandler.handleRules`) mengembalikan **bare array
top-level** — pada array, `e.rules` = `undefined` → invariant
throw → halaman Rules crash. API Clash/mihomo asli mengembalikan
`{"rules": [...]}`; handler kita menyimpang dari API asli.
Halaman Proxies tidak kena karena `/proxies` memang mengembalikan
objek.

**Yang berubah (hanya sisi API, aset yacd TIDAK disentuh).**
- `GET /rules` kini `json(200, obj { add("rules", rulesArray()) })`
  → `{"rules": [...]}`. Helper `jsonArray` yang kini tak terpakai
  dihapus.
- `GET /providers/rules` provider `default` dilengkapi `updatedAt`
  (ISO UTC saat itu) + `ruleCount` — temuan kedua: row provider
  yacd memanggil `formatDistance(new Date(updatedAt))`; tanpa
  `updatedAt` tab Providers di halaman yang sama akan crash juga.
- Per aturan, `payload` selalu string (`""` untuk FINAL, bukan
  null — penting karena frontend memanggil
  `payload.toLowerCase()` dan `payload.startsWith("(")`), `proxy`
  selalu string. Sudah aman, tidak diubah.

**Tes baru.** `ClashApiHandlerTest` — 1 diperbarui + 2 baru:
bentuk objek + field `type`/`payload`/`proxy` + FINAL `payload ==
""`; nol aturan → `{"rules": []}` (empty state, bukan error);
provider `updatedAt` lolos `Instant.parse` + `ruleCount` benar.

**Caveat.** Toggle on/off per aturan tidak ada di halaman ini
(sengaja): aturan kita tidak mengirim field `extra.disabled`, jadi
yacd tidak me-render switch — `PATCH /rules/disable` tetap no-op
204. Bila setelah perbaikan ini halaman Rules masih error di HP,
data yang dibutuhkan: isi persis respons `GET
http://127.0.0.1:9091/rules` (via curl dari Termux/ADB saat VPN
jalan) + baris log WebView/console bila ada.

## Cara tes di HP

1. Instal timpa v1.0.26 tanpa hapus data (grup "taptap" + "tes" +
   aturan lama terbawa).
2. Halaman **Rute**: baris FINAL ("Rute akhir") tanpa ikon
   naik/turun/edit/hapus dan tanpa toggle; aturan lain tetap punya
   keempat ikon + toggle.
3. Halaman **Grup**: baris "taptap" tanpa pensil/tong sampah; grup
   "tes" tetap punya pensil + tong sampah. Rename lewat kartu
   "Grup utama" → Simpan → nama berubah, FINAL tetap menunjuk
   grup itu (rute tetap jalan, tanpa restart).
4. **Dashboard**: kartu "tes" muncul sebagai node di dalam kartu
   "taptap" (dengan delay-nya), dan kartu "tes" tetap ada terpisah
   — Groups tetap 2. Ketuk node "tes" di dalam "taptap" → `now`
   taptap jadi "tes", trafik lewat anggota terbaik "tes". Buat grup
   baru lewat Tambah grup → otomatis muncul di dalam taptap.
5. Tekan ikon **penggaris** → halaman Rules tampil berisi daftar
   aturan (termasuk FINAL), bukan halaman error. Tab Providers di
   halaman Rules juga tampil tanpa crash.
6. Konek **iflix** + **81** tetap jalan (regresi dilarang).

## Batasan jujur

- Visual + perilaku dashboard hanya bisa dibuktikan dari
  screenshot HP (tidak ada Robolectric di tree ini); tes JVM hanya
  menegaskan nilai di source + bentuk respons API.
- `:app:testDebugUnitTest`, `:app:compileDebugKotlin`, dan
  `:app:assembleRelease` dijalankan di CI (Gradle diblokir di VM).
