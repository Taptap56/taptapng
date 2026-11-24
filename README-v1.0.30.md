# TaptapNG v1.0.30 (rantai koneksi leaf-first + dashboard bisa di-scroll sampai bawah)

Rilis 24 November 2026. APK `taptapng-v1.0.30.apk` (vc31, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
1 tes unit baru (total 1013 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.29 (HEAD `ca40381`); kedua perbaikan di bawah
sudah di-commit sebelum bump ini (`755e0e0`, `6615440`).

Referensi: tes HP v1.0.29 2026-11-24 07:57–07:58 (5 screenshot) —
(1) pilihan bersarang tampil "FINAL › taptap" di baris Connections,
hanya nama grup, bukan server 81; (2) dashboard tidak bisa di-scroll
sampai bawah (tambahan user 08:21).

## Masalah 1 — urutan `chains` terbalik dari mihomo

`GET /connections` mengirim `chains` grup-dulu (`["taptap","tes","81"]`),
padahal mihomo mengirim server-dulu (`["81","tes","taptap"]`): di
mihomo, leaf di-append saat dial (`NewConn`, base.go:294), grup
di-append SESUDAH dial anak (selector.go:27, urltest.go:61,
fallback.go:36). yacd menampilkan baris koneksi dari `chains[0]`
(`chainNode`), jadi urutan kami membuat baris menampilkan nama grup
("FINAL › taptap") bukan server. Detail ">" tetap benar (rantai penuh,
hanya terbalik: "81 → tes → taptap").

## Yang berubah (1)

- `core/RouteEngine.kt`: `resolveChainNames()` dibalik jadi
  leaf-first — anggota langsung `["81"]`, bersarang
  `["81","tes","taptap"]`, `["DIRECT"]` untuk bypass, `["REJECT"]`
  untuk blokir. KDoc `RouteEngine` + `ClashApiHandler` disesuaikan
  (urutan mihomo).
- Tes v1.0.29 yang mengunci urutan grup-dulu ikut dibalik
  (`RouteRecordTest`, `TunForwarderRouteRecordTest`,
  `ClashApiHandlerTest`) + 1 tes baru
  `chainNamesDirectCallIsLeafFirstForNested`.
- Pemanggil lain tidak mengandalkan urutan grup-dulu: `TunForwarder`
  hanya menyimpan/meneruskan `record.chains`; `TaptapVpnService`
  hanya memasang resolver; history/now dashboard pakai
  `resolveToServer` / `selectMemberRef`, bukan `chains`.

## Masalah 2 — dashboard tidak bisa di-scroll sampai bawah

WebView dashboard `MATCH_PARENT` di dalam `dashboard_container`
match_parent, sementara `bottom_bar` 64dp (`layout_gravity="bottom"`)
menutupi 64dp terbawahnya — viewport yacd (100vh) berakhir di bawah
bar, jadi kartu/baris terakhir + kaki halaman ("Showing …") tidak
bisa di-scroll ke atas bar. Daftar server menyelesaikan overlap yang
sama dengan `paddingBottom="80dp"` + `clipToPadding="false"`;
dashboard tidak punya padanan.

## Yang berubah (2)

- `ui/MainActivity.kt` (`createDashboardWebView()`): WebView kini
  pakai `FrameLayout.LayoutParams` dengan `bottomMargin` 80dp, supaya
  viewport yacd berakhir di atas bottom bar 64dp + FAB. Margin
  dipasang di WebView, bukan di container: `FrameLayout` selalu
  menghormati margin anak, sementara tinggi `MATCH_PARENT` container
  diatur `ScrollingViewBehavior`.
- Bottom bar, FAB, toolbar, dan tab tidak diubah. Berlaku untuk
  semua halaman dashboard (Proxies, Connections, Rules, Overview).

## Tes

- 50 @Test lolos lokal (kotlinc standalone + JUnit, Gradle diblokir
  di VM) di kode baru; 5 tes rantai bersarang gagal di kode lama
  (`RouteEngine` HEAD sebelum perbaikan) — membuktikan tes
  mendiskriminasi. Total tree: 1013 @Test (1012 di v1.0.29 + 1 baru).
- Tidak ada tes JVM untuk layout dashboard (tanpa Robolectric) —
  bukti visual hanya dari screenshot HP.

## Cara tes di HP

1. Pilih "tes" di dashboard (grup bersarang "tes" di dalam "taptap")
   → buka Connections → baris koneksi menampilkan
   "FINAL › 81" (bukan "FINAL › taptap").
2. Tekan ">" di koneksi itu → detail menampilkan rantai penuh
   "taptap → tes → 81".
3. Anggota langsung tetap benar: koneksi ke `hack-VLESS-H2-NonTLS`
   menampilkan "FINAL › hack-VLESS-H2-NonTLS".
4. Dashboard (Proxies / Connections / Rules / Overview) bisa
   di-scroll sampai bawah — kartu/baris terakhir + kaki
   "Showing …" kelihatan penuh tanpa tertutup bar bawah.
5. Konek iflix + 81 + hack-VLESS tetap jalan seperti v1.0.29.

## Batasan (jujur)

- Baris Connections + scroll dashboard hanya bisa dibuktikan dari
  screenshot HP — tes JVM membuktikan urutan `chains` + bentuk JSON,
  bukan tampilannya di yacd; layout WebView tidak punya tes JVM.
- Koneksi lama tetap di server lama sampai putus (sama seperti Clash);
  pindah server live hanya berlaku untuk koneksi baru.
