# TaptapNG v1.0.29 (detail koneksi: rule + rantai proxy di halaman Connections)

Rilis 24 November 2026. APK `taptapng-v1.0.29.apk` (vc30, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
23 tes unit baru (total 1012 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.28 (HEAD `2b4ad70`).

Referensi: pesan user 2026-11-24 06:44 — "Masih belum keliatan di log"
(screenshot Chrome, yacd online `#/con`, lingkaran merah di ">" koneksi
pertama 2001:678:8::123:123): detail koneksi di halaman Connections
tidak tampil — saat ">" ditekan, rule + rantai proxy tidak kelihatan.

## Masalah

`GET /connections` tidak mengirim `rule`/`rulePayload`/`chains` sama
sekali: `ConnectionInfo` (`ClashApiHandler.kt:28`) tidak punya ketiga
field itu, dan `connectionsSnapshotJson()` (:686) hanya mengirim
id/metadata/upload/download/start. Padahal frontend yacd yang dibundel
(`assets/index-tgGzoeh6.js`, normalizer `vJ`) me-render kolom + detail
koneksi dari `chains`, `rule`, `rulePayload` — jadi kolom rule/chains
kosong dan detail ">" kosong. Bukan salah yacd, bukan salah browser.

## Yang berubah

- `core/RouteEngine.kt`: baru `resolveDetailed(...)` — keputusan yang
  sama persis seperti `resolve()` lama (yang kini mendelegasikan ke
  sini), plus rekaman `RouteRecord(rule, rulePayload, chains)`:
  aturan yang cocok (tipe + pola normalisasi, "" untuk FINAL), rantai
  grup bersarang + nama server (`["taptap","tes","81"]`, langsung
  `["81"]`), `["DIRECT"]` untuk bypass, `["REJECT"]` untuk blokir,
  `GLOBAL`/`DIRECT` untuk mode Clash global/direct. `serverNames`
  (guid → display name, de-duplikasi seperti
  `ClashApiHandler.displayNames`) hanya dibaca untuk nama rantai,
  tidak pernah memengaruhi keputusan; guid tak dikenal → guid itu
  sendiri, tidak null.
- `service/TunForwarder.kt`: `TcpSession`/`UdpSession` menyimpan
  `rule`/`rulePayload`/`chains` (diisi di `dial()` / `handleProxyUdp()`,
  default aman `FINAL`/`""`/`[]`); `connectionRoutes()` mengembalikan
  rekaman per sesi hidup (key = `ConnectionInfo.id`); bila tidak ada
  record resolver, rekaman disintesis dari keputusan polos
  (`synthesizeRecord()`); `activeConnections()` kini membawa ketiga
  field itu ke dalam `ConnectionInfo` (TCP dan UDP).
- `service/ClashApiHandler.kt`: `ConnectionInfo` tambah `rule` /
  `rulePayload` / `chains` (default `""`/`""`/`[]`);
  `connectionsSnapshotJson()` mengirim ketiganya per koneksi (`chains`
  sebagai array string — persis bentuk yang dicek `Array.isArray` oleh
  `vJ`; yacd menampilkan kolom `terakhir -> pertama`, detail
  dibalik `" → "`, dan tipe outbound dari `chains[0]`).
- `service/TaptapVpnService.kt` (merge): service memasang
  `routeRecordResolver` di samping `routeResolver` lama — keputusan
  sama, plus rekaman; `serverNames` dibangun ulang tiap koneksi dari
  profile store supaya rename langsung terasa tanpa restart tunnel.

## Contoh nilai per jenis koneksi

| Koneksi | rule | rulePayload | chains |
|---|---|---|---|
| FINAL → proxy langsung | `FINAL` | `""` | `["81"]` |
| Pilihan bersarang | `FINAL` | `""` | `["taptap","tes","81"]` |
| Aturan DOMAIN-SUFFIX → grup | `DOMAIN-SUFFIX` | `example.com` | `["81"]` |
| Bypass (IP-CIDR → DIRECT) | `IP-CIDR` | `192.168.0.0/16` | `["DIRECT"]` |
| Blokir (DOMAIN → REJECT) | `DOMAIN` | `blocked.example` | `["REJECT"]` |

REJECT tidak punya sesi hidup (sesi langsung dihapus + RST sejak
dulu), jadi `["REJECT"]` terdefinisi di level engine tapi tidak
teramati di koneksi hidup. UDP tetap 0 byte (sudah didokumentasikan).

## Tes baru (23 — gagal di kode lama, lolos di baru)

- `RouteRecordTest.kt` (11): `resolveDetailed` untuk FINAL langsung,
  bersarang, DOMAIN-SUFFIX, DIRECT, REJECT, mode global/direct,
  tanpa aturan cocok.
- `TunForwarderRouteRecordTest.kt` (8 + 2 merge): rekaman sesi TCP/UDP
  + `connectionRoutes()`; 2 tes merge membuktikan `activeConnections()`
  membawa rule/rulePayload/chains (FINAL langsung + bersarang).
- `ClashApiHandlerTest.kt` (2): snapshot JSON membawa ketiga field
  (default kosong + nilai contoh 4 koneksi).

## Cara tes di HP

1. VPN jalan, buka Connections di dashboard — tiap baris menampilkan
   rule + rantai proxy (mis. `FINAL` + `81 -> taptap` untuk pilihan
   bersarang, `DIRECT` untuk bypass).
2. Tekan ">" di satu koneksi → detail tampil rule + proxy chain yang
   benar.
3. Konek iflix + 81 tetap jalan seperti v1.0.28.

## Batasan (jujur)

- Detail koneksi hanya bisa dibuktikan dari screenshot HP — tes JVM
  membuktikan rekaman + bentuk JSON, bukan tampilannya di yacd.
- Wiring service (`routeRecordResolver`) tidak punya tes JVM (butuh
  service Android) — tercakup compile CI + tes forwarder di atas.
