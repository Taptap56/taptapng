# TaptapNG v1.0.31 (paket hemat baterai)

Rilis 24 November 2026. APK `taptapng-v1.0.31.apk` (vc32, `com.taptap.ng`,
ditandatangani keystore rilis stabil — bisa menimpa v1.0.2 ke atas).
26 tes unit baru (total 1039 @Test, dihitung dari tree; dijalankan CI,
Gradle diblokir di VM), plus seluruh regresi yang sudah ada.
Dibangun di atas v1.0.30 (HEAD `39132d8`); perbaikan di bawah sudah
di-commit sebelum bump ini (`c51c6a9`, `062f08e`, merge `2a3b052`,
`3147da0`).

Referensi: laporan user 2026-11-24 14:43 (screenshot MIUI Baterai):
TaptapNG 60,61% (terbesar), YouTube 26,03%, Telegram 8,58% — kembali
ke level 60,89% idle (2026-11-21); build hemat v1.0.16 tidak
menggerakkan angka.

## Hasil audit (dari kode, sebelum membangun)

Perbaikan v1.0.16 memang sudah benar — sleep-until-due PemicuManager,
writer 30 dtk + WRITER_WAKE, gate layar-mati Observatory, MainActivity
tanpa poll berulang. Yang TIDAK diperbaiki v1.0.16 adalah dial-nya
sendiri: sleep-until-due menghemat bangun CPU, tapi tiap dial primer
tetap membangunkan radio seluler, dan interval 15 dtk lebih pendek
dari radio tail (~10–20 dtk) — radio praktis tidak pernah turun ke
idle selama VPN jalan. Tidak ada WakeLock di tree (nol hasil grep) —
drain bukan "CPU ditahan melek", melainkan dial + relay saat perangkat
terjaga. Sebagian 60% saat streaming adalah inheren: semua byte
YouTube disalin thread milik UID TaptapNG, jadi MIUI mengatribusikan
CPU relay itu ke TaptapNG, bukan ke YouTube — itu cara kerja semua VPN
in-app, bukan bug.

## Yang berubah

### 1. Backoff adaptif primer (H1) — `core/PemicuManager.kt`
- State backoff baru per host:port (`BackoffState(okStreak, step)`).
- Sesudah 4 PRIME OK beruntun, interval digandakan 15→30→60→120 dtk
  (cap 120 dtk, pola TB yang terbukti menahan jendela 2 jam); SATU
  kali PRIME GAGAL → kembali ke interval user (15 dtk) seketika.
- Backoff hidup DI DALAM `PemicuManager` (provider di call site
  statis, jadi tidak bisa via provider). `stop()`/`start()` menghapus
  state — sesi/jendela baru selalu mulai dari interval user.
- Jendela operator ~14–15 menit; prime tiap 120 dtk masih menahan
  dengan margin ~7×. Primer tidak pernah dihentikan; format baris
  log, target/domain/port, primeNowSync/manual, live-switch tidak
  diubah.
- Hitungan: **240 → ~30 dial/jam** saat jendela stabil (5.760 →
  720 dial/hari). Tangga dicapai ~7 menit sesudah start stabil.

### 2. UrlTestLoop diikat ke layar-mati (H3) — `service/TaptapVpnService.kt`
- Konstruktor `UrlTestLoop` kini menerima `isActive` yang sama seperti
  Observatory (`PowerManager.isInteractive`). Satu-satunya loop
  periodik yang lolos dari gate v1.0.16.
- Hitungan: **12 ronde/jam per grup → 0/jam saat layar mati**
  (interval default 300 dtk). Saat layar nyala tidak berubah.

### 3. Observatory hanya grup aktif (H2) — `core/Observatory.kt`
- `Observatory.selectableGuids(groups, rules, mainGroupId)`: hanya
  server yang bisa terpilih (anggota grup yang dirujuk aturan aktif,
  FINAL selalu aktif; grup bersarang di-expand, siklus aman; target
  DIRECT/REJECT tidak menyumbang server). `itemsProvider` menyaring
  profil ke himpunan itu.
- Hitungan (fixture 8 profil, 2 di grup aktif): **48 → ~12 dial/jam**
  saat layar nyala. Interval default, gate layar-mati, format saran
  log tidak berubah; tidak ada setting/UI baru.

### 4. Higiene DialLog + stream (H4+H5)
- `core/DialLog.kt`: ring menyimpan `(seq, line)` dengan counter
  monotonik; `latestSpeedLine()` cache baris SPEED terbaru di
  `AtomicReference`; `linesSince(fromSeq)` hanya baris baru.
  `updateSpeedDisplay()` tidak lagi menyalin ring penuh (s.d. 5000
  baris) tiap 2 dtk; `logsTailer()` berbasis sekuens (bonus: tailer
  lama berbasis `lastIndexOf` bisa melewatkan baris duplikat identik).
- `service/ClashApiServer.kt`: `StreamIdleGate` (timeout 60 dtk) di
  `serveChunked` + `serveWebSocket` — stream tutup sesudah 60 dtk
  tanpa frame baru; WS traffic/memory reconnect otomatis (handler
  `close` di yacd), logs WS fallback fetch.
- `service/ClashApiRuntime.kt`: `refreshGroups()` hanya `kick()`
  bila grup benar-benar berubah (fingerprint
  `Objects.hash(groups, rules, mainGroupId)`).

## Yang TIDAK diubah
Route/seleksi, live switch, grup bersarang, log url-test, detail
koneksi (rule/chains), scroll dashboard, kecepatan relay, mux default
(tetap OFF), payload default. Tidak ada NIO / non-blocking fd /
multiple writer / antrean lebih besar / txqueuelen, tidak ada Hello Go.

## Cara tes di HP (tes idle semalam yang benar)
1. Cas penuh → VPN jalan semalaman, layar mati → pagi lihat %
   TaptapNG di MIUI Baterai, bandingkan dengan 60,61%.
2. PRIME OK tetap mengalir — merenggang 15→30→60→120 dtk selama
   ~7 menit pertama, lalu stabil tiap 120 dtk; sesudah satu
   PRIME GAGAL kembali tiap ~15 dtk.
3. Entry tetap konek sesudah 30+ menit (iflix + 81 + hack-VLESS).
4. Url-test: ronde tetap jalan saat layar nyala, diam saat layar mati.
5. Observatory: baris `OBSERVATORY saran:` tetap muncul untuk server
   di grup aktif.
6. Dashboard: buka dashboard, pindah aplikasi lain >60 dtk, kembali —
   data tampil lagi tanpa retry/reload manual (cek juga halaman Logs).

## Caveat jujur
- Angka % MIUI adalah pangsa pemakaian, bukan drain absolut — hemat
  hanya bisa dibuktikan dari tes idle semalam di HP, bukan dari tes JVM.
- Penghematan H2 tergantung konfigurasi: karena
  `ensureNestedInMain()` menegakkan semua grup non-utama jadi anggota
  grup utama, pada konfigurasi default (grup utama berisi semua
  server) `selectableGuids` mengembalikan semua server — penghematan
  48→12/jam hanya terwujud untuk profil di luar grup aktif.
- Halaman Logs yacd: WS logs tidak punya handler `close` (hanya
  `error` → fetch fallback). Bila dashboard dibuka di halaman Logs +
  VPN mati + 60 dtk sepi, stream tertutup dan halaman Logs mungkin
  butuh pindah tab lalu kembali untuk menampilkan log baru sesudah
  VPN dinyalakan. Bila terbukti beku di HP, perbaikannya adalah
  mengecualikan /logs dari idle-close.
- Tes lokal worker A: 7 gagal di VM (loopback TCP VM abnormal —
  dial ke port tertutup 127.0.0.1 "berhasil", handshake TLS lokal
  timeout); baseline kode lama gagal identik (9 gagal). CI yang
  memutuskan; v1.0.30 hijau 1013 tes di CI yang sama.
- Tes JVM membuktikan urutan/fitur, bukan tampilan di HP dan bukan
  angka baterai.
