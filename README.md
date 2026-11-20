# TaptapX v1.0.19

Aplikasi Android BARU dari awal — UI persis v2rayNG 2.3.15 (Android
Views: XML layouts + RecyclerView + Material Components, **tanpa
Compose**), isinya protokol in-app (Kotlin/Java), **tanpa bundel
xray-core**. Arsitektur ala XVEON: protokol ditulis langsung di kode
app, jadi APK kecil (bukan 41 MB).

- **id** `com.taptap.x`, **versi** 1.0.19 (vc20)
- Data: `profiles.json` (Gson) di files dir privat app
- Terowongan: `VpnService` (`TaptapVpnService`, TUN 172.19.0.1/30)

## Arsitektur

```
MainActivity (Views) ──> MainViewModel ──> ProfileStore (profiles.json)
   ├─> ServerEditorActivity (Xray method: SlowDNS / Onering / Pemicu)
   ├─> SettingsActivity (PreferenceFragmentCompat), LogActivity (logcat)
   ├─> ScannerActivity (Camera1 + ZXing, QR import)
   └─> TaptapVpnService (TUN, start/stop)
Core (in-app, tanpa native):
   ├─> SshClient (JSch, pure Java) — Phase 1 proof-of-concept
   ├─> LinkParser (vmess/vless/trojan/ss/ssh share links + toUri)
   ├─> ServerTester (TCP delay / real ping)
   └─> (milestone berikut: VMess/VLESS/Trojan/SS, SlowDNS/DNSTT,
        Onering, PemicuManager)
```

## v1.0.19 — Buffer socket proxy naik (hipotesis window/RTT)

**Bottleneck PINDAH — dari log HP v1.0.18, bukan tebakan.** Log
v1.0.18 (taptapx-498628e3.txt, Speedtest 16:01) membuktikan tulis
TUN sudah beres: `TUNWRITER` tulisMs cuma 150–500ms per jendela 5
dtk, `tun` per koneksi 10–190ms (dulu 6046ms). Tapi relay kini
93–95% waktunya MENUNGGU data: TUTUP koneksi Speedtest
`tls+net=15170ms` dari 16,0 dtk, ws 111ms, vmess 585ms, build 96ms,
tun 154ms; down 8,04 MB = 0,50 MB/s per koneksi; total ~25 Mbps —
cocok dengan laporan "Masih sama". Semua tahap di app sudah kecil;
data dari proxy datangnya pelan.

Tersangkanya: buffer socket proxy **tidak pernah disetel** —
`Transport.open()` membuat `Socket()` polos tanpa
`receiveBufferSize`/`sendBufferSize`/`tcpNoDelay`. Kecepatan per
koneksi ≈ window TCP / RTT; dengan RTT ~150ms (ping Speedtest
164ms) + window default ~64–128KB → ~0,4–0,85 MB/s, cocok dengan
0,50 MB/s yang terukur. v2rayNG (xray-core, Go) setel buffer besar
→ 133 Mbps lewat proxy/server/jalur yang sama. **Ini perbaikan
hipotesis window/RTT — tes HP yang memutuskan.**

Perbaikannya (satu tempat, `Transport.open()`): SEBELUM `connect()`
setel `receiveBufferSize = 1 MB`, `sendBufferSize = 256 KB`,
`tcpNoDelay = true` (dibungkus `runCatching` + log bila gagal —
setelan gagal tidak boleh menggagalkan dial). Sesudah connect, log
nilai EFEKTIF yang dikabulkan kernel (baris DialLog `SOCKET rcv=…
snd=…`) — Linux melipatgandakan dan membatasi nilai ke
`rmem_max`/`wmem_max`, jadi baris ini penting untuk diagnosa log
berikutnya. SSLSocket membungkus socket yang sama, jadi buffer
terbawa — tidak perlu setel ulang di `TlsUtil`. Tidak ada perubahan
lain: protokol, relay, TunWriter, MSS/chunk, UI tetap seperti
v1.0.18.

**Tes HP** — konek entry biasa (VMess yang sama), jalankan SATU
Speedtest sampai SELESAI, BARU export Log + kirim file log +
screenshot hasil. Yang menentukan: angka download (bandingkan
langsung dengan v1.0.18); baris `SOCKET` di log menunjukkan buffer
efektif yang dikabulkan kernel; baris `SPEED` `tls+net` harusnya
turun bila window memang penyebabnya. Bila angka tidak naik,
log-nya tetap yang bicara — bukan tebakan.

## v1.0.18 — Thread penulis TUN khusus + antrean

**Perbaikan bottleneck yang TERBUKTI dari log HP.** Log v1.0.17
(taptapx-0d94e353.txt, Speedtest 15:27, 16,1 Mbps) menunjukkan tiap
koneksi Speedtest menghabiskan ~6 detik dari 8 detik cuma buat nulis
ke TUN (`tun=6046ms`, 1622 writes untuk 2,06 MB, ~3,7ms per write)
— 70-75% waktu relay thread — sementara WS (~20ms), dekrip VMess
(~100ms), dan bangun segmen (~30ms) negligible. Penyebabnya di
`TunForwarder.writePacket`: semua thread relay (satu per koneksi
TCP) antre lewat satu `synchronized(writeLock)`, lalu satu syscall
`write()` per segmen ~1460B di fd blocking — begitu antrean TUN
penuh, satu tulis nge-blok SAMBIL pegang kunci, semua koneksi ikut
ketahan. Pembanding: v2rayNG (xray-core) juga tulis ke TUN satu
paket per write, tapi lewat SATU goroutine penulis tanpa lock — dan
mencapai 133 Mbps ke Speedtest yang sama. Jadi batasnya bukan fd
TUN, tapi antrean kunci + banyak thread penulis.

Perbaikannya (kelas baru `TunWriter`): semua tulis TUN — segmen
data, SYN-ACK, RST, balasan DNS — lewat satu antrean FIFO bounded
(1024 paket, backpressure: relay nge-blok di `put()` bila penuh,
TANPA pegang kunci global) yang dikuras SATU thread penulis.
Urutan per koneksi terjaga (FIFO + satu penulis). `writeLock`
dihapus, `flush()` yang no-op (raw `FileOutputStream`) dihapus.
**Bukan** batching write: TUN fd menerima TEPAT SATU paket IP per
`write()` — gabung paket akan merusak paket. Jujur soal batasnya:
ini memperbaiki bentuk antrean, bukan fd-nya — angka di HP yang
menentukan.

Instrumentasi tetap bisa membuktikan: `tun` per koneksi kini
mengukur waktu ENQUEUE (harusnya mikrodetik — bukti relay tidak
lagi ketahan), plus baris agregat `TUNWRITER` tiap 5 detik saat
transfer aktif (`tulis=` paket ditulis, `antriMax=` kedalaman
antrean maks, `tulisMs=` total waktu di `write()`, `blokirMs=`
total waktu relay nge-blok di `put()`). Bila tulis fd masih
bottleneck, `tulisMs` tetap besar; bila penulis tidak sanggup
mengimbangi relay, `blokirMs` membesar. Tidak ada perubahan lain:
protokol, relay, MSS/chunk, UI tetap seperti v1.0.17.

**Tes HP** — konek entry biasa (VMess yang sama), jalankan SATU
Speedtest sampai SELESAI, BARU export Log + kirim file log +
screenshot hasil. Yang menentukan: angka download (bandingkan
langsung dengan 16,1 Mbps di v1.0.17), baris `SPEED` koneksi
Speedtest (`tun` harusnya kecil), dan baris `TUNWRITER`
(menunjukkan biaya tulis sebenarnya). Bila angka tidak naik,
log-nya tetap yang bicara — bukan tebakan.

## v1.0.17 — Buffer log 500 → 5000 baris

**Satu perubahan kecil, bukan perbaikan kecepatan.** `DialLog`
menyimpan log di ring buffer 500 baris — baris lama dibuang begitu
penuh. Dua log HP membuktikan fase download Speedtest terbuang
sebelum sempat di-export: log 14:01 (taptapx-40774e0e.txt) cuma
menyimpan fase upload (lebih baru, 8,11 MB), log 14:07
(taptapx-9c8c1aca.txt) cuma traffic background. Urutan export user
sudah benar — buffer-nya yang kekecilan. Sekarang buffer menahan
5000 baris (~500 KB memori), cukup untuk satu Speedtest penuh
beserta traffic background. Tidak ada perubahan lain: protokol,
relay, instrumentasi SPEED, dan UI tetap seperti v1.0.16.

**Tes HP** — konek entry biasa (VMess yang sama dengan tes
sebelumnya), jalankan SATU Speedtest sampai SELESAI (angka download
dan upload muncul di layar), BARU buka TaptapX → Log → export, lalu
kirim file log + screenshot hasil Speedtest. Fase download sekarang
harusnya utuh di log: cari baris `SPEED` koneksi Speedtest
(`:8080`) — tahap dengan angka terbesar di tiap jendela 5 detik
adalah bottleneck-nya, plus baris `TUTUP`-nya.

## v1.0.16 — Instrumentasi kecepatan (BUKAN perbaikan)

Speedtest HP 2026-11-20 12:52: v1.0.15 = 26,7 Mbps — TIDAK naik
dari ~30,9 Mbps (v1.0.14). Perbaikan relay v1.0.15 tidak mengubah
angka HP, jadi bottleneck BUKAN di relay/VMess-chunk. Versi ini
tidak mengubah perilaku relay sama sekali — hanya MENGUKUR, supaya
satu Speedtest + export Log menunjukkan tahap mana yang lambat
(jangan tebak lagi).

**Yang diukur** — per koneksi TCP, waktu dinding (wall-clock) per
tahap, arah download (proxy → TUN) yang membatasi Speedtest:

- `tls+net`: waktu baca dari transport (TLS unwrap + tunggu
  socket — tidak bisa dipisah di jalur SSLSocket, jadi satu label
  jujur). Saat transfer jenuh, ini ≈ unwrap TLS + biaya socket;
  jeda idle ikut terhitung (ini wall time, bukan CPU time).
- `ws`: parse frame WebSocket saja (header, unmask, rakit ulang) —
  waktu baca WsInputStream dikurangi waktu baca mentah (tls+net).
- `vmess`: dekrip AEAD chunk VMess saja (open per chunk).
- `rd`: total waktu `read()` relay (cross-check: rd ≈ tls+net +
  ws + vmess + overhead plumbing stream).
- `build`: bangun segmen TCP. `tun`: tulis segmen ke fd TUN
  (termasuk bila blokir).
- Upload (ringan): `upW` = tulis+flush writer (seal VMess + frame
  WS + wrap TLS + tulis socket, gabungan); `upVmess` = bagian seal
  VMess-nya (jadi upW − upVmess ≈ ws + tls + net arah upload).
  Baca TUN tidak diukur per sesi (thread reader dipakai bersama).

**Baris log** (tag `SPEED`, di Log app + logcat, selalu nyala,
hanya agregasi — bukan per paket):

```
SPEED 93.184.216.34:443 down=1.25MB 2.50MB/s tls+net=3120ms ws=180ms vmess=240ms rd=3600ms build=12ms tun=35ms
SPEED 93.184.216.34:443 TUTUP down=12.34MB 8.2s 1.50MB/s tls+net=3120ms ws=180ms vmess=240ms rd=3600ms build=12ms tun=35ms up=0.50MB upW=30ms upVmess=10ms frames=800 chunks=1600 tunW=9000
```

- Baris pertama: tiap 5 detik selama transfer aktif (down = MB
  di jendela itu, MB/s = kecepatan efektif jendela itu).
- Baris `TUTUP`: sekali saat sesi tutup (total koneksi itu —
  down total, durasi, MB/s efektif, total tiap tahap, total
  upload, jumlah frame WS / chunk VMess / tulis TUN).
- Relay satu thread per koneksi (baca → bangun → tulis, berurutan),
  jadi di jendela 5 detik yang jenuh semua tahap berjumlah ≈ 5000
  ms — tahap dengan angka terbesar ADALAH bottleneck-nya.
- Tes baru `SpeedStatsTest` (5 tes, in-memory + socket ::1):
  format baris SPEED dipatok persis, tiap tahap masuk embernya
  sendiri, forwarder mencatat window + TUTUP di transfer nyata.

**Tes HP (yang menentukan):** konek entry biasa (VMess yang sama
dengan tes sebelumnya), jalankan SATU Speedtest sampai selesai,
lalu export Log dari app dan kirim. Yang dicari di Log: baris
`SPEED` untuk koneksi Speedtest — tahap mana yang angkanya paling
besar di tiap jendela 5 detik, dan baris `TUTUP`-nya.

## v1.0.15 — Kecepatan relay

Speedtest 2026-11-20 back-to-back (entry sama, kondisi sama):
v2rayNG 133 Mbps, XVEON ~32 Mbps, TaptapX ~30,9 Mbps. Dua app
tanpa core mentok di ~30 Mbps — batasnya di relay in-app, bukan
di server. Perbaikan (tanpa ubah protokol, tanpa core, APK tetap
~2 MB):

- Chunk VMess 8KB → **16KB** (server xray-core menerima ukuran
  chunk berapa pun — reader-nya baca 2-byte size tanpa batas
  atas; yang 8KB itu cuma ukuran tulis server).
- MSS SYN-ACK 1360 → **1460** (MTU − 40; margin 100B XVEON untuk
  overhead terowongan luar tidak berlaku di link TUN lokal).
- Relay baca TUN: satu `read()` tarik sampai **32KB** (dulu satu
  segmen 1360B per read), segmen dibangun langsung dari buffer
  baca ke buffer paket yang dipakai ulang (tanpa `copyOf`, tanpa
  alokasi per segmen).
- `VmessBodyOutputStream` / `SsBodyOutputStream`: buffer pending
  jadi `ByteArray` (dulu `MutableList<Byte>` yang me-boxing tiap
  byte — 1460 alokasi per segmen).
- Parse TCP satu salinan (dulu `parseIp` + `parseTcp` menyalin
  segmen dua kali).
- Window terima tetap 256 KiB (sudah cukup, bukan bottleneck);
  fd TUN tetap blocking (v1.0.11) jadi sleep 10ms di loop baca
  tidak pernah jalan saat stream sibuk.
- Tes baru `RelayThroughputTest` (in-memory, tanpa socket):
  throughput relay download + round-trip codec chunk VMess,
  print MB/s di log CI (grep THROUGHPUT), floor konservatif.

**Tes HP (yang menentukan — angka lokal tidak membuktikan
kenaikan di HP):** Speedtest back-to-back, entry sama, kondisi
sama, lawan v2rayNG: (1) TaptapX, (2) v2rayNG, (3) TaptapX lagi.
Laporkan download/upload ketiganya. Target: TaptapX naik dari
~31 Mbps (tidak dijamin samakan 133 Mbps v2rayNG — jalur data
native Go tetap lebih cepat dari relay Java tulisan tangan).

## v1.0.1 — UI dibangun ulang dengan Views + fitur v2rayNG

- UI Compose diganti total ke Views (XML + RecyclerView + Material
  Components + AppCompat), meniru susunan v2rayNG 2.3.15: drawer
  (header 180dp + 10 item), top bar (judul Config, search, menu
  import +, menu more ⋮), tab grup, baris server (accent bar,
  tombol share/edit/delete, statistik, label protokol oranye, delay
  hijau), bottom status bar 64dp + FAB oranye yang overlap.
- Settings lengkap ala v2rayNG (UI / VPN / local proxy / DNS /
  advanced): tema (system/light/dark), bahasa (auto/en/id), dynamic
  color, double column, confirm remove, IPv6, local DNS, FakeDNS,
  VPN DNS, MTU, SOCKS, remote/domestic DNS, log level, auto-start.
- Import: from clipboard (parser link vmess/vless/trojan/ss/ssh,
  unit test `LinkParserTest`), from QR code (scan Camera1 + ZXing
  core — tanpa CameraX demi ukuran), from file (daftar link atau
  export profiles.json). Tambah manual per protokol, edit/hapus
  server, hapus grup (long-press tab grup), test/delay server
  (TCPing + real ping, sortir berdasar hasil tes), export ke file.
- Editor: chip protokol, field per protokol, seksi SSH method
  (Payload/Enhanced/TLS/SlowDNS) + seksi Xray method (SlowDNS /
  Onering / Pemicu + Domain/Port/Interval pemicu).
- SSH via JSch (pure Java): connect + exec + disconnect; unit test
  end-to-end melawan server MINA SSHD in-process (`SshClientTest`).
- VpnService kerangka: TUN interface + start/stop; DNS server ikut
  Settings (remote DNS). Auto-start on boot (bila izin VPN sudah
  diberikan).
- Build: Gradle (AGP 9.4.1, Kotlin 2.4.21, compileSdk/targetSdk 37,
  minSdk 24), **release + R8** (minify + shrinkResources, keep rules
  untuk Gson/JSch/ZXing/VpnService), ditandatangani keystore debug
  agar APK CI bisa diinstal. Gradle diblokir di VM, jadi build APK
  lewat GitHub Actions CI (`.github/workflows/build.yml`).

## Milestone berikut

- **M2 — VMess/VLESS/Trojan/SS in-app**: implementasi protokol di
  Kotlin (enkripsi + framing), WS + TLS transport, SNI mode.
  Bukti: unit test melawan server lokal + tes HP.
- **M3 — SlowDNS/DNSTT in-app**: transport DNSTT (DNS tunneling)
  + outbound DNSTT, chip SlowDNS di editor. Bukti: unit test + tes HP.
- **M4 — Onering**: bug domain di ext TLS 0xff00 (SNI = domain asli),
  format `onering:<real>:<bug>`. Bukti: unit test byte-level + tes HP.
- **M5 — Pemicu bawaan**: chip Pemicu + Domain/Port/Interval per entry;
  dial in-app SSLSocket + `VpnService.protect()` (tanpa root),
  tidak ganggu VMess. Bukti: unit test + tes HP (PRIME OK).
- **M6 — Terowongan penuh**: forwarding paket TUN <-> protokol
  (SOCKS5 lokal + routing), tes HP end-to-end (entry konek).

## Build

```sh
./gradlew :app:assembleRelease   # di CI (Gradle diblokir di VM ini)
```

CI: `.github/workflows/build.yml` (release, arm64-v8a).
Repo: https://github.com/Taptap56/taptapx

## Yang belum terverifikasi (butuh HP)

- Tampilan di HP (daftar server, editor, drawer, FAB, Settings, scan QR)
- VpnService: izin VPN + TUN benar-benar jalan di HP
- SSH ke server sungguhan (bukan server tes in-process)
- Import clipboard/QR/file di HP (parser baru, baru lolos unit test JVM)
- Semua protokol M2–M6 (belum dibangun)
