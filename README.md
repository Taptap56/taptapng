# TaptapX v1.0.25

Aplikasi Android BARU dari awal — UI persis v2rayNG 2.3.15 (Android
Views: XML layouts + RecyclerView + Material Components, **tanpa
Compose**), isinya protokol in-app (Kotlin/Java), **tanpa bundel
xray-core**. Arsitektur ala XVEON: protokol ditulis langsung di kode
app, jadi APK kecil (bukan 41 MB).

- **id** `com.taptap.x`, **versi** 1.0.25 (vc26)
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

## v1.0.25 — Paket hemat baterai (loop prime + writer + cache DNS)

**Kenapa.** Screenshot baterai 2026-11-21 01:55 (MIUI, VPN nyala
~21:00–01:55): TaptapX 60,89% — tertinggi. Audit READ-ONLY
(2026-11-21 02:01, tanpa ubah kode) menemukan: sebagian besar
angka itu kerja relay yang SAH (semua trafik app lain lewat relay
Java TaptapX dan MIUI menghitungnya ke TaptapX), TIDAK ada
WakeLock/WifiLock sama sekali — tapi ada tiga pemboros saat IDLE
yang bisa dipangkas tanpa mengubah perilaku:

1. **Loop prime tidur sampai jatuh tempo, bukan polling 1 dtk**
   (`PemicuManager`): loop bangun ~1×/interval (15 dtk default),
   bukan 1×/dtk. Prime tetap tepat waktu; loop tetap bisa
   dibangunkan lewat `interrupt()` saat entry diedit / VPN stop.
2. **Writer per-session `poll(100ms)` → `poll(1000ms)`**
   (`TunForwarder`): tiap session terbuka bangun 10×/dtk walau
   antrean kosong — penyebab boros idle #1 (10–20 session ×
   10 bangun/dtk). `poll(timeout)` langsung kembali saat ada data
   masuk, jadi ini TIDAK menambah latensi upload sama sekali —
   hanya menunda deteksi session tertutup maks 1 dtk.
3. **Prime DNS pakai cache 120 dtk** (`DnsResolver.resolveAll`):
   tiap prime tidak lagi 2 query UDP baru + wakeup radio; cache
   yang sama seperti `resolve()` (TTL 120 dtk, fallback IP
   terakhir bila lookup gagal).

**Yang TIDAK diubah.** Interval prime adaptif (usulan audit #4)
sengaja diputuskan terpisah — ia mengubah perilaku prime dan
primer bawaan sendiri belum terbukti di HP. KCP SlowDNS, poll
MainActivity, dan poller NIO juga tidak disentuh.

**Verifikasi di HP.** VPN nyala semalaman (idle, layar mati),
bandingkan pangsa baterai TaptapX dengan 60,89% sebelumnya.
Screenshot kedua 02:06 menegaskan diagnosis: saat user AKTIF
pakai HP, pangsa TaptapX cuma 7,66% (YouTube 31,05%) — TaptapX
mendominasi HANYA saat idle. Log `PRIME OK` harus tetap tepat
waktu tiap interval (tidak telat karena loop tidur).

## v1.0.24 — MILESTONE M5: Pemicu bawaan (primer di dalam TaptapX)

**Cara pakai.** Di editor entry, seksi Xray method: nyalakan chip
**Pemicu**, isi **Domain pemicu** (wajib — mis. `chat.sociomile.com`
untuk entry Sociomile, `support.zoom.us` untuk entry Zoom),
**Port pemicu** kosong = 443, **Interval pemicu** default 15 detik
(5..300). Domain kosong = entry TIDAK di-prime, tanpa fallback ke
address entry. Pemicu TIDAK ikut link (sama seperti v2rayNG) — sesudah
copy server, isi Domain pemicu manual di app penerima.

**Cara kerja.** Primer FULL PISAH dari entry (model TB v1.0.84 +
v2rayNG PemicuManager): dial SSLSocket in-app + `protect()` (bypass
TUN), dual-stack (IPv4 dulu, lalu IPv6), timeout TCP 5 dtk / TLS
10 dtk. SNI dial = Domain pemicu itu sendiri, bukan address entry.
Saat VPN konek, prime SEGERA sekali sebelum dial utama (probe), lalu
auto-prime tiap interval selama VPN jalan — jaga jendela operator
(~14 menit, per domain) tetap buka. Menu "⋮ → Prime sekarang"
prime entry terpilih sekali, kapan saja (VPN nyala atau mati).
Hasilnya di Log: `PRIME OK <host>:<port> <ms>` / `PRIME GAGAL
<host> (<alasan>)`. Prime gagal TIDAK PERNAH menggagalkan koneksi
VPN — hanya tercatat di Log.

**Tes HP penentu.** Matikan TB + pemicu.apk (jangan jalan bareng),
diamkan ~14 menit tanpa prime (jendela tutup), lalu konek TaptapX
dengan entry yang Domain pemicunya sudah diisi. Bila entry konek,
primer bawaan sendiri yang membuka jendela. Log harus ada baris
`PRIME OK` sebelum dial utama. Bila entry timeout padahal Log sudah
`PRIME OK`, masalahnya bukan jendela — cek entry/core-nya.

**Batas yang jujur.** Pemicu hanya menjaga SATU domain per entry
(domain yang diisi); entry tanpa Domain pemicu tidak di-prime sama
sekali. Prime loop hanya jalan untuk entry yang sedang konek — entry
lain yang Pemicu-nya nyala tidak ikut di-prime selama VPN jalan
(model v2rayNG mem-prime SEMUA entry; TaptapX M5 mem-prime entry
yang konek saja).

## v1.0.23 — MILESTONE M4: Onering (ext TLS 0xff00 via Bouncy Castle)

**Cara pakai.** Di editor entry, seksi Xray method: nyalakan chip
**Onering**, isi **Bug domain** (mis. `live.iflix.com`). SNI entry
tetap domain asli (mis. `support.zoom.us`) — chip yang mengatur
format `onering:<real>:<bug>` di link, jadi saling copy
v2rayNG↔TaptapX tetap jalan. Syarat: VMess/VLESS/Trojan + TLS nyala
+ network WS + Bug domain terisi. SS/SSH, Onering tanpa TLS/WS/bug,
dan Onering+SlowDNS tetap ditolak guard dengan pesan yang jelas.

**Kenapa Bouncy Castle.** SSLSocket/SSLEngine platform TIDAK punya
API ekstensi kustom — 0xff00 tidak bisa dikirim lewat javax.net.ssl
sama sekali. Patch byte ClientHello sesudah SSLEngine membuatnya
juga BUKAN jalan: transcript hash TLS dihitung dari ClientHello
asli, sementara server melihat yang sudah diubah, jadi Finished
gagal di TLS 1.2 maupun 1.3. Bouncy Castle (`bctls` 1.86, kripto
native BC `BcTlsCrypto` — BUKAN JCA platform: jalur JCA gagal
verifikasi RSA-PSS CertificateVerify TLS 1.3 karena nama algoritma
`SHA256WITHRSAANDMGF1` tidak dikenal JCA platform; bcprov ikut
transitif via bcutil) membangun ClientHello sendiri dari
`getClientExtensions()`, jadi 0xff00 masuk transcript sejak awal
dan handshake konsisten. Urutan dipaksa lewat `Hashtable` subclass
(`OrderedExtensions`, `keys()` enumerasi 0xff00 dulu) — BC menulis
ekstensi dengan iterasi `keys()`, dan `ensureExtensionsInitialised`
tidak menyalin tabelnya. **TLS 1.3 saja:** BC menulis ekstensi
KOSONG dulu, dan bila TLS 1.2 ikut ditawarkan ia menambahkan
`encrypt_then_mac` + `extended_master_secret` (keduanya kosong)
yang selalu mendahului 0xff00 di wire — jadi entry Onering hanya
menawarkan TLS 1.3 (server TLS 1.2-only tidak bisa lewat entry
Onering; semua proxy modern bisa 1.3). Isi data 0xff00
byte-identik dengan fork TC (`oneringBugExtensionData`:
server_name_list berisi bug). Ukuran APK naik ~433 KB gara-gara
BC (2.583.200 B vs 2.150.279 B di v1.0.22) — masih jauh di bawah
batas, tanpa core.

**Tes HP.** Entry Onering (contoh: Zoom onering, atau entry
leaseweb4 dengan bug `live.iflix.com` / `io.ruangguru.com`):
pancing dulu lewat v2rayNG/pemicu.apk bila jendela tutup —
Onering tetap butuh pancing, bukan pengganti pancing. Yang
menentukan: konek + Log menunjukkan `TLS ... Onering ... ok (bug
..., SNI ...)` + internet jalan. Bila entry Onering timeout
padahal konek di v2rayNG, pancing dulu, jangan utak-atik
fingerprint/address.

**Tidak diubah.** Relay/TUN/MTU 9000, buffer socket, SlowDNS,
salin server dua arah. Saran Claude berikutnya (flow control
ACK/window, ICMP port-unreachable UDP 443, cache DNS aplikasi)
belum dikerjakan.

## v1.0.22 — Cache DNS host proxy + rapikan teks UI

**Stabilitas.** `DnsResolver.resolveWithSystemFallback` kini menyimpan
hasil resolve host proxy 120 dtk. Sebelumnya SETIAP koneksi TCP dari TUN
memicu satu query UDP ke 8.8.8.8 lebih dulu (satu RTT ekstra per
koneksi, dan dial gagal bila query itu hilang). Bila lookup gagal, IP
terakhir yang berhasil dipakai. Tes: `DnsResolverTest` (cache tetap
menjawab saat server DNS mati).

**UI/teks.** Nilai baris Settings dibatasi 150dp + ellipsis (nilai
panjang tidak lagi menggencet judul jadi satu huruf per baris); label
delay di baris server dibatasi 140dp dan label gagal dipendekkan
(`formatDelayFailure`, tes di `DelayLabelTest`); status bar bawah maks
2 baris + ellipsis; "Belum didukung di M2" -> "Not supported yet".

**Tidak diubah.** Jalur data relay/TUN, MTU 9000, protokol. Temuan
audit relay (tanpa ACK/window dari aplikasi, UDP non-DNS dibuang)
dicatat untuk versi berikutnya — belum diubah karena butuh tes HP.

## v1.0.21 — MTU TUN 9000 + MSS 8960: segmen lebih besar, tulis lebih sedikit (eksperimen)

**Hipotesis — dari log HP v1.0.20, bukan tebakan.** Histogram
v1.0.20 (taptapx-77d1f821.txt) menjawab pertanyaan v1.0.20:
distribusinya RAPAT di `sedang` (91–96% write 50–500 us,
rata-rata ~140 us), BUKAN bimodal — jadi bukan beberapa write
yang nge-blok lama, melainkan hampir SETIAP write makan ~140 us
waktu kernel (API Java terbukti ~2 us di VM; saat drain write
cepat ~21 us, 17.600/dtk). Penulis tunggal mentok ~5000
tulis/dtk × 1460B ≈ 55–58 Mbps; Speedtest 52,4 Mbps. Karena
biaya kernel dihitung PER PAKET, satu-satunya jalan menaikkan
throughput tanpa menambah tulis/dtk adalah MEMBESARKAN tiap
paket: segmen 8960B membawa ~6× data per write dibanding 1460B,
jadi ceiling yang sama (~5000 tulis/dtk) menjadi ~350 Mbps
secara teori — bila biaya per write tidak ikut membesar.
sing-box TUN memakai MTU 9000 (dokumen resminya), jadi angka ini
bukan asal ambil.

**Yang diubah.** (1) MTU TUN default 1500 → 9000
(`TaptapVpnService`: fallback bila setting kosong/tidak valid;
setting MTU pengguna tetap dihormati, rentang 576..9000 tidak
berubah; `DISPLAY_VPN_MTU` ikut jadi "9000" supaya UI tidak
bohong). (2) MSS mengikuti MTU: `TunForwarder.maxMssForMtu`
= (MTU − 40), lantai 1140, langit 8960 — dipakai di SYN-ACK
(`synAckMss`), di cap MSS yang ditawarkan app di SYN, dan di
batas segmen relay (`segMss`); buffer paket relay membesar
menjadi 9000 byte (`MAX_PACKET_BYTES`). (3) Satu baris log saat
TUN naik: `TUN mtu=9000 mss=8960`. Histogram v1.0.20 dijaga
(cepat/sedang/lambat + tulisMaxUs) supaya log berikutnya
menunjukkan apakah laju tulis turun dan throughput naik.
Upload ikut tertangani: app mengirim segmen sampai sebesar MSS
yang kami iklankan (8960B), dan buffer baca TUN (64 KiB) +
antrean writer + chunk VMess 16 KiB semuanya muat.

**Yang TIDAK diubah.** Protokol, relay (kecuali batas segmen),
buffer socket (v1.0.19), TunWriter/antrean (v1.0.18), UI —
semuanya tetap seperti v1.0.20. Tidak ada batching paket per
write (TUN = satu paket per write), tidak ada gVisor/stack
TCP lain.

**Jujur soal batasnya — ini eksperimen.** Hasilnya tergantung
apakah app benar-benar menawarkan MSS 8960 setelah MTU TUN
naik (kernel app menghitung MSS dari MTU interface; baris `TUN`
di log membuktikan nilai yang dipakai, dan segmen di log SPEED
menunjukkan ukurannya). Bila app tetap menawarkan 1460, segmen
tetap 1460 dan angka tidak akan naik — itu jawaban juga, bukan
gagal. Bila angka naik tapi tidak sampai 133 Mbps, bottleneck
berikutnya akan terlihat di baris SPEED/TUNWRITER yang sama.

**Tes HP** — konek entry biasa (VMess yang sama), jalankan SATU
Speedtest sampai SELESAI, BARU export Log + kirim file log +
screenshot hasil. Yang menentukan: angka download (bandingkan
langsung dengan 52,4 Mbps di v1.0.19 — v1.0.20 hanya
instrumentasi, tanpa klaim kecepatan); baris `TUN` (mtu/mss) +
histogram TUNWRITER menunjukkan apakah laju tulis turun
(tulis/dtk lebih kecil untuk byte yang sama).

## v1.0.20 — Selidiki penulis TUN: histogram durasi write (bukan tebakan)

**Pertanyaan yang harus dijawab — dari log HP v1.0.19, bukan
tebakan.** Log v1.0.19 (taptapx-f3e2b3f2.txt, Speedtest 16:15,
52,4 Mbps) membuktikan buffer socket bekerja: `SOCKET
rcv=2097152 snd=524288` (penuh dikabulkan, kernel gandakan), data
dari proxy datang 12× lebih cepat (`tls+net` 15170ms → 1281ms per
koneksi). Tapi bottleneck PINDAH ke antrean TunWriter: `antriMax=
1024` (penuh) di 3 jendela 5 dtk berturut-turut, `blokirMs=
53840/72067/26184ms`, relay 81% waktunya nge-blok di enqueue
(`tun=9811ms` dari 12,1 dtk), penulis tunggal jenuh ~5000
tulis/dtk (`tulisMs=3918ms` per jendela 5 dtk, ~0,15ms per write).
Ceiling penulis ≈ 5000 × 1460B ≈ 58 Mbps — Speedtest 52,4 Mbps
tepat di bawahnya. Yang belum terjawab: kenapa tiap `write()`
makan ~0,15ms — (a) nge-blok karena antrean TUN kernel penuh
(laju kuras kernel/app adalah ceiling), atau (b) overhead
syscall/kernel per write?

**Yang diubah: instrumentasi pemisah, BUKAN jalur tulis.**
`TunWriter` kini mengukur durasi tiap `write()` dan
mengelompokkannya di baris agregat `TUNWRITER`: `cepat` (< 50 us,
syscall murni), `sedang` (50 us–0,5 ms), `lambat` (> 0,5 ms,
hampir pasti nge-blok di antrean penuh), plus `tulisMaxUs`
(write terlama di jendela, dalam mikrodetik). Ketiga hitungan
selalu berjumlah `tulis`. Cara baca: garis bimodal (kebanyakan
cepat + ekor lambat) membuktikan (a); distribusi rapat di sedang
membuktikan (b). Tanpa pemisah ini, perbaikan berikutnya cuma
tebak-tebakan — dan v1.0.15 sudah membuktikan tebak-tebakan gagal.

**Yang TIDAK diubah — dan kenapa (bukti lokal, bukan opini).**
Benchmark lokal di VM (20.000 write 1460B ke kernel pipe yang
terus dikuras): write mentah median ~2 us untuk FileOutputStream
(p50 2,1 us) MAUPUN FileChannel heap/direct (p50 1,4–1,5 us) —
beda API cuma ~0,7 us per write, tidak ada artinya di samping
150 us di HP, jadi penulis TIDAK dipindah ke NIO. Dengan drainer
pelan (buffer pipe penuh, write nge-blok) tandanya bimodal: p50
tetap ~1,4 us tapi p99 ~1 ms dan 93/3000 write masuk lambat —
persis yang histogram di atas dirancang untuk mendeteksi. Fd
non-blocking: tidak menaikkan laju — penulis tidak punya kerja
lain selagi antrean penuh, dan fd-nya dipakai bersama sisi baca
(v1.0.11 membersihkan O_NONBLOCK untuk read). Beberapa thread
penulis: kernel menserialisasi write ke satu fd TUN, dan urutan
per koneksi yang dijamin TunWriter akan rusak. Antrean lebih
besar (1024 → 4096): cuma menunda blokir, laju tulis steady-state
tetap — bukan perbaikan. `txqueuelen` TUN: butuh CAP_NET_ADMIN,
yang tidak dimiliki app — app tidak bisa memperbesar antrean
kernel. **Bila histogram membuktikan (a), ceiling-nya adalah
laju kuras kernel/app dan tidak ada perubahan jalur tulis di app
yang bisa menaikkannya — log berikutnya yang akan bilang begitu,
bukan klaim.**

Tidak ada perubahan lain: protokol, relay, buffer socket
(v1.0.19), TunWriter (kecuali histogram), MSS/chunk, UI tetap
seperti v1.0.19.

**Tes HP** — konek entry biasa (VMess yang sama), jalankan SATU
Speedtest sampai SELESAI, BARU export Log + kirim file log +
screenshot hasil. Yang menentukan: angka download (bandingkan
langsung dengan 52,4 Mbps di v1.0.19) DAN baris `TUNWRITER` yang
baru — `cepat`/`sedang`/`lambat` + `tulisMaxUs` menunjukkan
apakah write nge-blok di antrean penuh (bimodal) atau memang
mahal per syscall (rapat di sedang). Bila antrean masih penuh
dan distribusinya bimodal, itu bukti laju kuras kernel/app yang
membatasi — dan v1.0.20 tidak mengklaim menaikkan angka.

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
