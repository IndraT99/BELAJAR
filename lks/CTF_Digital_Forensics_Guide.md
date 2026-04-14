# 🔍 CTF Jeopardy — Digital Forensics: Panduan Lengkap untuk Pemula

> Dokumen ini ditulis untuk **pemula** yang baru pertama kali belajar Digital Forensics di CTF.
> Setiap konsep dijelaskan dari nol dengan langkah-langkah detail.

---

## Daftar Isi

- [Bagian 0: Fondasi — Apa itu Digital Forensics?](#bagian-0-fondasi--apa-itu-digital-forensics)
- [Bagian 1: Setup Environment](#bagian-1-setup-environment)
- [Bagian 2: Langkah Pertama — Analisis File Forensik](#bagian-2-langkah-pertama--analisis-file-forensik)
- [Bagian 3: File Carving](#bagian-3-file-carving)
- [Bagian 4: Network Forensics (PCAP/PCAPNG)](#bagian-4-network-forensics)
- [Bagian 5: OS Forensics — Windows](#bagian-5-os-forensics--windows)
- [Bagian 6: OS Forensics — Linux](#bagian-6-os-forensics--linux)
- [Bagian 7: Browser Forensics](#bagian-7-browser-forensics)
- [Bagian 8: AppData & Third Party App Forensics](#bagian-8-appdata--third-party-app-forensics)
- [Bagian 9: Memory Forensics (Volatility)](#bagian-9-memory-forensics-volatility)
- [Bagian 10: Malware Analysis](#bagian-10-malware-analysis)
- [Bagian 11: Walkthrough Soal CTF Forensics](#bagian-11-walkthrough-soal-ctf-forensics)
- [Bagian 12: Tempat Latihan & Resources](#bagian-12-tempat-latihan--resources)
- [Bagian 13: Cheat Sheet & Quick Reference](#bagian-13-cheat-sheet--quick-reference)

---

# Bagian 0: Fondasi — Apa itu Digital Forensics?

## Definisi

**Digital Forensics** = ilmu mengumpulkan, menganalisis, dan menyajikan bukti digital dari perangkat elektronik.

Dalam konteks **CTF**:
```
Kamu mendapat:  file bukti (disk image, memory dump, packet capture, file aneh, dll.)
Tujuan:         menemukan flag tersembunyi di dalam bukti tersebut
Caranya:        analisis, extract, decode, dan reconstruct data
```

## Analogi Sederhana

Bayangkan kamu seorang **detektif digital**:
- **File Carving** → Mencari barang bukti di tumpukan sampah (extract file dari raw data)
- **Network Forensics** → Menyadap dan membaca surat-surat yang dikirim (analisis traffic)
- **OS Forensics** → Memeriksa rumah tersangka (analisis file system, registry, logs)
- **Memory Forensics** → Membaca pikiran tersangka saat kejadian (dump RAM)
- **Malware Analysis** → Mempelajari senjata yang digunakan tersangka (analisis virus/trojan)

## Konsep Dasar

### 1. Apa itu File?

Setiap file di komputer sebenarnya adalah **kumpulan bytes (0 dan 1)**. Yang membedakan file satu dengan lainnya adalah **format** — aturan bagaimana bytes tersebut disusun.

```
File jenis apapun dimulai dengan "Magic Bytes" / "File Signature":
┌─────────────────────────────────────────────────────┐
│ Magic Bytes (penanda tipe)  │  Data konten file      │
│ FF D8 FF E0 (JPEG)         │  pixel data gambar...   │
│ 89 50 4E 47 (PNG)          │  pixel data gambar...   │
│ 50 4B 03 04 (ZIP)          │  compressed data...     │
│ 25 50 44 46 (PDF)          │  document data...       │
└─────────────────────────────────────────────────────┘
```

### Magic Bytes Penting

| Magic Bytes (Hex) | Tipe File | Keterangan |
|-------------------|-----------|------------|
| `FF D8 FF` | JPEG | Gambar |
| `89 50 4E 47` | PNG | Gambar (ada "PNG" di byte 1-3) |
| `47 49 46 38` | GIF | Gambar animasi |
| `42 4D` | BMP | Gambar bitmap |
| `50 4B 03 04` | ZIP | Arsip (juga DOCX, XLSX, APK, JAR!) |
| `52 61 72 21` | RAR | Arsip ("Rar!") |
| `1F 8B` | GZIP | Kompresi |
| `25 50 44 46` | PDF | Dokumen ("%PDF") |
| `7F 45 4C 46` | ELF | Linux binary |
| `4D 5A` | PE/EXE | Windows binary ("MZ") |
| `D0 CF 11 E0` | MS Office (old) | DOC, XLS, PPT |
| `37 7A BC AF` | 7z | Arsip 7-Zip |

### 2. Apa itu Metadata?

**Metadata** = "data tentang data". Informasi tersembunyi di dalam file.

```
Contoh metadata di foto (EXIF):
- Tanggal pengambilan: 2026-01-15 14:30:22
- Kamera: iPhone 15 Pro
- GPS koordinat: -6.2088, 106.8456 (Jakarta!)
- Software: Adobe Photoshop
- Author: "John Doe"
← Kadang FLAG tersembunyi di metadata!
```

### 3. Apa itu Hex?

**Hexadecimal (Hex)** = sistem bilangan basis 16 (0-9, A-F). Digunakan untuk merepresentasikan data biner secara ringkas.

```
Decimal:  0  1  2  3  4  5  6  7  8  9  10  11  12  13  14  15
Hex:      0  1  2  3  4  5  6  7  8  9   A   B   C   D   E   F

1 byte = 2 digit hex = 8 bit
Contoh: 0x41 = 65 desimal = karakter 'A' (ASCII)
        0xFF = 255 desimal = nilai byte maksimum
```

### 4. Apa itu Encoding?

**Encoding** = cara merepresentasikan data. Beberapa encoding umum di CTF:

```
ASCII:   karakter → angka (A=65, B=66, ...)
Base64:  binary → teks (SGVsbG8= → "Hello")
Hex:     binary → hex string (48656c6c6f → "Hello")
URL:     karakter special → %xx (%20 = spasi)
ROT13:   huruf digeser 13 posisi (A→N, B→O, ...)
```

---

# Bagian 1: Setup Environment

## Tools yang Perlu Diinstall

### Di Linux/WSL:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# ═══ File Analysis & Carving ═══
sudo apt install -y file               # identifikasi file
sudo apt install -y xxd                # hex dump
sudo apt install -y hexedit            # hex editor terminal
sudo apt install -y binwalk            # firmware/file analysis & extraction
sudo apt install -y foremost           # file carving
sudo apt install -y scalpel            # file carving (alternatif)
sudo apt install -y sleuthkit          # disk forensics toolkit
sudo apt install -y testdisk           # file recovery

# ═══ Network Forensics ═══
sudo apt install -y wireshark          # GUI packet analyzer (terkenal!)
sudo apt install -y tshark             # CLI wireshark
sudo apt install -y tcpdump            # packet capture CLI
sudo apt install -y ngrep              # grep untuk network
sudo apt install -y net-tools          # ifconfig, netstat

# ═══ Image/Steganography ═══
sudo apt install -y steghide           # stego tool
sudo apt install -y zsteg              # PNG/BMP stego
sudo apt install -y exiftool           # metadata reader
sudo apt install -y pngcheck           # cek integritas PNG
sudo apt install -y imagemagick        # manipulasi gambar
pip3 install stegoveritas              # automated stego analysis

# ═══ Memory Forensics ═══
pip3 install volatility3               # memory forensics framework

# ═══ Malware Analysis ═══
sudo apt install -y clamav             # antivirus (scan malware)
sudo apt install -y yara               # pattern matching
pip3 install oletools                   # analisis Office documents
pip3 install pefile                     # analisis PE files
pip3 install pyelftools                 # analisis ELF files

# ═══ General Utilities ═══
sudo apt install -y p7zip-full         # extract 7z, zip, rar
sudo apt install -y unrar              # extract rar
sudo apt install -y sqlite3            # baca database SQLite
sudo apt install -y jq                 # parse JSON
pip3 install pycryptodome              # crypto operations
```

### Di Windows:

```
Download & Install:
1. Wireshark         → https://www.wireshark.org/
2. HxD               → https://mh-nexus.de/en/hxd/
3. FTK Imager        → https://www.exterro.com/ftk-imager (disk forensics)
4. Autopsy           → https://www.autopsy.com/ (disk forensics GUI)
5. DB Browser SQLite → https://sqlitebrowser.org/
6. 7-Zip             → https://7-zip.org/
7. ExifTool          → https://exiftool.org/
8. NetworkMiner      → https://www.netresec.com/?page=NetworkMiner
```

### Bookmark Penting:

```
1. CyberChef          → https://gchq.github.io/CyberChef/
2. Hex Editor Online   → https://hexed.it/
3. Base64 Decode       → https://www.base64decode.org/
4. PCAP Online         → https://packettotal.com/
5. VirusTotal          → https://www.virustotal.com/
6. Hybrid Analysis     → https://www.hybrid-analysis.com/
7. AperiSolve          → https://www.aperisolve.com/ (stego otomatis)
```

---

# Bagian 2: Langkah Pertama — Analisis File Forensik

## Metodologi Universal (Selalu Mulai dari Sini!)

Setiap kali mendapat file challenge forensik, ikuti langkah ini:

```
LANGKAH 1: file → Apa tipe filenya?
LANGKAH 2: xxd / hexdump → Lihat raw bytes, cek magic bytes
LANGKAH 3: exiftool → Cek metadata
LANGKAH 4: strings → Cari string tersembunyi
LANGKAH 5: binwalk → Ada file embedded?
LANGKAH 6: Tool spesifik berdasarkan tipe file
```

### Langkah 1: Identifikasi File

```bash
$ file mystery_file

# Output kemungkinan:
mystery_file: JPEG image data, JFIF standard 1.01
mystery_file: PNG image data, 800 x 600, 8-bit/color RGBA
mystery_file: Zip archive data, at least v2.0 to extract
mystery_file: pcap capture file, microsecond ts (little-endian)
mystery_file: data    ← tidak dikenali! mungkin corrupt/encrypted/custom
```

**TIPS**: Jangan percaya extension file! Challenge sering mengganti extension.
```bash
$ file gambar.jpg
gambar.jpg: PNG image data    ← sebenarnya PNG, bukan JPEG!

$ file dokumen.pdf
dokumen.pdf: Zip archive data  ← sebenarnya ZIP, bukan PDF!
```

### Langkah 2: Lihat Raw Bytes

```bash
# xxd — lihat hex dump
$ xxd mystery_file | head -20
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0320 0000 0258 0802 0000 00...       ...........

# Kita bisa lihat: "PNG" di byte 1-3 → ini file PNG!

# Cek hanya beberapa byte pertama:
$ xxd -l 16 mystery_file
# -l 16 = hanya 16 bytes pertama

# Cek byte tertentu:
$ xxd -s 0x100 -l 32 mystery_file
# -s 0x100 = mulai dari offset 0x100
# -l 32    = tampilkan 32 bytes
```

### Langkah 3: Cek Metadata

```bash
$ exiftool mystery_file
# Output contoh:
ExifTool Version Number         : 12.40
File Name                       : mystery_file
File Size                       : 2.5 MB
File Type                       : JPEG
MIME Type                       : image/jpeg
Image Width                     : 1920
Image Height                    : 1080
Camera Model Name               : Canon EOS R5
GPS Latitude                    : 40 deg 42' 46.08" N
GPS Longitude                   : 74 deg 0' 21.60" W
Comment                         : flag{metadata_is_important}   ← FLAG!
Author                          : CTF_Player
Software                        : GIMP 2.10

# TIPS: Flag sering tersembunyi di field:
# - Comment
# - Author
# - Description
# - UserComment
# - XPComment
# - Subject
```

### Langkah 4: Cari Strings

```bash
$ strings mystery_file | grep -i "flag\|ctf\|key\|secret\|password"
# Mungkin langsung ketemu:
flag{hidden_in_plain_sight}

# Cari strings dengan panjang minimum:
$ strings -n 10 mystery_file      # minimal 10 karakter
$ strings -e l mystery_file       # Unicode (UTF-16LE) strings
```

### Langkah 5: Cek File Embedded

```bash
$ binwalk mystery_file
# Output:
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             PNG image, 800 x 600
153600        0x25800         Zip archive data
153800        0x25900         End of Zip archive

# Ada ZIP tersembunyi di dalam PNG!
$ binwalk -e mystery_file
# Files extracted ke folder: _mystery_file.extracted/
$ ls _mystery_file.extracted/
25800.zip
$ unzip _mystery_file.extracted/25800.zip
# → flag.txt: flag{binwalk_saves_the_day}
```

---

# Bagian 3: File Carving

## Apa itu File Carving?

**File Carving** = proses mengekstrak file dari raw data (disk image, memory dump, atau file besar) berdasarkan **file signatures** (magic bytes), **bukan** berdasarkan file system.

Analoginya: bayangkan kamu punya tumpukan kertas campur aduk. File carving = memilah kertas berdasarkan header/footer (misal: setiap surat dimulai dengan "Dear" dan diakhiri "Regards").

## Kapan Digunakan?

```
- File yang berisi data tersembunyi (steganografi)
- Disk image yang corrupt/dihapus
- Memory dump yang berisi file
- Firmware yang berisi embedded files
- File "data" yang tidak dikenali
```

## Tool 1: binwalk

**Apa**: Scanner yang mencari file signatures di dalam file lain.

### Penggunaan Lengkap:

```bash
# ═══ SCAN (lihat apa yang ada) ═══
$ binwalk challenge_file
# Output menunjukkan semua file yang ditemukan + offset

# ═══ EXTRACT (keluarkan semua file embedded) ═══
$ binwalk -e challenge_file
# Hasilnya di folder: _challenge_file.extracted/

# ═══ EXTRACT dengan opsi ═══
$ binwalk -e --dd='.*' challenge_file     # extract SEMUA tipe
$ binwalk --dd='png:png' challenge_file   # extract hanya PNG
$ binwalk --dd='zip:zip' challenge_file   # extract hanya ZIP

# ═══ ENTROPY ANALYSIS ═══
$ binwalk -E challenge_file
# Menampilkan grafik entropy
# Entropy tinggi (mendekati 1.0) = data encrypted/compressed
# Entropy rendah = data plaintext/kosong
# Perubahan entropy = batas antar data types

# ═══ RECURSIVE EXTRACT ═══
$ binwalk -eM challenge_file
# -M = matryoshka (recursive) — extract file di dalam file di dalam file
# Berguna jika ada nested archives

# ═══ RAW BYTES ═══
$ binwalk -R "\x89PNG" challenge_file
# Cari raw byte pattern secara manual

# ═══ CONTOH WORKFLOW ═══
$ binwalk firmware.bin
# Ditemukan:
# 0x0       → ELF header
# 0x40000   → Squashfs filesystem
# 0x200000  → JPEG image
# 0x250000  → Zip archive

$ binwalk -e firmware.bin
$ cd _firmware.bin.extracted/
$ ls
# 40000.squashfs  200000.jpeg  250000.zip
# Extract squashfs:
$ unsquashfs 40000.squashfs
# Sekarang bisa browse filesystem → cari flag!
```

### Tips binwalk untuk CTF:

```bash
# TIP 1: Jika binwalk tidak menemukan apa-apa, coba:
$ binwalk -B challenge_file    # scan ALL known signatures (lebih agresif)

# TIP 2: Menambahkan custom signature:
# Buat file signature custom di ~/.config/binwalk/magic

# TIP 3: Combine dengan grep
$ binwalk challenge_file | grep -i "zip\|png\|jpeg\|pdf"
```

## Tool 2: foremost

**Apa**: File carver yang lebih aggresif. Mencari file berdasarkan header, footer, dan internal data structure.

### Penggunaan:

```bash
# ═══ BASIC ═══
$ foremost -i challenge_file
# Output di folder: output/
# Terorganisir per tipe: output/jpg/ output/png/ output/zip/ dll.

$ ls output/
audit.txt  jpg/  png/  zip/  pdf/  ole/  exe/

# audit.txt berisi log semua file yang ditemukan

# ═══ SPECIFIC TYPES ═══
$ foremost -t jpg,png,gif -i challenge_file    # hanya gambar
$ foremost -t zip,rar -i challenge_file         # hanya arsip
$ foremost -t pdf -i challenge_file             # hanya PDF
$ foremost -t all -i challenge_file             # semua tipe

# ═══ DARI DISK IMAGE ═══
$ foremost -i disk_image.dd -o carved_files/
# -o = output directory

# ═══ FITUR YANG BERGUNA ═══
$ foremost -v -i challenge_file                 # verbose mode
$ foremost -q -i challenge_file                 # quick mode (hanya header)
```

### Perbedaan binwalk vs foremost:

```
binwalk:
  + Menunjukkan SEMUA signatures yang ditemukan
  + Support custom signatures
  + Entropy analysis
  + Recursive extraction
  - Kadang miss file yang fragmentasi

foremost:
  + Lebih agresif dalam carving
  + Mengorganisir output per tipe file
  + Bisa recover file dari disk image yang corrupt
  - Tidak punya entropy analysis
  
TIPS: Coba KEDUA tool! Kadang satu menemukan yang lain tidak.
```

## Tool 3: photorec

**Apa**: File recovery tool yang sangat powerful. Bisa recover file dari disk image, partisi, bahkan media yang di-format.

### Penggunaan:

```bash
# photorec biasanya interactive (menu-driven):
$ photorec challenge_image.dd

# Langkah-langkah di menu:
# 1. Pilih disk/image → Select
# 2. Pilih partisi → muncul daftar partisi
# 3. Pilih filesystem type: ext4/NTFS/FAT
# 4. Pilih area: "Free" (hanya area kosong) atau "Whole" (seluruh disk)
# 5. Pilih output directory
# 6. Photorec mulai scanning & recovering

# Hasilnya: folder recup_dir.1/ recup_dir.2/ dll.
# Berisi semua file yang di-recover

# ═══ NON-INTERACTIVE MODE ═══
$ photorec /d output_dir /cmd challenge_image.dd fileopt,everything,enable,search
```

## Tool 4: Carving Manual dengan dd

```bash
# Kadang kamu perlu extract secara MANUAL jika tools gagal.

# Contoh: binwalk menemukan ZIP di offset 0x25800, ukuran 500 bytes
$ dd if=challenge_file of=extracted.zip bs=1 skip=$((0x25800)) count=500

# Penjelasan:
# if=    → input file
# of=    → output file
# bs=1   → block size 1 byte (presisi tinggi)
# skip=  → mulai dari byte ke-berapa (hex di-convert ke decimal)
# count= → berapa banyak bytes yang diambil

# Jika tidak tahu ukurannya, ambil agak banyak:
$ dd if=challenge_file of=extracted.zip bs=1 skip=$((0x25800)) count=100000
# Lalu coba unzip → biasanya ZIP ignores trailing data
```

## Tool 5: scalpel

```bash
# Alternatif foremost, bisa dikonfigurasi lebih detail

# Edit config untuk menentukan tipe file yang dicari:
$ sudo nano /etc/scalpel/scalpel.conf
# Uncomment baris tipe file yang ingin di-carve
# Contoh: uncomment baris jpg, png, pdf, zip

# Jalankan:
$ scalpel -c /etc/scalpel/scalpel.conf -o output/ challenge_file
```

---

# Bagian 4: Network Forensics

## Apa itu Network Forensics?

**Network Forensics** = menganalisis **traffic jaringan** yang sudah di-capture untuk menemukan bukti atau flag.

File capture biasanya berformat:
- **.pcap** — format lama, paling umum
- **.pcapng** — format baru, lebih kaya fitur
- Keduanya bisa dibuka dengan **Wireshark**

## Apa yang Ada di Dalam PCAP?

```
PCAP berisi rekaman paket-paket jaringan:

Paket 1: [Timestamp] PC-A → Server: "GET /index.html HTTP/1.1"
Paket 2: [Timestamp] Server → PC-A: "HTTP/1.1 200 OK ... <html>..."
Paket 3: [Timestamp] PC-A → Server: "POST /login ..."
Paket 4: [Timestamp] PC-A → PC-B: "Hi, the password is s3cr3t"
...

Setiap paket berisi:
├── Frame (Layer 1-2): MAC address, Ethernet
├── Network (Layer 3): IP address source/destination
├── Transport (Layer 4): TCP/UDP, port number
└── Application (Layer 7): HTTP, DNS, FTP, SMTP, dll.
```

## Wireshark — Tutorial Lengkap untuk Pemula

### Membuka File

```
1. Buka Wireshark
2. File → Open → pilih file .pcap / .pcapng
3. Muncul daftar paket — setiap baris = 1 paket

Interface Wireshark:
┌──────────────────────────────────────────────────────────┐
│ Filter bar: [                                        ]   │
├──────────────────────────────────────────────────────────┤
│ No. | Time  | Source      | Dest       | Protocol | Info │ ← Packet list
│  1  | 0.000 | 192.168.1.5 | 10.0.0.1  | TCP      | ...  │
│  2  | 0.001 | 10.0.0.1    | 192.168.1.5| HTTP     | ...  │
│  3  | 0.050 | 192.168.1.5 | 10.0.0.1  | DNS      | ...  │
├──────────────────────────────────────────────────────────┤
│ Frame 1: ...                                              │ ← Packet detail
│ └─ Ethernet II                                            │
│    └─ Internet Protocol                                   │
│       └─ Transmission Control Protocol                    │
│          └─ Hypertext Transfer Protocol                   │
├──────────────────────────────────────────────────────────┤
│ 0000  48 65 6c 6c 6f                          Hello      │ ← Hex dump
└──────────────────────────────────────────────────────────┘
```

### Filter — Senjata Utama di Wireshark!

```
Filter paling berguna untuk CTF:

═══ FILTER BY PROTOCOL ═══
http                          # hanya paket HTTP
dns                           # hanya paket DNS
ftp                           # hanya paket FTP
ftp-data                      # hanya data transfer FTP
tcp                           # hanya paket TCP
udp                           # hanya paket UDP
smtp                          # hanya email SMTP
imap                          # hanya email IMAP
icmp                          # hanya ping

═══ FILTER BY IP ═══
ip.addr == 192.168.1.5        # semua paket dari/ke IP ini
ip.src == 192.168.1.5         # hanya dari IP ini
ip.dst == 10.0.0.1            # hanya ke IP ini

═══ FILTER BY PORT ═══
tcp.port == 80                # HTTP
tcp.port == 443               # HTTPS
tcp.port == 21                # FTP control
tcp.port == 22                # SSH
tcp.port == 25                # SMTP
udp.port == 53                # DNS

═══ FILTER BY CONTENT ═══
http.request.uri contains "flag"        # URL mengandung "flag"
http.response.code == 200               # hanya response sukses
frame contains "flag{"                  # cari "flag{" di semua paket
frame contains "password"               # cari "password" di semua paket
tcp contains "secret"                   # cari di TCP payload

═══ FILTER KOMBINASI ═══
http && ip.src == 192.168.1.5           # HTTP dari IP tertentu
dns && frame contains "suspicious"       # DNS yang mencurigakan
tcp.port == 4444                         # reverse shell common port!
```

### Langkah-Langkah Analisis PCAP di CTF

```
STEP 1: Buka di Wireshark → lihat overview

STEP 2: Statistics → Protocol Hierarchy
  → Menunjukkan protokol apa saja yang ada
  → Cari yang tidak biasa (ICMP banyak? DNS banyak? Port aneh?)

STEP 3: Statistics → Conversations
  → Siapa bicara dengan siapa?
  → Cari volume data terbesar → kemungkinan transfer file

STEP 4: Statistics → Endpoints
  → Daftar semua IP/host

STEP 5: Cari yang mencurigakan:
  → HTTP POST (mungkin ada credential/flag)
  → FTP transfer (mungkin ada file)
  → DNS unusual (mungkin DNS exfiltration)
  → Port tidak standar (4444, 1337, dll.)
  → Plaintext credential

STEP 6: Follow stream (lihat percakapan lengkap)
  → Klik kanan paket → Follow → TCP Stream (atau HTTP, UDP)
  → Muncul seluruh percakapan antara client dan server
```

### Extract File dari PCAP

```
═══ METODE 1: Wireshark GUI ═══

Untuk HTTP:
1. File → Export Objects → HTTP
2. Muncul daftar semua file yang ditransfer via HTTP
3. Pilih file → Save / Save All
4. Cek setiap file — mungkin ada flag.txt, secret.png, dll.

Untuk DICOM/IMF/SMB/TFTP:
1. File → Export Objects → pilih protokol yang sesuai

═══ METODE 2: Follow Stream ═══

1. Klik kanan pada paket data → Follow → TCP Stream
2. Muncul dialog dengan data mentah
3. Ganti "Show data as" → Raw
4. Save As → simpan sebagai file
5. Carve secara manual jika perlu

═══ METODE 3: tshark (CLI) ═══

# Export semua HTTP objects
$ tshark -r capture.pcap --export-objects "http,exported_files/"

# Export data dari stream tertentu
$ tshark -r capture.pcap -z follow,tcp,raw,0 > stream_0.txt

# Cari string di semua paket
$ tshark -r capture.pcap -Y 'frame contains "flag"' -T fields -e data
```

### Skenario Umum di CTF

#### Skenario 1: HTTP Login — Credential Leak

```
Filter: http.request.method == "POST"
Cari: POST /login → klik → lihat form data di panel bawah
Mungkin terlihat: username=admin&password=flag{http_is_insecure}
```

#### Skenario 2: FTP Transfer — File Tersembunyi

```
Filter: ftp
Cari: "RETR secret.txt" atau "STOR flag.zip"
Lalu filter: ftp-data
Follow TCP Stream → Save data → buka file
```

#### Skenario 3: DNS Exfiltration — Data di DNS Queries

```
Filter: dns
Cari DNS query yang tidak biasa:
  Query: ZmxhZ3t.example.com         ← Base64 encoded!
  Query: kJHSD8.example.com
  
Ambil semua subdomain → decode Base64 → flag!
```

```python
# Script decode DNS exfiltration
import base64

# Ambil subdomain queries dari Wireshark (export CSV atau manual)
queries = [
    "ZmxhZ3t",
    "kZG5zX2",
    "V4ZmlsX",
    "dHJhdGl",
    "vbn0="
]

encoded = ''.join(queries)
decoded = base64.b64decode(encoded)
print(decoded)  # flag{dns_exfiltration}
```

#### Skenario 4: ICMP Tunneling — Data di Ping

```
Filter: icmp
Banyak paket ICMP (ping) dengan data payload yang tidak biasa?
→ Data mungkin tersembunyi di ICMP payload!
→ Klik paket → lihat Data field → extract & decode
```

```python
# Extract ICMP data
from scapy.all import *

packets = rdpcap("challenge.pcap")
data = b""
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo request
        if pkt.haslayer(Raw):
            data += bytes(pkt[Raw])

print(data)  # mungkin flag tersembunyi di sini
```

#### Skenario 5: Wireless — WPA Handshake Crack

```bash
# Jika PCAP berisi WiFi traffic + WPA handshake:
# Crack password WiFi:
$ aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.pcap

# Setelah crack, decrypt traffic:
# Wireshark → Edit → Preferences → Protocols → IEEE 802.11
# → Decryption Keys → Edit → Tambahkan key
```

---

# Bagian 5: OS Forensics — Windows

## Apa yang Dicari di Windows Forensics?

```
Windows menyimpan BANYAK informasi yang berguna:
├── Registry        → konfigurasi system + user activities
├── Event Logs      → log kejadian system
├── Prefetch        → program yang pernah dijalankan
├── Recent Files    → file yang baru dibuka
├── Recycle Bin     → file yang "dihapus" (masih recoverable!)
├── Browser Data    → history, cookies, password
├── USBStor         → histori USB yang pernah di-colok
└── NTFS Artifacts  → MFT, $LogFile, timestamps
```

## Windows Registry

### Apa itu Registry?

**Registry** = database konfigurasi Windows. Berisi pengaturan OS, aplikasi, dan aktivitas pengguna.

```
Registry terdiri dari "hive files":
├── SAM        → user accounts & password hashes
├── SYSTEM     → system configuration, services
├── SOFTWARE   → installed software settings
├── NTUSER.DAT → per-user settings (di C:\Users\<name>\)
├── SECURITY   → security policies
└── UsrClass.dat → user file associations
```

### Lokasi File Registry:

```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SECURITY
C:\Users\<username>\NTUSER.DAT
C:\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

### Analisis Registry dengan regripper:

```bash
# Install
sudo apt install -y regripper

# Parse registry hive
$ regripper -r NTUSER.DAT -p all > ntuser_output.txt
$ regripper -r SAM -p all > sam_output.txt
$ regripper -r SYSTEM -p all > system_output.txt
$ regripper -r SOFTWARE -p all > software_output.txt

# Atau plugin spesifik:
$ regripper -r NTUSER.DAT -p recentdocs    # file yang baru dibuka
$ regripper -r NTUSER.DAT -p userassist    # program yang dijalankan
$ regripper -r NTUSER.DAT -p typedurls     # URL yang diketik
$ regripper -r SYSTEM -p usbstor           # USB yang pernah di-colok
$ regripper -r SAM -p samparse             # user accounts
```

### Registry Keys Penting untuk CTF:

```
═══ PROGRAM YANG DIJALANKAN ═══
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
  → Program yang dijalankan user + jumlah eksekusi + timestamp
  → Data di-encode ROT13! Decode untuk baca

NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  → Command yang dijalankan via Win+R (Run dialog)

═══ FILE YANG DIAKSES ═══
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
  → File yang baru-baru ini dibuka

NTUSER\Software\Microsoft\Office\<version>\<app>\File MRU
  → File terbaru di Microsoft Office

═══ USB DEVICES ═══
SYSTEM\CurrentControlSet\Enum\USBSTOR
  → Semua USB device yang pernah dihubungkan

═══ NETWORK ═══
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures
  → WiFi networks yang pernah terhubung
  
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
  → Network adapter configuration

═══ USER ACCOUNTS ═══
SAM\Domains\Account\Users
  → User accounts + password hashes (bisa di-crack!)
```

## Windows Event Logs

```bash
# Lokasi: C:\Windows\System32\winevt\Logs\
# Format: .evtx

# Parse dengan python-evtx:
$ pip3 install python-evtx
$ python3 -c "
from Evtx.Evtx import FileHeader
import Evtx.Views as e_views

with open('Security.evtx', 'r') as f:
    fh = FileHeader(f)
    for xml, record in e_views.evtx_file_xml_view(fh):
        print(xml)
" > events.txt

# Atau gunakan tool:
$ evtx_dump.py Security.evtx > events.xml

# Event ID penting:
# 4624  → Successful logon
# 4625  → Failed logon
# 4688  → Process creation
# 4720  → User account created
# 7045  → Service installed
# 1102  → Audit log cleared (suspicious!)
```

## Windows Prefetch

```bash
# Lokasi: C:\Windows\Prefetch\
# Berisi: program yang pernah dijalankan + kapan + berapa kali

# Parse dengan PECmd / prefetchparser:
$ pip3 install prefetch-parser

# Atau gunakan Eric Zimmerman's tools (Windows):
# Download: https://ericzimmerman.github.io/
# PECmd.exe -f "NOTEPAD.EXE-12345678.pf" --csv output/
```

## Windows Recycle Bin

```bash
# Lokasi: C:\$Recycle.Bin\<SID>\
# File yang "dihapus" masih ada di sini!

# File diawali $I (metadata) dan $R (data asli):
# $I... → berisi: ukuran file, tanggal hapus, path asli
# $R... → berisi: DATA FILE ASLI (bisa di-recover!)

# Parse $I file:
$ python3 << 'EOF'
import struct, datetime

with open('$IABCDEF.txt', 'rb') as f:
    f.read(8)   # header
    size = struct.unpack('<Q', f.read(8))[0]
    timestamp = struct.unpack('<Q', f.read(8))[0]
    # Convert Windows FILETIME to datetime
    dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=timestamp//10)
    path = f.read().decode('utf-16le').rstrip('\x00')
    print(f"Original path: {path}")
    print(f"Size: {size} bytes")
    print(f"Deleted: {dt}")
EOF

# File $R yang cocok berisi data asli → rename dan buka!
```

---

# Bagian 6: OS Forensics — Linux

## Artifact Penting di Linux

```
Linux menyimpan informasi di:
├── /var/log/          → system logs
├── /etc/passwd        → user accounts
├── /etc/shadow        → password hashes
├── /home/<user>/      → user files
│   ├── .bash_history  → command history ← SERING ADA FLAG!
│   ├── .ssh/          → SSH keys
│   ├── .gnupg/        → GPG keys
│   └── .local/share/  → application data
├── /tmp/              → temporary files
└── /root/             → root user home
```

## Log Analysis

```bash
# ═══ AUTH LOG — login attempts ═══
$ cat /var/log/auth.log | grep -i "fail\|success\|accepted"
# Cari: login gagal berulang, SSH brute force, sudo usage

# ═══ SYSLOG — system events ═══
$ cat /var/log/syslog | grep -i "error\|warning\|critical"

# ═══ BASH HISTORY — command yang dijalankan user ═══
$ cat /home/user/.bash_history
# Mungkin berisi:
# curl http://evil.com/flag.txt
# echo "flag{bash_history}" > /dev/null
# openssl enc -d -aes-256-cbc -in secret.enc -out flag.txt -pass pass:mykey123
# ← Semua command terlihat! Termasuk password & flag!

# ═══ CRONTAB — scheduled tasks ═══
$ cat /var/spool/cron/crontabs/*
$ cat /etc/crontab
# Cari: script mencurigakan yang dijalankan secara berkala

# ═══ LAST LOGIN ═══
$ last -f /var/log/wtmp        # login history
$ lastb -f /var/log/btmp       # failed login attempts
```

## File System Analysis

```bash
# Jika dapat disk image (.dd, .img, .E01):

# ═══ MOUNT DISK IMAGE ═══
$ sudo mkdir /mnt/evidence
$ sudo mount -o ro,loop disk_image.dd /mnt/evidence
# -o ro = read-only (jangan modifikasi bukti!)
# -o loop = mount file sebagai disk

# ═══ BROWSE ═══
$ ls -la /mnt/evidence/
$ find /mnt/evidence/ -name "*flag*"
$ grep -r "flag{" /mnt/evidence/

# ═══ CARI FILE YANG DIHAPUS ═══
# Tool: autopsy, sleuthkit, extundelete

# Dengan sleuthkit:
$ fls -r disk_image.dd         # list semua file (termasuk deleted!)
# Output: * menandakan file yang dihapus
# d/d 11: home
# r/r * 15: deleted_secret.txt   ← file dihapus!

$ icat disk_image.dd 15 > recovered_secret.txt    # recover file!
$ cat recovered_secret.txt
# flag{deleted_but_not_gone}

# ═══ TIMELINE ANALYSIS ═══
$ fls -m "/" -r disk_image.dd > bodyfile.txt
$ mactime -b bodyfile.txt > timeline.csv
# Timeline menunjukkan KAPAN file dibuat/dimodifikasi/diakses
```

## File Timestamps (MAC Times)

```
Setiap file punya 3 timestamp:
- Modified  → kapan isi file terakhir diubah
- Accessed  → kapan file terakhir dibaca
- Changed   → kapan metadata file terakhir berubah (Linux: inode change)

$ stat suspicious_file
  Access: 2026-01-15 14:30:00
  Modify: 2026-01-10 09:15:00
  Change: 2026-01-10 09:15:00

# Di CTF: timestamp bisa jadi clue!
# Misal: file dibuat tepat jam 13:37 → "leet" → mungkin penting
```

---

# Bagian 7: Browser Forensics

## Apa yang Disimpan Browser?

```
Browser menyimpan BANYAK data:
├── History          → URL yang dikunjungi + timestamp
├── Bookmarks        → halaman yang di-bookmark
├── Cookies          → session data, tracking
├── Cache            → file yang di-cache (gambar, JS, CSS)
├── Passwords        → saved credentials (encrypted!)
├── Downloads        → daftar file yang didownload
├── Form Data        → data yang pernah diisi di form
├── Sessions         → tab yang terbuka
└── Extensions       → browser extensions terinstall
```

## Lokasi Data Browser

### Google Chrome:

```
Windows:
  C:\Users\<name>\AppData\Local\Google\Chrome\User Data\Default\
  
Linux:
  /home/<name>/.config/google-chrome/Default/

macOS:
  /Users/<name>/Library/Application Support/Google/Chrome/Default/

File penting:
├── History          → SQLite database (browsing history)
├── Cookies          → SQLite database
├── Login Data       → SQLite database (saved passwords, encrypted!)
├── Web Data         → SQLite database (form autofill)
├── Bookmarks        → JSON file
├── Preferences      → JSON file
├── Cache/           → cached files
├── Local Storage/   → website local storage
└── Extensions/      → installed extensions
```

### Mozilla Firefox:

```
Windows:
  C:\Users\<name>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>/

Linux:
  /home/<name>/.mozilla/firefox/<profile>/

File penting:
├── places.sqlite    → history + bookmarks
├── cookies.sqlite   → cookies
├── logins.json      → saved passwords (encrypted with key4.db)
├── key4.db          → encryption key for passwords
├── formhistory.sqlite → form data
├── sessionstore.jsonlz4 → open tabs/sessions
└── cache2/          → cached files
```

### Microsoft Edge:

```
Windows:
  C:\Users\<name>\AppData\Local\Microsoft\Edge\User Data\Default\
  (Struktur sama persis dengan Chrome karena berbasis Chromium)
```

## Analisis Browser Data

### Membaca History (SQLite)

```bash
# Chrome/Edge History:
$ sqlite3 History
sqlite> .tables
# downloads  keyword_search_terms  urls  visits  ...

sqlite> SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600,'unixepoch') 
        FROM urls ORDER BY last_visit_time DESC LIMIT 20;
# Menampilkan: URL, judul, kunjungan, waktu

# Cari hal mencurigakan:
sqlite> SELECT url, title FROM urls WHERE url LIKE '%flag%' OR title LIKE '%secret%';
sqlite> SELECT url FROM urls WHERE url LIKE '%pastebin%' OR url LIKE '%drive.google%';

# Firefox History:
$ sqlite3 places.sqlite
sqlite> SELECT url, title, visit_count FROM moz_places 
        WHERE url LIKE '%flag%' ORDER BY last_visit_date DESC;
```

### Membaca Cookies

```bash
$ sqlite3 Cookies
sqlite> SELECT host_key, name, value, datetime(creation_utc/1000000-11644473600,'unixepoch')
        FROM cookies WHERE name LIKE '%flag%' OR value LIKE '%flag%';
```

### Extract Cache

```bash
# Chrome cache:
# Cache file ada di folder "Cache/Cache_Data/" (Chrome baru)
# Atau "Cache/" (Chrome lama)

# Parse dengan ChromeCacheView (Windows):
# https://www.nirsoft.net/utils/chrome_cache_view.html

# Atau manual:
# Cari file berdasarkan content type:
$ file Cache/Cache_Data/*
# Rename sesuai tipe dan buka

# Firefox cache:
$ ls cache2/entries/
# File bernama hex → identify dan rename
```

### Recover Password

```bash
# Chrome passwords (Login Data):
# Di-encrypt dengan DPAPI (Windows) atau OS keychain (Linux/Mac)

# Lihat encrypted data:
$ sqlite3 "Login Data"
sqlite> SELECT origin_url, username_value, hex(password_value) FROM logins;

# Decrypt memerlukan master key dari OS
# Tool: mimikatz (Windows), chrome_password_decryptor

# Firefox passwords:
# Encrypted dengan key4.db → decrypt dengan firefox_decrypt:
$ pip3 install firefox-decrypt
$ python3 firefox_decrypt.py /path/to/firefox/profile/
```

### Tool Otomatis — Hindsight (Chrome)

```bash
# Install
$ pip3 install pyhindsight

# Jalankan
$ hindsight -i "C:\Users\name\AppData\Local\Google\Chrome\User Data\Default" -o output
# Output: file Excel/SQLite dengan SEMUA data browser terorganisir!
```

---

# Bagian 8: AppData & Third Party App Forensics

## Apa yang Ada di AppData?

```
AppData (Windows) = folder tempat aplikasi menyimpan data:

C:\Users\<name>\AppData\
├── Local\        → app data yang TIDAK roaming
│   ├── Microsoft\     → Windows apps (Edge, Teams, etc.)
│   ├── Google\Chrome\ → Chrome browser data
│   ├── Discord\       → Discord app data
│   ├── Temp\          → temporary files
│   └── ...
├── LocalLow\     → low-integrity app data
└── Roaming\      → app data yang roaming (sync across devices)
    ├── Mozilla\Firefox\ → Firefox data
    ├── Microsoft\Teams\ → Teams data
    ├── Telegram Desktop\ → Telegram messages
    ├── discord\          → Discord
    └── ...

Linux equivalent:
/home/<name>/
├── .config/       → app configurations
├── .local/share/  → app data
├── .cache/        → cached data
└── .mozilla/      → Firefox
```

## Third Party App Forensics

### Discord

```bash
# Windows: C:\Users\<name>\AppData\Roaming\discord\
# Linux: /home/<name>/.config/discord/

# Data penting:
# Local Storage/ → LevelDB database
# Cache/ → cached images, files
# blob_storage/ → attachments

# Analisis:
$ python3 << 'EOF'
# Parse Discord Local Storage (LevelDB)
import plyvel
import json

db = plyvel.DB('Local Storage/leveldb/', create_if_missing=False)
for key, value in db:
    decoded_val = value.decode('utf-8', errors='ignore')
    if 'token' in decoded_val.lower() or 'flag' in decoded_val.lower():
        print(f"Key: {key}")
        print(f"Value: {decoded_val[:200]}")
        print("---")
db.close()
EOF

# Atau cari token Discord:
$ strings "Local Storage/leveldb/"*.log | grep -E "[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"
```

### Telegram Desktop

```bash
# Windows: C:\Users\<name>\AppData\Roaming\Telegram Desktop\
# Linux: /home/<name>/.local/share/TelegramDesktop/

# Data tersimpan terenkripsi di tdata/
# Tanpa key, sulit di-decrypt
# Tapi: cache images mungkin tidak encrypt!
# Cari di: tdata/user_data/cache/

# file dan binwalk pada cache files bisa reveal gambar/file
```

### Slack

```bash
# Windows: C:\Users\<name>\AppData\Roaming\Slack\
# Data: Local Storage, Cache, Cookies (mirip Chrome structure)

$ sqlite3 "Slack/Cookies"
sqlite> SELECT * FROM cookies WHERE name LIKE '%flag%';
```

### Email Client (Thunderbird)

```bash
# Windows: C:\Users\<name>\AppData\Roaming\Thunderbird\Profiles\<profile>/
# Linux: /home/<name>/.thunderbird/<profile>/

# Mail disimpan dalam format MBOX:
$ cat ImapMail/mail.example.com/INBOX
# Plaintext email! Cari flag di dalamnya.
$ grep -i "flag\|secret\|password" ImapMail/*/INBOX
```

## Digital Artifact Discovery — Pattern Umum

```bash
# ═══ CARI FILE BERDASARKAN WAKTU ═══
# File yang dimodifikasi dalam 24 jam terakhir:
$ find /evidence/ -mtime -1 -type f

# File yang diakses dalam 7 hari terakhir:  
$ find /evidence/ -atime -7 -type f

# ═══ CARI FILE TERSEMBUNYI ═══
$ find /evidence/ -name ".*" -type f              # hidden files (dimulai titik)
$ find /evidence/ -name "*.txt" -size +0           # text files non-kosong
$ find /evidence/ -name "flag*"                     # file bernama flag*

# ═══ CARI BERDASARKAN KONTEN ═══
$ grep -r "flag{" /evidence/                        # plaintext flags
$ grep -r "password\|secret\|key" /evidence/

# ═══ CARI FILE YANG DIHAPUS (di disk image) ═══
$ fls -r -d disk.dd                                 # list deleted files
$ icat disk.dd <inode_number> > recovered.file      # recover

# ═══ CARI ALTERNATE DATA STREAMS (NTFS-Windows) ═══
# ADS = data tersembunyi yang disisipkan ke file normal
$ dir /r                                            # (di Windows CMD)
# Contoh: file.txt:hidden_stream:$DATA
# Baca: more < file.txt:hidden_stream

# Di Linux (mount NTFS):
$ getfattr -n ntfs.streams.list file.txt
$ cat file.txt:hidden_stream
```

---

# Bagian 9: Memory Forensics (Volatility)

## Apa itu Memory Forensics?

**Memory Forensics** = menganalisis **dump RAM** (memori) komputer. RAM berisi data yang sedang digunakan saat komputer hidup.

```
Kenapa penting?
- Malware yang hanya berjalan di memori (fileless malware)
- Password/key yang belum di-write ke disk
- Network connections yang aktif
- Proses dan DLL yang berjalan
- Command yang sedang/baru dieksekusi
- Registry key yang di-load ke memori
- Decrypted data (sebelum di-encrypt kembali ke disk)
```

## Volatility — Tool Utama Memory Forensics

### Volatility 2 vs Volatility 3

```
Volatility 2 (legacy, masih banyak dipakai):
  - Python 2/3, matang, banyak plugin
  - Command format: vol.py --profile=Win7SP1x64 -f memory.dmp <plugin>
  - Perlu spesifikasi "profile" (OS version)

Volatility 3 (modern, recommended):
  - Python 3 only, lebih cepat
  - Command format: vol -f memory.dmp <plugin>
  - Auto-detect OS (tidak perlu profile manual)
  - Masih berkembang, beberapa plugin vol2 belum ada
```

### Instalasi

```bash
# Volatility 3:
pip3 install volatility3

# Volatility 2 (jika perlu):
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
pip2 install -r requirements.txt
# Atau gunakan standalone binary dari releases
```

### Workflow Memory Forensics — Step by Step

#### Step 1: Identifikasi OS

```bash
# Volatility 3 (auto-detect):
$ vol -f memory.dmp windows.info
# atau
$ vol -f memory.dmp linux.info
$ vol -f memory.dmp mac.info

# Volatility 2:
$ vol.py -f memory.dmp imageinfo
# Output:
# Suggested Profile(s): Win7SP1x64, Win7SP0x64, Win2008R2SP0x64
# → Gunakan profile pertama (paling likely)
```

#### Step 2: List Proses yang Berjalan

```bash
# ═══ Volatility 3 ═══
$ vol -f memory.dmp windows.pslist
# Output: PID, PPID, nama proses, waktu start
#  PID   PPID  Name              CreateTime
#  4     0     System            2026-01-15 10:00:00
#  344   4     smss.exe
#  492   344   csrss.exe
#  2184  1456  cmd.exe           ← Command prompt!
#  3456  2184  suspicious.exe    ← Mencurigakan!
#  4012  1456  firefox.exe       ← Browser

# ═══ Proses tree (parent-child relationship) ═══
$ vol -f memory.dmp windows.pstree
# Menunjukkan hirarki proses:
# System
# └── smss.exe
#     └── csrss.exe
#     └── explorer.exe
#         └── cmd.exe
#             └── suspicious.exe    ← dijalankan dari cmd!

# ═══ Hidden processes ═══
$ vol -f memory.dmp windows.psscan
# psscan menemukan proses yang DISEMBUNYIKAN dari pslist
# Bandingkan output pslist vs psscan → yang ada di psscan tapi
# tidak di pslist = proses tersembunyi (rootkit!)

# ═══ Volatility 2 ═══
$ vol.py --profile=Win7SP1x64 -f memory.dmp pslist
$ vol.py --profile=Win7SP1x64 -f memory.dmp pstree
$ vol.py --profile=Win7SP1x64 -f memory.dmp psscan
```

#### Step 3: Cari Command History

```bash
# ═══ Command-line arguments ═══
$ vol -f memory.dmp windows.cmdline
# Output:
#  PID   Process        Args
#  2184  cmd.exe        cmd.exe
#  3456  suspicious.exe suspicious.exe -decrypt flag.enc -key s3cr3t
#                       ← KEY DAN FILE TERLIHAT!

# ═══ Console history (cmd.exe history) ═══
$ vol -f memory.dmp windows.consoles
# Menunjukkan SELURUH perintah yang diketik di cmd.exe:
# > dir
# > type secret.txt
# > echo flag{memory_forensics_ftw}
# > del secret.txt
# ← semua command terlihat!

# Volatility 2:
$ vol.py --profile=Win7SP1x64 -f memory.dmp cmdscan
$ vol.py --profile=Win7SP1x64 -f memory.dmp consoles
```

#### Step 4: Network Connections

```bash
$ vol -f memory.dmp windows.netscan
# Output:
# Offset    Proto  Local Address     Foreign Address   State    PID
# 0x...     TCP    192.168.1.5:49152  10.10.10.10:4444 ESTABLISHED  3456
#                                                      ← Reverse shell!
# 0x...     TCP    192.168.1.5:80     0.0.0.0:0        LISTENING  

# Port 4444 dari proses suspicious.exe = reverse shell / C2 connection!

# Volatility 2:
$ vol.py --profile=Win7SP1x64 -f memory.dmp netscan
```

#### Step 5: Dump File/Proses dari Memory

```bash
# ═══ Dump executable dari proses ═══
$ vol -f memory.dmp windows.dumpfiles --pid 3456
# Output: file .exe di-dump ke current directory
# Sekarang bisa analisis suspicious.exe di Ghidra/VirusTotal!

# ═══ Dump spesifik proses memory ═══
$ vol -f memory.dmp windows.memmap --pid 3456 --dump
# Dump seluruh memory space proses → cari strings di dalamnya

# ═══ Dump DLL yang diload ═══
$ vol -f memory.dmp windows.dlllist --pid 3456
# List semua DLL → cari yang mencurigakan (injected DLL?)

# Volatility 2:
$ vol.py --profile=Win7SP1x64 -f memory.dmp procdump -p 3456 -D output/
$ vol.py --profile=Win7SP1x64 -f memory.dmp memdump -p 3456 -D output/
```

#### Step 6: Registry dari Memory

```bash
$ vol -f memory.dmp windows.registry.printkey
# List registry keys yang ada di memory

$ vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
# Cari auto-run programs (persistence mechanism)

# Dump password hashes:
$ vol -f memory.dmp windows.hashdump
# Output: username:RID:LM_hash:NT_hash
# Crack hash dengan: hashcat -m 1000 hash.txt rockyou.txt

# Volatility 2:
$ vol.py --profile=Win7SP1x64 -f memory.dmp printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
$ vol.py --profile=Win7SP1x64 -f memory.dmp hashdump
```

#### Step 7: Cari Strings & Flag

```bash
# Dump strings dari seluruh memory:
$ strings memory.dmp > all_strings.txt
$ grep -i "flag{" all_strings.txt
$ grep -i "password\|secret\|key\|credential" all_strings.txt

# Strings dari proses spesifik:
$ vol -f memory.dmp windows.memmap --pid 3456 --dump
$ strings pid.3456.dmp | grep -i "flag"

# Cari file di memory:
$ vol -f memory.dmp windows.filescan | grep -i "flag\|secret\|key"
# Output: offset dan nama file → dump file tersebut
$ vol -f memory.dmp windows.dumpfiles --virtaddr 0x.... 
```

### Volatility Plugins Penting — Reference

```bash
# ═══ WINDOWS ═══
windows.info          # OS information
windows.pslist        # running processes
windows.pstree        # process tree
windows.psscan        # scan for hidden processes
windows.cmdline       # process command line args
windows.consoles      # console history
windows.netscan       # network connections
windows.filescan      # scan for files in memory
windows.dumpfiles     # dump files from memory
windows.memmap        # dump process memory
windows.dlllist       # list loaded DLLs
windows.handles       # list handles (files, registry, etc.)
windows.registry.printkey    # registry keys
windows.registry.hivelist    # list registry hives
windows.hashdump      # dump password hashes
windows.clipboard     # clipboard contents (vol2 only currently)
windows.screenshot    # take screenshot from memory (vol2)
windows.malfind       # find injected code / malware

# ═══ LINUX ═══
linux.pslist          # running processes
linux.pstree          # process tree
linux.bash            # bash command history
linux.check_afinfo    # network connections
linux.lsof            # open files
linux.proc.maps       # process memory maps
linux.tty_check       # terminal data
```

---

# Bagian 10: Malware Analysis

## Apa itu Malware Analysis di CTF?

Di CTF, malware analysis biasanya berupa:
- File mencurigakan yang perlu dianalisis **perilakunya**
- Script obfuscated (PowerShell, VBA, JavaScript)
- Document berbahaya (DOCX, XLSX, PDF dengan macro)
- Binary yang melakukan sesuatu tersembunyi

> **⚠️ PENTING**: Selalu analisis malware di **environment terisolasi** (VM/sandbox)! JANGAN di komputer asli.

## Tipe 1: Static Malware Analysis

### Analisis Awal

```bash
# ═══ IDENTIFIKASI ═══
$ file malware_sample
$ strings malware_sample | head -50
$ strings malware_sample | grep -i "http\|url\|cmd\|powershell\|exec\|shell"

# ═══ HASH — cek apakah malware sudah dikenal ═══
$ md5sum malware_sample
$ sha256sum malware_sample
# Upload hash ke: https://www.virustotal.com/
# Jika sudah dikenal → baca report → mungkin ada flag di report/strings

# ═══ IMPORT TABLE — fungsi yang dipanggil ═══
$ objdump -p malware_sample | grep -A 100 "IMPORT"
# Fungsi mencurigakan:
# - CreateRemoteThread    → inject ke proses lain
# - VirtualAllocEx        → allocate memory di proses lain
# - URLDownloadToFile     → download file dari internet
# - WinExec / ShellExecute → jalankan command
# - RegSetValue           → modifikasi registry
# - InternetOpen          → HTTP connection
```

### Analisis Office Documents (DOCX, XLSX, PPTX)

```bash
# Office .docx/.xlsx = ZIP file yang berisi XML
$ unzip malicious.docx -d extracted/
$ ls extracted/
# [Content_Types].xml  _rels/  docProps/  word/

# ═══ CARI MACRO VBA ═══
$ pip3 install oletools

# Scan untuk macro:
$ olevba malicious.docm
# Output menunjukkan:
# - Macro code (VBA) yang embedded
# - Suspicious keywords: Shell, Exec, PowerShell, Download
# - Strings: URLs, encoded data
# - IOCs (Indicators of Compromise)

# ═══ DECODE OBFUSCATED VBA ═══
# VBA macro sering obfuscated. Contoh:
#   Dim x As String
#   x = Chr(102) & Chr(108) & Chr(97) & Chr(103)    ← "flag"!
# Jalankan decode:
$ python3 -c "print(chr(102)+chr(108)+chr(97)+chr(103))"
# flag

# ═══ ANALISIS OLE OBJECTS ═══
$ oleobj malicious.docx          # extract OLE objects
$ rtfobj malicious.rtf           # extract dari RTF
```

### Analisis PDF

```bash
# ═══ SCAN PDF ═══
$ pip3 install peepdf
$ python3 -m peepdf.peepdf malicious.pdf -i

# Atau:
$ pdfid.py malicious.pdf
# Cari:
# /JavaScript    → kode JavaScript embedded
# /OpenAction    → auto-execute saat buka
# /AA            → additional actions
# /Launch        → launch external program
# /EmbeddedFile  → file yang tersembunyi

# ═══ EXTRACT JAVASCRIPT DARI PDF ═══
$ pdf-parser.py -w malicious.pdf          # parse objects
$ pdf-parser.py --object 5 malicious.pdf  # lihat object #5
# JavaScript mungkin obfuscated → decode di CyberChef
```

### Analisis PowerShell Script

```bash
# PowerShell malware sering obfuscated. Pattern umum:

# Layer 1: Base64 encoded
# powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
$ echo "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==" | base64 -d
# Invoke-WebRequest  ← decoded!

# Layer 2: Character concatenation
# $a = 'fl' + 'ag' + '{' + 'ps' + '1' + '}'
# → flag{ps1}

# Layer 3: Replace obfuscation  
# "fXXlXXaXXg" -replace 'XX',''
# → flag

# Layer 4: Compressed + encoded
# Decompress: [System.IO.StreamReader]::new([System.IO.Compression.GZipStream]...)
# Decode step by step → CyberChef sangat membantu!
```

## Tipe 2: Dynamic Malware Analysis

### Sandbox Analysis (Aman)

```
Upload ke sandbox online (GRATIS!):
1. VirusTotal       → https://www.virustotal.com/ (file analysis)
2. Hybrid Analysis  → https://www.hybrid-analysis.com/ (behavioral analysis)
3. Any.Run          → https://any.run/ (interactive sandbox)
4. Joe Sandbox      → https://www.joesandbox.com/

Sandbox menunjukkan:
- File yang dibuat/dimodifikasi/dihapus
- Registry yang diubah  
- Network connections (URLs, IPs, DNS)
- Process yang dibuat
- Screenshot aktivitas
- Extracted strings & IOCs
```

### Analisis dengan YARA Rules

```bash
# YARA = pattern matching tool khusus malware

# Install
sudo apt install yara

# Buat rule:
cat > flag_finder.yar << 'EOF'
rule FindFlag {
    strings:
        $flag1 = "flag{" nocase
        $flag2 = "CTF{" nocase
        $b64 = /[A-Za-z0-9+\/]{20,}={0,2}/ 
    condition:
        any of ($flag*) or $b64
}
EOF

# Scan:
$ yara flag_finder.yar malware_sample
# Output: FindFlag malware_sample    ← match!
```

---

# Bagian 11: Walkthrough Soal CTF Forensics

## Contoh 1: Hidden in Image (Level: Easy)

```
Soal: File "mystery.png" — temukan flag.

═══ STEP 1: Recon ═══
$ file mystery.png
mystery.png: PNG image data, 800 x 600, 8-bit/color RGBA

$ exiftool mystery.png
Comment: Nothing here...
Author: admin

$ strings mystery.png | grep -i flag
flag{strings_are_underrated}     ← DONE!

FLAG: flag{strings_are_underrated}
Waktu: 10 detik
```

## Contoh 2: File dalam File (Level: Easy)

```
Soal: File "photo.jpg" — temukan flag.

═══ STEP 1: Recon ═══
$ strings photo.jpg | grep flag     → tidak ada

═══ STEP 2: binwalk ═══
$ binwalk photo.jpg
DECIMAL       HEX           DESCRIPTION
0             0x0           JPEG image
245760        0x3C000       Zip archive data
246200        0x3C1A8       End of Zip archive

═══ STEP 3: Extract ═══
$ binwalk -e photo.jpg
$ ls _photo.jpg.extracted/
3C000.zip

$ unzip _photo.jpg.extracted/3C000.zip
Archive: 3C000.zip
  inflating: flag.txt

$ cat flag.txt
flag{binwalk_revealed_the_truth}

FLAG: flag{binwalk_revealed_the_truth}
```

## Contoh 3: PCAP Analysis (Level: Medium)

```
Soal: File "traffic.pcap" — temukan flag.

═══ STEP 1: Buka di Wireshark ═══
File → Open → traffic.pcap
Statistics → Protocol Hierarchy
  → HTTP: 45%
  → TCP: 30%
  → DNS: 25%

═══ STEP 2: Cek HTTP ═══
Filter: http
Terlihat beberapa request ke /login, /upload, /download

Filter: http.request.method == "POST"
Paket: POST /login HTTP/1.1
  → Follow TCP Stream
  → username=admin&password=p4ssw0rd123

Filter: http contains "flag"
Paket: GET /secret/flag.txt
  → Follow TCP Stream
  → Response body: flag{pcap_analysis_101}

FLAG: flag{pcap_analysis_101}
```

## Contoh 4: Memory Dump (Level: Medium-Hard)

```
Soal: File "evidence.dmp" — temukan flag.

═══ STEP 1: Identifikasi OS ═══
$ vol -f evidence.dmp windows.info
# Windows 10 x64

═══ STEP 2: List proses ═══
$ vol -f evidence.dmp windows.pslist
#  PID   Name             CreateTime
#  1234  notepad.exe      2026-01-15 14:30:00
#  5678  cmd.exe          2026-01-15 14:28:00
#  9012  firefox.exe      2026-01-15 14:25:00

═══ STEP 3: Command history ═══
$ vol -f evidence.dmp windows.cmdline
#  PID   Name       Args
#  5678  cmd.exe    cmd.exe
#  1234  notepad.exe notepad.exe C:\Users\admin\secret.txt

═══ STEP 4: Cari file ═══
$ vol -f evidence.dmp windows.filescan | grep "secret"
# 0x... secret.txt

$ vol -f evidence.dmp windows.dumpfiles --virtaddr 0x...
# File di-dump!

$ cat file.0x....dat
flag{volatility_is_powerful}

FLAG: flag{volatility_is_powerful}
```

## Contoh 5: Registry + Deleted Files (Level: Hard)

```
Soal: Disk image "suspect.dd" — temukan flag.

═══ STEP 1: Mount image ═══
$ sudo mount -o ro,loop suspect.dd /mnt/evidence/

═══ STEP 2: Browser history ═══
$ sqlite3 "/mnt/evidence/Users/suspect/AppData/Local/Google/Chrome/User Data/Default/History"
sqlite> SELECT url, title FROM urls WHERE url LIKE '%pastebin%';
# https://pastebin.com/raw/abc123 → "Encrypted Flag"

═══ STEP 3: Bash/CMD history ═══
$ cat /mnt/evidence/Users/suspect/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt
# openssl enc -aes-256-cbc -d -in flag.enc -out flag.txt -pass pass:s3cr3tK3y
# del flag.txt

═══ STEP 4: Recover deleted file ═══
$ fls -r suspect.dd | grep "flag"
# r/r * 12345: Users/suspect/Desktop/flag.enc   ← DIHAPUS ← recover!
$ icat suspect.dd 12345 > flag.enc

═══ STEP 5: Decrypt ═══
$ openssl enc -aes-256-cbc -d -in flag.enc -out flag.txt -pass pass:s3cr3tK3y
$ cat flag.txt
flag{digital_detective}
```

---

# Bagian 12: Tempat Latihan & Resources

## Platform Latihan

| Platform | URL | Kategori | Level |
|----------|-----|----------|-------|
| **picoCTF** | https://picoctf.org/ | Forensics | Pemula |
| **CyberDefenders** | https://cyberdefenders.org/ | DFIR | Menengah |
| **MemLabs** | https://github.com/stuxnet999/MemLabs | Memory | Pemula-Menengah |
| **DFRWS** | https://dfrws.org/forensic-challenges | All Forensics | Menengah-Sulit |
| **CTFlearn** | https://ctflearn.com/ | Mixed | Pemula |
| **root-me** | https://root-me.org/ | Forensics | Semua |
| **Blue Team Labs** | https://blueteamlabs.online/ | DFIR | Menengah |
| **HackTheBox** | https://hackthebox.com/ | Forensics | Menengah |
| **TryHackMe** | https://tryhackme.com/ | Guided Labs | Pemula |

## Path Belajar

```
MINGGU 1-2: Fondasi
├── Pahami file signatures, hex, encoding
├── Install tools (binwalk, Wireshark, exiftool)
├── Latihan:
│   ├── picoCTF Forensics easy
│   └── Coba CyberChef untuk encode/decode
└── Target: bisa identifikasi tipe file dan extract embedded data

MINGGU 3-4: File Carving & Steganography
├── Kuasai binwalk, foremost, strings
├── Belajar steganography (steghide, zsteg)
├── Latihan:
│   ├── picoCTF Forensics medium
│   └── CTFlearn forensics challenges
└── Target: bisa extract file tersembunyi

MINGGU 5-6: Network Forensics
├── Kuasai Wireshark: filter, follow stream, export objects
├── Pelajari skenario: HTTP, FTP, DNS exfil
├── Latihan:
│   ├── CyberDefenders network challenges
│   └── Wireshark sample captures
└── Target: bisa analisis PCAP dan extract data

MINGGU 7-8: Memory & OS Forensics
├── Kuasai Volatility: pslist, cmdline, filescan, dumpfiles
├── Pelajari: Windows registry, browser forensics
├── Latihan:
│   ├── MemLabs (semua labs)
│   └── CyberDefenders DFIR challenges
└── Target: bisa analisis memory dump dan disk image

MINGGU 9-10: Malware Analysis
├── Analisis Office macros, PowerShell, scripts
├── Sandbox analysis
├── Latihan:
│   ├── Any.Run sampel malware
│   └── MalwareBazaar sample analysis
└── Target: bisa identifikasi IOC dan deobfuscate scripts
```

## Resources Belajar

```
Video:
- 13Cubed (YouTube) — Memory & DFIR forensics
- DFIRmadness — Forensics walkthroughs
- NetworkChuck — Wireshark tutorial
- John Hammond — CTF forensics walkthroughs

Buku:
- "The Art of Memory Forensics" — Volatility framework book
- "Network Forensics" — Sherri Davidoff
- "File System Forensic Analysis" — Brian Carrier (sleuthkit author)

Cheat Sheets:
- SANS DFIR Cheat Sheets — https://www.sans.org/posters/
- Volatility Cheat Sheet — https://book.hacktricks.xyz/forensics/volatility
```

---

# Bagian 13: Cheat Sheet & Quick Reference

## Workflow Universal

```
┌──────────────────────────────────────────┐
│          DAPAT FILE CHALLENGE             │
└────────────────┬─────────────────────────┘
                 ▼
┌──────────────────────────────────────────┐
│  file → xxd → exiftool → strings         │
│  → binwalk                                │
└────────────────┬─────────────────────────┘
                 ▼
    ┌────────────┼────────────┬─────────────┐
    ▼            ▼            ▼             ▼
 Gambar       PCAP        Disk/Memory    Document
 ┌──────┐   ┌──────┐    ┌──────────┐   ┌────────┐
 │exif  │   │Wire  │    │Volatility│   │oletools│
 │steg  │   │shark │    │Sleuthkit │   │pdfid   │
 │binwlk│   │tshark│    │Autopsy   │   │unzip   │
 └──┬───┘   └──┬───┘    └────┬─────┘   └───┬────┘
    └───────────┴─────────────┴─────────────┘
                           ▼
                      FLAG! 🏴
```

## Command Cheat Sheet

```bash
# ══════════ IDENTIFIKASI ══════════
file challenge                        # tipe file
xxd challenge | head                  # hex bytes
exiftool challenge                    # metadata
strings challenge | grep flag         # strings
binwalk challenge                     # embedded files
binwalk -e challenge                  # extract

# ══════════ FILE CARVING ══════════
foremost -i challenge                 # carve semua tipe
dd if=file of=out bs=1 skip=X count=Y # manual extract
scalpel -o output/ challenge          # alternatif foremost

# ══════════ NETWORK ══════════
wireshark capture.pcap                # GUI analysis
tshark -r capture.pcap -Y 'http'     # CLI filter
tshark -r capture.pcap --export-objects "http,output/"  # export files
tshark -r capture.pcap -Y 'frame contains "flag"'      # cari flag

# ══════════ MEMORY ══════════
vol -f mem.dmp windows.info           # OS info
vol -f mem.dmp windows.pslist         # processes
vol -f mem.dmp windows.pstree         # process tree
vol -f mem.dmp windows.cmdline        # command lines
vol -f mem.dmp windows.netscan        # network
vol -f mem.dmp windows.filescan       # files in memory
vol -f mem.dmp windows.dumpfiles --pid X  # dump files
vol -f mem.dmp windows.hashdump       # password hashes
strings mem.dmp | grep "flag{"        # brute search

# ══════════ DISK/OS ══════════
sudo mount -o ro,loop disk.dd /mnt/   # mount image
fls -r disk.dd                        # list files (incl. deleted)
icat disk.dd <inode>                  # recover file
sqlite3 History < query.sql           # browser history
regripper -r NTUSER.DAT -p all        # Windows registry

# ══════════ MALWARE ══════════
olevba malicious.docm                 # extract VBA macros
pdfid.py malicious.pdf                # scan PDF
yara rules.yar sample                 # pattern matching
```

## Encoding Quick Decode

```bash
# Base64
echo "ZmxhZ3t0ZXN0fQ==" | base64 -d          # flag{test}

# Hex
echo "666c61677b746573747d" | xxd -r -p        # flag{test}

# ROT13
echo "synt{grfg}" | tr 'a-zA-Z' 'n-za-mN-ZA-M'  # flag{test}

# URL encode
python3 -c "import urllib.parse; print(urllib.parse.unquote('flag%7Btest%7D'))"

# Binary
python3 -c "print(''.join(chr(int(b,2)) for b in '01100110 01101100 01100001 01100111'.split()))"

# Atau gunakan CyberChef untuk SEMUA encoding!
# https://gchq.github.io/CyberChef/
# Fitur "Magic" auto-detect encoding!
```

## Wireshark Filter Cheat Sheet

```
http                         → hanya HTTP
tcp.port == 80               → port 80
ip.addr == 192.168.1.5       → IP tertentu
frame contains "flag"        → cari string di semua paket
http.request.method == POST  → HTTP POST
dns                          → DNS queries
ftp                          → FTP control
ftp-data                     → FTP data transfer
tcp.flags.syn == 1           → SYN packets
http.response.code == 200    → HTTP 200 OK
!(arp || dns || icmp)        → filter noise umum
```

## Volatility Plugin Cheat Sheet

```
windows.pslist    → proses yang berjalan
windows.pstree    → tree view proses
windows.psscan    → scan hidden processes  
windows.cmdline   → command line arguments
windows.consoles  → cmd.exe history
windows.netscan   → network connections
windows.filescan  → files in memory
windows.dumpfiles → dump files
windows.hashdump  → password hashes
windows.malfind   → detect injected code
windows.registry.printkey → registry
```

---

> **🎉 Selamat!** Kamu sudah membaca panduan lengkap Digital Forensics CTF.
> 
> **Langkah selanjutnya:**
> 1. Install tools (Bagian 1)
> 2. Mulai dari **picoCTF** → kategori Forensics
> 3. Lanjut ke **MemLabs** untuk memory forensics
> 4. Ikut CTF online (cek jadwal di https://ctftime.org/)
> 
> **Tip terpenting:** Di forensics, **SELALU coba `strings` dan `binwalk` terlebih dahulu** — banyak flag yang bisa ditemukan hanya dengan 2 command ini! 🔍
