# 🛠️ CTF Digital Forensics — Tools Reference Guide

Panduan lengkap instalasi & penggunaan setiap tool untuk CTF Digital Forensics.

---

## Daftar Isi

1. [File Analysis & Identification](#1-file-analysis--identification)
2. [File Carving & Recovery](#2-file-carving--recovery)
3. [Network Forensics](#3-network-forensics)
4. [Disk & Filesystem Forensics](#4-disk--filesystem-forensics)
5. [Memory Forensics](#5-memory-forensics)
6. [Browser & App Forensics](#6-browser--app-forensics)
7. [Malware Analysis](#7-malware-analysis)
8. [Steganography](#8-steganography)
9. [Encoding, Decoding & Crypto](#9-encoding-decoding--crypto)
10. [Hex Editors](#10-hex-editors)
11. [Tool Selection Cheat Sheet](#-tool-selection-cheat-sheet)

---

## 1. File Analysis & Identification

---

### 🔷 file

**Apa itu**: Identifikasi tipe file berdasarkan magic bytes (header), bukan extension.

```bash
# Sudah terinstall di Linux/macOS/WSL

# Penggunaan
$ file mystery
mystery: PNG image data, 800 x 600, 8-bit/color RGBA

$ file strange.pdf
strange.pdf: Zip archive data    # ← Extension tipu-tipu! Sebenarnya ZIP

$ file *                         # scan semua file di folder
$ file -i mystery                # tampilkan MIME type
mystery: image/png; charset=binary

$ file -z archive.gz             # lihat tipe file DI DALAM arsip
```

---

### 🔷 exiftool

**Apa itu**: Membaca, menulis, dan mengedit metadata dari hampir semua tipe file (EXIF, IPTC, XMP, dll.)

**Instalasi:**
```bash
sudo apt install libimage-exiftool-perl
# Windows: download dari https://exiftool.org/
```

**Penggunaan:**
```bash
# Lihat SEMUA metadata
$ exiftool photo.jpg
File Name                       : photo.jpg
File Size                       : 2.5 MB
File Type                       : JPEG
Image Width                     : 1920
Image Height                    : 1080
Camera Model Name               : Canon EOS R5
GPS Latitude                    : 40 deg 42' 46.08" N
GPS Longitude                   : 74 deg 0' 21.60" W
Create Date                     : 2026:01:15 14:30:22
Comment                         : flag{check_your_exif}    ← FLAG!

# Metadata spesifik
$ exiftool -Comment photo.jpg           # hanya field Comment
$ exiftool -GPSLatitude photo.jpg       # hanya GPS Latitude
$ exiftool -Author document.pdf

# Scan multiple files
$ exiftool -r ./folder/                 # recursive scan folder
$ exiftool -r -ext jpg ./              # hanya scan .jpg

# Lihat metadata LENGKAP (termasuk binary data)
$ exiftool -v3 photo.jpg              # very verbose

# HAPUS semua metadata (berguna untuk CTF juga)
$ exiftool -all= photo.jpg            # strip semua metadata
```

**Tips CTF:**
```bash
# Flag sering tersembunyi di field-field ini:
$ exiftool photo.jpg | grep -i "comment\|author\|description\|subject\|title\|creator\|copyright"

# Cek GPS → mungkin flag berupa koordinat/lokasi
$ exiftool -GPS* photo.jpg
```

---

### 🔷 xxd

**Apa itu**: Hex dump tool — menampilkan isi file dalam format hexadecimal.

```bash
# Sudah terinstall di Linux (bagian dari vim)

# Lihat hex dump
$ xxd challenge_file | head -20       # 20 baris pertama
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR

# Lihat N bytes pertama
$ xxd -l 32 challenge_file            # hanya 32 bytes pertama

# Mulai dari offset tertentu
$ xxd -s 0x1000 -l 64 challenge_file  # 64 bytes dari offset 0x1000

# Hanya hex tanpa ASCII
$ xxd -p challenge_file               # plain hex output

# Convert hex string kembali ke binary
$ echo "666c61677b746573747d" | xxd -r -p
flag{test}

# Convert file hex ke binary
$ xxd -r hex_dump.txt > binary_file
```

---

### 🔷 pngcheck

**Apa itu**: Verifikasi integritas file PNG. Mendeteksi chunk yang rusak/dimodifikasi.

```bash
sudo apt install pngcheck

$ pngcheck -v image.png
# Menampilkan semua PNG chunks:
# IHDR (header), IDAT (data), IEND (end), tEXt (text), etc.

# Jika ada error:
# → chunk CRC salah → mungkin dimensi gambar diubah!
# → Perbaiki dimensi di IHDR → render ulang → flag tersembunyi!

$ pngcheck -c image.png          # print Chrome sRGB warning
$ pngcheck -t image.png          # print text chunks
```

**Tips CTF — Fix PNG Dimensions:**
```python
# Sering di CTF: dimensi PNG diubah untuk menyembunyikan bagian gambar
# pngcheck menunjukkan CRC error → fix lebar/tinggi

import struct, zlib

with open('corrupted.png', 'rb') as f:
    data = bytearray(f.read())

# IHDR chunk dimulai di byte 16 (setelah 8-byte signature + 4-byte length + 4-byte type)
# Width: bytes 16-19, Height: bytes 20-23

# Brute-force height yang benar berdasarkan CRC
for height in range(1, 5000):
    # Ganti height
    data[20:24] = struct.pack('>I', height)
    # Hitung CRC dari IHDR chunk (type + data = 17 bytes)
    crc = zlib.crc32(data[12:29]) & 0xFFFFFFFF
    # Bandingkan dengan CRC yang tersimpan (bytes 29-32)
    stored_crc = struct.unpack('>I', data[29:33])[0]
    if crc == stored_crc:
        print(f"Correct height: {height}")
        with open('fixed.png', 'wb') as f:
            f.write(data)
        break
```

---

## 2. File Carving & Recovery

---

### 🔷 binwalk

**Apa itu**: Analisis firmware & file multi-layer. Mencari file signatures embedded di dalam file lain.

**Instalasi:**
```bash
sudo apt install binwalk
# Atau: pip3 install binwalk
```

**Penggunaan Lengkap:**
```bash
# ═══ SCAN — lihat apa yang ada ═══
$ binwalk challenge_file
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             PNG image, 800 x 600
153600        0x25800         Zip archive data
200000        0x30D40         JPEG image

# ═══ EXTRACT — keluarkan semua file ═══
$ binwalk -e challenge_file
$ ls _challenge_file.extracted/
25800.zip  30D40.jpg

# ═══ RECURSIVE EXTRACT ═══
$ binwalk -eM challenge_file    # extract file di dalam file di dalam file

# ═══ FORCE EXTRACT SEMUA ═══
$ binwalk --dd='.*' challenge_file

# ═══ ENTROPY ANALYSIS ═══
$ binwalk -E challenge_file
# Menampilkan grafik entropy
# Entropy tinggi = encrypted/compressed
# Entropy rendah = plaintext
# Berguna untuk identifikasi batas antar sections

# ═══ CARI RAW PATTERN ═══
$ binwalk -R "\x50\x4b\x03\x04" challenge_file    # cari ZIP header
$ binwalk -R "flag{" challenge_file                 # cari string

# ═══ OPCODE SCAN ═══
$ binwalk -A challenge_file    # scan instruction opcodes
```

---

### 🔷 foremost

**Apa itu**: File carver yang menggunakan header, footer, dan data structures untuk recover file.

**Instalasi:**
```bash
sudo apt install foremost
```

**Penggunaan:**
```bash
# Basic — carve semua tipe
$ foremost -i disk_image.dd
$ ls output/
audit.txt  jpg/  png/  zip/  pdf/  doc/  xls/

# Tipe spesifik
$ foremost -t jpg,png -i disk_image.dd           # hanya gambar
$ foremost -t zip,rar,7z -i disk_image.dd        # hanya arsip
$ foremost -t all -i disk_image.dd               # semua tipe
$ foremost -t pdf,doc,xls,ppt -i disk_image.dd   # dokumen

# Custom output directory
$ foremost -i disk_image.dd -o /tmp/carved/

# Verbose
$ foremost -v -i disk_image.dd

# Quick mode (hanya header, lebih cepat)
$ foremost -q -i disk_image.dd

# Baca audit.txt untuk summary
$ cat output/audit.txt
```

---

### 🔷 photorec

**Apa itu**: File recovery tool yang sangat powerful, bisa recover file dari disk image bahkan setelah di-format.

**Instalasi:**
```bash
sudo apt install testdisk    # photorec termasuk di paket testdisk
```

**Penggunaan:**
```bash
# Interactive mode (menu-driven)
$ photorec disk_image.dd
# 1. Pilih disk → Proceed
# 2. Pilih partition type (Intel jika tidak yakin)
# 3. Pilih partition
# 4. Pilih filesystem: ext4 / NTFS / FAT
# 5. Pilih scope: Free (hanya deleted) / Whole (semua)
# 6. Pilih output directory
# 7. Tekan C untuk start

# Non-interactive mode
$ photorec /d output_dir/ /cmd disk_image.dd partition_type,search

# Output files di: recup_dir.1/, recup_dir.2/, dll.
$ ls recup_dir.1/
f0000001.jpg  f0000002.png  f0000003.pdf  ...
```

---

### 🔷 sleuthkit (fls, icat, mmls, fsstat)

**Apa itu**: Collection tool CLI untuk analisis disk image dan file system.

**Instalasi:**
```bash
sudo apt install sleuthkit
```

**Penggunaan:**
```bash
# ═══ PARTITION INFO ═══
$ mmls disk_image.dd
#    Slot  Start       End         Length      Description
#    00    0000000000  0000000000  0000000001  Primary Table
#    01    0000002048  0000206847  0000204800  NTFS (0x07)
#    02    0000206848  0000999423  0000792576  Linux ext4 (0x83)

# ═══ FILESYSTEM INFO ═══
$ fsstat -o 2048 disk_image.dd    # -o = offset partition (dari mmls)

# ═══ LIST FILES (termasuk yang DIHAPUS!) ═══
$ fls -r disk_image.dd                    # semua file recursively
$ fls -r -o 2048 disk_image.dd            # dari partition tertentu
$ fls -r -d disk_image.dd                 # HANYA file yang dihapus!
# Output:
# r/r   5:   Documents/report.pdf
# r/r * 12:  Desktop/secret.txt          ← * = DIHAPUS tapi recoverable!

# ═══ RECOVER FILE ═══
$ icat disk_image.dd 12 > recovered_secret.txt
# 12 = inode number dari fls output
$ cat recovered_secret.txt
# flag{deleted_files_never_die}

# ═══ TIMELINE ═══
$ fls -m "/" -r disk_image.dd > bodyfile.txt
$ mactime -b bodyfile.txt -d > timeline.csv
# Timeline menunjukkan created/modified/accessed timestamps
```

---

### 🔷 Autopsy (GUI)

**Apa itu**: GUI forensics platform. Versi open-source dari forensics tools komersial.

**Instalasi:**
```bash
# Download: https://www.autopsy.com/download/
# Windows: installer .msi
# Linux: versi web-based

# Atau via package manager:
sudo apt install autopsy
```

**Penggunaan:**
```
1. Buka Autopsy → New Case
2. Add Data Source → pilih disk image
3. Tunggu analisis (bisa lama untuk image besar)
4. Browse:
   - File Views → By Extension → cari file menarik
   - Extracted Content → Web History, Email, dll.
   - Keyword Hits → jika search enabled (flag, password, dll.)
   - Deleted Files → file yang dihapus tapi masih recoverable
5. Export file yang menarik → analisis lebih lanjut
```

---

## 3. Network Forensics

---

### 🔷 Wireshark

**Apa itu**: Network packet analyzer paling populer. GUI untuk membuka dan menganalisis file PCAP/PCAPNG.

**Instalasi:**
```bash
sudo apt install wireshark
# Saat install: pilih "Yes" agar non-root bisa capture
# Tambahkan user ke group: sudo usermod -aG wireshark $USER

# Windows: download dari https://www.wireshark.org/
```

**Penggunaan Lengkap:**
```
═══ BUKA FILE ═══
File → Open → pilih .pcap / .pcapng

═══ INTERFACE ═══
┌─────────────────────────────────────────────────┐
│ Display Filter: [http.request.method == "POST"] │ ← Filter bar
├─────────────────────────────────────────────────┤
│ Packet List: daftar semua paket                  │
├─────────────────────────────────────────────────┤
│ Packet Details: detail layer-by-layer            │
├─────────────────────────────────────────────────┤
│ Packet Bytes: hex dump paket                     │
└─────────────────────────────────────────────────┘

═══ FILTER YANG WAJIB DIHAPAL ═══
http                                 # HTTP traffic
dns                                  # DNS queries
ftp                                  # FTP commands
ftp-data                             # FTP file transfers
tcp.port == 4444                     # suspicious port
ip.addr == 192.168.1.5               # specific IP  
frame contains "flag"                # string search ALL packets
http.request.method == "POST"        # HTTP POST (credentials!)
http.response.code == 200            # successful responses
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN scan detection
!(arp || dns || icmp)                # remove noise

═══ FOLLOW STREAM ═══
Klik kanan paket → Follow → TCP Stream
  → Menampilkan SELURUH percakapan client ↔ server
  → Bisa lihat: HTTP request/response, FTP transfer, plain text

═══ EXPORT FILES ═══
File → Export Objects → HTTP     # extract semua file dari HTTP
File → Export Objects → IMF      # extract email
File → Export Objects → SMB      # extract file dari SMB/CIFS
File → Export Objects → TFTP     # extract file dari TFTP

═══ STATISTICS ═══
Statistics → Protocol Hierarchy   # breakdown protokol
Statistics → Conversations        # siapa bicara dengan siapa
Statistics → Endpoints            # daftar semua host
Statistics → HTTP → Requests      # daftar semua HTTP request
Statistics → IO Graphs            # traffic over time

═══ COLORING RULES ═══
View → Coloring Rules
  → Warna berbeda untuk TCP errors, HTTP, DNS, dll.
  → Bisa custom: "flag" di payload → warna khusus

═══ TIPS CTF ═══
1. Pertama: Statistics → Protocol Hierarchy → overview
2. Cari plain-text credentials: http.request.method == POST
3. Cari file transfer: File → Export Objects
4. Cari data exfiltration: DNS query yang panjang/aneh
5. Cari reverse shell: tcp.port == 4444
6. Gunakan "frame contains" untuk brute-search strings
```

---

### 🔷 tshark

**Apa itu**: CLI version dari Wireshark. Lebih cepat untuk scripting dan batch processing.

**Instalasi:**
```bash
sudo apt install tshark
```

**Penggunaan:**
```bash
# ═══ BACA PCAP ═══
$ tshark -r capture.pcap                          # tampilkan semua paket
$ tshark -r capture.pcap -c 20                    # 20 paket pertama

# ═══ FILTER ═══
$ tshark -r capture.pcap -Y 'http'                # hanya HTTP
$ tshark -r capture.pcap -Y 'dns'                 # hanya DNS
$ tshark -r capture.pcap -Y 'frame contains "flag"'  # cari string
$ tshark -r capture.pcap -Y 'http.request.method == "POST"'

# ═══ EXTRACT FIELDS ═══
$ tshark -r capture.pcap -Y 'http' -T fields -e http.host -e http.request.uri
# Output: hostname dan URL path

$ tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name
# Output: semua DNS queries

# ═══ EXPORT FILES ═══
$ tshark -r capture.pcap --export-objects "http,output/"
# Semua HTTP files di-extract ke folder output/

# ═══ FOLLOW STREAM ═══
$ tshark -r capture.pcap -z follow,tcp,ascii,0    # follow TCP stream 0
$ tshark -r capture.pcap -z follow,tcp,raw,0      # raw hex data

# ═══ STATISTICS ═══
$ tshark -r capture.pcap -z io,stat,1             # IO stats per detik
$ tshark -r capture.pcap -z conv,tcp              # TCP conversations
$ tshark -r capture.pcap -z endpoints,ip          # IP endpoints

# ═══ DNS EXFILTRATION DETECTION ═══
$ tshark -r capture.pcap -Y 'dns.qry.name contains "."' -T fields -e dns.qry.name | sort -u
# Cari domain yang mencurigakan / subdomain yang aneh
```

---

### 🔷 NetworkMiner

**Apa itu**: Network forensics tool yang auto-extract files, images, messages, dan credentials dari PCAP.

**Instalasi:**
```bash
# Windows: download dari https://www.netresec.com/?page=NetworkMiner
# Linux: bisa via Mono

# Free version cukup untuk CTF!
```

**Penggunaan:**
```
1. File → Open → pilih PCAP
2. Tab yang berguna:
   - Hosts: semua host yang berkomunikasi
   - Files: SEMUA file yang berhasil di-extract (auto!)
   - Images: gambar yang di-transfer
   - Messages: chat/email yang terdeteksi
   - Credentials: username/password yang terdeteksi
   - Sessions: daftar koneksi
   - DNS: semua DNS queries
3. Klik file → Open → buka langsung!
```

---

### 🔷 scapy (Python)

**Apa itu**: Library Python untuk manipulasi paket jaringan. Scripting custom PCAP analysis.

```bash
pip3 install scapy
```

```python
from scapy.all import *

# Baca PCAP
packets = rdpcap("capture.pcap")

# Iterate semua paket
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
        if b"flag{" in payload:
            print(f"Found flag in packet: {payload}")

# Extract DNS queries
for pkt in packets:
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query
        query = pkt[DNS].qd.qname.decode()
        print(f"DNS Query: {query}")

# Extract HTTP data
for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load.decode(errors='ignore')
            if "POST" in data or "flag" in data.lower():
                print(data)

# Extract ICMP payload (ICMP tunneling)
icmp_data = b""
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        if pkt.haslayer(Raw):
            icmp_data += bytes(pkt[Raw])
print(f"ICMP data: {icmp_data}")
```

---

## 4. Disk & Filesystem Forensics

---

### 🔷 FTK Imager

**Apa itu**: Tool dari Exterro untuk membuat dan menganalisis disk image. Support E01, DD, AFF.

```
Download: https://www.exterro.com/ftk-imager (gratis, Windows only)

Penggunaan:
1. File → Add Evidence Item → Image File
2. Browse file system
3. Klik kanan file → Export Files (recover!)
4. Klik kanan deleted file → Export Files (recover deleted!)
5. Evidence Tree menunjukkan partisi, files, deleted files

Tips CTF:
- Cek $Recycle.Bin → file yang "dihapus"
- Cek Alternate Data Streams → data tersembunyi
- Export semua file → lalu search strings
```

---

### 🔷 regripper

**Apa itu**: Parser untuk Windows Registry hive files. Auto-extract informasi forensik.

**Instalasi:**
```bash
sudo apt install regripper
# Atau: https://github.com/keydet89/RegRipper3.0
```

**Penggunaan:**
```bash
# Parse dengan semua plugin
$ regripper -r NTUSER.DAT -p all > ntuser_report.txt
$ regripper -r SAM -p all > sam_report.txt
$ regripper -r SYSTEM -p all > system_report.txt
$ regripper -r SOFTWARE -p all > software_report.txt

# Plugin spesifik
$ regripper -r NTUSER.DAT -p userassist       # program yang dijalankan
$ regripper -r NTUSER.DAT -p recentdocs       # file yang dibuka
$ regripper -r NTUSER.DAT -p typedurls        # URL yang diketik di IE
$ regripper -r NTUSER.DAT -p runmru           # command di Run dialog
$ regripper -r SYSTEM -p usbstor              # USB device history
$ regripper -r SYSTEM -p timezone             # timezone setting
$ regripper -r SAM -p samparse                # user accounts + last login
$ regripper -r SOFTWARE -p uninstall          # installed software
$ regripper -r SOFTWARE -p networklist        # WiFi networks

# List semua plugin tersedia
$ regripper -l
```

---

### 🔷 Eric Zimmerman Tools (Windows)

**Apa itu**: Collection tools forensik Windows dari Eric Zimmerman. Sangat comprehensive.

```
Download: https://ericzimmerman.github.io/#!index.md

Tools penting:
├── MFTECmd.exe        → parse $MFT (Master File Table NTFS)
├── PECmd.exe          → parse Prefetch files
├── LECmd.exe          → parse LNK (shortcut) files
├── JLECmd.exe         → parse Jump Lists
├── SBECmd.exe         → parse ShellBags
├── RECmd.exe          → registry explorer
├── AmcacheParser.exe  → parse Amcache.hve
├── AppCompatCacheParser.exe → Shimcache
├── WxTCmd.exe         → parse Windows 10 Timeline
├── EvtxECmd.exe       → parse Event Logs
└── TimelineExplorer   → GUI viewer untuk CSV output
```

```powershell
# Contoh penggunaan (PowerShell):

# Parse Prefetch (program yang pernah berjalan)
PECmd.exe -d "C:\Windows\Prefetch" --csv output\ --csvf prefetch.csv

# Parse MFT (semua file di NTFS, termasuk timestamps)
MFTECmd.exe -f "$MFT" --csv output\ --csvf mft.csv

# Parse Event Logs  
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv output\

# Parse LNK files (accessed files history)
LECmd.exe -d "C:\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv output\

# Buka CSV results di TimelineExplorer untuk analisis
```

---

## 5. Memory Forensics

---

### 🔷 Volatility 3

**Apa itu**: Framework #1 untuk memory forensics. Menganalisis RAM dump.

**Instalasi:**
```bash
pip3 install volatility3

# Atau clone repo:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
```

**Penggunaan Lengkap:**
```bash
# ═══ OS IDENTIFICATION ═══
$ vol -f memory.dmp windows.info
$ vol -f memory.dmp linux.info
$ vol -f memory.dmp mac.info

# ═══ PROCESS ANALYSIS ═══
$ vol -f mem.dmp windows.pslist           # list proses
$ vol -f mem.dmp windows.pstree           # tree view
$ vol -f mem.dmp windows.psscan           # scan hidden proses
$ vol -f mem.dmp windows.cmdline          # command line arguments
$ vol -f mem.dmp windows.consoles         # cmd.exe input history

# ═══ NETWORK ═══
$ vol -f mem.dmp windows.netscan          # connections & listeners
$ vol -f mem.dmp windows.netstat          # active connections

# ═══ FILE ANALYSIS ═══
$ vol -f mem.dmp windows.filescan         # cari files in memory
$ vol -f mem.dmp windows.filescan | grep -i "flag\|secret\|password"
$ vol -f mem.dmp windows.dumpfiles --pid 1234     # dump files dari PID
$ vol -f mem.dmp windows.dumpfiles --virtaddr 0x... # dump file di address

# ═══ MALWARE DETECTION ═══
$ vol -f mem.dmp windows.malfind          # detect injected/hidden code
$ vol -f mem.dmp windows.dlllist --pid X  # DLLs loaded by process
$ vol -f mem.dmp windows.handles --pid X  # handles (files, reg, etc.)
$ vol -f mem.dmp windows.svcscan          # Windows services

# ═══ REGISTRY ═══
$ vol -f mem.dmp windows.registry.hivelist    # list hives in memory
$ vol -f mem.dmp windows.registry.printkey    # dump registry keys
$ vol -f mem.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# ═══ CREDENTIALS ═══
$ vol -f mem.dmp windows.hashdump         # dump NTLM hashes
$ vol -f mem.dmp windows.lsadump          # dump LSA secrets
$ vol -f mem.dmp windows.cachedump        # cached domain creds

# ═══ MISC ═══
$ vol -f mem.dmp windows.envars           # environment variables
$ vol -f mem.dmp windows.clipboard        # clipboard data (vol2-style)
$ vol -f mem.dmp windows.modules          # kernel modules

# ═══ PRO TIP: STRINGS ═══
$ strings mem.dmp | grep "flag{"          # brute-force string search
$ strings -e l mem.dmp | grep "flag{"     # Unicode strings juga!
```

---

### 🔷 Volatility 2 (Legacy)

**Apa itu**: Versi lama Volatility, masih berguna karena beberapa plugin belum di-port ke vol3.

**Instalasi:**
```bash
# Gunakan standalone:
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2 vol.py --info
```

**Penggunaan:**
```bash
# Butuh profile (beda dari vol3!)
$ python2 vol.py -f mem.dmp imageinfo
# Suggested Profile(s): Win7SP1x64

# Semua command butuh --profile
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp pslist
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp pstree
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp cmdscan
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp consoles
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp netscan
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp filescan
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp dumpfiles -Q 0x... -D output/
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp hashdump
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp clipboard
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp screenshot -D output/

# Plugin unik vol2 (belum ada di vol3):
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp clipboard      # clipboard
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp screenshot     # screenshots
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp mftparser      # MFT entries
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp timeliner      # timeline
$ python2 vol.py --profile=Win7SP1x64 -f mem.dmp iehistory      # IE history
```

---

## 6. Browser & App Forensics

---

### 🔷 sqlite3

**Apa itu**: CLI tool untuk membaca database SQLite. Browser data (history, cookies, bookmarks) disimpan di SQLite.

**Instalasi:**
```bash
sudo apt install sqlite3
# Windows: download dari https://www.sqlite.org/download.html
# Atau gunakan GUI: DB Browser for SQLite → https://sqlitebrowser.org/
```

**Penggunaan:**
```bash
$ sqlite3 History
# Masuk ke SQLite prompt

sqlite> .tables                      # list semua tabel
# downloads  keyword_search_terms  urls  visits  ...

sqlite> .schema urls                 # lihat schema tabel urls

sqlite> SELECT url, title, visit_count,
        datetime(last_visit_time/1000000-11644473600, 'unixepoch')
        FROM urls ORDER BY last_visit_time DESC LIMIT 20;
# Tampilkan 20 URL terakhir yang dikunjungi

sqlite> SELECT url, title FROM urls WHERE url LIKE '%flag%';
# Cari URL yang mengandung "flag"

sqlite> SELECT url, title FROM urls WHERE url LIKE '%pastebin%';
# Cari URL pastebin

# ═══ COOKIES ═══
$ sqlite3 Cookies
sqlite> SELECT host_key, name, value FROM cookies 
        WHERE value LIKE '%flag%';

# ═══ LOGIN DATA (passwords — encrypted!) ═══
$ sqlite3 "Login Data"
sqlite> SELECT origin_url, username_value, hex(password_value)
        FROM logins;

# ═══ FIREFOX (places.sqlite) ═══
$ sqlite3 places.sqlite
sqlite> SELECT url, title, visit_count FROM moz_places 
        ORDER BY last_visit_date DESC LIMIT 20;

# ═══ NON-INTERACTIVE (one-liner) ═══
$ sqlite3 History "SELECT url, title FROM urls WHERE url LIKE '%flag%'"
```

---

### 🔷 Hindsight (Chrome Analysis)

**Apa itu**: Otomatis parse semua Chrome/Edge data (history, cache, cookies, downloads, bookmarks, dll.)

```bash
pip3 install pyhindsight

$ hindsight -i "/path/to/Chrome/User Data/Default" -o report
# Output: file Excel + SQLite dengan SEMUA data terorganisir
```

---

### 🔷 firefox_decrypt

**Apa itu**: Decrypt saved passwords dari Firefox.

```bash
pip3 install firefox-decrypt

$ python3 -m firefox_decrypt "/path/to/firefox/profile/"
# Output: URL, username, password (decrypted!)
```

---

## 7. Malware Analysis

---

### 🔷 oletools

**Apa itu**: Collection tools untuk analisis malicious Office documents (DOC, DOCX, XLS, PPT).

**Instalasi:**
```bash
pip3 install oletools
```

**Penggunaan:**
```bash
# ═══ OLEVBA — Extract & Analyze VBA Macros ═══
$ olevba malicious.docm
# Output:
# - VBA source code
# - Suspicious keywords terdeteksi
# - IOCs (URLs, IPs, file paths)
# - Obfuscation indicators

$ olevba --decode malicious.docm     # auto-decode obfuscation
$ olevba --reveal malicious.docm     # reveal hidden content

# ═══ OLEID — Quick identification ═══
$ oleid malicious.doc
# Menunjukkan: ada VBA macro? encrypted? external links?

# ═══ OLEOBJ — Extract OLE objects ═══
$ oleobj malicious.docx
# Extract embedded objects (executables, scripts)

# ═══ RTFOBJ — Analyze RTF documents ═══
$ rtfobj malicious.rtf
# Extract OLE objects dari RTF

# ═══ MRAPTOR — Detect auto-execution ═══
$ mraptor malicious.docm
# Cek: apakah macro auto-execute? (AutoOpen, Document_Open, etc.)
```

---

### 🔷 YARA

**Apa itu**: Pattern matching tool untuk mengidentifikasi dan mengklasifikasi malware.

**Instalasi:**
```bash
sudo apt install yara
pip3 install yara-python
```

**Penggunaan:**
```bash
# ═══ BUAT RULE ═══
cat > my_rules.yar << 'EOF'
rule SuspiciousPowerShell {
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-encodedcommand" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "IEX" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        any of ($ps*) and $b64
}

rule FlagFinder {
    strings:
        $flag = /flag\{[^\}]+\}/
        $ctf = /CTF\{[^\}]+\}/
    condition:
        any of them
}
EOF

# ═══ SCAN ═══
$ yara my_rules.yar suspicious_file
# Output: SuspiciousPowerShell suspicious_file

# Scan folder
$ yara -r my_rules.yar /path/to/files/

# Scan dengan tags
$ yara -t malware my_rules.yar suspicious_file
```

---

### 🔷 VirusTotal (Online)

**Apa itu**: Platform online yang men-scan file dengan 70+ antivirus engines + behavioral analysis.

```
URL: https://www.virustotal.com/

Cara pakai:
1. Upload file (atau cari by hash)
2. Lihat:
   - Detection tab → berapa AV yang mendeteksi
   - Details tab → file metadata, imports, sections
   - Relations tab → related files, URLs, domains
   - Behavior tab → sandbox analysis (apa yang dilakukan saat dijalankan)
   - Community tab → comments (kadang ada flag/clue!)

Tips CTF:
- Cari by hash (MD5/SHA256) → mungkin sudah ada analisis
- Behavior tab SANGAT berguna → menunjukkan network activity, file creation
- Jangan upload file sensitif ke VT → diakses publik!
```

---

## 8. Steganography

---

### 🔷 steghide

**Apa itu**: Menyembunyikan dan mengextract data dari file JPEG/BMP/WAV/AU.

```bash
sudo apt install steghide

# Extract data tersembunyi
$ steghide extract -sf photo.jpg
Enter passphrase: [coba kosong dulu / password dari clue]
# Output: flag.txt

# Jika butuh password → brute force:
# Gunakan stegcracker
$ pip3 install stegcracker
$ stegcracker photo.jpg /usr/share/wordlists/rockyou.txt
```

---

### 🔷 zsteg

**Apa itu**: Deteksi steganography di file PNG dan BMP. Cek LSB dan berbagai encoding.

```bash
gem install zsteg

$ zsteg image.png
# Output:
# b1,r,lsb,xy    : text: "flag{lsb_stego}"    ← FLAG di LSB red channel!
# b1,rgb,lsb,xy  : text: "hidden message"
# ...
# zsteg mencoba BANYAK kombinasi otomatis

$ zsteg -a image.png           # coba SEMUA metode
$ zsteg -e "b1,r,lsb,xy" image.png > extracted.txt  # extract specific
```

---

### 🔷 stegoveritas

**Apa itu**: All-in-one steganography analysis tool. Mencoba banyak teknik otomatis.

```bash
pip3 install stegoveritas

$ stegoveritas photo.jpg
# Otomatis menjalankan:
# - exiftool (metadata)
# - binwalk (embedded files)
# - strings  
# - zsteg (LSB analysis, jika PNG)
# - Foremost (file carving)
# - Color plane analysis
# Output di folder: results/
```

---

### 🔷 AperiSolve (Online)

**Apa itu**: Platform online yang menjalankan BANYAK stego tools sekaligus.

```
URL: https://www.aperisolve.com/

Upload gambar → otomatis menjalankan:
- exiftool, binwalk, strings
- zsteg (PNG/BMP)
- steghide (JPEG)
- foremost
- Color plane separation (RGB, CMYK)
- Bit plane analysis

SANGAT BERGUNA untuk CTF → satu upload, banyak analisis!
```

---

## 9. Encoding, Decoding & Crypto

---

### 🔷 CyberChef

**Apa itu**: Swiss Army Knife untuk data transformation. Web-based, 300+ operasi.

```
URL: https://gchq.github.io/CyberChef/

Operasi paling berguna:
├── From/To Base64               # base64 encode/decode
├── From/To Hex                  # hex encode/decode
├── XOR / XOR Brute Force        # XOR decrypt
├── ROT13 / ROT47                # rotation cipher
├── URL Decode                   # decode URL encoding
├── From/To Binary               # binary encode/decode
├── Gunzip / Unzip               # dekompresi
├── AES/DES/3DES Decrypt         # symmetric decrypt
├── RSA Decrypt                  # asymmetric decrypt
├── Magic                        # AUTO-DETECT encoding!
├── Render Image                 # render raw bytes sebagai gambar
├── Extract URLs                 # extract URLs dari teks
├── Strings                      # extract strings dari binary
└── Entropy                      # hitung entropy

FITUR TERBAIK: "Magic" button
→ Auto-detect dan auto-decode encoding!
→ Bisa chain multiple operasi: Hex → Base64 → XOR → plaintext

Tips: Klik "Recipe" di kiri → drag operasi ke area recipe
→ Chain operasi secara visual
```

---

### 🔷 base64 (CLI)

```bash
# Decode
$ echo "ZmxhZ3t0ZXN0fQ==" | base64 -d
flag{test}

# Encode
$ echo "flag{test}" | base64
ZmxhZ3t0ZXN0fQ==

# Decode file
$ base64 -d encoded.txt > decoded.bin

# Encode file
$ base64 binary_file > encoded.txt
```

---

### 🔷 openssl

**Apa itu**: Toolkit kriptografi. Berguna untuk decrypt file yang di-encrypt dengan algoritma standar.

```bash
# ═══ DECRYPT FILE ═══
$ openssl enc -d -aes-256-cbc -in encrypted.bin -out decrypted.txt -pass pass:mypassword
$ openssl enc -d -des3 -in encrypted.bin -out decrypted.txt -k mykey

# ═══ HASH ═══
$ openssl md5 file               # MD5 hash
$ openssl sha256 file            # SHA256 hash

# ═══ CERTIFICATE ANALYSIS ═══
$ openssl x509 -in cert.pem -text -noout    # read certificate
$ openssl pkcs12 -in cert.pfx -out cert.pem # convert PFX to PEM
```

---

### 🔷 hashcat / john

**Apa itu**: Password hash cracker. Berguna untuk crack hash yang ditemukan di evidence.

```bash
# ═══ HASHCAT ═══
$ hashcat -m 0 hash.txt rockyou.txt          # MD5
$ hashcat -m 100 hash.txt rockyou.txt        # SHA1
$ hashcat -m 1000 hash.txt rockyou.txt       # NTLM (Windows)
$ hashcat -m 1800 hash.txt rockyou.txt       # sha512crypt (Linux)

# ═══ JOHN THE RIPPER ═══
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
$ john --show hash.txt    # tampilkan hasil crack
```

---

## 10. Hex Editors

---

### 🔷 HxD (Windows, Gratis)

```
Download: https://mh-nexus.de/en/hxd/

Fitur:
- View & edit hex + ASCII side by side
- Search: Ctrl+F (string/hex/regex)
- Replace: Ctrl+H
- Go to offset: Ctrl+G
- Compare files: Analysis → Data Comparison
- Statistics: Analysis → Statistics (byte frequency)
- Insert/delete bytes
- Very fast even for large files
```

---

### 🔷 ImHex (Cross-platform, Gratis)

```
Download: https://imhex.werwolv.net/

Fitur:
- Modern UI
- Pattern language (define struct untuk auto-parse)
- Built-in hash calculator
- Data processor (visual data transformation)  
- Bookmarks & highlights
- Diff view
```

---

## 11. Tambahan

---

### 🔷 bulk_extractor

**Apa itu**: Scan disk image / file besar untuk extract email, URLs, credit cards, coordinates, dan data forensik lainnya.

```bash
sudo apt install bulk-extractor

$ bulk_extractor -o output/ disk_image.dd
# Output files:
# email.txt      → extracted email addresses
# url.txt        → extracted URLs  
# domain.txt     → extracted domain names
# telephone.txt  → phone numbers
# ccn.txt        → credit card numbers
# ip.txt         → IP addresses
```

---

### 🔷 volatility-gui (VolWeb)

```
# Web GUI untuk Volatility:
# https://github.com/k1nd0ne/VolWeb
# Berguna jika lebih suka GUI daripada CLI
```

---

## 📊 Tool Selection Cheat Sheet

| Situasi | Tool Pertama | Tool Kedua |
|---------|-------------|------------|
| File tidak dikenali | `file` + `xxd` | `binwalk` |
| Cari metadata | `exiftool` | `strings` |
| File embedded / tersembunyi | `binwalk -e` | `foremost` |
| Gambar stego | AperiSolve / `zsteg` | `steghide` + `stegcracker` |
| PCAP analysis | Wireshark | `tshark` + `NetworkMiner` |
| Extract files dari PCAP | Wireshark Export Objects | `NetworkMiner` |
| DNS exfiltration | `tshark` filter dns | Python + scapy |
| Disk image | `fls` + `icat` | Autopsy / FTK Imager |
| Deleted files | `fls -d` + `icat` | `photorec` |
| Windows Registry | `regripper` | Eric Zimmerman's RECmd |
| Browser history | `sqlite3` | Hindsight |
| Memory dump | `vol -f X windows.pslist` | `strings` brute search |
| Process analysis | `windows.pstree` | `windows.cmdline` |
| Network in memory | `windows.netscan` | `windows.handles` |
| Password hashes | `windows.hashdump` | hashcat/john |
| Office malware | `olevba` | `oleobj` + `mraptor` |
| PDF malware | `pdfid.py` | `pdf-parser.py` |
| Encoding/decoding | CyberChef | Python one-liners |
| Encrypted file | `openssl` / CyberChef | Python pycryptodome |
| Malware identification | VirusTotal | YARA + strings |

---

> **💡 Untuk pemula**: mulai kuasai **5 tools ini** dulu:
> 1. **`file` + `strings` + `exiftool`** — identifikasi & quick wins
> 2. **`binwalk`** — extract file tersembunyi
> 3. **Wireshark** — network analysis
> 4. **Volatility** — memory forensics
> 5. **CyberChef** — decode segalanya
>
> Setelah nyaman, perluas ke foremost, regripper, oletools, dan stego tools.
