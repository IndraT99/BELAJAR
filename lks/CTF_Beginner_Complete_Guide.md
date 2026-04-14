# 🏴 CTF Reverse Engineering — Panduan Lengkap untuk Pemula

> Dokumen ini ditulis khusus untuk **pemula absolut** yang baru pertama kali belajar Reverse Engineering dan CTF.
> Setiap konsep dijelaskan dari nol, termasuk "kenapa" dan "bagaimana" di balik setiap langkah.

---

## Daftar Isi

- [Bagian 0: Fondasi — Apa itu CTF & Reverse Engineering?](#bagian-0-fondasi)
- [Bagian 1: Setup Environment dari Nol](#bagian-1-setup-environment-dari-nol)
- [Bagian 2: Langkah Pertama — Analisis Binary](#bagian-2-langkah-pertama--analisis-binary)
- [Bagian 3: Static Analysis — Membaca Binary Tanpa Menjalankan](#bagian-3-static-analysis)
- [Bagian 4: Dynamic Analysis — Debug Step by Step](#bagian-4-dynamic-analysis)
- [Bagian 5: Constraint Solving dengan Z3](#bagian-5-constraint-solving-dengan-z3)
- [Bagian 6: Anti-RE dan Cara Mengatasinya](#bagian-6-anti-re)
- [Bagian 7: Format File & Bytecode](#bagian-7-format-file--bytecode)
- [Bagian 8: Mengenali Bahasa Pemrograman dari Binary](#bagian-8-mengenali-bahasa-pemrograman)
- [Bagian 9: Arsitektur Prosesor untuk Pemula](#bagian-9-arsitektur-prosesor)
- [Bagian 10: Mobile Reverse Engineering](#bagian-10-mobile-reverse-engineering)
- [Bagian 11: Framework Khusus](#bagian-11-framework-khusus)
- [Bagian 12: Obfuscation & Binary Patching](#bagian-12-obfuscation--binary-patching)
- [Bagian 13: Walkthrough Soal CTF — Dari Awal Sampai Flag](#bagian-13-walkthrough-soal-ctf)
- [Bagian 14: Tempat Latihan & Resources](#bagian-14-tempat-latihan--resources)
- [Bagian 15: Cheat Sheet & Quick Reference](#bagian-15-cheat-sheet--quick-reference)

---

# Bagian 0: Fondasi

## Apa itu CTF?

**CTF (Capture The Flag)** adalah kompetisi keamanan siber di mana peserta harus menyelesaikan tantangan untuk menemukan "flag" — biasanya string dengan format seperti `flag{ini_adalah_flag}` atau `CTF{rahasia_tersembunyi}`.

### Jenis CTF:
- **Jeopardy**: Soal-soal individual dengan poin berbeda (yang kita bahas di sini)
- **Attack-Defense**: Tim menyerang & mempertahankan server
- **King of the Hill**: Rebut dan pertahankan mesin

### Kategori dalam CTF Jeopardy:
| Kategori | Deskripsi |
|----------|-----------|
| **Reverse Engineering (RE)** | Membongkar program untuk memahami cara kerjanya |
| **Pwn (Binary Exploitation)** | Mengeksploitasi kerentanan di program |
| **Web** | Menyerang kerentanan di aplikasi web |
| **Crypto** | Memecahkan kriptografi |
| **Forensics** | Menganalisis bukti digital |
| **Misc** | Soal lain-lain |

## Apa itu Reverse Engineering?

**Reverse Engineering (RE)** = memahami cara kerja sebuah program **tanpa** melihat source code aslinya.

Bayangkan kamu dapat sebuah **mesin** tanpa manual. RE adalah proses membongkar mesin tersebut, mempelajari setiap komponen, dan memahami cara kerjanya.

Dalam konteks CTF:
```
Kamu mendapat: binary (file .exe, ELF, APK, dll.)
Tujuan:        menemukan flag yang tersembunyi di dalamnya
Caranya:        bongkar dan pahami logika program
```

## Konsep Dasar yang WAJIB Dipahami

### 1. Apa itu Binary?

**Binary** = file yang berisi instruksi mesin (0 dan 1) yang bisa dijalankan oleh komputer.

Ketika programmer menulis code:
```
Source Code (C/Python/Java) → Compiler/Interpreter → Binary (machine code)
```

Contoh:
```c
// Source code (C) — BISA dibaca manusia
int main() {
    if (input == "password123") {
        printf("Flag: flag{easy_peasy}");
    }
    return 0;
}
```

Setelah di-compile, menjadi:
```
Binary — TIDAK bisa dibaca manusia langsung
55 48 89 e5 48 83 ec 10 c7 45 fc 00 00 00 00 ...
```

**Tugas kita**: mengubah binary kembali menjadi sesuatu yang bisa dipahami.

### 2. Apa itu Assembly?

**Assembly** = bahasa tingkat rendah yang paling dekat dengan machine code, tapi masih bisa dibaca manusia.

```nasm
; Contoh assembly x86_64 (Intel syntax)
mov eax, 5          ; simpan angka 5 ke register EAX
add eax, 3          ; tambahkan 3 ke EAX (sekarang EAX = 8)
cmp eax, 8          ; bandingkan EAX dengan 8
je  success         ; jika sama, lompat ke label "success"
```

Kamu **tidak perlu menghafal** semua instruksi assembly. Cukup pahami yang sering muncul:

| Instruksi | Arti | Analogi |
|-----------|------|---------|
| `mov a, b` | Copy nilai b ke a | `a = b` |
| `add a, b` | Tambahkan b ke a | `a = a + b` |
| `sub a, b` | Kurangi b dari a | `a = a - b` |
| `xor a, b` | XOR a dengan b | `a = a ^ b` |
| `cmp a, b` | Bandingkan a dan b | `if (a ? b)` |
| `test a, a` | Cek apakah a nol | `if (a == 0)` |
| `je label` | Jump if Equal | `if (==) goto label` |
| `jne label` | Jump if Not Equal | `if (!=) goto label` |
| `jg label` | Jump if Greater | `if (>) goto label` |
| `jl label` | Jump if Less | `if (<) goto label` |
| `jmp label` | Jump (selalu) | `goto label` |
| `call func` | Panggil fungsi | `func()` |
| `ret` | Kembali dari fungsi | `return` |
| `push val` | Taruh nilai ke stack | simpan sementara |
| `pop reg` | Ambil nilai dari stack | ambil kembali |
| `lea a, [b]` | Load alamat ke a | `a = &b` |
| `nop` | No Operation (tidak ngapa-ngapain) | skip |

### 3. Apa itu Register?

**Register** = "variabel" super cepat di dalam prosesor. Jumlahnya terbatas.

Bayangkan register sebagai **laci kecil** di meja kerja prosesor:

```
x86_64 Register (64-bit):
┌────────────────────────────────────────────────┐
│ RAX (64-bit)                                    │  ← Return value & accumulator
│ ├── EAX (32-bit bawah)                         │
│ │   ├── AX (16-bit bawah)                      │
│ │   │   ├── AH (8-bit atas) │ AL (8-bit bawah) │
│ │   │   └─────────────────────────────────────┘│
├────────────────────────────────────────────────┤
│ RBX, RCX, RDX        ← General purpose         │
│ RSI, RDI              ← Source/Destination       │
│ RSP                   ← Stack Pointer (puncak stack) │
│ RBP                   ← Base Pointer (dasar frame) │
│ RIP                   ← Instruction Pointer (instruksi berikutnya) │
│ R8-R15                ← Register tambahan       │
│ RFLAGS                ← Flags (hasil comparison) │
└────────────────────────────────────────────────┘
```

**Yang paling penting untuk CTF:**
- **RAX** → menyimpan return value fungsi (`return 0` berarti RAX = 0)
- **RDI, RSI, RDX, RCX** → menyimpan parameter fungsi ke-1, 2, 3, 4
- **RSP** → menunjuk ke puncak stack
- **RIP** → menunjuk ke instruksi yang akan dieksekusi berikutnya

### 4. Apa itu Stack?

**Stack** = area memori yang digunakan untuk menyimpan data sementara (variabel lokal, return address, parameter fungsi).

```
Bayangkan stack seperti tumpukan piring:
- PUSH = taruh piring baru di atas
- POP  = ambil piring paling atas

Alamat Tinggi
┌──────────────┐
│  ...         │
├──────────────┤
│  return addr │ ← alamat untuk kembali setelah fungsi selesai
├──────────────┤
│  saved RBP   │ ← frame pointer lama
├──────────────┤
│  var_local_1 │ ← variabel lokal pertama
├──────────────┤
│  var_local_2 │ ← variabel lokal kedua
├──────────────┤ ← RSP menunjuk ke sini (puncak stack)
│              │
Alamat Rendah
```

### 5. Apa itu Calling Convention?

Ketika fungsi `A` memanggil fungsi `B`, ada aturan tentang **di mana parameter disimpan** dan **siapa yang membersihkan stack**. Ini disebut **calling convention**.

```
Linux x86_64 (System V ABI):
- Parameter 1 → RDI
- Parameter 2 → RSI
- Parameter 3 → RDX
- Parameter 4 → RCX
- Parameter 5 → R8
- Parameter 6 → R9
- Parameter 7+ → di stack
- Return value → RAX

Contoh:
  strcmp(input, "secret")
  ↓
  RDI = pointer ke "input"
  RSI = pointer ke "secret"
  call strcmp
  ; hasil di RAX (0 = sama, bukan 0 = berbeda)
```

---

# Bagian 1: Setup Environment dari Nol

## Opsi 1: Windows + WSL (Recommended untuk pemula)

WSL (Windows Subsystem for Linux) memungkinkan kamu menjalankan Linux di dalam Windows.

### Langkah 1: Install WSL

```powershell
# Buka PowerShell sebagai Administrator, lalu jalankan:
wsl --install

# Restart komputer setelah selesai
# Saat pertama kali buka Ubuntu, buat username & password
```

### Langkah 2: Install Tools Dasar di WSL

```bash
# Update package manager
sudo apt update && sudo apt upgrade -y

# Install tools essential
sudo apt install -y build-essential    # gcc, make, dll.
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y git wget curl unzip
sudo apt install -y gdb                # debugger
sudo apt install -y file               # identifikasi file
sudo apt install -y binutils           # strings, objdump, readelf
sudo apt install -y ltrace strace      # tracing tools
sudo apt install -y binwalk            # extract embedded files
sudo apt install -y radare2            # disassembler CLI
sudo apt install -y default-jdk        # untuk Ghidra (butuh Java)

# Install Python tools
pip3 install pwntools                  # checksec, packing, networking
pip3 install z3-solver                 # constraint solver
pip3 install frida-tools               # dynamic instrumentation
pip3 install uncompyle6                # Python decompiler
```

### Langkah 3: Install Ghidra

```bash
# Download Ghidra (cek versi terbaru di https://ghidra-sre.org/)
cd ~
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip

# Extract
unzip ghidra_*.zip

# Jalankan (butuh GUI → gunakan dari Windows dengan XServer,
# atau langsung download Ghidra untuk Windows)
```

**Untuk Ghidra di Windows (lebih mudah):**
1. Download dari https://ghidra-sre.org/
2. Install Java JDK 17+ dari https://adoptium.net/
3. Extract Ghidra ZIP
4. Jalankan `ghidraRun.bat`

### Langkah 4: Install pwndbg (GDB Plugin)

```bash
# Di WSL/Linux:
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Sekarang setiap kali kamu menjalankan gdb, pwndbg otomatis aktif
# Test:
gdb --version
```

### Langkah 5: Install Tools Windows

Download dan install ini di Windows:
1. **x64dbg** — https://x64dbg.com/ (debugger Windows)
2. **HxD** — https://mh-nexus.de/en/hxd/ (hex editor)
3. **DIE (Detect It Easy)** — https://github.com/horsicq/Detect-It-Easy/releases
4. **dnSpy** — https://github.com/dnSpyEx/dnSpy/releases (untuk .NET)
5. **7-Zip** — https://7-zip.org/ (extract arsip)

### Langkah 6: Bookmark Penting

Buka di browser dan bookmark:
1. **CyberChef** — https://gchq.github.io/CyberChef/
2. **Compiler Explorer** — https://godbolt.org/ (lihat C → assembly)
3. **Online Disassembler** — https://onlinedisassembler.com/
4. **Decompiler Explorer** — https://dogbolt.org/ (multiple decompilers)
5. **Binary Ninja Cloud** — https://cloud.binary.ninja/ (disassembler gratis)

## Opsi 2: Virtual Machine (Alternatif)

Jika tidak mau pakai WSL, buat VM Linux:

```
1. Download VirtualBox: https://www.virtualbox.org/
2. Download Ubuntu ISO: https://ubuntu.com/download
3. Buat VM baru → pilih Ubuntu → allocate 4GB RAM, 40GB disk
4. Install Ubuntu di VM
5. Install semua tools dari Langkah 2-4 di atas
```

## Opsi 3: Kali Linux (Shortcut)

Kali Linux sudah include banyak tools RE:

```
1. Download Kali: https://www.kali.org/get-kali/
2. Bisa sebagai VM atau dual boot
3. Banyak tools sudah pre-installed
4. Tambahkan: pip3 install z3-solver angr
```

## Verifikasi Setup

Jalankan perintah berikut untuk memastikan semua terinstall:

```bash
# Cek satu per satu
file --version            # identifikasi file
strings --version         # extract strings dari binary
gdb --version             # debugger
python3 -c "import z3; print('Z3 OK')"
python3 -c "from pwn import *; print('pwntools OK')"
checksec --version        # cek proteksi binary
objdump --version         # disassembler CLI
radare2 -v                # framework RE

# Jika semua OK → kamu siap!
```

---

# Bagian 2: Langkah Pertama — Analisis Binary

## Metodologi: Selalu Mulai dari Sini!

Setiap kali kamu mendapat file challenge CTF, **SELALU** ikuti langkah ini:

```
Langkah 1: file → Apa tipe filenya?
Langkah 2: strings → Ada string menarik?
Langkah 3: checksec → Proteksi apa yang aktif?
Langkah 4: ltrace/strace → Apa yang dilakukan saat dijalankan?
Langkah 5: Baru buka di Ghidra/IDA/x64dbg
```

### Langkah 1: Identifikasi File

```bash
$ file challenge

# Kemungkinan output:
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
           dynamically linked, for GNU/Linux 3.2.0, not stripped
```

**Cara baca output:**
```
ELF              → format Linux executable
64-bit           → arsitektur 64-bit
LSB              → Little-endian (urutan byte)
executable       → bisa langsung dijalankan
x86-64           → arsitektur prosesor Intel/AMD 64-bit
dynamically linked → pakai shared library (libc, dll.)
not stripped     → nama fungsi MASIH ADA (lebih mudah di-RE!)
stripped         → nama fungsi DIHAPUS (lebih sulit)
```

**Tipe file lain yang mungkin muncul:**
```
PE32+ executable     → Windows .exe 64-bit
PE32 executable      → Windows .exe 32-bit
Mach-O 64-bit        → macOS/iOS binary
Java class data      → Java bytecode (.class)
python 3.8 byte-compiled → Python bytecode (.pyc)
gzip compressed      → file terkompres (extract dulu!)
data                 → tidak dikenali (mungkin encrypted/custom format)
```

### Langkah 2: Extract Strings

```bash
$ strings challenge | head -30        # lihat 30 strings pertama
$ strings challenge | grep -i flag    # cari string "flag" (case insensitive)
$ strings challenge | grep -i "pass\|key\|secret\|correct\|wrong\|yes\|no"

# Contoh output JACKPOT:
Enter the password:
Wrong password!
Correct! The flag is: flag{strings_are_useful}     ← LANGSUNG KETEMU!
```

**Kenapa ini penting?**
- Banyak challenge level mudah yang flagnya **langsung terlihat** dari strings
- Bahkan jika flag tidak langsung terlihat, strings memberikan petunjuk:
  - Nama fungsi: `checkPassword`, `validateKey`, `decrypt`
  - Pesan error: "Wrong!", "Try again", "Access denied"
  - Library/framework yang digunakan
  - Versi compiler

### Langkah 3: Cek Proteksi

```bash
$ checksec ./challenge
# Output:
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**Apa arti masing-masing?** (untuk pemula, yang paling penting: PIE)

| Proteksi | Artinya | Dampak untuk RE |
|----------|---------|----------------|
| **PIE** | Position Independent Executable | Jika **No PIE**: alamat fungsi tetap (lebih mudah). Jika **PIE**: alamat berubah setiap run |
| **NX** | No-Execute (stack tidak bisa dieksekusi) | Lebih relevan untuk Pwn, bukan RE |
| **Canary** | Stack protector | Lebih relevan untuk Pwn |
| **RELRO** | Read-Only relocations | Lebih relevan untuk Pwn |
| **Stripped** | Nama fungsi dihapus | Membuat RE lebih sulit |

### Langkah 4: Jalankan Program (hati-hati!)

```bash
# PENTING: Selalu jalankan challenge di environment yang aman!
# Di WSL/VM, JANGAN di host OS jika tidak yakin aman

# Jalankan dan lihat apa yang diminta
$ chmod +x challenge     # beri permission execute
$ ./challenge
Enter password: hello
Wrong password!

# Sekarang kita tahu: program meminta password → validasi → benar/salah
```

### Langkah 5: Trace Library Calls (SENJATA RAHASIA!)

```bash
$ ltrace ./challenge
# Output:
printf("Enter password: ")                        = 17
fgets("hello\n", 100, 0x7f...)                     = 0x7fff...
strcmp("hello", "sup3r_s3cr3t_p4ss!")               = -1
# ↑↑↑ LIHAT! strcmp membandingkan input dengan "sup3r_s3cr3t_p4ss!" ← ITU PASSWORDNYA!
puts("Wrong password!")                             = 16

# Jalankan ulang dengan password yang benar:
$ ./challenge
Enter password: sup3r_s3cr3t_p4ss!
Correct! flag{ltrace_is_your_best_friend}
```

**Kenapa ltrace sangat powerful?**
- `ltrace` menunjukkan **semua panggilan ke library functions** beserta argumennya
- `strcmp(input, "password")` → langsung terlihat password yang benar!
- `memcmp`, `strncmp`, `strcasecmp` → semua comparison functions terlihat

```bash
# strace — trace system calls (lebih rendah dari ltrace)
$ strace ./challenge 2>&1 | grep -E "open|read|write"
# Berguna untuk melihat file apa yang dibuka/dibaca program
# Contoh: program membaca key dari file tersembunyi
openat(AT_FDCWD, "/tmp/.hidden_key", O_RDONLY) = 3
read(3, "secret_key_123", 14) = 14
```

---

# Bagian 3: Static Analysis

## Apa itu Static Analysis?

**Static analysis** = menganalisis binary **tanpa menjalankannya**. Kita membaca kode assembly/decompiled code.

Analoginya: membaca blueprint/buku manual mesin tanpa menyalakan mesinnya.

## Menggunakan Ghidra — Tutorial Step by Step

### Langkah 1: Buat Project

```
1. Buka Ghidra (jalankan ghidraRun.bat di Windows atau ghidraRun di Linux)
2. Saat pertama kali buka: "Welcome to Ghidra" → OK
3. File → New Project → Non-Shared Project
4. Pilih folder untuk menyimpan project (misal: D:\CTF_Projects)
5. Beri nama project: "CTF_Challenge_1"
6. OK
```

### Langkah 2: Import Binary

```
1. File → Import File (atau drag & drop file ke project window)
2. Pilih file challenge binary
3. Dialog "Import" muncul:
   - Format: biasanya auto-detect (ELF, PE, dll.)
   - Language: biasanya auto-detect (x86:LE:64:default, dll.)
   - JANGAN ubah apapun → klik OK
4. Dialog "Analyze?": klik YES
5. "Analysis Options" muncul: biarkan default → klik Analyze
6. Tunggu sampai progress bar di kanan bawah selesai (bisa 10-60 detik)
```

### Langkah 3: Kenali Interface

```
Setelah file terbuka, kamu melihat beberapa panel:

┌──────────────┬────────────────────────────┬──────────────────┐
│ Program      │                            │                  │
│ Trees        │     LISTING                │   DECOMPILE      │
│              │     (Assembly Code)        │   (Pseudo-C)     │
│ - Functions  │                            │                  │
│ - Labels     │     mov rdi, rsp           │   int main() {   │
│ - Classes    │     call printf            │     printf(...)   │
│ - ...        │     cmp eax, 0             │     if (x == 0)  │
│              │     je 0x401280            │       goto fail; │
│              │                            │                  │
├──────────────┼────────────────────────────┤                  │
│ Data Types   │     CONSOLE / BYTES        │                  │
│              │                            │                  │
└──────────────┴────────────────────────────┴──────────────────┘

Panel penting:
- KIRI: Symbol Tree → daftar fungsi, label, data
- TENGAH: Listing → kode assembly
- KANAN: Decompile → terjemahan ke pseudo-C (PALING BERGUNA!)
```

### Langkah 4: Cari Fungsi Main

```
Di panel kiri (Symbol Tree):
1. Expand "Functions"
2. Cari "main" → double-click
   - Jika tidak ada "main", cari "entry" → ikuti panggilan ke __libc_start_main
   - Parameter pertama __libc_start_main biasanya adalah alamat main

3. Setelah klik "main", panel tengah (listing) dan kanan (decompile) 
   akan menunjukkan kode main
```

### Langkah 5: Baca Decompiled Code

```c
// Contoh output Decompile window:

undefined8 main(void) {
    int iVar1;
    char local_38 [40];          // ← variabel lokal (di stack)
    
    printf("Enter password: ");
    fgets(local_38, 0x28, stdin);
    
    // local_38 = input user
    // Dibandingkan dengan string hardcoded
    iVar1 = strcmp(local_38, "s3cr3t_fl4g!");
    
    if (iVar1 == 0) {            // strcmp return 0 = sama
        puts("Correct!");
        printf("Flag: flag{%s}\n", "easy_reverse");
    } else {
        puts("Wrong!");
    }
    return 0;
}
```

**Cara membaca decompiled code:**
- `undefined8` → tipe return value (biasanya int/long, Ghidra belum tahu pastinya)
- `local_38` → variabel lokal di stack (Ghidra auto-naming, bisa di-rename)
- `iVar1` → variabel integer sementara
- Logikanya: ambil input → strcmp dengan password → jika sama → print flag

### Langkah 6: Rename Variabel (Penting!)

```
1. Klik kanan pada "local_38" di decompile window
2. Pilih "Rename Variable" (atau tekan L)
3. Ketik nama yang bermakna, misal: "user_input"
4. Enter

Sebelum:
  iVar1 = strcmp(local_38, "s3cr3t_fl4g!");

Sesudah:
  result = strcmp(user_input, "s3cr3t_fl4g!");

→ JAUH lebih mudah dibaca!
```

### Langkah 7: Cari Strings di Ghidra

```
1. Menu Window → Defined Strings
   - Tabel berisi semua strings di binary
   - Cari: "flag", "correct", "wrong", "password"

2. Double-click string yang menarik → jump ke lokasi string di listing

3. Klik kanan string → References → Find References to this address
   - Ini menunjukkan FUNGSI MANA yang menggunakan string ini
   - Klik reference → jump ke fungsi yang menggunakan string
```

### Langkah 8: Cari Cross-References (XREF)

```
XREF = "siapa yang menggunakan/memanggil ini?"

Contoh workflow:
1. Cari string "Wrong password"
2. Klik kanan → References → Find References to
3. Muncul: fungsi "validate_password" di alamat 0x401234
4. Double-click → Ghidra jump ke fungsi validate_password
5. Baca logikanya → pahami cara validasi → solve!
```

### Langkah 9: Graph View

```
1. Di listing window, klik kanan → Function Graph
   - Atau: Window → Function Graph

2. Muncul visual seperti flowchart:
   - Kotak = blok instruksi
   - Panah = alur eksekusi
   - Hijau = true/ya
   - Merah = false/tidak

3. Ini sangat membantu untuk memahami alur if/else dan loop
```

---

## Menggunakan IDA Free — Tutorial Step by Step

### Langkah Dasar:

```
1. BUKA: Drag & drop binary ke IDA, atau File → Open
2. IDA auto-detect format → klik OK
3. Tunggu analysis selesai (progress bar kiri bawah)

4. CARI MAIN:
   - Panel kiri "Functions": cari "main"
   - Atau: tekan G → ketik "main" → Go

5. GRAPH VIEW:
   - Tekan Space → toggle antara text/graph view
   - Graph view menunjukkan alur program secara visual

6. STRINGS:
   - View → Open Subviews → Strings (atau Shift+F12)
   - Double-click string → jump ke lokasi
   - Tekan X untuk melihat cross-references

7. DECOMPILE (IDA Free 8.x+):
   - Kursor di fungsi → tekan F5
   - Pseudocode window muncul → baca logika

8. RENAME:
   - Klik variabel/fungsi → tekan N → ketik nama baru

9. COMMENT:
   - Klik di baris → tekan ; → ketik komentar
```

---

# Bagian 4: Dynamic Analysis

## Apa itu Dynamic Analysis?

**Dynamic analysis** = menganalisis binary **sambil menjalankannya**. Kita bisa pause, inspect memori, dan mengubah variabel saat runtime.

Analoginya: menyalakan mesin, lalu memperlambat dan mengamati satu per satu bagian yang bergerak.

## Menggunakan GDB + pwndbg — Tutorial Lengkap

### Skenario: Binary meminta password, kita ingin menemukan flag

```bash
# Langkah 1: Buka binary di GDB
$ gdb ./challenge

# ============================================
# Setelah masuk GDB, kamu lihat prompt:
# (gdb) atau pwndbg> (jika pwndbg terinstall)
# ============================================

# Langkah 2: Set syntax Intel (lebih readable)
(gdb) set disassembly-flavor intel

# Langkah 3: Lihat fungsi apa saja yang ada
(gdb) info functions
# Output:
# 0x0000000000401146  main
# 0x00000000004011a0  check_password
# 0x0000000000401200  print_flag
# ← Fungsi check_password dan print_flag terlihat!

# Langkah 4: Disassemble fungsi yang menarik
(gdb) disassemble check_password
# Output:
# 0x4011a0: push rbp
# 0x4011a1: mov  rbp, rsp
# 0x4011a4: mov  rdi, [rbp+0x8]     ← parameter1 = input
# 0x4011a8: lea  rsi, [0x402010]    ← parameter2 = string hardcoded
# 0x4011af: call strcmp              ← bandingkan!
# 0x4011b4: test eax, eax           ← cek hasil
# 0x4011b6: je   0x4011c0           ← jika sama, jump
# 0x4011b8: mov  eax, 0             ← return 0 (salah)
# 0x4011bd: ret
# 0x4011c0: mov  eax, 1             ← return 1 (benar)
# 0x4011c5: ret

# Langkah 5: Lihat string yang dibandingkan
(gdb) x/s 0x402010
# 0x402010: "my_s3cret_pass"  ← INI PASSWORD-NYA!

# ============================================
# Alternatif: Jalankan dengan breakpoint
# ============================================

# Langkah A: Set breakpoint di check_password
(gdb) break check_password
# Breakpoint 1 at 0x4011a0

# Langkah B: Jalankan program
(gdb) run
# Program berjalan, mungkin minta input:
# Enter password: [ketik apa saja, misal "test"]
# Breakpoint 1 hit! Program berhenti di check_password

# Langkah C: Lihat register (pwndbg otomatis tampilkan)
# Jika pakai pwndbg, registr, stack, dan code otomatis ditampilkan
# Jika GDB biasa:
(gdb) info registers
# rdi: 0x7ffd...  ← pointer ke input kita
# rsi: 0x402010   ← pointer ke password benar

# Langkah D: Baca string di register
(gdb) x/s $rdi
# 0x7ffd...: "test"      ← input kita
(gdb) x/s $rsi
# 0x402010: "my_s3cret_pass"  ← PASSWORD!

# Langkah E: BYPASS — Force return value
# Set breakpoint SETELAH strcmp
(gdb) break *0x4011b4     # di "test eax, eax"
(gdb) continue
# Hit breakpoint
(gdb) set $eax = 0         # force strcmp return 0 (= strings sama)
(gdb) continue
# → Program berpikir password benar → menampilkan flag!
```

### GDB Commands — Reference Cepat untuk Pemula

```bash
# ══════════════════════════════════════
# MEMULAI
# ══════════════════════════════════════
gdb ./program                  # buka program
run                            # jalankan
run <<< "input"                # jalankan dengan input

# ══════════════════════════════════════
# BREAKPOINTS (titik berhenti)
# ══════════════════════════════════════
break main                     # berhenti di awal fungsi main
break check_password           # berhenti di fungsi tertentu
break *0x401234                # berhenti di alamat tertentu  
info breakpoints               # lihat semua breakpoints
delete 1                       # hapus breakpoint nomor 1

# ══════════════════════════════════════
# EKSEKUSI (setelah breakpoint hit)
# ══════════════════════════════════════
ni                             # Next Instruction — eksekusi 1 instruksi
                               # TIDAK masuk ke dalam call
si                             # Step Into — eksekusi 1 instruksi
                               # MASUK ke dalam call
continue                       # Lanjut sampai breakpoint berikutnya
finish                         # Lanjut sampai fungsi saat ini selesai (return)

# ══════════════════════════════════════
# MELIHAT DATA
# ══════════════════════════════════════
info registers                 # lihat SEMUA register
print $rax                     # lihat isi register RAX
print/x $rax                   # lihat dalam hexadecimal
x/s $rdi                       # baca STRING yang ditunjuk RDI
x/s 0x402000                   # baca STRING di alamat 0x402000
x/10x $rsp                     # lihat 10 HEX WORDS di stack
x/20bx $rsp                    # lihat 20 BYTES di stack (hex)
x/10i $rip                     # lihat 10 INSTRUKSI berikutnya

# ══════════════════════════════════════
# MENGUBAH DATA (untuk bypass)
# ══════════════════════════════════════
set $rax = 1                   # ubah register RAX jadi 1
set $eax = 0                   # ubah register EAX jadi 0
set $rip = 0x401300            # lompat ke alamat lain
set {int}0x404060 = 42         # ubah nilai di memori
```

---

## Menggunakan x64dbg (Windows) — Tutorial Lengkap

### Langkah-Langkah:

```
1. BUKA BINARY
   a. Jalankan x64dbg (atau x32dbg untuk 32-bit)
   b. File → Open → pilih file .exe challenge
   c. Program otomatis berhenti di System Breakpoint

2. LANJUT KE ENTRY POINT
   a. Tekan F9 (Run) sampai address berubah ke range program
      (bukan ntdll atau kernel32)
   b. Atau: Debug → Run to User Code

3. CARI STRING
   a. Klik kanan di area disassembly
   b. Search For → All Referenced Strings
   c. Muncul panel baru dengan semua string
   d. Cari "flag", "correct", "wrong", "password"
   e. Double-click → jump ke lokasi kode yang mereferensi string

4. SET BREAKPOINT
   a. Klik di baris instruksi → tekan F2 (muncul titik merah)
   b. Atau: Ctrl+G → masukkan alamat → F2

5. STEP THROUGH
   a. F7 = Step Into (masuk ke call)
   b. F8 = Step Over (skip call)
   c. F9 = Run (lanjut)
   d. Ctrl+F9 = Run sampai Return

6. LIHAT REGISTER & STACK
   a. Panel kanan atas: Register values
   b. Panel kanan bawah: Stack
   c. Panel bawah: Memory dump

7. MODIFY Register
   a. Double-click register di panel register
   b. Ubah nilainya → OK
   c. Atau klik flag (ZF, CF) untuk toggle

8. PATCH INSTRUKSI
   a. Klik instruksi → tekan Space
   b. Dialog assembler muncul
   c. Ketik instruksi baru, misal: "jmp 0x401300" atau "nop"
   d. OK
   e. Simpan: File → Patch File → Patch File

CONTOH BYPASS:
   Jika ada:     je 0x401280  (jump ke "Wrong!")
   Ubah menjadi: jne 0x401280 (BALIK logikanya)
   Atau:         nop          (hapus jump, selalu lanjut)
   Atau:         jmp 0x401290 (lompat ke "Correct!")
```

---

# Bagian 5: Constraint Solving dengan Z3

## Apa itu Z3?

**Z3** adalah "mesin pemecah persamaan" otomatis. Kita memberikan sekumpulan kondisi (constraints), dan Z3 mencari nilai yang memenuhi SEMUA kondisi tersebut.

## Kapan Pakai Z3?

Saat kamu menemukan validasi yang **terlalu kompleks untuk dibalik manual**.

Contoh di decompiled code:
```c
if ((input[0] * 3 + input[1]) ^ 0x42 == 0x9A &&
    (input[2] + input[3] * 7) % 256 == 0xBE &&
    input[0] ^ input[2] ^ input[4] == 0x37 &&
    // ... 20 kondisi lainnya
    ) {
    printf("Correct!");
}
```

20 kondisi × 5+ variabel → terlalu banyak untuk dicoba manual!

## Tutorial Z3 dari Nol

### Level 1: Persamaan Sederhana

```python
# File: solve.py
# Jalankan: python3 solve.py

from z3 import *

# SOAL: Cari x dan y dimana x + y = 10 dan x - y = 4

# Buat variabel
x = Int('x')    # x adalah integer
y = Int('y')    # y adalah integer

# Buat solver
s = Solver()

# Tambahkan constraint (kondisi)
s.add(x + y == 10)
s.add(x - y == 4)

# Solve!
if s.check() == sat:      # sat = satisfiable (ada solusi)
    model = s.model()
    print(f"x = {model[x]}")  # x = 7
    print(f"y = {model[y]}")  # y = 3
else:
    print("Tidak ada solusi!")
```

### Level 2: Cari Karakter (CTF Pattern)

```python
from z3 import *

# SOAL: Flag 5 karakter, tiap karakter harus memenuhi kondisi

# Buat variabel: 5 karakter, masing-masing 8-bit
flag = [BitVec(f'char_{i}', 8) for i in range(5)]

s = Solver()

# Constraint 1: semua karakter harus printable ASCII (32-126)
for c in flag:
    s.add(c >= 32)    # spasi
    s.add(c <= 126)   # ~

# Constraint 2: dari binary (yang kita baca via Ghidra)
s.add(flag[0] == ord('f'))           # karakter pertama = 'f'
s.add(flag[1] == ord('l'))           # karakter kedua = 'l'
s.add(flag[2] ^ 0x10 == ord('q'))    # flag[2] XOR 0x10 = 'q' → flag[2] = 'a'
s.add(flag[3] + 5 == ord('l'))       # flag[3] + 5 = 'l' → flag[3] = 'g'
s.add(flag[4] == ord('!'))           # karakter terakhir = '!'

# Solve
if s.check() == sat:
    m = s.model()
    # Ambil nilai setiap karakter
    result = ''
    for c in flag:
        value = m[c].as_long()    # ambil nilai integer
        result += chr(value)       # convert ke karakter
    print(f"Flag: {result}")       # Flag: flag!
else:
    print("UNSAT - tidak ada solusi")
```

### Level 3: Real CTF Pattern (Constraint dari Loop)

```python
from z3 import *

# SKENARIO: Decompiled code menunjukkan:
# char key[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
# char expected[] = {0x76, 0x5a, 0x30, 0x1e, 0xfb};
# for (int i = 0; i < 5; i++) {
#     if (((input[i] ^ key[i]) + i) & 0xFF != expected[i])
#         return WRONG;
# }
# return CORRECT;

key =      [0x12, 0x34, 0x56, 0x78, 0x9a]
expected = [0x76, 0x5a, 0x30, 0x1e, 0xfb]

flag = [BitVec(f'f{i}', 8) for i in range(5)]
s = Solver()

# Printable ASCII
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# Reconstruct loop sebagai constraint
for i in range(5):
    s.add(((flag[i] ^ key[i]) + i) & 0xFF == expected[i])

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[c].as_long()) for c in flag)
    print(f"Flag: {result}")
else:
    print("UNSAT")
```

### Level 4: Workflow Lengkap (Ghidra → Z3)

```
LANGKAH 1: Buka binary di Ghidra
LANGKAH 2: Cari fungsi validasi (biasanya dekat string "correct"/"wrong")
LANGKAH 3: Baca decompiled code
LANGKAH 4: Identifikasi:
           - Berapa panjang input yang diharapkan?
           - Operasi apa yang dilakukan pada input? (XOR, ADD, MUL, dll.)
           - Apa expected result setelah operasi?
LANGKAH 5: Tulis Z3 script:
           - Buat variabel symbolic untuk setiap karakter input
           - Tambahkan constraint printable ASCII
           - Terjemahkan setiap kondisi validasi ke s.add(...)
           - Solve → hasilnya adalah flag!
```

---

# Bagian 6: Anti-RE

## Apa itu Anti-RE?

**Anti-RE** = teknik yang digunakan challenge untuk mempersulit proses reverse engineering. Ada 3 kategori:

### 1. Anti-Debug

**Apa**: Program mendeteksi jika sedang di-debug → exit/crash.
**Kenapa**: Membuat dynamic analysis lebih sulit.

```
Cara kerja (Linux):
- ptrace(PTRACE_TRACEME) → jika gagal, berarti ada debugger
- Cek /proc/self/status → field "TracerPid" tidak 0 = sedang di-debug
- Timing check → jika terlalu lambat, berarti di-single-step

Cara kerja (Windows):
- IsDebuggerPresent() → return true jika di-debug
- CheckRemoteDebuggerPresent()
- NtQueryInformationProcess()
```

**Cara Bypass (Pemula-Friendly):**

```bash
# ═══ METODE 1: LD_PRELOAD (Linux, paling mudah) ═══

# Buat file fake_ptrace.c:
cat > /tmp/fake_ptrace.c << 'EOF'
long ptrace(int request, ...) {
    return 0;  // selalu return sukses, seolah-olah tidak di-debug
}
EOF

# Compile:
gcc -shared -o /tmp/fake_ptrace.so /tmp/fake_ptrace.c

# Jalankan challenge dengan override ptrace:
LD_PRELOAD=/tmp/fake_ptrace.so ./challenge

# Sekarang program tidak bisa mendeteksi debugger!

# ═══ METODE 2: GDB — Skip ptrace (mudah) ═══

gdb ./challenge
(gdb) catch syscall ptrace    # breakpoint saat ptrace dipanggil
(gdb) run
# Hit! Program memanggil ptrace
(gdb) set $rax = 0            # force return value = 0 (sukses)
(gdb) continue
# Program berjalan normal, anti-debug bypassed!

# ═══ METODE 3: Patch binary (permanent) ═══

# Di Ghidra: cari call ptrace → ganti dengan NOP (90 90 90 90 90)
# Atau ganti dengan: xor eax, eax; nop; nop; nop (31 c0 90 90 90)
```

### 2. Anti-Disassembly

**Apa**: Menyisipkan byte palsu yang membingungkan disassembler.
**Kenapa**: Membuat output Ghidra/IDA salah/aneh.

```nasm
; Binary asli:
    jmp skip_junk    ; loncat ke kode asli
    db 0xE8          ; byte palsu! terlihat seperti awal instruksi "call"
skip_junk:
    mov eax, 1       ; kode asli
```

**Ghidra mungkin menampilkan:**
```
SALAH (confused):
    jmp skip_junk
    call 0x????????    ← Ghidra salah parse byte 0xE8 sebagai call!
    (kode berikutnya jadi kacau)
```

**Cara Mengatasi:**
```
1. Di Ghidra: klik kanan di byte 0xE8 → Clear Code Block
2. Klik kanan di alamat yang benar (skip_junk) → Disassemble
3. Sekarang Ghidra menampilkan kode yang benar!

Atau gunakan dynamic analysis (GDB) → trace kode yang BENAR-BENAR dieksekusi
```

### 3. Anti-Decompiler

**Apa**: Teknik yang membuat decompiler menampilkan output yang salah.
**Kenapa**: Pseudo-C code menjadi tidak masuk akal.

**Cara Mengatasi:**
```
1. JANGAN hanya percaya decompiler — crosscheck dengan assembly!
2. Gunakan GDB untuk trace eksekusi sebenarnya
3. Di Ghidra: retype variabel, buat struct custom
4. Rename semua variabel dan fungsi agar lebih readable
```

---

# Bagian 7: Format File & Bytecode

## Mengenali Tipe File

```bash
# Selalu cek dengan 'file' terlebih dahulu!
$ file mystery

# Jika output: "data" → cek magic bytes manual:
$ xxd mystery | head -5
# 00000000: 7f45 4c46 ...  → ELF (Linux binary)
# 00000000: 4d5a 9000 ...  → PE/MZ (Windows binary)
# 00000000: cafe babe ...  → Java class ATAU Mach-O fat binary
# 00000000: 5044 ...       → Python pyc
# 00000000: 504b 0304 ...  → ZIP archive (APK juga ZIP!)
# 00000000: 0061 736d ...  → WebAssembly
```

## Panduan per Tipe

### Python .pyc → Decompile ke Source

```bash
# Langkah 1: Identifikasi
$ file challenge.pyc
# python 3.8 byte-compiled

# Langkah 2: Decompile
$ uncompyle6 challenge.pyc
# Output: source code Python yang readable!

# Jika uncompyle6 gagal:
$ pip3 install decompyle3
$ decompyle3 challenge.pyc

# Jika masih gagal (Python 3.9+):
# Download pycdc dari https://github.com/zrax/pycdc
$ ./pycdc challenge.pyc

# Langkah 3: Baca source code → solve!
```

### Java .class/.jar → Decompile ke Java

```bash
# Langkah 1: Identifikasi
$ file challenge.jar
# Java archive data

# Langkah 2: Decompile
$ jadx challenge.jar -d output/
$ ls output/sources/   # source code Java!

# Atau GUI:
$ jadx-gui challenge.jar
# Browse class tree → baca source → solve

# Langkah 3: Cari flag
$ grep -r "flag\|password\|key" output/sources/
```

### .NET .exe/.dll → Decompile di dnSpy

```
1. Buka dnSpy.exe (Windows)
2. File → Open → pilih challenge.exe
3. Panel kiri: browse namespace → class → method
4. Klik method → lihat C# source code (hampir SEMPURNA!)
5. Cari method dengan nama mencurigakan: Check, Validate, Flag
6. Baca logika → solve

BONUS: Bisa EDIT & RECOMPILE langsung di dnSpy!
- Klik kanan method → Edit Method (C#)
- Ubah: return false → return true
- File → Save Module → simpan
- Jalankan file baru → flag muncul!
```

---

# Bagian 8: Mengenali Bahasa Pemrograman

## Quick Identification

```bash
# LANGKAH 1: Identifikasi menggunakan strings
$ strings challenge | head -50

# Cari patterns berikut:
```

| Jika muncul... | Bahasa | Tool untuk RE |
|----------------|--------|---------------|
| `GCC:`, `__libc_start_main` | C | Ghidra |
| `_ZN`, `std::`, `vtable` | C++ | Ghidra + c++filt |
| `runtime.gopanic`, `main.main`, `go.` | Go | Ghidra + GoReSym |
| `core::panicking`, `rust_begin_unwind` | Rust | Ghidra + rustfilt |
| `System.`, `_CorExeMain` | .NET (C#) | dnSpy |
| `kotlin.`, `Metadata` | Kotlin | jadx |
| `com.google.`, `flutter` | Flutter | Blutter |

## Kenapa Ini Penting?

Setiap bahasa punya pattern dan tools khusus:

```
C/C++:
- Decompile paling bersih karena compile langsung ke native
- Ghidra/IDA sudah sangat baik
- String biasanya null-terminated

Go:
- Binary SANGAT BESAR (10-30 MB untuk program sederhana)
  karena runtime dimasukkan seluruhnya
- String BUKAN null-terminated (pakai length prefix)
- Tool khusus: GoReSym untuk extract metadata

Rust:
- Juga binary besar
- Banyak panic handler di mana-mana
- Nama fungsi panjang dan aneh → gunakan demangling

.NET:
- PALING MUDAH di-reverse! dnSpy menghasilkan source hampir identik
- Karena .NET = bytecode (MSIL), bukan native code
```

---

# Bagian 9: Arsitektur Prosesor

## x86 vs x64 vs ARM — Apa Bedanya?

```
x86 (32-bit):
- Arsitektur prosesor Intel/AMD yang lebih tua
- Register 32-bit: EAX, EBX, ECX, EDX
- Menjalankan program 32-bit
- Masih sering muncul di CTF

x64 / x86_64 / amd64 (64-bit):
- Versi modern 64-bit dari x86
- Register 64-bit: RAX, RBX, RCX, RDX
- Backward compatible (bisa jalankan x86 juga)
- PALING SERING di CTF

ARM (32-bit) / AArch64 (64-bit):
- Arsitektur berbeda, digunakan di ponsel & tablet
- Register: R0-R15 (ARM32) atau X0-X30 (ARM64)
- Muncul di CTF mobile atau IoT
```

## Jika Dapat ARM Binary di Komputer x86

```bash
# Kamu TIDAK BISA langsung menjalankannya!
# Solusi: gunakan QEMU (emulator)

# Install
sudo apt install qemu-user qemu-user-static

# Jalankan ARM binary
qemu-arm ./challenge_arm32        # ARM 32-bit
qemu-aarch64 ./challenge_arm64    # ARM 64-bit

# Debug ARM binary
qemu-arm -g 1234 ./challenge_arm &    # jalankan dengan debug port
gdb-multiarch ./challenge_arm          # di terminal lain
(gdb) target remote localhost:1234     # connect ke QEMU
(gdb) break main
(gdb) continue

# Ghidra bisa langsung buka ARM binary tanpa emulator!
# Auto-detect arsitektur → analisis seperti biasa
```

---

# Bagian 10: Mobile Reverse Engineering

## Android RE — Panduan Pemula

### Apa itu APK?

```
APK = Android Package = basically file ZIP yang berisi:
├── AndroidManifest.xml    ← deskripsi app (permissions, activities)
├── classes.dex            ← Dalvik bytecode (kode app)
├── classes2.dex           ← (jika app besar)
├── lib/                   ← native libraries (.so files)
│   ├── arm64-v8a/
│   ├── armeabi-v7a/
│   └── x86_64/
├── res/                   ← resources (gambar, layout, strings)
├── assets/                ← raw files (database, config)
└── META-INF/              ← signature
```

### Langkah Lengkap untuk Pemula

```bash
# ═══ LANGKAH 1: Download jadx ═══
# https://github.com/skylot/jadx/releases
# Pilih jadx-gui-xxx-with-jre-win.zip (sudah include Java)

# ═══ LANGKAH 2: Buka APK di jadx-gui ═══
# Jalankan jadx-gui.exe → File → Open → pilih challenge.apk
# Tunggu decompilation selesai (progress bar)

# ═══ LANGKAH 3: Explore ═══
# Panel kiri: class tree
# Buka package utama (biasanya com.example.challenge atau nama app)
# Cari:
#   - MainActivity → fungsi utama app
#   - classes dengan nama: Flag, Secret, Check, Validate, Crypto

# ═══ LANGKAH 4: Search ═══
# Navigation → Text Search (Ctrl+Shift+F)
# Cari: "flag", "CTF", "secret", "password", "key"
# jadx akan menunjukkan SEMUA file yang mengandung kata tersebut

# ═══ LANGKAH 5: Baca Logika Validasi ═══
# Biasanya ada pattern:
#   onClick() → ambil input dari EditText → panggil checkFlag(input)
#   checkFlag() → validasi → return true/false
# Baca logika checkFlag() → solve dengan Z3 atau manual

# ═══ LANGKAH 6 (opsional): Jika ada native library ═══
# Cari folder lib/ → ambil .so file
# Buka .so di Ghidra → cari fungsi Java_com_... (JNI functions)
# Analisis seperti binary biasa
```

### Contoh: Solve Android Challenge

```java
// Decompiled code dari jadx:
public class MainActivity {
    
    private boolean checkFlag(String input) {
        // Flag harus 20 karakter
        if (input.length() != 20) return false;
        
        // XOR setiap karakter dengan key
        byte[] key = {0x12, 0x05, 0x1a, 0x0b, 0x4a, ...};
        byte[] expected = {0x74, 0x66, 0x7a, 0x68, 0x2a, ...};
        
        for (int i = 0; i < 20; i++) {
            if ((input.charAt(i) ^ key[i]) != expected[i]) {
                return false;
            }
        }
        return true;
    }
}
```

```python
# Solve dengan Python:
key =      [0x12, 0x05, 0x1a, 0x0b, 0x4a]  # dari decompiled code
expected = [0x74, 0x66, 0x7a, 0x68, 0x2a]   # dari decompiled code

flag = ''
for i in range(len(key)):
    # input[i] ^ key[i] = expected[i]
    # Maka: input[i] = expected[i] ^ key[i]
    flag += chr(expected[i] ^ key[i])

print(f"Flag: {flag}")
```

### Menggunakan Frida — Penjelasan Pemula

```
Apa itu Frida?
- Tool untuk MENGGANTI perilaku fungsi saat app berjalan
- Bisa mengubah return value, membaca parameter, dll.
- Tanpa perlu memodifikasi APK!

Analogi:
- Bayangkan ada pintu yang dikunci dengan kode
- Frida = kamu MENGGANTI kunci pintunya saat pintu terbuka
  sehingga SEMUA kode diterima

Contoh:
- App punya fungsi: checkPassword(input) → true/false
- Dengan Frida, kita override: checkPassword → SELALU return true
- App berpikir password benar → menampilkan flag
```

```bash
# Setup Frida untuk Android:

# 1. Hubungkan HP/Emulator via ADB
adb devices   # pastikan terdeteksi

# 2. Push frida-server ke device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 3. Tulis hook script (hook.js)
```

```javascript
// hook.js — bypass checkFlag
Java.perform(function() {
    // Cari class MainActivity
    var MainActivity = Java.use("com.ctf.challenge.MainActivity");
    
    // Override method checkFlag
    MainActivity.checkFlag.implementation = function(input) {
        // Cetak input yang diberikan user
        console.log("[*] checkFlag dipanggil dengan: " + input);
        
        // Panggil fungsi asli (untuk lihat return aslinya)
        var result = this.checkFlag(input);
        console.log("[*] Return asli: " + result);
        
        // FORCE return true!
        return true;
    };
    
    console.log("[*] Hook berhasil dipasang!");
});
```

```bash
# 4. Jalankan Frida
frida -U -f com.ctf.challenge -l hook.js --no-pause

# -U      = USB device
# -f      = spawn (mulai app baru)
# -l      = load script
# --no-pause = langsung jalankan
```

---

# Bagian 11: Framework Khusus

## Flutter → Blutter

```
MASALAH: Flutter compile Dart ke native code (AOT snapshot)
         → jadx TIDAK BISA decompile!
         → Ghidra bisa buka, tapi nama fungsi hilang

SOLUSI: Blutter
```

```bash
# 1. Extract APK
apktool d flutter_challenge.apk -o extracted/

# 2. Jalankan Blutter
python3 blutter.py extracted/lib/arm64-v8a/ output/

# 3. Baca output
cat output/pp.txt              # strings & constants → cari flag/key
ls output/asm/                 # assembly per class, sudah ada nama fungsi!
cat output/blutter_frida.js    # auto-generated Frida hooks!
```

## Unity IL2CPP → Il2CppDumper

```
MASALAH: Unity IL2CPP compile C# → C++ → native
         → dnSpy TIDAK BISA decompile
         → Ghidra bisa buka, tapi nama fungsi hilang

SOLUSI: Il2CppDumper
```

```bash
# 1. Butuh 2 file:
#    - libil2cpp.so      (dari lib/arm64-v8a/)
#    - global-metadata.dat (dari assets/bin/Data/Managed/Metadata/)

# 2. Jalankan Il2CppDumper
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/

# 3. Baca output
cat output/dump.cs             # C# class definitions!
cat output/stringliteral.json  # SEMUA string literals
```

## Electron → Extract JavaScript

```bash
# 1. Cari file app.asar di folder program
# Biasanya: resources/app.asar

# 2. Extract
npx asar extract resources/app.asar extracted/

# 3. Baca JavaScript source
cat extracted/main.js
# Atau cari flag:
grep -r "flag\|secret\|key" extracted/
```

---

# Bagian 12: Obfuscation & Binary Patching

## Mendeteksi Obfuscation

```bash
# 1. Cek apakah binary di-pack
$ strings challenge | grep -i "upx\|aspack\|vmprotect"

# 2. Gunakan DIE (Detect It Easy)
$ diec challenge
# Output: "Packer: UPX(3.96)" ← packed!

# 3. Cek entropy (tingkat keacakan data)
# Entropy tinggi (>7.0) = kemungkinan packed/encrypted
```

## Unpacking UPX

```bash
# PALING UMUM di CTF!
# Cek:
$ strings challenge | grep UPX
# Jika ada "UPX!" → tinggal:
$ upx -d challenge -o challenge_unpacked
# Sekarang analisis challenge_unpacked seperti biasa!
```

## Binary Patching untuk Pemula

### Konsep

```
Binary patching = mengubah instruksi di binary agar perilakunya berubah.

Contoh paling umum:
SEBELUM: je 0x401280     (je = jump if equal → lompat ke "Wrong!")
SESUDAH: jne 0x401280    (jne = jump if NOT equal → lompat ke "Wrong!" hanya jika BENAR)
         → logika terbalik! Sekarang password APAPUN diterima!

Atau:
SEBELUM: je 0x401280     (jump ke "Wrong!")
SESUDAH: nop; nop        (tidak melakukan apa-apa → selalu ke "Correct!")
```

### Cara Patch di Ghidra

```
1. Buka binary di Ghidra
2. Cari instruksi yang ingin diubah (misal: je 0x401280)
3. Klik kanan instruksi → Patch Instruction
4. Ketik instruksi baru: "JNE 0x401280" atau "NOP"
5. Enter
6. File → Export Program → pilih format → save sebagai file baru
7. Jalankan file baru → flag muncul!
```

### Cara Patch di x64dbg

```
1. Buka .exe di x64dbg
2. Cari instruksi (misal via string search → find reference)
3. Klik instruksi → tekan Space
4. Ketik instruksi baru → OK
5. File → Patch File → Patch File → simpan
```

### Cara Patch dengan Python

```python
# Untuk pemula, ini cara paling fleksibel

# Baca file
with open('challenge', 'rb') as f:
    data = bytearray(f.read())

# Cari tahu OFFSET instruksi yang ingin diubah:
# - Di Ghidra: lihat "Byte" column di listing
# - Atau hitung: virtual_address - base_address = file_offset
# Contoh: alamat 0x401234, base 0x400000 → offset = 0x1234

offset = 0x1234

# Ubah je (0x74) → jne (0x75)
data[offset] = 0x75

# Atau NOP out (hapus instruksi):
# je = 2 bytes (74 xx), ganti jadi NOP NOP (90 90)
data[offset] = 0x90
data[offset + 1] = 0x90

# Simpan
with open('challenge_patched', 'wb') as f:
    f.write(data)

# Jalankan
# chmod +x challenge_patched && ./challenge_patched
```

### Tabel Byte Penting untuk Patching

| Instruksi | Hex | Kegunaan |
|-----------|-----|----------|
| NOP | 90 | Hapus instruksi (do nothing) |
| JE (short) | 74 xx | Jump if equal |
| JNE (short) | 75 xx | Jump if not equal |
| JMP (short) | EB xx | Jump always |
| RET | C3 | Return dari fungsi |
| XOR EAX, EAX | 31 C0 | Set EAX = 0 |
| MOV EAX, 1 | B8 01 00 00 00 | Set EAX = 1 |

```
TIPS: Untuk membalik logic, biasanya cukup ubah 1 byte:
  74 → 75  (je → jne, atau sebaliknya)
  84 → 85  (je near → jne near, dengan prefix 0F)
```

---

# Bagian 13: Walkthrough Soal CTF

## Contoh 1: Binary Sederhana (Level: Easy)

```
Soal: File "simple_check" — temukan flag.

══ STEP 1: Recon ══

$ file simple_check
simple_check: ELF 64-bit LSB executable, x86-64, not stripped

$ strings simple_check | grep -i flag
Enter the flag:
Wrong flag!
Correct! Well done!

$ ltrace ./simple_check <<< "test"
printf("Enter the flag: ")
fgets("test\n", 50, ...)
strcmp("test\n", "flag{ltrace_wins}\n")    ← FLAG!
puts("Wrong flag!")

DONE! Flag: flag{ltrace_wins}
Total waktu: 30 detik
```

## Contoh 2: XOR Encryption (Level: Easy-Medium)

```
Soal: File "xor_me" — temukan flag.

══ STEP 1: Recon ══

$ file xor_me
xor_me: ELF 64-bit LSB executable, x86-64, not stripped

$ ltrace ./xor_me <<< "test"
# Tidak ada strcmp/memcmp yang jelas → perlu static analysis

══ STEP 2: Ghidra ══

Buka di Ghidra → cari main → decompile:

int main() {
    char input[32];
    char encrypted[20] = {0x16, 0x0f, 0x03, 0x09, ...};
    char key = 0x42;
    
    printf("Enter flag: ");
    fgets(input, 32, stdin);
    
    for (int i = 0; i < 20; i++) {
        if ((input[i] ^ key) != encrypted[i]) {
            puts("Wrong!");
            return 1;
        }
    }
    puts("Correct!");
    return 0;
}

══ STEP 3: Solve ══

# Logika: input[i] ^ 0x42 == encrypted[i]
# Maka:   input[i] == encrypted[i] ^ 0x42
```

```python
encrypted = [0x16, 0x0f, 0x03, 0x09]  # ambil dari Ghidra
key = 0x42

flag = ''.join(chr(b ^ key) for b in encrypted)
print(flag)  # flag = "Tame" (contoh)
```

## Contoh 3: Constraint Solving (Level: Medium)

```
Soal: File "constraint_me" — temukan flag.

══ STEP 1-2: Recon + Ghidra ══

Decompiled code menunjukkan:

bool check(char *input) {
    if (strlen(input) != 10) return false;
    if (input[0] + input[1] != 0xCB) return false;
    if (input[2] ^ input[3] != 0x5A) return false;
    if (input[4] * 2 + input[5] != 0x15E) return false;
    if ((input[6] - input[7]) != 0x09) return false;
    if (input[8] + input[9] != 0xE0) return false;
    // ... 5 kondisi lainnya
    return true;
}

══ STEP 3: Z3 ══
```

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(10)]
s = Solver()

for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

s.add(flag[0] + flag[1] == 0xCB)
s.add(flag[2] ^ flag[3] == 0x5A)
s.add(flag[4] * 2 + flag[5] == 0x15E)
s.add((flag[6] - flag[7]) == 0x09)
s.add(flag[8] + flag[9] == 0xE0)

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

## Contoh 4: GDB Bypass (Level: Medium)

```
Soal: Binary "locked" yang minta license key. Flag ditampilkan setelah key benar.

══ STEP 1: Recon ══

$ ltrace ./locked <<< "test"
# Tidak ada strcmp sederhana → lebih kompleks

══ STEP 2: GDB ══

$ gdb ./locked
(gdb) info functions
# 0x401200 validate_license
# 0x401350 show_flag         ← MENARIK!
# 0x401400 main

(gdb) disassemble main
# ...
# 0x401450: call validate_license
# 0x401455: test eax, eax         ← cek return value
# 0x401457: je   0x401470         ← jika 0, jump ke "wrong"
# 0x401459: call show_flag        ← PANGGIL show_flag!
# 0x40145e: jmp  0x401480
# 0x401470: call print_wrong
# ...

══ STEP 3: Bypass ══

# Metode A: Override return value dari validate_license
(gdb) break *0x401455
(gdb) run <<< "anything"
# Hit breakpoint
(gdb) set $eax = 1          # force: valid!
(gdb) continue
# → show_flag dipanggil → flag ditampilkan!

# Metode B: Langsung panggil show_flag
(gdb) break main
(gdb) run
(gdb) call (void)show_flag()
# → flag ditampilkan!
```

---

# Bagian 14: Tempat Latihan & Resources

## Platform Latihan CTF (Gratis!)

| Platform | URL | Level | Deskripsi |
|----------|-----|-------|-----------|
| **picoCTF** | https://picoctf.org/ | Pemula | Platform terbaik untuk pemula! Soal bertahap |
| **crackmes.one** | https://crackmes.one/ | Pemula-Menengah | Kumpulan crackme khusus RE |
| **Reversing.kr** | http://reversing.kr/ | Menengah | Kumpulan challenge RE klasik |
| **CTFlearn** | https://ctflearn.com/ | Pemula | Platform belajar CTF multi-kategori |
| **HackTheBox** | https://hackthebox.com/ | Menengah | Challenge RE + mesin lengkap |
| **TryHackMe** | https://tryhackme.com/ | Pemula | Room-based learning, ada guided RE rooms |
| **OverTheWire** | https://overthewire.org/ | Pemula | Wargames, mulai dari "Bandit" |
| **root-me** | https://root-me.org/ | Semua | Banyak challenge cracking/RE |
| **Nightmare** | https://guyinatuxedo.github.io/ | Menengah | Kumpulan RE writeups terstruktur |

## Path Belajar yang Direkomendasikan

```
MINGGU 1-2: Fondasi
├── Pahami konsep assembly dasar (register, instruksi, stack)
├── Install tools (Ghidra, GDB+pwndbg)
├── Latihan:
│   ├── picoCTF → kategori "Reverse Engineering" → soal easiest
│   └── crackmes.one → difficulty 1.0-2.0
└── Target: bisa buka binary di Ghidra dan baca decompiled code

MINGGU 3-4: Static Analysis
├── Latih membaca decompiled code (Ghidra/IDA)
├── Pelajari pattern: strcmp, XOR, loop validation
├── Belajar Z3 dasar
├── Latihan:
│   ├── picoCTF RE soal medium
│   └── crackmes.one difficulty 2.0-3.0
└── Target: bisa solve challenge XOR dan constraint sederhana

MINGGU 5-6: Dynamic Analysis
├── Kuasai GDB: breakpoint, step, inspect, modify
├── Pelajari ltrace, strace
├── Belajar bypass anti-debug sederhana
├── Latihan:
│   ├── Reversing.kr soal Easy
│   └── root-me → App - System → soal RE
└── Target: bisa bypass password check dengan GDB

MINGGU 7-8: Advanced Topics
├── Mobile RE (jadx, Frida)
├── Binary patching
├── Packed binaries (UPX)
├── angr symbolic execution
├── Latihan:
│   ├── HackTheBox challenges
│   └── Ikut CTF online (CTFtime.org → calendar)
└── Target: bisa solve challenge medium di CTF real
```

## Resources Belajar

### Video/Course (Gratis):
- **LiveOverflow** (YouTube) — penjelasan RE & CTF yang sangat baik
- **John Hammond** (YouTube) — CTF walkthroughs
- **GynvaelColdwind** (YouTube) — RE dan security streams
- **0xdf** (YouTube) — HackTheBox walkthroughs
- **pwn.college** — course gratis dari ASU, structured learning

### Buku:
- **"Reverse Engineering for Beginners"** oleh Dennis Yurichev (GRATIS!)
  - https://beginners.re/
- **"Practical Binary Analysis"** oleh Dennis Andriesse
- **"Practical Malware Analysis"** — bagus untuk belajar RE

### Writeups:
- **CTFtime** — https://ctftime.org/writeups — writeup dari berbagai CTF
- **GitHub** — search "CTF writeup reverse engineering"

---

# Bagian 15: Cheat Sheet & Quick Reference

## Workflow Umum (Untuk Dicetak!)

```
┌─────────────────────────────────────────┐
│  DAPAT FILE CHALLENGE                    │
└─────────────────┬───────────────────────┘
                  ▼
┌─────────────────────────────────────────┐
│  1. file challenge                       │ ← Tipe apa?
│  2. strings challenge | grep flag        │ ← Ada string flag?
│  3. ltrace ./challenge                   │ ← Leak password?
└─────────────────┬───────────────────────┘
                  ▼
         ┌────────┴────────┐
    Ketemu?              Belum?
    ↓ YA                 ↓ TIDAK
  SELESAI!         ┌─────────────────────┐
                   │ 4. checksec          │
                   │ 5. Buka di Ghidra    │
                   │ 6. Cari main         │
                   │ 7. Baca decompile    │
                   └────────┬────────────┘
                            ▼
                   ┌────────┴────────┐
              Paham?              Sulit?
              ↓                   ↓
     ┌────────────────┐  ┌────────────────┐
     │ Solve manual   │  │ Dynamic:       │
     │ atau Z3        │  │ GDB bypass     │
     │                │  │ atau Frida     │
     │                │  │ atau Patch     │
     └────────────────┘  └────────────────┘
              ↓                   ↓
         FLAG! 🏴            FLAG! 🏴
```

## Command Cheat Sheet

```bash
# ══════════ RECON ══════════
file challenge                    # tipe file
strings challenge | grep flag     # cari strings
checksec ./challenge              # proteksi
ltrace ./challenge                # trace lib calls
strace ./challenge                # trace syscalls
binwalk challenge                 # embedded files
xxd challenge | head              # lihat hex bytes

# ══════════ GDB ══════════
gdb ./challenge                   # mulai debug
break main                        # breakpoint di main
break *0x401234                   # breakpoint di alamat
run                               # jalankan
run <<< "input"                   # jalankan dengan input
ni                                # next instruction
si                                # step into
continue                          # lanjut
info registers                    # lihat register
x/s $rdi                          # baca string
x/10x $rsp                       # lihat stack
set $eax = 1                      # ubah register
set $rip = 0x401300               # jump ke alamat

# ══════════ PYTHON ══════════
# XOR decrypt
''.join(chr(b ^ key) for b in encrypted)

# Z3
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(N)]
s = Solver()
s.add(constraint)
s.check() == sat
m = s.model()

# ══════════ PATCHING ══════════
# je→jne: ubah byte 74→75 atau 0F84→0F85
# NOP: 90
# ret: C3
```

## Tabel Opcode Penting

```
JUMP CONDITIONS:
  74 = JE/JZ   (jump if equal/zero)
  75 = JNE/JNZ (jump if not equal/not zero)
  7C = JL      (jump if less)
  7D = JGE     (jump if greater or equal)
  7E = JLE     (jump if less or equal)
  7F = JG      (jump if greater)
  EB = JMP     (unconditional short jump)
  
COMMON INSTRUCTIONS:
  90       = NOP
  C3       = RET
  CC       = INT3 (breakpoint trap)
  31 C0    = XOR EAX, EAX (set EAX=0)
  B8 xx    = MOV EAX, xx
  E8 xx    = CALL (relative)
  E9 xx    = JMP (relative, near)
  
ANTI-DEBUG:
  CALL to ptrace = E8 xx xx xx xx
  → untuk bypass, ganti jadi: 31 C0 90 90 90 (xor eax,eax + nop padding)
```

---

> **🎉 Selamat!** Kamu sudah membaca panduan lengkap RE/CTF untuk pemula.
> 
> **Langkah selanjutnya:**
> 1. Install tools (Bagian 1)
> 2. Mulai solve soal di **picoCTF** (Bagian 14)
> 3. Setiap kali stuck, buka lagi panduan ini
> 4. Setiap kali solve, tulis notes apa yang kamu pelajari
> 
> **Ingat:** RE itu skill yang diasah lewat LATIHAN. Semakin banyak challenge kamu solve, semakin cepat kamu membaca dan memahami binary. Jangan menyerah jika awalnya terasa sulit — semua orang mulai dari sini! 💪
