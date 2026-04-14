# 🛠️ CTF Reverse Engineering — Tools Reference Guide

Panduan lengkap instalasi & penggunaan setiap tool untuk CTF Reverse Engineering.

---

## Daftar Isi

1. [Disassembler & Decompiler](#1-disassembler--decompiler)
2. [Debugger](#2-debugger)
3. [Binary Analysis & Recon](#3-binary-analysis--recon)
4. [Constraint Solver & Symbolic Execution](#4-constraint-solver--symbolic-execution)
5. [Dynamic Instrumentation](#5-dynamic-instrumentation)
6. [Bytecode Decompiler](#6-bytecode-decompiler)
7. [Mobile RE Tools](#7-mobile-re-tools)
8. [Packer & Obfuscation Tools](#8-packer--obfuscation-tools)
9. [Hex Editor & Patching](#9-hex-editor--patching)
10. [Emulator & Sandbox](#10-emulator--sandbox)
11. [Tambahan & Utility](#11-tambahan--utility)
12. [Tool Selection Cheat Sheet](#-tool-selection-cheat-sheet)

---

## 1. Disassembler & Decompiler

Fungsi utama: mengubah binary (machine code) → assembly → pseudo-C untuk dipahami manusia.

---

### 🔷 Ghidra

**Apa itu**: Disassembler + decompiler gratis dari NSA. Mendukung hampir semua arsitektur prosesor.

**Instalasi:**

```bash
# Download dari https://ghidra-sre.org/
# Butuh Java JDK 17+

# Windows:
choco install ghidra    # via Chocolatey
# Atau download ZIP → extract → jalankan ghidraRun.bat

# Linux:
sudo apt install default-jdk
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC.zip
unzip ghidra_11.0_PUBLIC.zip
./ghidra_11.0_PUBLIC/ghidraRun
```

**Cara Penggunaan:**

```
1. BUAT PROJECT
   - File → New Project → Non-Shared Project
   - Pilih lokasi → beri nama project

2. IMPORT BINARY
   - File → Import File → pilih binary challenge
   - Ghidra biasanya auto-detect format & arsitektur
   - Klik OK → Yes untuk auto-analysis

3. NAVIGASI DASAR
   - Symbol Tree (kiri): browse fungsi, classes, labels
   - Listing (tengah): assembly code
   - Decompile (kanan): pseudo-C code
   - Klik fungsi di Symbol Tree → langsung jump ke sana

4. ANALISIS FUNGSI
   - Cari "main" di Symbol Tree → klik
   - Baca Decompile window → logika program
   - Double-click fungsi di decompile → jump ke fungsi tersebut

5. CROSS-REFERENCE (XREF)
   - Klik kanan pada string/fungsi → References → Find References
   - Atau tekan Ctrl+Shift+F → search string
   - Ini SANGAT BERGUNA: cari xref ke "wrong", "correct", "flag"

6. RENAME & RETYPE (Essential!)
   - Klik kanan variabel → Rename Variable (L)
   - Klik kanan fungsi → Rename Function
   - Klik kanan variabel → Retype Variable
   - Ini membuat decompiled code JAUH lebih readable

7. PATCHING
   - Klik kanan instruksi → Patch Instruction
   - Atau: klik kanan byte → Patch Data
   - File → Export Program → pilih format (ELF, PE) → save patched binary

8. SCRIPTING
   - Window → Script Manager
   - Bisa menulis script Python (Jython) atau Java
   - Banyak community scripts untuk analisis otomatis
```

**Keyboard Shortcuts Penting:**

| Shortcut | Fungsi |
|----------|--------|
| `G` | Go to address |
| `L` | Rename label/variable |
| `T` | Change type |
| `Ctrl+Shift+F` | Search strings |
| `;` | Add comment |
| `X` | Show cross-references |
| `Space` | Toggle listing/graph view |
| `Ctrl+E` | Edit bytes |

**Contoh Workflow CTF:**

```
1. Import binary → tunggu auto-analysis selesai
2. Window → Defined Strings → cari "flag", "correct", "wrong"
3. Double-click string "Correct!" → pergi ke lokasi string
4. Klik kanan → References → Find References to → lihat fungsi mana yang pakai
5. Jump ke fungsi tersebut → baca decompile → pahami logika validasi
6. Rename variabel agar readable → solve
```

---

### 🔷 IDA Pro / IDA Free

**Apa itu**: Disassembler industri standar. IDA Free support x86/x64, IDA Pro berbayar (support semua arch + decompiler).

**Instalasi:**

```bash
# IDA Free: https://hex-rays.com/ida-free/
# Download installer → install seperti biasa
# Windows: jalankan ida64.exe atau ida.exe
```

**Cara Penggunaan:**

```
1. BUKA BINARY
   - Drag & drop file ke IDA
   - Atau: File → Open → pilih binary
   - IDA auto-detect processor type → OK
   - Tunggu auto-analysis (progress bar di bawah)

2. NAVIGASI
   - IDA View-A: assembly code (tekan Space untuk graph view)
   - Functions window (kiri): daftar semua fungsi
   - Strings window: View → Open Subviews → Strings (Shift+F12)
   - Hex View: View → Open Subviews → Hex Dump

3. GRAPH VIEW (sangat berguna!)
   - Tekan Space di IDA View → toggle text/graph
   - Graph menunjukkan alur control flow (if/else, loop) secara visual
   - Hijau = true branch, Merah = false branch

4. DECOMPILE (IDA Pro / Free 8.x+)
   - Kursor di fungsi → tekan F5
   - Pseudocode window muncul
   - Klik kanan variabel → Rename, Set Type

5. CROSS-REFERENCES
   - Kursor di fungsi/string → tekan X
   - Muncul list siapa yang memanggil/mereferensi

6. DEBUGGING (IDA Pro)
   - Debugger → Select Debugger → Local/Remote
   - F2: toggle breakpoint
   - F9: run
   - F7: step into
   - F8: step over

7. PATCHING
   - Edit → Patch Program → Assemble / Change Byte
   - Edit → Patch Program → Apply Patches to Input File
```

**Keyboard Shortcuts:**

| Shortcut | Fungsi |
|----------|--------|
| `Space` | Toggle graph/text view |
| `F5` | Decompile (Hex-Rays) |
| `X` | Cross-references |
| `N` | Rename |
| `Y` | Change type |
| `G` | Jump to address |
| `Shift+F12` | Strings window |
| `F2` | Set breakpoint |
| `;` | Add comment |

---

### 🔷 Binary Ninja

**Apa itu**: Disassembler modern dengan UI bersih. Versi Cloud (gratis), Personal ($299), Commercial.

**Instalasi:**

```bash
# https://binary.ninja/
# Download → install
# Atau versi cloud: https://cloud.binary.ninja (gratis, web-based)
```

**Cara Penggunaan:**

```
1. Open file → auto-analysis
2. Navigasi mirip IDA: graph view, linear view, decompiler
3. Kelebihan: API Python yang sangat baik untuk scripting
4. HLIL (High Level IL): decompiled view yang sangat readable
5. Klik kanan → banyak opsi analisis otomatis
```

---

## 2. Debugger

Fungsi: menjalankan program step-by-step, inspect memory & register saat runtime.

---

### 🔷 GDB (GNU Debugger)

**Apa itu**: Debugger CLI standar di Linux. Sangat powerful dengan plugin.

**Instalasi:**

```bash
# Linux (biasanya sudah terinstall)
sudo apt install gdb

# Dengan plugin pwndbg (SANGAT RECOMMENDED):
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Atau GEF (alternatif):
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Untuk debug ARM binary:
sudo apt install gdb-multiarch
```

**Cara Penggunaan Lengkap:**

```bash
# ==================================
# MEMULAI DEBUG
# ==================================
gdb ./challenge                    # load binary
gdb -q ./challenge                 # quiet mode (tanpa banner)
gdb --args ./challenge arg1 arg2   # dengan argumen

# ==================================
# BREAKPOINTS
# ==================================
(gdb) break main                   # breakpoint di fungsi main
(gdb) break *0x401234              # breakpoint di alamat spesifik
(gdb) break check_flag             # breakpoint di fungsi bernama
(gdb) info breakpoints             # list semua breakpoints
(gdb) delete 1                     # hapus breakpoint #1
(gdb) disable 2                    # nonaktifkan breakpoint #2
(gdb) break *0x401234 if $rax==5   # conditional breakpoint

# ==================================
# MENJALANKAN
# ==================================
(gdb) run                          # jalankan program
(gdb) run < input.txt              # jalankan dengan file input
(gdb) run <<< "hello"             # jalankan dengan string input
(gdb) continue                     # c - lanjut ke breakpoint berikut
(gdb) ni                           # next instruction (skip call)
(gdb) si                           # step into (masuk ke call)
(gdb) finish                       # jalankan sampai fungsi return

# ==================================
# INSPECT REGISTER
# ==================================
(gdb) info registers               # semua register
(gdb) info registers rax rbx       # register tertentu
(gdb) print $rax                   # print nilai RAX
(gdb) print/x $rax                 # print dalam hex
(gdb) print/d $rax                 # print dalam decimal
(gdb) print/t $rax                 # print dalam binary
(gdb) print/c $rax                 # print sebagai char

# ==================================
# INSPECT MEMORY
# ==================================
(gdb) x/10x $rsp                   # 10 hex words dari RSP
(gdb) x/s 0x404000                 # print string di alamat
(gdb) x/20b 0x404000               # 20 bytes
(gdb) x/10i $rip                   # 10 instruksi dari RIP
(gdb) x/10wx $rsp                  # 10 words (32-bit) hex
(gdb) x/10gx $rsp                  # 10 giant words (64-bit) hex

# Format: x/[jumlah][format][size]
# format: x(hex) d(decimal) s(string) i(instruction) c(char)
# size:   b(byte) h(halfword) w(word) g(giant/8byte)

# ==================================
# MODIFY RUNTIME
# ==================================
(gdb) set $rax = 1                 # ubah register
(gdb) set $rip = 0x401300          # jump ke alamat lain
(gdb) set {int}0x404060 = 42       # ubah memory
(gdb) set {char}0x404060 = 'A'     # ubah 1 byte memory

# ==================================
# DISASSEMBLE
# ==================================
(gdb) disassemble main             # disassemble fungsi
(gdb) disassemble $rip,+50         # disassemble 50 bytes dari RIP
(gdb) set disassembly-flavor intel # Intel syntax (lebih readable)

# ==================================
# SEARCHING
# ==================================
(gdb) find 0x400000,0x500000,"FLAG"       # cari string di range
(gdb) find /b 0x400000,0x500000,0x90,0x90 # cari byte pattern

# ==================================
# USEFUL
# ==================================
(gdb) vmmap                        # (pwndbg) memory map
(gdb) telescope $rsp 20            # (pwndbg) smart stack view
(gdb) context                      # (pwndbg) full context display
```

**Contoh: Bypass Password Check dengan GDB**

```bash
gdb ./challenge
(gdb) set disassembly-flavor intel
(gdb) break main
(gdb) run

# Cari fungsi validasi
(gdb) disassemble
# Misal terlihat:
#   0x401250: call   check_password
#   0x401255: test   eax, eax
#   0x401257: je     0x401280  (jump ke "Wrong!")

# Set breakpoint setelah check_password return
(gdb) break *0x401255
(gdb) continue
(gdb) set $eax = 1          # force return value = true
(gdb) continue
# → Program mencetak flag!
```

---

### 🔷 pwndbg (GDB Plugin)

**Apa itu**: Plugin GDB yang menampilkan register, stack, disassembly, dan memory secara otomatis setelah setiap step. Membuat GDB 10x lebih mudah digunakan.

**Instalasi:**

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
# Otomatis ter-load setiap kali gdb dijalankan
```

**Fitur Tambahan dari pwndbg:**

```bash
(gdb) context              # tampilkan full context (auto setiap step)
(gdb) telescope $rsp 30    # smart stack view dengan pointer dereferencing
(gdb) vmmap                # memory map (RWX permissions)
(gdb) search -s "FLAG"     # search string di seluruh memory
(gdb) hexdump $rsp 64      # hex dump yang rapi
(gdb) nearpc               # disassembly di sekitar PC
(gdb) canary               # cari stack canary value
(gdb) checksec             # cek binary protections
(gdb) got                  # tampilkan GOT entries
(gdb) plt                  # tampilkan PLT entries
(gdb) retaddr              # cari return addresses di stack
(gdb) cyclic 200           # generate De Bruijn pattern
(gdb) cyclic -l 0x61616166 # find offset in pattern
```

---

### 🔷 x64dbg (Windows)

**Apa itu**: Debugger GUI open-source untuk Windows 32/64-bit executables.

**Instalasi:**

```bash
# https://x64dbg.com/
# Download → extract → jalankan x96dbg.exe (launcher)
# Pilih x32dbg.exe atau x64dbg.exe tergantung target
```

**Cara Penggunaan:**

```
1. BUKA BINARY
   - File → Open → pilih .exe
   - Atau drag & drop
   - Program otomatis break di entry point

2. INTERFACE
   - Panel atas: CPU (disassembly + register + stack + dump)
   - Tab bawah: Breakpoints, Memory Map, Call Stack, Threads

3. BREAKPOINTS
   - Klik kiri di alamat → F2 (toggle breakpoint)
   - Atau: Ctrl+G → masukkan alamat → F2
   - Memory breakpoint: klik kanan di Dump → Breakpoint → Memory

4. NAVIGASI
   - F7: Step Into
   - F8: Step Over
   - F9: Run
   - Ctrl+F9: Run until return
   - Ctrl+G: Go to address
   - Space: Modify instruction (assembler!)

5. PATCHING
   - Klik instruksi → tekan Space → ketik assembly baru
   - Contoh: ganti "je 0x401280" → "jmp 0x401290"
   - File → Patch File → Apply ke binary baru

6. SEARCH
   - Ctrl+B: Search for binary pattern
   - Klik kanan → Search For → All Referenced Strings
   - Klik kanan → Search For → Current Module → Pattern

7. TIPS CTF
   - Klik kanan di string "Wrong" → Find References
   - Breakpoint di comparison sebelum jump
   - Modify register/flag di panel register (double-click)
   - ZF (Zero Flag): klik untuk toggle → bypass conditional jump
```

**Plugin Penting:**

```
- ScyllaHide: anti-anti-debug (bypass semua anti-debug Windows)
- x64dbg Plugin Manager: install plugins dengan mudah
- Snowman: decompiler terintegrasi
- SwissArmyKnife: auto-set breakpoints di common anti-debug API
```

---

### 🔷 WinDbg (Windows)

**Apa itu**: Debugger Microsoft untuk Windows. Support kernel-mode debugging.

**Instalasi:**

```bash
# Modern WinDbg (Preview) - dari Microsoft Store
# Atau: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
# Termasuk dalam Windows SDK
```

**Cara Penggunaan Dasar:**

```
File → Open Executable → pilih target

# Commands
g                    # go (run)
bp 0x401234          # breakpoint
bl                   # list breakpoints
t                    # trace (step into)
p                    # step over
r                    # show registers
r rax=1              # set register
db 0x404000          # display bytes
da 0x404000          # display ASCII string
du 0x404000          # display Unicode string
dd 0x404000          # display DWORDs
u 0x401000           # unassemble (disassemble)
s -a 0 L?80000000 "flag"  # search ASCII string
!peb                 # Process Environment Block
lm                   # list modules
```

---

## 3. Binary Analysis & Recon

Tools untuk analisis awal sebelum deep-dive.

---

### 🔷 file

**Apa itu**: Command untuk identifikasi tipe file berdasarkan magic bytes.

```bash
# Sudah ada di Linux/macOS
# Windows: install via Git Bash, WSL, atau MSYS2

file challenge
# Output contoh:
# challenge: ELF 64-bit LSB executable, x86-64, dynamically linked
# challenge: PE32+ executable (console) x86-64, for MS Windows
# challenge: Mach-O 64-bit x86_64 executable

file mystery_file
# mystery_file: Java class data, version 55.0 (Java 11)
# mystery_file: python 3.8 byte-compiled
# mystery_file: gzip compressed data
```

---

### 🔷 strings

**Apa itu**: Ekstrak semua printable strings dari binary.

```bash
# Basic
strings challenge                  # default: min 4 chars
strings -n 8 challenge             # min 8 chars
strings -a challenge               # scan entire file
strings challenge | grep -i flag   # cari "flag"
strings challenge | grep -i "pass\|key\|secret\|correct\|wrong"

# Encoding
strings -e l challenge             # 16-bit little-endian (Unicode)
strings -e b challenge             # 16-bit big-endian

# Windows (FLOSS - advanced string extraction)
# FLOSS juga extract strings yang di-obfuscate!
pip install flare-floss
floss challenge.exe
```

---

### 🔷 checksec

**Apa itu**: Cek security protections pada binary (ASLR, NX, canary, PIE, RELRO).

```bash
# Install
pip install pwntools    # checksec termasuk di pwntools

# Penggunaan
checksec ./challenge
# Output:
#   Arch:     amd64-64-little
#   RELRO:    Full RELRO
#   Stack:    Canary found
#   NX:       NX enabled
#   PIE:      PIE enabled

# Atau dari Python:
python3 -c "from pwn import *; print(ELF('./challenge').checksec())"
```

---

### 🔷 readelf & objdump

**Apa itu**: Tools standar untuk analisis file ELF (Linux executables).

```bash
# readelf — header & metadata
readelf -h challenge        # ELF header (arsitektur, entry point)
readelf -S challenge        # section headers (.text, .data, .rodata)
readelf -s challenge        # symbol table (fungsi + variabel)
readelf -d challenge        # dynamic section (shared libraries)
readelf -l challenge        # program headers (segments)
readelf --notes challenge   # build notes (compiler info)

# objdump — disassembly
objdump -d challenge                   # disassemble .text section
objdump -d -M intel challenge         # Intel syntax (lebih readable!)
objdump -d -j .text challenge         # section tertentu saja
objdump -t challenge                   # symbol table
objdump -R challenge                   # relocation entries
objdump -s -j .rodata challenge       # dump section contents (strings!)
```

---

### 🔷 ltrace & strace

**Apa itu**: Trace library calls (ltrace) dan system calls (strace) saat runtime.

```bash
# ltrace — library calls (strcmp, printf, malloc)
ltrace ./challenge
# Output contoh:
# printf("Enter password: ")
# fgets("hello\n", 100, stdin)
# strcmp("hello", "s3cr3t_fl4g")  ← FLAG LEAKED!
# puts("Wrong!")

ltrace -e strcmp ./challenge      # filter hanya strcmp
ltrace -s 200 ./challenge         # show 200 chars per string

# strace — system calls (open, read, write, mmap)
strace ./challenge
# Output contoh:
# openat(AT_FDCWD, "/tmp/.secret", O_RDONLY) = 3
# read(3, "flag{hidden_file}", 100) = 17

strace -e openat ./challenge     # filter hanya openat
strace -f ./challenge            # follow forked processes
strace -e trace=network ./challenge  # hanya network calls
```

> **💡 TIP**: **ltrace** adalah senjata rahasia di CTF! Banyak challenge sederhana yang langsung leak flag melalui `strcmp()` call. SELALU coba ltrace terlebih dahulu.

---

### 🔷 binwalk

**Apa itu**: Analisis & extract embedded files/data dalam binary.

```bash
# Install
sudo apt install binwalk
pip install binwalk

# Penggunaan
binwalk challenge            # scan untuk embedded files
# Output:
# DECIMAL    HEXADECIMAL  DESCRIPTION
# 0          0x0          ELF, 64-bit LSB executable
# 53248      0xD000       Zip archive data
# 65536      0x10000      PNG image

binwalk -e challenge         # extract semua embedded files
binwalk --dd='.*' challenge  # extract SEMUA tanpa filter
binwalk -E challenge         # entropy analysis (detect encrypted)

# Contoh: firmware challenge
binwalk -e firmware.bin
cd _firmware.bin.extracted/
ls  # mungkin ada filesystem, config, keys
```

---

## 4. Constraint Solver & Symbolic Execution

---

### 🔷 Z3 (Python)

**Apa itu**: SMT solver dari Microsoft. Memecahkan constraint matematis/logika — "cari input yang memenuhi semua kondisi ini."

**Instalasi:**

```bash
pip install z3-solver
```

**Cara Penggunaan Lengkap:**

```python
from z3 import *

# ============================================
# BASIC: Buat variabel & constraint
# ============================================

# Integer
x = Int('x')
y = Int('y')
s = Solver()
s.add(x + y == 10)
s.add(x - y == 4)
if s.check() == sat:
    print(s.model())  # [x = 7, y = 3]

# BitVector (untuk operasi binary: XOR, shift, overflow)
a = BitVec('a', 8)    # 8-bit variable
b = BitVec('b', 8)
s = Solver()
s.add(a ^ b == 0x37)
s.add(a + b == 0xCA)
if s.check() == sat:
    m = s.model()
    print(f"a={m[a]}, b={m[b]}")

# ============================================
# CTF PATTERN: Solve flag character by character
# ============================================

flag = [BitVec(f'f{i}', 8) for i in range(20)]  # 20-char flag
s = Solver()

# Constraint: printable ASCII
for c in flag:
    s.add(c >= 32, c <= 126)

# Constraint: flag format
s.add(flag[0] == ord('f'))
s.add(flag[1] == ord('l'))
s.add(flag[2] == ord('a'))
s.add(flag[3] == ord('g'))
s.add(flag[4] == ord('{'))
s.add(flag[19] == ord('}'))

# Constraint dari decompiled validation:
# for (i=5; i<19; i++) { if ((flag[i] * 7 + 3) ^ key[i] != expected[i]) return 0; }
key      = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
expected = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]

for i in range(14):
    s.add(((flag[i+5] * 7 + 3) ^ key[i]) & 0xFF == expected[i])

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[flag[i]].as_long()) for i in range(20))
    print(f"Flag: {result}")

# ============================================
# ADVANCED: Matrix constraints
# ============================================
from z3 import *
flag = [BitVec(f'f{i}', 32) for i in range(4)]
s = Solver()

# Matrix multiplication: M * flag == target
M = [[1,2,3,4], [5,6,7,8], [9,10,11,12], [13,14,15,16]]
target = [0x1234, 0x5678, 0x9ABC, 0xDEF0]

for row in range(4):
    expr = sum(M[row][col] * flag[col] for col in range(4))
    s.add(expr == target[row])
```

---

### 🔷 angr

**Apa itu**: Framework symbolic execution. Otomatis "jelajahi" semua path eksekusi program dan cari input yang menuju target.

**Instalasi:**

```bash
pip install angr
```

**Cara Penggunaan:**

```python
import angr
import claripy

# ============================================
# BASIC: Find path to "Correct!" / avoid "Wrong!"
# ============================================

proj = angr.Project('./challenge', auto_load_libs=False)

# Mulai dari entry point
state = proj.factory.entry_state()

# Buat simulation manager
simgr = proj.factory.simgr(state)

# Cari path yang sampai ke alamat "Correct!" dan hindari "Wrong!"
simgr.explore(
    find=0x401234,    # alamat instruksi yang print "Correct!"
    avoid=0x401280    # alamat instruksi yang print "Wrong!"
)

if simgr.found:
    found_state = simgr.found[0]
    print(found_state.posix.dumps(0))  # stdin = flag

# ============================================
# ADVANCED: Symbolic argv + constraints
# ============================================

proj = angr.Project('./challenge', auto_load_libs=False)

# Buat symbolic input (contoh: 32-byte key)
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.entry_state(
    args=['./challenge', flag],
    add_options=angr.options.unicorn  # speedup dengan Unicorn engine
)

# Constraint: printable ASCII only
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401280)

if simgr.found:
    s = simgr.found[0]
    solution = s.solver.eval(flag, cast_to=bytes)
    print(f"Flag: {solution}")

# ============================================
# TIPS:
# - find/avoid bisa list: find=[0x401234, 0x401300]
# - Gunakan lambda: find=lambda s: b"Correct" in s.posix.dumps(1)
# - Jika lambat: batasi explore depth atau gunakan DFS
# ============================================
```

> **⚠️ PENTING — Z3 vs angr**: Gunakan **Z3** jika kamu sudah bisa membaca dan merekonstruksi constraint dari decompiled code. Gunakan **angr** jika binary terlalu kompleks untuk dianalisis manual — angr otomatis explore semua path.

---

## 5. Dynamic Instrumentation

---

### 🔷 Frida

**Apa itu**: Framework dynamic instrumentation cross-platform. Bisa hook, intercept, dan modify fungsi saat runtime tanpa perlu recompile.

**Instalasi:**

```bash
# CLI tools (host machine)
pip install frida-tools

# Server (untuk mobile — jalankan di device)
# Download dari: https://github.com/frida/frida/releases

# Android:
adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

**Cara Penggunaan:**

```bash
# LIST PROSES
frida-ps                           # list proses lokal
frida-ps -U                        # list proses di USB device (Android/iOS)
frida-ps -U | grep challenge       # cari proses target

# ATTACH KE PROSES
frida -p 1234 -l hook.js           # attach ke PID
frida -n "challenge" -l hook.js    # attach by name
frida -U -f com.ctf.app -l hook.js --no-pause  # spawn app (mobile)

# TRACE FUNGSI
frida-trace -i "strcmp" ./challenge           # trace strcmp calls
frida-trace -i "open*" ./challenge            # trace semua fungsi "open..."
frida-trace -U -i "check*" com.ctf.app       # trace di mobile
```

**Script Frida (JavaScript):**

```javascript
// ============================================
// HOOK NATIVE FUNCTION (C/C++)
// ============================================

// Hook strcmp — leak password comparison
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        var arg0 = Memory.readUtf8String(args[0]);
        var arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${arg0}", "${arg1}")`);
    },
    onLeave: function(retval) {
        retval.replace(0);  // Force strcmp return 0 (strings equal)
    }
});

// ============================================
// HOOK JAVA METHOD (Android)
// ============================================

Java.perform(function() {
    var MainActivity = Java.use("com.challenge.ctf.MainActivity");

    // Hook method checkFlag
    MainActivity.checkFlag.implementation = function(input) {
        console.log("[*] checkFlag called: " + input);
        var result = this.checkFlag(input);
        console.log("[*] Result: " + result);
        return true;  // bypass check
    };

    // Hook constructor
    var SecretKey = Java.use("com.ctf.challenge.SecretKey");
    SecretKey.$init.overload('java.lang.String').implementation = function(key) {
        console.log("[*] SecretKey created with: " + key);
        this.$init(key);
    };

    // Enumerate loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("ctf") || className.includes("flag")) {
                console.log("[*] Found: " + className);
            }
        },
        onComplete: function() {}
    });

    // Call method langsung (tanpa interaksi UI)
    Java.choose("com.ctf.challenge.FlagGenerator", {
        onMatch: function(inst) {
            console.log("[*] Flag: " + inst.getFlag());
        },
        onComplete: function() {}
    });
});

// ============================================
// HOOK NATIVE FUNGSI DI SPECIFIC LIBRARY
// ============================================

var base = Module.findBaseAddress("libchallenge.so");
console.log("Base: " + base);

// Hook fungsi di offset tertentu
Interceptor.attach(base.add(0x1234), {
    onEnter: function(args) {
        console.log("[*] Called with: " + args[0] + ", " + args[1]);
        console.log("[*] String arg: " + Memory.readUtf8String(args[0]));
        console.log(hexdump(args[0], {length: 64}));
    },
    onLeave: function(retval) {
        console.log("[*] Return: " + retval);
    }
});

// ============================================
// MEMORY MANIPULATION
// ============================================

// Baca memory
var data = Memory.readByteArray(ptr("0x401000"), 32);
console.log(hexdump(data));

// Tulis memory
Memory.writeUtf8String(ptr("0x404000"), "patched_string");

// Scan memory untuk pattern
Memory.scan(base, 0x10000, "48 89 E5 ?? ?? 48 83", {
    onMatch: function(address, size) {
        console.log("Found at: " + address);
    },
    onComplete: function() {}
});
```

---

### 🔷 objection

**Apa itu**: Wrapper Frida yang mempermudah common mobile RE tasks.

```bash
pip install objection

# Penggunaan
objection -g com.ctf.app explore

# Dalam objection REPL:
    android sslpinning disable         # bypass SSL pinning
    android root disable               # bypass root detection
    android hooking list classes        # list semua class
    android hooking list class_methods com.ctf.challenge.MainActivity
    android hooking watch class_method com.ctf.challenge.MainActivity.checkFlag --dump-args --dump-return
    memory dump all dump/              # dump semua memory
    android keystore list              # list keystore entries
```

---

## 6. Bytecode Decompiler

---

### 🔷 jadx (Java/Android)

**Apa itu**: Decompiler DEX/APK/JAR → readable Java source code. Tool #1 untuk Android RE.

**Instalasi:**

```bash
# Download: https://github.com/skylot/jadx/releases
# Atau:
sudo apt install jadx
brew install jadx           # macOS
```

**Cara Penggunaan:**

```bash
# GUI mode (recommended untuk CTF)
jadx-gui challenge.apk
# - Browse class tree di panel kiri
# - Double-click class → lihat decompiled Java
# - Ctrl+F: search di file
# - Navigation → Text Search (Ctrl+Shift+F): search SEMUA files
# - Navigation → Usage Search: find references

# CLI mode
jadx challenge.apk -d output/      # decompile ke folder
jadx --show-bad-code challenge.apk  # tampilkan meskipun error decompile
jadx --deobf challenge.apk          # auto rename obfuscated names

# Tips CTF:
# 1. Buka APK di jadx-gui
# 2. Text Search → cari "flag", "secret", "password", "key"
# 3. Cari class yang handle user input
# 4. Trace ke fungsi validasi
# 5. Pahami logika → solve
```

---

### 🔷 uncompyle6 / decompyle3 / pycdc (Python)

**Apa itu**: Decompile Python bytecode (.pyc) kembali ke source code.

```bash
# Install
pip install uncompyle6     # Python 2.7-3.8
pip install decompyle3     # Python 3.7-3.9

# Penggunaan
uncompyle6 challenge.pyc > challenge.py
decompyle3 challenge.pyc > challenge.py

# Untuk Python 3.9+: gunakan pycdc (Decompyle++)
git clone https://github.com/zrax/pycdc
cd pycdc && cmake . && make
./pycdc challenge.pyc > challenge.py

# Manual disassemble (jika decompiler gagal)
python3 -c "
import dis, marshal
with open('challenge.pyc', 'rb') as f:
    magic = f.read(4)
    flags = f.read(4)
    timestamp = f.read(4)
    size = f.read(4)
    code = marshal.load(f)
dis.dis(code)
"

# Tips: jika pyc header corrupt, fix magic number:
# Python 3.8:  b'\x55\x0d\x0d\x0a'
# Python 3.9:  b'\x61\x0d\x0d\x0a'
# Python 3.10: b'\x6f\x0d\x0d\x0a'
# Python 3.11: b'\xa7\x0d\x0d\x0a'
```

---

### 🔷 dnSpy (.NET)

**Apa itu**: Decompiler + debugger untuk .NET (C#/VB.NET). Bisa decompile, edit, debug, dan rebuild .NET assemblies.

**Instalasi:**

```bash
# Fork aktif: https://github.com/dnSpyEx/dnSpy/releases
# Download → extract → jalankan dnSpy.exe (Windows only)
```

**Cara Penggunaan:**

```
1. BUKA ASSEMBLY
   - File → Open → pilih .exe atau .dll
   - Assembly Explorer (kiri): browse namespace, class, method
   - Klik method → lihat decompiled C# code

2. SEARCH
   - Edit → Search Assemblies (Ctrl+Shift+K)
   - Cari: "flag", "password", method names, string literals

3. DECOMPILE
   - C# decompilation biasanya SANGAT baik di .NET
   - Bisa pilih bahasa: C#, VB, IL
   - Right-click → Go To → Analyzer → lihat who calls this method

4. DEBUGGING (sangat powerful!)
   - Debug → Start Debugging (F5)
   - Set breakpoint: klik di margin kiri
   - Inspect variabel: hover atau Locals window
   - Bisa debug entry point, constructor, any method
   - Watch window: tambahkan ekspresi custom

5. EDIT & RECOMPILE
   - Klik kanan method → Edit Method Body (IL)
   - Atau: Edit Method (C#) — edit dalam C# langsung!
   - File → Save Module → simpan sebagai file baru
   - Sangat berguna untuk patching .NET challenges

6. CONTOH CTF
   - Buka challenge.exe di dnSpy
   - Cari method "CheckPassword" atau similar
   - Baca logika validasi → solve
   - ATAU: edit method untuk return true → save → run
```

> **💡 TIP**: **dnSpy** adalah tool paling powerful untuk .NET RE. Hampir semua .NET challenge bisa di-solve hanya dengan dnSpy karena decompilasi .NET hampir sempurna.

---

### 🔷 de4dot (.NET Deobfuscator)

**Apa itu**: Otomatis deobfuscate .NET assemblies.

```bash
# https://github.com/de4dot/de4dot
de4dot challenge_obfuscated.exe
# Output: challenge_obfuscated-cleaned.exe

# Supported: ConfuserEx, Dotfuscator, SmartAssembly, Babel.NET, dll.
```

---

## 7. Mobile RE Tools

---

### 🔷 apktool (Android)

**Apa itu**: Decode APK ke smali code + resources, dan rebuild APK.

```bash
# Install: https://apktool.org/docs/install
# Atau: sudo apt install apktool

# DECODE APK
apktool d challenge.apk -o decoded/
# Hasilnya:
# decoded/
# ├── AndroidManifest.xml    ← permissions, activities, entry points
# ├── smali/                 ← Dalvik bytecode (editable!)
# ├── res/                   ← resources (layouts, strings, images)
# └── assets/                ← raw assets (databases, configs)

# INSPECT
cat decoded/AndroidManifest.xml
grep -r "flag\|secret" decoded/res/
grep -r "flag\|secret" decoded/smali/

# MODIFY SMALI (binary patching untuk Android)
# Contoh: bypass check
# Sebelum:
#   invoke-virtual {p0, p1}, Lcom/ctf/MainActivity;->checkFlag(...)Z
#   move-result v0
#   if-eqz v0, :wrong
# Sesudah:
#   const/4 v0, 0x1        ← force v0 = true
#   if-eqz v0, :wrong      ← never jumps

# REBUILD APK
apktool b decoded/ -o patched.apk

# SIGN APK
keytool -genkey -v -keystore debug.keystore -alias debug \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass password -keypass password -dname "CN=Debug"

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
    -keystore debug.keystore patched.apk debug

# INSTALL
adb install patched.apk
```

---

### 🔷 Blutter (Flutter/Dart AOT)

**Apa itu**: Analyzer untuk Dart AOT snapshot di Flutter apps.

```bash
# Install
git clone https://github.com/worawit/blutter
cd blutter
python3 setup.py

# Penggunaan
apktool d flutter_app.apk -o extracted/
python3 blutter.py extracted/lib/arm64-v8a/ output/

# Output:
# output/
# ├── asm/              ← readable assembly per class
# ├── pp.txt            ← Object pool (strings, constants)
# ├── objs.txt          ← Dart objects info
# └── blutter_frida.js  ← auto-generated Frida hooks!

# Analisis
cat output/pp.txt | grep -i "flag\|key\|secret"
cat output/asm/com.ctf.challenge/FlagChecker.dart

# Hook dengan auto-generated Frida script
frida -U -f com.ctf.flutter -l output/blutter_frida.js
```

---

### 🔷 Il2CppDumper (Unity IL2CPP)

**Apa itu**: Extract metadata dari Unity IL2CPP builds.

```bash
# Download: https://github.com/Perfare/Il2CppDumper/releases

# File yang dibutuhkan:
#   Android: lib/arm64-v8a/libil2cpp.so + assets/.../global-metadata.dat
#   iOS: UnityFramework + global-metadata.dat

# Jalankan
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/

# Output:
# output/
# ├── dump.cs              ← C# class definitions
# ├── script.json          ← method addresses
# ├── stringliteral.json   ← semua string literals
# └── DummyDll/            ← dummy DLLs untuk dnSpy

grep -n "flag\|Flag\|password\|key" output/dump.cs

# Alternatif: Cpp2IL (lebih modern)
Cpp2IL --game-path . --exe-name libil2cpp.so
```

---

### 🔷 MobSF (Mobile Security Framework)

**Apa itu**: Automated static & dynamic analysis untuk mobile apps (Android + iOS).

```bash
# Install via Docker (recommended)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Buka browser → http://localhost:8000
# Upload APK/IPA → otomatis analisis:
# - Permissions analysis
# - Code analysis (hardcoded secrets, API keys)
# - Malware indicators
# - Binary protections check
# - String extraction
```

---

## 8. Packer & Obfuscation Tools

---

### 🔷 UPX

**Apa itu**: Packer paling umum di CTF.

```bash
# Install
sudo apt install upx

# Deteksi
strings challenge | grep -i upx

# Unpack
upx -d challenge -o challenge_unpacked

# Jika UPX header dimodifikasi:
python3 << 'EOF'
data = bytearray(open('challenge', 'rb').read())
# Fix UPX magic bytes: "UPX!" = 55 50 58 21
# Cari dan perbaiki lokasi yang dirusak
open('fixed_challenge', 'wb').write(data)
EOF
upx -d fixed_challenge
```

---

### 🔷 DIE (Detect It Easy)

**Apa itu**: Identifier tool — deteksi compiler, packer, protector.

```bash
# Download: https://github.com/horsicq/Detect-It-Easy/releases

# CLI
diec challenge.exe
# Output:
#   PE64
#   Compiler: Microsoft Visual C/C++(2019)
#   Packer: UPX(3.96)
#   Linker: Microsoft Linker(14.29)

diec -a challenge      # deep analysis
```

---

### 🔷 FLOSS (FireEye Labs Obfuscated String Solver)

**Apa itu**: Extract strings termasuk yang di-obfuscate (XOR, stack strings, dll.)

```bash
pip install flare-floss

floss challenge.exe
# Output: static strings + decoded obfuscated strings + stack strings
# Bisa menemukan strings yang tidak terlihat oleh `strings` biasa!
```

---

## 9. Hex Editor & Patching

---

### 🔷 radare2 (r2)

**Apa itu**: Framework RE open-source — disassembly, debugging, patching, analysis.

```bash
# Install
sudo apt install radare2

# ANALISIS
r2 ./challenge
[0x00401000]> aaa          # analyze all
[0x00401000]> afl          # list all functions
[0x00401000]> s main       # seek to main
[0x00401000]> pdf          # print disassembly of function
[0x00401000]> VV           # visual graph mode

# STRINGS
[0x00401000]> iz           # strings di data section
[0x00401000]> izz          # strings di seluruh binary
[0x00401000]> / flag       # search string "flag"
[0x00401000]> /x 90909090  # search hex pattern

# CROSS-REFERENCES
[0x00401000]> axt @@ str.* # xrefs ke semua strings

# PATCHING (mode write)
r2 -w ./challenge
[0x00401234]> wx 90909090              # write NOP bytes
[0x00401234]> wa jmp 0x401300          # write assembly
[0x00401234]> wa nop                   # write NOP
[0x00401234]> "wa ret"                 # write return

# DEBUGGING
r2 -d ./challenge
[0x7f...]> db 0x401234                 # set breakpoint
[0x7f...]> dc                          # continue
[0x7f...]> dr                          # show registers
[0x7f...]> dr rax=1                    # set register
[0x7f...]> px 64 @ rsp                 # hexdump
[0x7f...]> ds                          # step
```

---

### 🔷 Hex Editors

**HxD** (Windows, gratis):
```
- Download: https://mh-nexus.de/en/hxd/
- Buka file → lihat hex + ASCII side by side
- Ctrl+F: search hex/string
- Ctrl+H: search & replace
- Ctrl+G: go to offset
```

**010 Editor** (cross-platform, berbayar):
```
- Download: https://www.sweetscape.com/010editor/
- Fitur utama: Binary Templates (auto-parse file format!)
- Template library: ELF, PE, PNG, ZIP, dll.
- Regex search & replace
- Scripting support
```

**ImHex** (cross-platform, gratis):
```
- Download: https://imhex.werwolv.net/
- Modern UI, mirip 010 Editor
- Pattern language untuk define struct
- Built-in hash calculator
- Data processor (transform data visually)
```

---

## 10. Emulator & Sandbox

---

### 🔷 QEMU

**Apa itu**: Emulator untuk menjalankan binary arsitektur asing di x86 machine.

```bash
# Install
sudo apt install qemu-user qemu-user-static qemu-system-arm

# USER MODE — jalankan single binary
qemu-arm ./challenge_arm32
qemu-aarch64 ./challenge_arm64
qemu-mips ./challenge_mips
qemu-mipsel ./challenge_mipsel

# Dengan sysroot
qemu-arm -L /usr/arm-linux-gnueabihf/ ./challenge_arm32

# Debug via QEMU
qemu-arm -g 1234 ./challenge_arm &
gdb-multiarch ./challenge_arm
(gdb) target remote localhost:1234
(gdb) break main
(gdb) continue

# SYSTEM MODE — emulasi full system
qemu-system-arm -M versatilepb -kernel zImage \
    -drive file=rootfs.img -append "root=/dev/sda" -nographic
```

---

### 🔷 Unicorn Engine

**Apa itu**: Lightweight CPU emulator. Menjalankan potongan assembly tanpa OS.

```bash
pip install unicorn
```

```python
from unicorn import *
from unicorn.x86_const import *

# Machine code yang ingin diemulasi
CODE = b'\x31\xc0\x48\x89\xc1...'

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map memory
BASE = 0x400000
mu.mem_map(BASE, 0x10000)
mu.mem_write(BASE, CODE)

# Setup stack
STACK = 0x7fff0000
mu.mem_map(STACK - 0x10000, 0x20000)
mu.reg_write(UC_X86_REG_RSP, STACK)

# Tulis input ke memory
INPUT_ADDR = 0x500000
mu.mem_map(INPUT_ADDR, 0x1000)
mu.mem_write(INPUT_ADDR, b"encrypted_data_here")
mu.reg_write(UC_X86_REG_RDI, INPUT_ADDR)

# Hook (optional: trace execution)
def hook_code(mu, address, size, user_data):
    print(f"Executing: 0x{address:x}")
mu.hook_add(UC_HOOK_CODE, hook_code)

# Emulasi!
mu.emu_start(BASE, BASE + len(CODE))

# Baca hasil
result = mu.mem_read(INPUT_ADDR, 32)
print(f"Decrypted: {result}")
```

---

## 11. Tambahan & Utility

---

### 🔷 CyberChef

**Apa itu**: "Swiss Army Knife" untuk encoding/decoding. Web-based, 300+ operasi.

```
URL: https://gchq.github.io/CyberChef/

Operasi berguna:
- From Hex / To Hex
- From Base64 / To Base64 (+ custom alphabet!)
- XOR / XOR Brute Force
- ROT13 / ROT47
- URL Decode
- Gunzip / Unzip
- AES/DES Decrypt
- Magic (auto-detect encoding!)

Tips: chain multiple operasi di "Recipe"
Contoh: From Hex → XOR(key=0x42) → From Base64 → hasil!
```

---

### 🔷 pwntools (Python)

**Apa itu**: Library Python serba guna untuk CTF.

```python
from pwn import *

# CONNECT & INTERACT
r = remote('ctf.example.com', 1337)     # remote
p = process('./challenge')               # local
r.recvuntil(b'Enter password:')
r.sendline(b'my_answer')
response = r.recvline()
print(response)
r.interactive()

# BINARY MANIPULATION
elf = ELF('./challenge')
print(hex(elf.symbols['main']))
print(hex(elf.got['puts']))
print(hex(elf.plt['puts']))
print(elf.checksec())

# PACKING / UNPACKING
p64(0xdeadbeef)                          # pack 64-bit LE
p32(0xcafebabe)                          # pack 32-bit
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')  # unpack

# SHELLCODE
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

# UTILITIES
xor(b'hello', b'key')                   # XOR bytes
cyclic(100)                              # De Bruijn pattern
cyclic_find(0x61616166)                  # find offset
flat(0x41414141, 0x42424242)             # flatten data
enhex(b'hello')                          # bytes to hex
unhex('68656c6c6f')                      # hex to bytes
```

---

### 🔷 Ghidra Scripts (Python/Java)

```python
# Contoh: list semua string references
from ghidra.program.util import DefinedDataIterator

for data in DefinedDataIterator.definedStrings(currentProgram):
    print(f"{data.getAddress()}: {data.getValue()}")

# Contoh: cari referensi ke string yang mengandung "flag"
for data in DefinedDataIterator.definedStrings(currentProgram):
    if "flag" in str(data.getValue()).lower():
        refs = getReferencesTo(data.getAddress())
        for ref in refs:
            print(f"'{data.getValue()}' referenced at {ref.getFromAddress()}")
```

---

### 🔷 GoReSym (Golang)

**Apa itu**: Extract metadata dari Go binaries (function names, types, source paths).

```bash
# Download: https://github.com/mandiant/GoReSym/releases

GoReSym -t -d -p challenge > metadata.json
# Output: structured JSON with all Go symbols
```

---

### 🔷 rustfilt (Rust)

**Apa itu**: Demangle Rust symbol names.

```bash
cargo install rustfilt

# Penggunaan
echo "_ZN4core3fmt3num52_$LT$impl..." | rustfilt
# Output: core::fmt::num::<impl ...>

# Atau pipe dari objdump/nm
nm challenge | rustfilt
objdump -d challenge | rustfilt
```

---

## 📊 Tool Selection Cheat Sheet

| Situasi | Tool Pertama | Tool Kedua |
|---------|-------------|------------|
| ELF Linux binary | Ghidra | GDB + pwndbg |
| Windows PE | IDA Free / x64dbg | Ghidra |
| APK Android | jadx-gui | apktool + Frida |
| iOS IPA | class-dump + Hopper | Frida |
| .NET exe/dll | dnSpy | de4dot (jika obfuscated) |
| Python .pyc | uncompyle6/pycdc | dis module |
| Java .jar/.class | jadx / jd-gui | javap |
| Flutter app | Blutter | Frida |
| Unity IL2CPP | Il2CppDumper | Ghidra |
| Packed binary | DIE → upx -d | Manual unpack + GDB |
| ARM binary di x86 | QEMU | gdb-multiarch |
| Encoding/crypto | CyberChef | Python script |
| Constraint solving | Z3 | angr |
| CTF networking | pwntools | netcat |
| Obfuscated strings | FLOSS | CyberChef XOR brute |
| Golang binary | GoReSym + Ghidra | GDB |
| Rust binary | rustfilt + Ghidra | GDB |

---

> **💡 Untuk pemula**: mulai kuasai **5 tools ini** dulu:
> 1. **Ghidra** — disassembly & decompile segalanya
> 2. **GDB + pwndbg** — dynamic debugging
> 3. **strings + file + ltrace** — quick recon
> 4. **Python (Z3 + pwntools)** — scripting & solving
> 5. **CyberChef** — encoding/decoding cepat
>
> Setelah nyaman, perluas ke Frida, angr, dan tools mobile.
