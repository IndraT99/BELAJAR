# 🏴 CTF Jeopardy — Reverse Engineering: Panduan Lengkap

Panduan langkah-langkah penyelesaian CTF Jeopardy untuk setiap kategori Reverse Engineering.

---

## Daftar Isi

1. [Static Analysis & Reconstruct Algorithm (Z3)](#1-static-analysis--reconstruct-algorithm-z3-solver)
2. [Dynamic Analysis (Tracing & GDB)](#2-dynamic-analysis-tracing--gdb)
3. [Low Level File Formats (Assembly & Bytecodes)](#3-low-level-file-formats-assembly--bytecodes)
4. [Anti-RE Techniques](#4-anti-re-techniques)
5. [Compiled Language Patterns in Executables](#5-compiled-language-patterns-in-executables)
6. [Arsitektur: x86_64, x64, ARM](#6-arsitektur-x86_64-x64-arm)
7. [Special Frameworks](#7-special-frameworks)
8. [Obfuscation & Binary Patching](#8-obfuscation--binary-patching)
9. [Mobile Reverse Engineering](#9-mobile-reverse-engineering)
10. [General Methodology Cheat Sheet](#-general-ctf-re-methodology--cheat-sheet)

---

## 1. Static Analysis & Reconstruct Algorithm (Z3 Solver)

### Kapan Digunakan

Ketika binary melakukan **validasi input** melalui serangkaian operasi matematis/logika yang kompleks — misal: "masukkan key yang memenuhi 20 constraint sekaligus."

### Workflow

```
Binary → Disassemble (IDA/Ghidra) → Identifikasi Fungsi Validasi
→ Ekstrak Constraint → Modelkan di Z3 → Solve → Flag
```

#### Step 1: Identifikasi Binary

```bash
file challenge_binary
strings challenge_binary | grep -i "flag\|correct\|wrong\|input"
```

#### Step 2: Load ke Disassembler

- **Ghidra** (gratis) atau **IDA Pro** (berbayar)
- Cari fungsi `main()` → trace alur ke fungsi validasi
- Perhatikan pattern: `if (check(input)) → "Correct!"`

#### Step 3: Decompile & Pahami Algoritma

- Gunakan decompiler (Ghidra → "Decompile" window, IDA → F5)
- Identifikasi operasi pada input: XOR, shift, add, multiply, modulo, dll.
- Catat semua constraint (kondisi if/else)

#### Step 4: Modelkan dengan Z3 (Python)

```python
from z3 import *

# Buat symbolic variables untuk setiap karakter input
flag = [BitVec(f'f{i}', 8) for i in range(32)]
s = Solver()

# Constraint: printable ASCII
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# Constraint dari binary (contoh)
s.add(flag[0] ^ flag[1] == 0x37)
s.add(flag[2] + flag[3] == 0xCA)
s.add(flag[0] * 3 + flag[4] == 0x1B2)
# ... tambahkan semua constraint yang ditemukan

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[c].as_long()) for c in flag)
    print(f"Flag: {result}")
else:
    print("UNSAT - cek ulang constraint")
```

#### Step 5: Advanced Z3 Patterns

```python
# Untuk loop/array operations
from z3 import *

flag = [BitVec(f'f{i}', 32) for i in range(16)]
s = Solver()

# Reconstruct loop dari decompiled code:
# for (i=0; i<16; i++) { result[i] = (input[i] * 7 + 3) ^ key[i]; }
key = [0x4a, 0x3f, 0x12, ...]  # dari binary
expected = [0x7c, 0x9a, 0x55, ...]  # expected output

for i in range(16):
    s.add(((flag[i] * 7 + 3) ^ key[i]) & 0xFF == expected[i])
```

> **💡 Z3 vs Angr**: Gunakan Z3 jika constraint sudah jelas terlihat dari decompiled code. Gunakan **angr** (symbolic execution) jika alur programnya terlalu kompleks untuk direkonstruksi manual.

### Tools

| Tool | Fungsi |
|------|--------|
| Ghidra / IDA Pro | Disassembly & Decompilation |
| Z3 (Python) | Constraint solving |
| angr | Symbolic execution otomatis |
| Binary Ninja | Alternatif disassembler |

---

## 2. Dynamic Analysis (Tracing & GDB)

### Kapan Digunakan

Ketika static analysis terlalu sulit (obfuscated, self-modifying code, packed binary), atau perlu melihat **state runtime** (register, memory, return value).

### Workflow

```
Binary → Run dengan GDB → Set Breakpoint di fungsi kritis
→ Inspect register/memory → Trace eksekusi → Ekstrak flag
```

#### Step 1: Recon Awal

```bash
file challenge
checksec challenge          # cek proteksi (PIE, ASLR, canary)
ltrace ./challenge          # trace library calls
strace ./challenge          # trace system calls
```

#### Step 2: GDB Basics

```bash
gdb ./challenge

# Dalam GDB:
(gdb) info functions                    # list semua fungsi
(gdb) disassemble main                  # disassemble main
(gdb) break *0x401234                   # breakpoint di alamat
(gdb) break check_password              # breakpoint di fungsi
(gdb) run                               # jalankan program
(gdb) run <<< "test_input"              # jalankan dengan input
```

#### Step 3: Inspect State saat Breakpoint

```bash
(gdb) info registers                    # lihat semua register
(gdb) x/20x $rsp                        # examine 20 hex words di stack
(gdb) x/s $rdi                          # print string di RDI
(gdb) x/32bx 0x404060                   # examine 32 bytes di alamat
(gdb) print $rax                        # print nilai RAX
(gdb) telescope $rsp 20                 # (pwndbg) stack visualization
```

#### Step 4: Kontrol Eksekusi

```bash
(gdb) ni                                # next instruction (skip call)
(gdb) si                                # step into (masuk call)
(gdb) finish                            # jalankan sampai return
(gdb) continue                          # lanjut ke breakpoint berikut
(gdb) set $rax = 1                      # modify register (bypass check!)
(gdb) set {int}0x404060 = 0x1           # modify memory
(gdb) jump *0x401300                    # lompat ke alamat tertentu
```

#### Step 5: Bypass Validation dengan GDB

```bash
# Jika ada: cmp eax, 0 → je fail
# Set breakpoint SEBELUM comparison, lalu:
(gdb) break *0x40128a
(gdb) run
(gdb) set $eax = 0          # atau nilai yang diharapkan
(gdb) continue
# → Program melanjutkan ke branch "correct" → cetak flag
```

#### Step 6: Advanced — GDB Scripting

```python
# gdb_script.py — jalankan: gdb -x gdb_script.py ./challenge
import gdb

gdb.execute("break *0x401234")
gdb.execute("run <<< 'AAAA'")

rax = int(gdb.parse_and_eval("$rax"))
print(f"RAX = {hex(rax)}")

# Automasi: trace setiap iterasi loop
for i in range(256):
    gdb.execute(f"set $rdi = {i}")
    gdb.execute("continue")
    result = int(gdb.parse_and_eval("$rax"))
    if result == 1:
        print(f"Found: {chr(i)}")
        break
```

> **💡 Gunakan GDB plugins** untuk pengalaman lebih baik:
> - **pwndbg**: Visualisasi stack, heap, register yang sangat baik
> - **GEF**: Fitur serupa pwndbg, lebih ringan
> - **peda**: Plugin classic, masih banyak dipakai

### Tracing Tools Lainnya

| Tool | Platform | Keunggulan |
|------|----------|------------|
| `ltrace` | Linux | Trace library calls (strcmp, malloc) |
| `strace` | Linux | Trace syscalls (open, read, write) |
| `x64dbg` | Windows | Debugger GUI untuk Windows PE |
| `WinDbg` | Windows | Kernel + user-mode debugging |
| `Frida` | Cross-platform | Dynamic instrumentation, hook fungsi |
| `DynamoRIO` | Cross-platform | Binary instrumentation framework |

---

## 3. Low Level File Formats (Assembly & Bytecodes)

### Kapan Digunakan

Ketika challenge memberikan file selain ELF/PE biasa — misal: bytecode custom VM, Java `.class`, Python `.pyc`, .NET `.dll`, WebAssembly `.wasm`.

### Workflow per Format

#### A. ELF (Linux) & PE (Windows)

```bash
# Identifikasi
file challenge
readelf -h challenge        # ELF header
readelf -S challenge        # sections (.text, .data, .rodata)
objdump -d challenge        # full disassembly
objdump -d -M intel challenge  # Intel syntax

# PE (Windows)
python3 -c "import pefile; pe=pefile.PE('challenge.exe'); print(pe.dump_info())"
```

#### B. Java Bytecode (.class / .jar)

```bash
# Decompile
javap -c -p Challenge.class              # disassemble bytecode
jadx challenge.jar                        # decompile ke Java source
cfr challenge.jar                         # alternatif decompiler
jd-gui challenge.jar                      # GUI decompiler

# Contoh bytecode → source mapping:
# bipush 42        →   int x = 42;
# iload_1          →   load local var 1
# if_icmpne 0x20   →   if (a != b) goto 0x20
```

#### C. Python Bytecode (.pyc)

```bash
# Decompile
uncompyle6 challenge.pyc                  # Python 2.7-3.8
decompyle3 challenge.pyc                  # Python 3.7-3.9
pycdc challenge.pyc                       # Decompyle++ (wider version support)

# Manual disassemble
python3 -c "
import dis, marshal, types
with open('challenge.pyc', 'rb') as f:
    f.read(16)  # skip header (varies by Python version)
    code = marshal.load(f)
    dis.dis(code)
"
```

#### D. .NET (C#) — .dll / .exe

```bash
# Decompile
dnSpy challenge.exe                       # GUI decompiler + debugger (Windows)
ilspy challenge.dll                       # ILSpy decompiler
dotPeek challenge.exe                     # JetBrains decompiler

# CLI
monodis challenge.exe                     # Mono disassembler
ildasm challenge.exe                      # Microsoft IL Disassembler
```

#### E. WebAssembly (.wasm)

```bash
# Text format
wasm2wat challenge.wasm > challenge.wat   # binary → text
wasm-decompile challenge.wasm             # pseudo-C decompilation

# Browser DevTools:
# 1. Load wasm di browser
# 2. DevTools → Sources → .wasm file → step through
# 3. Atau gunakan Ghidra (mendukung WASM processor)
```

#### F. Custom VM Bytecode

```
Langkah:
1. Identifikasi opcode table (biasanya switch-case di main loop)
2. Map setiap opcode ke operasi (PUSH, POP, ADD, XOR, CMP, JMP)
3. Tulis disassembler sederhana
4. Trace eksekusi bytecode secara manual atau otomatis
5. Rekonstruksi logika → solve
```

```python
# Contoh custom VM disassembler
opcodes = {
    0x01: ("PUSH", 1),    # 1 byte operand
    0x02: ("POP", 0),
    0x03: ("ADD", 0),
    0x04: ("XOR", 0),
    0x05: ("CMP", 0),
    0x06: ("JZ", 2),      # 2 byte operand (jump target)
    0x07: ("PRINT", 0),
}

bytecode = open("challenge.vm", "rb").read()
pc = 0
while pc < len(bytecode):
    op = bytecode[pc]
    name, operand_size = opcodes.get(op, ("UNK", 0))
    operand = bytecode[pc+1:pc+1+operand_size]
    print(f"0x{pc:04x}: {name} {operand.hex()}")
    pc += 1 + operand_size
```

> **⚠️ PENTING**: Selalu cek **magic bytes** file terlebih dahulu! Banyak challenge yang sengaja mengubah extension atau header untuk menyesatkan.

---

## 4. Anti-RE Techniques

### Overview

Challenge CTF sering menggunakan teknik anti-reverse-engineering. Kuncinya: **identifikasi teknik → gunakan counter yang sesuai**.

### A. Anti-Debug: PTRACE

**Mekanisme**: Program memanggil `ptrace(PTRACE_TRACEME, ...)` pada dirinya sendiri. Jika berhasil → bukan di-debug. Jika gagal (karena debugger sudah attach) → exit/crash.

```c
// Kode anti-debug typical:
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    printf("Debugger detected!\n");
    exit(1);
}
```

**Counter Measures:**

```bash
# Method 1: LD_PRELOAD — override ptrace
cat > fake_ptrace.c << 'EOF'
#include <sys/types.h>
long ptrace(int request, ...) { return 0; }
EOF
gcc -shared -o fake_ptrace.so fake_ptrace.c
LD_PRELOAD=./fake_ptrace.so ./challenge

# Method 2: GDB — skip ptrace call
(gdb) catch syscall ptrace
(gdb) run
# Saat hit:
(gdb) set $rax = 0              # force return value = 0
(gdb) continue

# Method 3: Binary Patch — NOP out ptrace call
# Cari: call ptrace (e8 xx xx xx xx)
# Ganti dengan: nop (90 90 90 90 90) + set eax=0
```

**Anti-Debug Lainnya (Linux):**

```bash
# Cek /proc/self/status → TracerPid
# Counter: echo 0 > /proc/self/status (atau patch)

# Cek waktu eksekusi (timing check)
# Counter: set breakpoint → modifikasi timestamp register

# Cek parent process name
# Counter: rename gdb, gunakan wrapper
```

**Anti-Debug (Windows):**

```
IsDebuggerPresent()          → Patch atau set PEB.BeingDebugged = 0
CheckRemoteDebuggerPresent() → Hook/patch return value
NtQueryInformationProcess()  → Hook ntdll
OutputDebugString trick      → Ignore
```

### B. Anti-Disassembly

**Mekanisme**: Memasukkan **junk bytes** atau **opaque predicates** untuk membingungkan disassembler linear.

```nasm
; Contoh: junk byte setelah unconditional jump
    jmp real_code
    db 0xE8            ; opcode palsu (call), membingungkan disassembler
real_code:
    mov eax, 1

; Contoh: opaque predicate
    xor eax, eax
    jz real_code       ; selalu jump (karena ZF=1)
    db 0xFF, 0xFF      ; junk bytes, never executed
real_code:
    ; actual code
```

**Counter Measures:**

```
1. Switch disassembler ke mode "Graph" (bukan linear)
2. Manual undefine + re-analyze di IDA/Ghidra:
   - IDA: Tekan 'U' (undefine) lalu 'C' (make code) pada alamat benar
   - Ghidra: Clear Code Block → Disassemble
3. Identifikasi pattern junk byte → tulis script untuk auto-patch
4. Gunakan dynamic analysis untuk trace alur sebenarnya
```

### C. Anti-Decompiler

**Mekanisme**: Teknik yang membuat decompiler menghasilkan output yang salah/unreadable.

```
- Switch-case obfuscation (computed jumps)
- Stack manipulation yang membingungkan analisis stack frame
- Overlapping instructions
- Exception-based control flow (SEH/signal handlers)
- Indirect calls melalui function pointers
```

**Counter Measures:**

```
1. Jangan 100% percaya decompiler — crosscheck dengan assembly
2. Gunakan debugger untuk trace actual execution path
3. Buat type/struct annotations manual di Ghidra/IDA
4. Patch anti-decompiler tricks:
   - IDA: Edit → Patch → Change Byte
   - Ghidra: Retype variables, create structs
5. Rename variabel & fungsi untuk clarity
```

> **⚠️ WARNING**: Challenge tingkat lanjut sering **menggabungkan** beberapa teknik Anti-RE sekaligus. Selalu jalankan `strings` dan dynamic analysis terlebih dahulu sebelum dive deep ke static.

---

## 5. Compiled Language Patterns in Executables

### Mengapa Penting

Setiap bahasa pemrograman menghasilkan **pattern khas** di binary. Mengenali bahasa sumber mempercepat analisis secara signifikan.

### A. C / C++

```
Ciri-ciri:
- Straightforward compilation, decompile relatif bersih
- C++: name mangling (_ZN...), vtable, RTTI info
- Stdlib calls: printf, malloc, strcmp, memcpy
- Sections standar: .text, .data, .bss, .rodata

Tips:
- strings binary → cari "GCC:", "clang", RTTI names
- C++ demangling: c++filt _ZN3Foo3barEv → "Foo::bar()"
- IDA/Ghidra: aktifkan C++ analysis plugin
```

### B. Golang

```
Ciri-ciri:
- Binary SANGAT BESAR (statically linked, includes runtime)
- Goroutine scheduler, garbage collector terikut
- Fungsi diawali "main.main", "main.checkFlag"
- String TIDAK null-terminated (length-prefixed)
- Struct info tersimpan di runtime type metadata

Tips:
- Gunakan plugin: IDAGolangHelper, GoReSym
- strings binary | grep "main\." → list fungsi penting
- Perhatikan: Go string disimpan sebagai (pointer, length)
  → JANGAN percaya "strings" command sepenuhnya
- Ghidra: install GoLang plugin dari GitHub
```

```bash
# GoReSym — extract Go metadata
GoReSym -t -d -p challenge > metadata.json
# Output: function names, types, source file paths
```

### C. Rust

```
Ciri-ciri:
- Binary besar (seperti Go, tapi pattern berbeda)
- Name mangling: _ZN4core3fmt... atau hash suffix
- Banyak panic/unwrap handlers
- Enum/Option/Result pattern di assembly
- String: str (UTF-8, length-prefixed)

Tips:
- strings binary | grep "rust" → verifikasi
- Cari "core::panicking" → trace balik ke logika utama
- Demangling: rustfilt atau Ghidra built-in
- Banyak inline + monomorphization → fungsi terasa repetitif
```

### D. C# / .NET

```
Ciri-ciri:
- File PE dengan CLR header
- Managed code → MSIL bytecode
- Metadata lengkap: class names, method names, string literals

Tips:
- dnSpy: decompile + debug sekaligus (SANGAT powerful)
- Source code hampir 100% recoverable
- Cek Resources section → sometimes flag/key tersimpan di sini
- Obfuscation tools: ConfuserEx, Dotfuscator → gunakan de4dot
```

```bash
de4dot challenge_obfuscated.exe -o challenge_clean.exe
```

### E. Tabel Identifikasi Cepat

| Indikator | Bahasa |
|-----------|--------|
| `GCC:`, `__libc_start_main` | C |
| `_ZN`, vtable, RTTI | C++ |
| `runtime.gopanic`, `main.main` | Go |
| `core::panicking`, `_ZN..h..` | Rust |
| CLR header, `System.`, MSIL | C# / .NET |
| `_Jv_`, `java/lang/String` | Java (native) |

---

## 6. Arsitektur: x86_64, x64, ARM

### Quick Reference per Arsitektur

#### x86 / x86_64 (Intel/AMD)

```
Register penting:
- RAX/EAX: return value, accumulator
- RDI, RSI, RDX, RCX, R8, R9: parameter fungsi (Linux SysV ABI)
- RCX, RDX, R8, R9: parameter fungsi (Windows x64)
- RSP: stack pointer
- RBP: base pointer (frame pointer)
- RIP: instruction pointer

Calling convention (Linux x86_64):
- Args: RDI, RSI, RDX, RCX, R8, R9 → stack
- Return: RAX

Instruksi kunci untuk RE:
- cmp / test → comparison (sets flags)
- je/jne/jg/jl → conditional jump
- call / ret → function call/return
- xor rax, rax → zero register (common idiom)
- lea → load effective address (sering untuk aritmatika)
```

#### ARM (32-bit) / AArch64 (64-bit)

```
Register penting (ARM64/AArch64):
- X0-X7: parameter fungsi + return value (X0)
- X29 (FP): frame pointer
- X30 (LR): link register (return address)
- SP: stack pointer
- PC: program counter

Register (ARM32):
- R0-R3: parameter fungsi + return value (R0)
- R11 (FP), R13 (SP), R14 (LR), R15 (PC)

Perbedaan penting vs x86:
- RISC: instruksi fixed-length (4 bytes pada ARM, 2 pada Thumb)
- Load/store architecture (tidak bisa operate langsung ke memory)
- Conditional execution pada setiap instruksi (ARM32)
- No PUSH/POP per-se di AArch64 → STP/LDP pairs
```

#### Cross-Architecture Debugging

```bash
# ARM binary di x86 machine:
# Install QEMU user-mode
sudo apt install qemu-user qemu-user-static

# Run ARM binary
qemu-arm ./challenge_arm
qemu-aarch64 ./challenge_arm64

# Debug ARM binary
qemu-arm -g 1234 ./challenge_arm &
gdb-multiarch -ex "target remote :1234" -ex "file ./challenge_arm"

# Ghidra: tinggal buka file → otomatis deteksi arsitektur
```

> **💡 TIP**: Untuk challenge **multi-arch**, Ghidra sangat superior karena mendukung hampir semua arsitektur prosesor secara native tanpa plugin tambahan.

---

## 7. Special Frameworks

### A. Flutter (Dart AOT)

```
Ciri-ciri:
- APK/IPA dengan libapp.so / App.framework
- Dart AOT compiled → snapshot format
- Class/method names STRIPPED secara default

Workflow:
1. Extract APK: apktool d challenge.apk
2. Cari: lib/arm64-v8a/libapp.so
3. Tools:
   - reFlutter: patch & intercept Flutter network traffic
   - Doldrums: parse Dart snapshot
   - Blutter: Dart AOT snapshot analyzer (RECOMMENDED)
```

```bash
# Blutter usage
python3 blutter.py path/to/libapp.so output_dir
# Menghasilkan: function names, class info, readable assembly
```

### B. Kotlin / Android Native

```
Kotlin di APK:
- Decompile APK: jadx challenge.apk
- Kotlin compiles ke JVM bytecode → sama seperti Java
- Cari: kotlin.Metadata annotations
- Perhatikan: companion object, extension functions, coroutines
- Lambda/closure mapping bisa confusing → trace patiently

Android Native (JNI):
- Cari: lib/*.so files
- Load .so di Ghidra → cari JNI_OnLoad, Java_*
- Gunakan Frida untuk hook native functions
```

### C. Desktop Apps — Qt Framework

```
Ciri-ciri:
- Link ke Qt libraries (Qt5Core, Qt5Widgets, dll.)
- Signal/Slot mechanism
- QObject metadata (MOC generated)
- Resource files (.qrc) embedded

Workflow:
1. strings binary | grep "Qt" → verifikasi
2. Extract Qt resources:
   - rcc tool (Qt resource compiler, bisa decompile)
   - binwalk untuk extract embedded resources
3. Analisis signal/slot connections untuk trace logic
4. Ghidra: perhatikan qt_metacall, staticMetaObject
5. Jika QML-based: cari .qml files di resources
```

### D. Electron (JavaScript + Node.js)

```
Ciri-ciri:
- Folder berisi: electron.exe + resources/app.asar
- Atau: app bundled dengan Chromium

Workflow:
1. Extract ASAR:
   npx asar extract resources/app.asar extracted/
2. Baca JavaScript source → usually readable/obfuscated JS
3. Cari main.js, index.js → trace logic
4. De-obfuscate jika perlu:
   - synchrony, js-beautify, de4js
5. Cari strings/keys di JavaScript files
```

### E. Unity (C# / IL2CPP)

```
Mono Build:
- Cari: Managed/Assembly-CSharp.dll
- Decompile dengan dnSpy → almost full source recovery

IL2CPP Build:
- C# compiled → C++ → native binary (MUCH harder)
- Cari: libil2cpp.so + global-metadata.dat
- Tools:
  - Il2CppDumper: extract class/method info + dummy DLLs
  - Cpp2IL: improved version
  - Ghidra + Il2CppDumper output for full analysis
```

---

## 8. Obfuscation & Binary Patching

### A. Identifikasi Obfuscation

```
Tanda-tanda obfuscation:
- Entropy tinggi (>7.0 pada section .text) → kemungkinan packed/encrypted
- Tidak ada strings yang readable
- Import table sangat kecil (hanya LoadLibrary, GetProcAddress)
- Entry point di section aneh (bukan .text)
- Size section vs virtual size sangat berbeda
```

```bash
# Cek entropy
python3 -c "
import math
data = open('challenge','rb').read()
freq = [0]*256
for b in data: freq[b] += 1
entropy = -sum((f/len(data))*math.log2(f/len(data)) for f in freq if f>0)
print(f'Entropy: {entropy:.2f}')
# >7.5 = likely encrypted/compressed, 5-6 = normal code
"
```

### B. Common Packers & Unpacking

| Packer | Identifikasi | Unpacking |
|--------|-------------|-----------|
| UPX | `strings \| grep UPX` | `upx -d challenge` |
| ASPack | Section `.aspack` | Manual / ASPackDie |
| Themida/VMProtect | VM-based protection | Manual + Unicorn emulation |
| Custom | Entropy analysis | Dump at OEP (Original Entry Point) |

```bash
# UPX — paling umum di CTF
upx -d challenge -o challenge_unpacked

# Jika UPX header dirusak:
# 1. Fix UPX magic bytes
# 2. Atau manual unpack: debug → dump di OEP
```

### C. Known Encryption Patterns

```python
# XOR cipher — PALING UMUM di CTF
def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# RC4
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

# Base64 custom alphabet
import base64
import string
custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0123456789+/"
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
decoded = base64.b64decode(encoded.translate(str.maketrans(custom, standard)))

# TEA / XTEA — sering muncul di CTF
# Identifikasi: konstanta magic 0x9E3779B9 (golden ratio)
```

### D. Binary Patching

```bash
# Dengan Python
import struct

with open('challenge', 'rb') as f:
    data = bytearray(f.read())

# Patch: ubah conditional jump je → jne (atau sebaliknya)
# je  = 0x74, jne = 0x75
# je  = 0x0F 0x84, jne = 0x0F 0x85

offset = 0x1234  # offset dalam file (bukan virtual address!)
data[offset] = 0x75  # je → jne

# Patch: NOP out instruksi (misal skip anti-debug)
for i in range(5):  # 5-byte call instruction
    data[offset + i] = 0x90  # NOP

# Patch: force jump (unconditional)
data[offset] = 0xEB  # jmp short

with open('challenge_patched', 'wb') as f:
    f.write(data)
```

```bash
# Dengan radare2
r2 -w challenge
[0x00401000]> s 0x401234         # seek to address
[0x00401234]> wx 75              # write hex (je → jne)
[0x00401234]> wa nop;nop;nop     # write assembly NOPs
[0x00401234]> wa jmp 0x401300    # write jump
[0x00401234]> quit
```

> **⚠️ CAUTION**: Saat patching, perhatikan perbedaan **file offset** vs **virtual address**! Gunakan `readelf -S` atau PE section headers untuk konversi.

---

## 9. Mobile Reverse Engineering

### A. Android RE

#### Workflow Lengkap

```
APK → apktool (smali) + jadx (Java)
  → Analisis manifest, permissions, activities
  → Cari logic validasi di Java/Kotlin code
  → Jika ada native lib → Ghidra pada .so files
  → Dynamic: Frida hook untuk bypass/extract
```

#### Step-by-Step

```bash
# 1. Extract & Decompile
apktool d challenge.apk -o apk_extracted/
jadx challenge.apk -d jadx_output/

# 2. Quick analysis
cat apk_extracted/AndroidManifest.xml   # permissions, activities, services
grep -r "flag\|secret\|key\|password" jadx_output/ --include="*.java"

# 3. Identifikasi entry point
# Cari: android.intent.action.MAIN → activity utama
# Trace: onCreate() → input handling → validation logic

# 4. Smali modification (jika perlu patch)
# Edit smali files di apk_extracted/smali/
# Contoh: ubah if-eqz → if-nez (bypass check)
# Rebuild:
apktool b apk_extracted/ -o patched.apk
# Sign:
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore test.keystore patched.apk test
```

#### Frida — Dynamic Instrumentation

```javascript
// frida_hook.js — hook Java method
Java.perform(function() {
    var MainActivity = Java.use("com.challenge.ctf.MainActivity");

    // Hook method checkFlag
    MainActivity.checkFlag.implementation = function(input) {
        console.log("[*] checkFlag called with: " + input);
        var result = this.checkFlag(input);
        console.log("[*] checkFlag returned: " + result);
        return true; // force return true
    };

    // Hook native method
    var addr = Module.findExportByName("libchallenge.so", "verify");
    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("[*] verify(" + Memory.readUtf8String(args[0]) + ")");
        },
        onReturn: function(retval) {
            console.log("[*] verify returned: " + retval);
            retval.replace(1); // force return 1
        }
    });
});
```

```bash
# Jalankan Frida
frida -U -f com.challenge.ctf -l frida_hook.js --no-pause
```

### B. iOS RE

```
Workflow:
IPA → unzip → Mach-O binary
  → class-dump (Objective-C classes)
  → Ghidra/Hopper (disassemble)
  → Frida (dynamic analysis)
```

```bash
# 1. Extract IPA
unzip challenge.ipa -d ipa_extracted/
# Binary: ipa_extracted/Payload/Challenge.app/Challenge

# 2. Analisis Mach-O
file Challenge
otool -L Challenge              # linked libraries
class-dump Challenge > headers.h  # ObjC class dump

# 3. Jika Swift:
# Cari Swift metadata, demangling:
swift-demangle '_$s7Challenge...'

# 4. Disassemble
# Load di Ghidra → pilih ARM64 processor
# Atau Hopper Disassembler (macOS, berbayar tapi powerful untuk iOS)

# 5. Frida (perlu jailbroken device atau Corellium)
frida -U -f com.challenge.ctf -l hook.js
```

### C. Tools Summary — Mobile RE

| Tool | Platform | Fungsi |
|------|----------|--------|
| apktool | Android | Decode/rebuild APK, smali edit |
| jadx | Android | Decompile DEX → Java |
| Frida | Both | Dynamic instrumentation, hooking |
| objection | Both | Frida wrapper, exploration tools |
| class-dump | iOS | Extract ObjC headers |
| Hopper | iOS/macOS | Disassembler + decompiler |
| MobSF | Both | Automated static analysis |
| Magisk | Android | Root + hide root detection |

---

## 🎯 General CTF RE Methodology — Cheat Sheet

```
┌─────────────────────────────────────────────────┐
│              CTF RE Challenge                    │
└──────────────────────┬──────────────────────────┘
                       │
              ┌────────▼────────┐
              │   1. RECON      │
              │   file, strings │
              │   checksec      │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  2. IDENTIFY    │
              │  Language?      │
              │  Architecture?  │
              │  Packed?        │
              │  Framework?     │
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────▼────┐   ┌────▼────┐  ┌────▼────┐
    │ STATIC  │   │ DYNAMIC │  │ HYBRID  │
    │ Ghidra  │   │ GDB     │  │ angr    │
    │ IDA     │   │ Frida   │  │ Unicorn │
    │ jadx    │   │ strace  │  │ Triton  │
    └────┬────┘   └────┬────┘  └────┬────┘
         │             │            │
         └──────┬──────┘────────────┘
                │
       ┌────────▼────────┐
       │ 3. UNDERSTAND   │
       │ Algorithm?      │
       │ Constraints?    │
       │ Anti-RE?        │
       └────────┬────────┘
                │
       ┌────────▼────────┐
       │ 4. SOLVE        │
       │ Z3 / manual     │
       │ Patch binary    │
       │ Decrypt/decode  │
       └────────┬────────┘
                │
       ┌────────▼────────┐
       │ 5. FLAG 🏴      │
       └─────────────────┘
```

### Pro Tips

> 1. **Selalu mulai dari `strings`** — banyak flag tersembunyi yang langsung muncul
> 2. **Jangan langsung dive ke assembly** — coba decompiler dulu
> 3. **Cek cross-references (xrefs)** ke string "wrong"/"correct" → langsung ke validasi
> 4. **Rename & annotate** fungsi/variabel di disassembler → jauh lebih readable
> 5. **Simpan notes** — RE adalah proses iteratif, catat setiap progress
> 6. **Jika stuck di static → pivot ke dynamic** (dan sebaliknya)
> 7. **Google error strings & constants** — banyak challenge berdasarkan algoritma known
> 8. **Constant magic numbers**: `0x9E3779B9` = TEA, `0x61707865` = ChaCha/Salsa
