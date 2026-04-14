# 📋 CTF Master Cheatsheet — Links, Tools, Scripts & Boilerplate

> Satu file untuk semua referensi cepat: links, GitHub repos, scripts siap pakai, dan boilerplate.
> Bookmark file ini — buka saat lomba untuk akses cepat.

---

## Daftar Isi

1. [Web Tools & Online Resources](#1-web-tools--online-resources)
2. [GitHub Repositories Wajib](#2-github-repositories)
3. [Script Siap Pakai — Reverse Engineering](#3-scripts--re)
4. [Script Siap Pakai — Forensics](#4-scripts--forensics)
5. [Script Siap Pakai — SOC/SIEM](#5-scripts--socsiem)
6. [One-Liner Commands](#6-one-liner-commands)
7. [Encoding & Decoding Reference](#7-encoding--decoding)
8. [Event ID Cheatsheet](#8-event-id-cheatsheet)
9. [Splunk SPL Cheatsheet](#9-splunk-spl-cheatsheet)
10. [Wazuh KQL Cheatsheet](#10-wazuh-kql-cheatsheet)
11. [Assembly & Binary Cheatsheet](#11-assembly--binary-cheatsheet)
12. [File Signatures (Magic Bytes)](#12-file-signatures)
13. [Hash Identification](#13-hash-identification)
14. [Wordlists & Dictionaries](#14-wordlists)
15. [Platform Latihan CTF](#15-platform-latihan)
16. [Install Script — Setup Sekali Jalan](#16-install-script)

---

# 1. Web Tools & Online Resources

## Multi-Purpose

| Tool | URL | Fungsi |
|------|-----|--------|
| **CyberChef** | https://gchq.github.io/CyberChef/ | Encode/decode/encrypt/decrypt SEGALANYA |
| **dCode** | https://www.dcode.fr/en | 200+ cipher & encoding solver |
| **Boxentriq** | https://www.boxentriq.com/code-breaking | Cipher identification & solving |
| **Rumkin Cipher Tools** | http://rumkin.com/tools/cipher/ | Classic cipher tools |

## Reverse Engineering

| Tool | URL | Fungsi |
|------|-----|--------|
| **Dogbolt** | https://dogbolt.org/ | Multiple decompilers sekaligus (Ghidra, IDA, Binary Ninja, dll.) |
| **Compiler Explorer** | https://godbolt.org/ | C/C++ → Assembly (lihat bagaimana code di-compile) |
| **Binary Ninja Cloud** | https://cloud.binary.ninja/ | Disassembler online gratis |
| **Online Disassembler** | https://onlinedisassembler.com/ | Disassemble binary online |
| **Decompiler Explorer** | https://dogbolt.org/ | Bandingkan output multiple decompilers |
| **Syscall Table** | https://syscalls.mebeim.net/ | Linux syscall reference (x86, x64, ARM) |
| **x86 Reference** | https://www.felixcloutier.com/x86/ | Referensi instruksi x86 lengkap |
| **ARM Reference** | https://developer.arm.com/documentation/ | Dokumentasi ARM instruction set |
| **Shell-storm** | http://shell-storm.org/shellcode/ | Database shellcode |

## Forensics

| Tool | URL | Fungsi |
|------|-----|--------|
| **AperiSolve** | https://www.aperisolve.com/ | Auto stego analysis (upload gambar → hasil lengkap) |
| **FotoForensics** | https://fotoforensics.com/ | ELA analysis, metadata, hidden data |
| **Stegano Online** | https://stylesuxx.github.io/steganography/ | LSB encode/decode online |
| **HexEd.it** | https://hexed.it/ | Hex editor online |
| **Wireshark OUI Lookup** | https://www.wireshark.org/tools/oui-lookup.html | Cari vendor dari MAC address |
| **PacketTotal** | https://packettotal.com/ | Analisis PCAP online |
| **PCAP Analyzer** | https://apackets.com/ | Visualisasi PCAP online |
| **File Signature DB** | https://filesignatures.net/ | Database file signatures / magic bytes |
| **Gary Kessler Signatures** | https://www.garykessler.net/library/file_sigs.html | File signature reference lengkap |

## SOC / SIEM / Threat Intelligence

| Tool | URL | Fungsi |
|------|-----|--------|
| **VirusTotal** | https://www.virustotal.com/ | Scan file/hash/URL dengan 70+ AV |
| **Hybrid Analysis** | https://www.hybrid-analysis.com/ | Free malware sandbox |
| **Any.Run** | https://any.run/ | Interactive malware sandbox |
| **Joe Sandbox** | https://www.joesandbox.com/ | Malware analysis sandbox |
| **MalwareBazaar** | https://bazaar.abuse.ch/ | Malware sample database |
| **URLhaus** | https://urlhaus.abuse.ch/ | Malicious URL database |
| **Shodan** | https://www.shodan.io/ | Search engine for IoT/devices |
| **AbuseIPDB** | https://www.abuseipdb.com/ | Cek reputasi IP address |
| **ThreatFox** | https://threatfox.abuse.ch/ | IOC database |
| **MITRE ATT&CK** | https://attack.mitre.org/ | Framework teknik serangan |
| **Sigma Rules** | https://github.com/SigmaHQ/sigma | Detection rules (SIEM-agnostic) |
| **LOLBAS** | https://lolbas-project.github.io/ | Living Off The Land Binaries (Windows) |
| **GTFOBins** | https://gtfobins.github.io/ | Unix binaries for privilege escalation |
| **CyberChef (GCHQ)** | https://gchq.github.io/CyberChef/ | Swiss army knife data transform |
| **Uncoder.io** | https://uncoder.io/ | Convert detection rules antar SIEM |

## Crypto

| Tool | URL | Fungsi |
|------|-----|--------|
| **CrackStation** | https://crackstation.net/ | Online hash lookup (MD5, SHA, dll.) |
| **Hashes.com** | https://hashes.com/en/decrypt/hash | Hash decrypt online |
| **factordb** | http://factordb.com/ | Faktorisasi bilangan besar (RSA) |
| **RsaCtfTool** | https://github.com/RsaCtfTool/RsaCtfTool | RSA attack automation |
| **quipqiup** | https://quipqiup.com/ | Substitution cipher solver |
| **dCode Cipher Identifier** | https://www.dcode.fr/cipher-identifier | Auto-identify cipher type |

---

# 2. GitHub Repositories

## 🔴 Reverse Engineering

```
DISASSEMBLER & DECOMPILER:
├── Ghidra           → https://github.com/NationalSecurityAgency/ghidra
├── radare2          → https://github.com/radareorg/radare2
├── Cutter (r2 GUI)  → https://github.com/rizinorg/cutter
├── iaito (r2 GUI)   → https://github.com/radareorg/iaito
└── ImHex            → https://github.com/WerWolv/ImHex

DEBUGGER:
├── pwndbg           → https://github.com/pwndbg/pwndbg
├── GEF              → https://github.com/hugsy/gef
├── peda             → https://github.com/longld/peda
└── x64dbg           → https://github.com/x64dbg/x64dbg

SOLVER & ANALYSIS:
├── angr             → https://github.com/angr/angr
├── z3               → https://github.com/Z3Prover/z3
├── unicorn          → https://github.com/unicorn-engine/unicorn
├── qiling           → https://github.com/qilingframework/qiling
└── triton           → https://github.com/JonathanSalwan/Triton

LANGUAGE-SPECIFIC:
├── GoReSym (Go)     → https://github.com/mandiant/GoReSym
├── Blutter (Flutter)→ https://github.com/worawit/blutter
├── Il2CppDumper     → https://github.com/Perfare/Il2CppDumper
├── Cpp2IL (Unity)   → https://github.com/SamboyCoding/Cpp2IL
├── dnSpyEx (.NET)   → https://github.com/dnSpyEx/dnSpy
├── de4dot (.NET)    → https://github.com/de4dot/de4dot
├── jadx (Java/APK)  → https://github.com/skylot/jadx
├── pycdc (Python)   → https://github.com/zrax/pycdc
└── rustfilt (Rust)  → https://github.com/luser/rustfilt

MOBILE:
├── Frida            → https://github.com/frida/frida
├── objection        → https://github.com/sensepost/objection
├── apktool          → https://github.com/iBotPeaches/Apktool
├── MobSF            → https://github.com/MobSF/Mobile-Security-Framework-MobSF
└── reFlutter        → https://github.com/nicolo-ribaudo/reFlutter

ANTI-RE:
├── ScyllaHide       → https://github.com/x64dbg/ScyllaHide
└── al-khaser        → https://github.com/LordNoteworthy/al-khaser (anti-* reference)
```

## 🔵 Digital Forensics

```
FILE CARVING & ANALYSIS:
├── binwalk          → https://github.com/ReFirmLabs/binwalk
├── foremost         → (apt install foremost)
├── sleuthkit        → https://github.com/sleuthkit/sleuthkit
├── Autopsy          → https://github.com/sleuthkit/autopsy
└── bulk_extractor   → https://github.com/simsong/bulk_extractor

MEMORY FORENSICS:
├── Volatility 3     → https://github.com/volatilityfoundation/volatility3
├── Volatility 2     → https://github.com/volatilityfoundation/volatility
├── MemProcFS        → https://github.com/ufrisk/MemProcFS
└── VolWeb           → https://github.com/k1nd0ne/VolWeb

NETWORK FORENSICS:
├── Wireshark        → https://github.com/wireshark/wireshark
├── NetworkMiner     → https://www.netresec.com/?page=NetworkMiner
├── Zeek (Bro)       → https://github.com/zeek/zeek
└── Scapy            → https://github.com/secdev/scapy

STEGANOGRAPHY:
├── zsteg            → https://github.com/zed-0xff/zsteg
├── stegoveritas     → https://github.com/bannsec/steganern
├── steghide         → (apt install steghide)
├── stegcracker      → https://github.com/Paradoxis/StegCracker
├── stegseek         → https://github.com/RickdeJager/stegseek (FAST steghide crack)
├── Stegsolve        → https://github.com/Giotino/stegsolve
└── jsteg            → https://github.com/lukechampine/jsteg

BROWSER & REGISTRY:
├── Hindsight        → https://github.com/obsidianforensics/hindsight
├── RegRipper        → https://github.com/keydet89/RegRipper3.0
└── Eric Zimmerman   → https://ericzimmerman.github.io/
```

## 🟢 SOC / SIEM / Log Analysis

```
EVTX ANALYSIS:
├── Chainsaw         → https://github.com/WithSecureLabs/chainsaw
├── Hayabusa         → https://github.com/Yamato-Security/hayabusa
├── evtx (Rust)      → https://github.com/omerbenamram/evtx
├── python-evtx      → https://github.com/williballenthin/python-evtx
├── APT-Hunter       → https://github.com/ahmedkhlief/APT-Hunter
└── DeepBlueCLI      → https://github.com/sans-blue-team/DeepBlueCLI

DETECTION & HUNTING:
├── Sigma Rules      → https://github.com/SigmaHQ/sigma
├── YARA Rules       → https://github.com/Yara-Rules/rules
├── Elastic Detection→ https://github.com/elastic/detection-rules
└── Splunk Security  → https://github.com/splunk/security_content

MALWARE ANALYSIS:
├── oletools         → https://github.com/decalage2/oletools
├── FLOSS            → https://github.com/mandiant/flare-floss
├── DIE              → https://github.com/horsicq/Detect-It-Easy
├── capa             → https://github.com/mandiant/capa
├── pe-sieve         → https://github.com/hasherezade/pe-sieve
└── pestudio         → https://www.winitor.com/download
```

## ⭐ CTF-Specific Collections

```
MUST-STAR:
├── CTF Tools Collection       → https://github.com/zardus/ctf-tools
├── PayloadsAllTheThings       → https://github.com/swisskyrepo/PayloadsAllTheThings
├── HackTricks                 → https://github.com/carlospolop/hacktricks
├── HackTricks (book)          → https://book.hacktricks.xyz/
├── Awesome CTF                → https://github.com/apsdehal/awesome-ctf
├── CTF Katana                 → https://github.com/JohnHammond/ctf-katana
└── Nightmare (RE writeups)    → https://guyinatuxedo.github.io/
```

---

# 3. Scripts — RE

## Boilerplate: Z3 Solver

```python
#!/usr/bin/env python3
"""Z3 CTF Solver Boilerplate — copy & modify untuk setiap challenge"""
from z3 import *

# ═══ KONFIGURASI ═══
FLAG_LEN = 32                    # panjang flag (sesuaikan!)
FLAG_PREFIX = b"flag{"           # prefix (sesuaikan!)
FLAG_SUFFIX = b"}"

# ═══ BUAT VARIABEL ═══
flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# ═══ CONSTRAINT: Printable ASCII ═══
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# ═══ CONSTRAINT: Prefix/Suffix ═══
for i, b in enumerate(FLAG_PREFIX):
    s.add(flag[i] == b)
s.add(flag[FLAG_LEN - 1] == ord('}'))

# ═══════════════════════════════════════════
# TAMBAHKAN CONSTRAINT DARI BINARY DI SINI!
# ═══════════════════════════════════════════
# Contoh:
# s.add(flag[5] ^ 0x42 == 0x24)
# s.add(flag[6] + flag[7] == 0xCA)
# 
# Untuk loop:
# key = [0x12, 0x34, 0x56, ...]        # dari binary
# expected = [0xAB, 0xCD, 0xEF, ...]   # dari binary
# for i in range(len(key)):
#     s.add(((flag[i+5] ^ key[i]) + i) & 0xFF == expected[i])


# ═══ SOLVE ═══
if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[flag[i]].as_long()) for i in range(FLAG_LEN))
    print(f"[+] Flag: {result}")
else:
    print("[-] UNSAT — cek ulang constraint!")
```

## Boilerplate: angr Solver

```python
#!/usr/bin/env python3
"""angr CTF Solver Boilerplate"""
import angr, claripy

BINARY = './challenge'           # path ke binary
FIND_ADDR = 0x401234             # alamat "Correct!" (dari Ghidra)
AVOID_ADDR = 0x401280            # alamat "Wrong!" (dari Ghidra)

proj = angr.Project(BINARY, auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

print("[*] Exploring...")
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    flag = found.posix.dumps(0)  # stdin
    print(f"[+] Flag: {flag.decode(errors='ignore')}")
else:
    print("[-] Not found")
```

## Boilerplate: XOR Decrypt

```python
#!/usr/bin/env python3
"""XOR Decryptor — paling umum di CTF"""

# ═══ SINGLE-BYTE XOR ═══
def xor_single(data, key):
    return bytes([b ^ key for b in data])

# ═══ MULTI-BYTE XOR ═══
def xor_multi(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# ═══ XOR BRUTE FORCE (single byte) ═══
def xor_bruteforce(data, known_prefix=b"flag{"):
    for key in range(256):
        result = xor_single(data, key)
        if result.startswith(known_prefix):
            print(f"[+] Key=0x{key:02x}: {result}")

# ═══ CONTOH PENGGUNAAN ═══
encrypted = bytes([0x16, 0x0f, 0x03, 0x09, 0x5b])  # dari binary

# Jika tahu key:
key = 0x42
print(xor_single(encrypted, key))

# Jika tahu key multi-byte:
key = b"KEY"
print(xor_multi(encrypted, key))

# Jika TIDAK tahu key:
xor_bruteforce(encrypted)

# ═══ DERIVE KEY dari known plaintext ═══
# Jika tahu plaintext="flag{" dan ciphertext=[0x16,0x0f,...]
plaintext = b"flag{"
ciphertext = bytes([0x16, 0x0f, 0x03, 0x09, 0x5b])
key = bytes([p ^ c for p, c in zip(plaintext, ciphertext)])
print(f"[+] Derived key: {key}")
```

## Boilerplate: GDB Auto-Solver Script

```python
#!/usr/bin/env python3
"""GDB scripting — jalankan: gdb -x solve_gdb.py ./challenge"""
import gdb

# Config
STRCMP_ADDR = "0x401234"  # alamat call strcmp (dari Ghidra)

gdb.execute("set disassembly-flavor intel")
gdb.execute(f"break *{STRCMP_ADDR}")
gdb.execute("run <<< 'AAAA'")

# Setelah hit breakpoint di strcmp, baca argumen:
# RDI = arg1 (input kita), RSI = arg2 (password benar)
password = gdb.execute("x/s $rsi", to_string=True)
print(f"\n{'='*50}")
print(f"[+] PASSWORD: {password}")
print(f"{'='*50}\n")
gdb.execute("quit")
```

## Boilerplate: Frida Hook (Android)

```javascript
// frida_hook.js — jalankan: frida -U -f com.ctf.app -l frida_hook.js --no-pause
Java.perform(function() {
    console.log("[*] Frida hook started");

    // ═══ Hook method checkFlag ═══
    var target = Java.use("com.ctf.challenge.MainActivity");
    target.checkFlag.implementation = function(input) {
        console.log("[*] checkFlag(" + input + ")");
        var result = this.checkFlag(input);
        console.log("[*] Original result: " + result);
        return true; // bypass!
    };

    // ═══ Hook semua String comparisons ═══
    var String = Java.use("java.lang.String");
    String.equals.implementation = function(other) {
        var result = this.equals(other);
        if (this.toString().length > 3 && this.toString().length < 50) {
            console.log("[*] equals('" + this + "', '" + other + "') = " + result);
        }
        return result;
    };

    // ═══ Enumerate classes ═══
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.includes("flag") || name.includes("ctf") || name.includes("check")) {
                console.log("[*] Class: " + name);
            }
        },
        onComplete: function() {}
    });
});
```

---

# 4. Scripts — Forensics

## Boilerplate: PCAP Analyzer

```python
#!/usr/bin/env python3
"""PCAP Quick Analyzer — extract data berguna dari PCAP"""
from scapy.all import *
import base64, sys

pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
packets = rdpcap(pcap_file)
print(f"[*] Loaded {len(packets)} packets from {pcap_file}\n")

# ═══ 1. CARI FLAG DI SEMUA PAYLOAD ═══
print("=== FLAG SEARCH ===")
for i, pkt in enumerate(packets):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw])
        if b"flag{" in data or b"CTF{" in data or b"FLAG{" in data:
            print(f"[+] Packet #{i}: {data}")

# ═══ 2. EXTRACT HTTP DATA ═══
print("\n=== HTTP REQUESTS ===")
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if payload.startswith(("GET ", "POST ", "HTTP/")):
            first_line = payload.split('\r\n')[0]
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            print(f"  {src} → {dst}: {first_line}")

# ═══ 3. DNS QUERIES ═══
print("\n=== DNS QUERIES ===")
dns_queries = set()
for pkt in packets:
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        query = pkt[DNS].qd.qname.decode()
        if query not in dns_queries:
            dns_queries.add(query)
            print(f"  {query}")

# ═══ 4. CREDENTIALS (POST data) ═══
print("\n=== POSSIBLE CREDENTIALS ===")
for pkt in packets:
    if pkt.haslayer(Raw):
        data = pkt[Raw].load.decode(errors='ignore')
        for keyword in ['password', 'passwd', 'pass=', 'user=', 'login', 'token', 'secret', 'key=']:
            if keyword in data.lower():
                print(f"  {data[:200]}")
                break

# ═══ 5. ICMP DATA (tunneling check) ═══
icmp_data = b""
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        icmp_data += bytes(pkt[Raw])
if icmp_data:
    print(f"\n=== ICMP PAYLOAD ({len(icmp_data)} bytes) ===")
    print(f"  Raw: {icmp_data[:200]}")
    try:
        print(f"  B64: {base64.b64decode(icmp_data).decode(errors='ignore')}")
    except:
        pass
```

## Boilerplate: EVTX Parser

```python
#!/usr/bin/env python3
"""EVTX Quick Analyzer — parse Windows Event Logs"""
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import sys, json
from collections import Counter

evtx_file = sys.argv[1] if len(sys.argv) > 1 else "Security.evtx"
ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

events = []
with evtx.Evtx(evtx_file) as log:
    for record in log.records():
        try:
            root = ET.fromstring(record.xml())
            eid = root.find('.//ns:EventID', ns).text
            time = root.find('.//ns:TimeCreated', ns).get('SystemTime', '')
            computer = root.find('.//ns:Computer', ns).text
            data = {}
            for d in root.findall('.//ns:Data', ns):
                if d.get('Name') and d.text:
                    data[d.get('Name')] = d.text
            events.append({'EventID': eid, 'Time': time, 'Computer': computer, 'Data': data})
        except:
            continue

print(f"[*] Parsed {len(events)} events from {evtx_file}\n")

# ═══ 1. EVENT ID DISTRIBUTION ═══
print("=== EVENT ID COUNTS ===")
eid_counts = Counter(e['EventID'] for e in events)
for eid, count in eid_counts.most_common(20):
    label = {
        '4624':'Login OK','4625':'Login FAIL','4634':'Logoff',
        '4648':'Explicit Creds','4672':'Admin Login','4688':'Process Created',
        '4720':'User Created','4697':'Service Installed','4698':'Task Created',
        '1102':'LOG CLEARED!'
    }.get(eid, '')
    print(f"  {eid:>6} : {count:>6}  {label}")

# ═══ 2. FAILED LOGINS ═══
print("\n=== FAILED LOGINS (4625) ===")
fails = [e for e in events if e['EventID'] == '4625']
ip_counts = Counter(e['Data'].get('IpAddress','?') for e in fails)
for ip, count in ip_counts.most_common(10):
    print(f"  {ip:>20} : {count} attempts")

# ═══ 3. SUCCESSFUL LOGINS ═══
print("\n=== SUCCESSFUL LOGINS (4624) ===")
logins = [e for e in events if e['EventID'] == '4624']
for e in logins[-20:]:
    user = e['Data'].get('TargetUserName', '?')
    ip = e['Data'].get('IpAddress', '?')
    ltype = e['Data'].get('LogonType', '?')
    ltype_name = {'2':'Interactive','3':'Network','10':'RDP','7':'Unlock'}.get(ltype, ltype)
    print(f"  [{e['Time'][:19]}] {user:>15} from {ip:>20} ({ltype_name})")

# ═══ 4. PROCESS CREATION ═══
print("\n=== SUSPICIOUS PROCESSES (4688) ===")
procs = [e for e in events if e['EventID'] == '4688']
suspicious = ['powershell','cmd.exe','whoami','net.exe','net1.exe','mimikatz',
              'certutil','bitsadmin','mshta','wscript','cscript','reg.exe',
              'schtasks','wmic','rundll32','regsvr32','msiexec']
for e in procs:
    proc = e['Data'].get('NewProcessName', '').lower()
    cmd = e['Data'].get('CommandLine', '')
    if any(s in proc for s in suspicious):
        print(f"  [{e['Time'][:19]}] {proc}")
        if cmd:
            print(f"    CMD: {cmd[:150]}")

# ═══ 5. FLAG SEARCH ═══
print("\n=== FLAG SEARCH ===")
for e in events:
    raw = json.dumps(e['Data'])
    if 'flag{' in raw.lower() or 'ctf{' in raw.lower():
        print(f"  [{e['Time'][:19]}] EventID={e['EventID']}: {raw[:200]}")

# ═══ 6. LOG CLEARED ═══
clears = [e for e in events if e['EventID'] == '1102']
if clears:
    print("\n=== ⚠️  LOG CLEARED (1102) ===")
    for e in clears:
        print(f"  [{e['Time'][:19]}] by {e['Data'].get('SubjectUserName','?')}")
```

## Boilerplate: Stego All-in-One

```bash
#!/bin/bash
# stego_check.sh — jalankan: bash stego_check.sh <image_file>
FILE=$1
echo "========================================="
echo " STEGO CHECK: $FILE"
echo "========================================="

echo -e "\n[1] FILE TYPE"
file "$FILE"

echo -e "\n[2] EXIFTOOL"
exiftool "$FILE" 2>/dev/null | grep -i "comment\|author\|description\|flag\|secret\|key\|title"

echo -e "\n[3] STRINGS"
strings "$FILE" | grep -iE "flag\{|ctf\{|key\{|secret|password"

echo -e "\n[4] BINWALK"
binwalk "$FILE"

echo -e "\n[5] ZSTEG (PNG/BMP only)"
zsteg "$FILE" 2>/dev/null | head -20

echo -e "\n[6] STEGHIDE (JPEG only, no password)"
steghide extract -sf "$FILE" -p "" -f 2>/dev/null && echo "[+] Extracted!" || echo "[-] No data / needs password"

echo -e "\n[7] PNGCHECK"
pngcheck -v "$FILE" 2>/dev/null | head -10

echo -e "\n========================================="
echo " Done. Check results above."
echo "========================================="
```

---

# 5. Scripts — SOC/SIEM

## Boilerplate: Log Analyzer (Linux Auth/Web)

```bash
#!/bin/bash
# log_analyzer.sh — jalankan: bash log_analyzer.sh <logfile>
LOG=$1
echo "========================================="
echo " LOG ANALYSIS: $LOG"
echo "========================================="

echo -e "\n[1] TOTAL LINES"
wc -l "$LOG"

echo -e "\n[2] FAILED AUTH ATTEMPTS"
grep -c -i "failed\|failure\|denied\|invalid" "$LOG"

echo -e "\n[3] TOP IPs (if present)"
grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' "$LOG" | sort | uniq -c | sort -rn | head -10

echo -e "\n[4] TOP PAGES/URIs (web log)"
awk '{print $7}' "$LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo -e "\n[5] HTTP STATUS CODES"
awk '{print $9}' "$LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo -e "\n[6] SUSPICIOUS PATTERNS"
grep -inE "union|select|insert|drop|exec|script|<|>|\.\.\/|cmd=|whoami|passwd|shadow|eval|base64" "$LOG" | head -20

echo -e "\n[7] FLAG SEARCH"
grep -iE "flag\{|ctf\{" "$LOG"

echo -e "\n[8] TIMELINE (first & last entry)"
echo "First: $(head -1 "$LOG")"
echo "Last:  $(tail -1 "$LOG")"
echo "========================================="
```

---

# 6. One-Liner Commands

## Identifikasi & Recon

```bash
# Identifikasi file
file *                                          # scan semua file
file challenge && xxd -l 32 challenge           # type + first bytes

# Strings cepat
strings -n 8 challenge | grep -iE "flag|pass|key|secret|ctf"

# Metadata
exiftool * 2>/dev/null | grep -iE "comment|author|flag|secret"

# Entropy (deteksi encryption/packing)
binwalk -E challenge

# Embedded files
binwalk -e challenge && ls _challenge.extracted/
```

## Encoding/Decoding

```bash
# Base64
echo "ZmxhZ3t0ZXN0fQ==" | base64 -d

# Hex → ASCII
echo "666c61677b746573747d" | xxd -r -p

# ASCII → Hex
echo -n "flag{test}" | xxd -p

# ROT13
echo "synt{grfg}" | tr 'a-zA-Z' 'n-za-mN-ZA-M'

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('flag%7Btest%7D'))"

# Binary → ASCII
python3 -c "print(''.join(chr(int(b,2)) for b in '01100110 01101100 01100001 01100111'.split()))"

# Decimal → ASCII
python3 -c "print(''.join(chr(int(x)) for x in '102 108 97 103'.split()))"

# Reverse string
echo "}tset{galf" | rev
```

## Forensics

```bash
# Mount disk image (read-only!)
sudo mount -o ro,loop disk.dd /mnt/evidence

# Recover deleted files
fls -r -d disk.dd                               # list deleted
icat disk.dd <inode> > recovered.file            # recover by inode

# Browser history quick
sqlite3 History "SELECT url,title FROM urls ORDER BY last_visit_time DESC LIMIT 20"

# Extract all files from PCAP
tshark -r capture.pcap --export-objects "http,exported/"

# Memory dump strings search
strings -e l memory.dmp | grep -i "flag\|password\|secret" | head -50
```

## Hash & Password

```bash
# Generate hashes
md5sum file && sha1sum file && sha256sum file

# Identify hash type
python3 -c "
h = input('Hash: ')
sizes = {32:'MD5', 40:'SHA1', 56:'SHA224', 64:'SHA256', 96:'SHA384', 128:'SHA512'}
print(sizes.get(len(h), f'Unknown ({len(h)} chars)'))
"

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Crack NTLM with hashcat
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

---

# 7. Encoding & Decoding

| Encoding | Contoh | Cara Decode |
|----------|--------|-------------|
| **Base64** | `ZmxhZ3t0ZXN0fQ==` | `echo ... \| base64 -d` |
| **Base32** | `MZWGCZ33ONXW2===` | CyberChef: From Base32 |
| **Hex** | `666c6167` | `echo ... \| xxd -r -p` |
| **URL** | `flag%7Btest%7D` | CyberChef: URL Decode |
| **HTML Entity** | `&#102;&#108;&#97;&#103;` | CyberChef: From HTML Entity |
| **Octal** | `\146\154\141\147` | `echo -e "\146\154\141\147"` |
| **Binary** | `01100110 01101100` | Python / CyberChef |
| **ROT13** | `synt{grfg}` | `echo ... \| tr 'a-zA-Z' 'n-za-mN-ZA-M'` |
| **ROT47** | `7=28LEC:Ln` | CyberChef: ROT47 |
| **Morse** | `.. - ... / .- / ..-. .-.. .- --.` | CyberChef: From Morse |
| **Decimal** | `102 108 97 103` | Python: `chr()` |
| **Braille** | `⠋⠇⠁⠛` | CyberChef / online converter |
| **JWT** | `eyJhbGci...` | https://jwt.io/ |

---

# 8. Event ID Cheatsheet

```
══════ AUTHENTICATION ══════
4624  Logon SUCCESS             ← Siapa masuk?
4625  Logon FAIL                ← Brute force?
4634  Logoff
4647  User initiated logoff
4648  Explicit credentials      ← Pass-the-hash?
4672  Special privileges (admin)← Admin login!
4776  Credential validation     ← NTLM auth

══════ ACCOUNT MANAGEMENT ══════
4720  User CREATED              ← Backdoor?
4722  User ENABLED
4724  Password RESET
4725  User DISABLED
4726  User DELETED
4728  Added to SECURITY GROUP   ← Privesc?
4732  Added to LOCAL GROUP
4756  Added to UNIVERSAL GROUP

══════ PROCESS & SERVICE ══════
4688  Process CREATED           ← Malware? Command?
4689  Process exited
4697  Service INSTALLED         ← Persistence?
7045  Service INSTALLED (System log)

══════ SCHEDULED TASK ══════
4698  Task CREATED              ← Persistence?
4699  Task DELETED
4700  Task ENABLED
4702  Task UPDATED

══════ OBJECT ACCESS ══════
4663  Object ACCESS attempt     ← File access
5140  Network SHARE accessed    ← Lateral movement
5145  Network share check

══════ FIREWALL ══════
5156  Connection ALLOWED
5157  Connection BLOCKED

══════ ANTI-FORENSICS ══════
1102  AUDIT LOG CLEARED!        ← Covering tracks!!

══════ LOGON TYPES ══════
 2  Interactive (local keyboard)
 3  Network (SMB share)
 4  Batch (scheduled task)
 5  Service
 7  Unlock
 8  Network Cleartext
 9  NewCredentials (RunAs)
10  RDP (Remote Desktop!)
11  Cached credentials
```

---

# 9. Splunk SPL Cheatsheet

```spl
# ══════ SEARCH ══════
index=* "keyword"
index=* EventCode=4624
index=* sourcetype=WinEventLog:Security

# ══════ TIME ══════
earliest=-24h latest=now
earliest="01/15/2026:00:00:00" latest="01/16/2026:00:00:00"

# ══════ FILTER ══════
... | search field=value
... | where count > 10
... | dedup field_name

# ══════ STATS ══════
... | stats count BY Source_Network_Address
... | stats count BY Account_Name, EventCode
... | stats values(Account_Name) BY Source_Network_Address
... | stats earliest(_time) latest(_time) count BY Account_Name
... | stats dc(Account_Name) AS unique_users BY Source_Network_Address

# ══════ DISPLAY ══════
... | table _time, Account_Name, Source_Network_Address
... | sort _time
... | sort -count
... | head 20
... | top 10 field_name
... | rare 10 field_name
... | rename Source_Network_Address AS "Attacker IP"

# ══════ TIME CHART ══════
... | timechart span=1h count BY Source_Network_Address

# ══════ REGEX ══════
... | rex field=_raw "(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
... | rex field=_raw "flag\{(?<flag>[^\}]+)\}"

# ══════ EVAL ══════
... | eval label=case(EventCode=="4624","LOGIN", EventCode=="4625","FAIL", 1==1,"OTHER")
... | eval logon_method=if(Logon_Type=="10","RDP","Other")

# ══════ TRANSACTION ══════
... | transaction Source_Network_Address maxspan=5m
... | where eventcount > 5

# ══════ QUICK WINS ══════
index=* "flag{"                                              # direct flag search!
index=* EventCode=4625 | stats count BY Source_Network_Address | sort -count  # brute force IP
index=* EventCode=4624 Logon_Type=10 | table _time, Account_Name, Source_Network_Address  # RDP
index=* EventCode=4688 | search *powershell* OR *cmd* OR *whoami*  # suspicious procs
index=* EventCode=1102 | table _time, SubjectUserName       # log cleared!
```

---

# 10. Wazuh KQL Cheatsheet

```
# ══════ SEARCH ══════
data.win.system.eventID: "4624"
data.win.system.eventID: "4625"
rule.level: >= 12
agent.name: "DC01"
"flag{"

# ══════ COMBINE ══════
data.win.system.eventID: "4625" AND data.srcip: "10.10.14.5"
rule.id: "5720" OR rule.description: *brute*
data.win.system.eventID: "4688" AND data.win.eventdata.newProcessName: *powershell*
NOT data.win.eventdata.logonType: "5"

# ══════ WILDCARD ══════
data.win.eventdata.newProcessName: *mimikatz*
agent.name: server*
```

---

# 11. Assembly & Binary Cheatsheet

```
══════ CONDITIONAL JUMPS ══════
74 = JE/JZ    (==)     ↔ 75 = JNE/JNZ  (!=)
7C = JL       (<)      ↔ 7D = JGE      (>=)
7E = JLE      (<=)     ↔ 7F = JG       (>)
72 = JB/JC    (< uns)  ↔ 73 = JAE/JNC  (>= uns)
76 = JBE      (<= uns) ↔ 77 = JA       (> uns)
EB = JMP      (always)
0F 84 = JE (near)      ↔ 0F 85 = JNE (near)

══════ COMMON BYTES ══════
90 = NOP                C3 = RET
CC = INT3 (breakpoint)  31 C0 = XOR EAX,EAX (=0)
B8 xx = MOV EAX, xx     E8 xx = CALL (rel)
E9 xx = JMP (rel near)  FF 25 = JMP [addr]

══════ CALLING CONVENTION (Linux x64) ══════
RDI = arg1   RSI = arg2   RDX = arg3
RCX = arg4   R8  = arg5   R9  = arg6
RAX = return value
Stack = arg7+

══════ CALLING CONVENTION (Windows x64) ══════
RCX = arg1   RDX = arg2   R8  = arg3   R9  = arg4
RAX = return value
Stack = arg5+

══════ PATCHING TRICKS ══════
Flip logic:    74 → 75  (je→jne)  or  75 → 74
Force jump:    74 xx → EB xx (je→jmp)
Skip call:     E8 xx xx xx xx → 90 90 90 90 90 (5 NOPs)
Force return 0: 31 C0 C3 (xor eax,eax; ret)
Force return 1: B8 01 00 00 00 C3 (mov eax,1; ret)

══════ CRYPTO CONSTANTS ══════
0x9E3779B9 = TEA/XTEA (golden ratio)
0x61707865 = ChaCha20/Salsa20 ("expa")
0x67452301 = MD5 init
0x6A09E667 = SHA256 init
```

---

# 12. File Signatures

```
══════ IMAGES ══════
FF D8 FF       = JPEG
89 50 4E 47    = PNG
47 49 46 38    = GIF
42 4D          = BMP
52 49 46 46    = WEBP (RIFF container)
49 49 2A 00    = TIFF (little-endian)
4D 4D 00 2A    = TIFF (big-endian)

══════ ARCHIVES ══════
50 4B 03 04    = ZIP (also DOCX, XLSX, APK, JAR!)
50 4B 05 06    = ZIP (empty)
52 61 72 21    = RAR ("Rar!")
1F 8B          = GZIP
42 5A 68       = BZIP2 ("BZh")
37 7A BC AF    = 7z
FD 37 7A 58    = XZ

══════ DOCUMENTS ══════
25 50 44 46    = PDF ("%PDF")
D0 CF 11 E0    = MS Office (DOC, XLS, PPT)
50 4B 03 04    = MS Office 2007+ (DOCX, XLSX, PPTX = ZIP!)

══════ EXECUTABLES ══════
7F 45 4C 46    = ELF (Linux)
4D 5A          = PE/EXE (Windows, "MZ")
FE ED FA CE    = Mach-O 32-bit
FE ED FA CF    = Mach-O 64-bit
CA FE BA BE    = Mach-O fat / Java class
00 61 73 6D    = WebAssembly

══════ DATABASE ══════
53 51 4C 69    = SQLite ("SQLi...")

══════ AUDIO/VIDEO ══════
49 44 33       = MP3 (ID3 tag)
FF FB          = MP3
52 49 46 46    = WAV/AVI (RIFF)
1A 45 DF A3    = MKV/WebM

══════ MISC ══════
00 00 00 xx 66 74 79 70 = MP4/MOV (ftyp)
4F 67 67 53    = OGG
25 21 50 53    = PostScript
7B 5C 72 74    = RTF ("{\rt")
```

---

# 13. Hash Identification

| Length (chars) | Hash Type | Hashcat Mode |
|---|---|---|
| 32 | MD5 | `-m 0` |
| 40 | SHA1 | `-m 100` |
| 56 | SHA224 | `-m 1300` |
| 64 | SHA256 | `-m 1400` |
| 96 | SHA384 | `-m 10800` |
| 128 | SHA512 | `-m 1700` |
| 32 (all hex, Windows) | NTLM | `-m 1000` |
| `$1$...` | md5crypt (Linux) | `-m 500` |
| `$5$...` | sha256crypt (Linux) | `-m 7400` |
| `$6$...` | sha512crypt (Linux) | `-m 1800` |
| `$2b$...` / `$2a$...` | bcrypt | `-m 3200` |
| `$apr1$...` | Apache MD5 | `-m 1600` |

---

# 14. Wordlists

```bash
# Lokasi wordlist umum di Kali/Parrot:
/usr/share/wordlists/rockyou.txt           # passwords (14M entries)
/usr/share/wordlists/dirbuster/            # web directory brute
/usr/share/wordlists/seclists/             # comprehensive collection
/usr/share/dirb/wordlists/                 # directory brute

# Download rockyou.txt:
sudo apt install wordlists
# Atau:
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# SecLists (comprehensive):
git clone https://github.com/danielmiessler/SecLists.git
# Atau: sudo apt install seclists
```

---

# 15. Platform Latihan

| Platform | URL | Fokus | Level |
|----------|-----|-------|-------|
| **picoCTF** | https://picoctf.org/ | Semua kategori | Pemula |
| **CyberDefenders** | https://cyberdefenders.org/ | Blue Team / DFIR | Menengah |
| **LetsDefend** | https://letsdefend.io/ | SOC Analyst | Pemula-Menengah |
| **Blue Team Labs** | https://blueteamlabs.online/ | Blue Team | Menengah |
| **TryHackMe** | https://tryhackme.com/ | Guided rooms | Pemula |
| **HackTheBox** | https://hackthebox.com/ | Challenge + mesin | Menengah |
| **root-me** | https://root-me.org/ | Semua kategori | Semua |
| **CTFlearn** | https://ctflearn.com/ | Semua kategori | Pemula |
| **crackmes.one** | https://crackmes.one/ | RE only | Pemula-Menengah |
| **MemLabs** | https://github.com/stuxnet999/MemLabs | Memory forensics | Menengah |
| **Reversing.kr** | http://reversing.kr/ | RE only | Menengah |
| **Malware Traffic** | https://www.malware-traffic-analysis.net/ | PCAP analysis | Menengah |
| **SANS Holiday Hack** | https://www.holidayhackchallenge.com/ | Multi-skill | Pemula-Sulit |
| **CTFtime** | https://ctftime.org/ | CTF event calendar | Semua |
| **pwn.college** | https://pwn.college/ | RE + Pwn course | Pemula |

---

# 16. Install Script — Setup Sekali Jalan

Simpan dan jalankan di **WSL/Ubuntu** untuk install semua tools:

```bash
#!/bin/bash
# ctf_setup.sh — Install semua tools CTF
# Jalankan: chmod +x ctf_setup.sh && sudo ./ctf_setup.sh

echo "[*] Updating system..."
apt update && apt upgrade -y

echo "[*] Installing basic tools..."
apt install -y build-essential git wget curl unzip p7zip-full jq

echo "[*] Installing RE tools..."
apt install -y gdb radare2 binutils file ltrace strace default-jdk

echo "[*] Installing forensic tools..."
apt install -y binwalk foremost scalpel sleuthkit testdisk
apt install -y steghide pngcheck imagemagick
apt install -y wireshark tshark tcpdump ngrep
apt install -y sqlite3 hexedit
apt install -y libimage-exiftool-perl
apt install -y yara clamav

echo "[*] Installing Python tools..."
pip3 install pwntools z3-solver angr
pip3 install frida-tools objection
pip3 install uncompyle6 decompyle3
pip3 install volatility3
pip3 install oletools pefile pyelftools
pip3 install python-evtx
pip3 install stegoveritas stegcracker
pip3 install scapy pycryptodome pyhindsight

echo "[*] Installing pwndbg..."
cd /opt
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
cd ~

echo "[*] Installing Chainsaw..."
cd /opt
wget -q https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw-x86_64-unknown-linux-gnu.tar.gz
tar xzf chainsaw-*.tar.gz
rm chainsaw-*.tar.gz
ln -sf /opt/chainsaw/chainsaw /usr/local/bin/chainsaw

echo "[*] Installing zsteg..."
gem install zsteg 2>/dev/null || echo "[-] Ruby/gem not found, skip zsteg"

echo "[*] Installing wordlists..."
apt install -y wordlists seclists 2>/dev/null

echo ""
echo "========================================="
echo " ✅ CTF Setup Complete!"
echo " pwndbg: auto-loaded with gdb"
echo " Ghidra: install separately (needs GUI)"
echo " x64dbg: Windows only"
echo " dnSpy: Windows only"
echo "========================================="
```

---

> **🏆 Tips Terakhir untuk Lomba:**
> 1. **Buka CyberChef** di tab pertama browser — kamu PASTI butuh
> 2. **Bookmark file ini** — buka saat lomba untuk referensi cepat
> 3. **Copy script boilerplate** ke folder kerja SEBELUM lomba mulai
> 4. **Jangan panik** — ikuti metodologi: `file` → `strings` → `binwalk` → analisis lebih dalam
> 5. **Kerjakan yang mudah dulu** — kumpulkan poin cepat sebelum tackle soal sulit
> 6. **Baca soal baik-baik** — kadang hint tersembunyi di deskripsi soal
> 7. **Coba `grep flag{`** pada setiap file/log/memory dump — sering works!
>
> **Semoga sukses di lomba LKS! 💪🏆**
