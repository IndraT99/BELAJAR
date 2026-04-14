# 🎯 CTF LKS Blue Team — Topik Lanjutan: Email Forensics, Phishing & SQLi in PCAP

> File ini melengkapi panduan yang sudah ada dengan topik yang **sering muncul di LKS**
> tapi belum tercakup: analisis email, phishing/typosquatting, dan SQL injection dari PCAP.

---

## Daftar Isi

- [Bagian 1: Email Forensics (.eml)](#bagian-1-email-forensics)
- [Bagian 2: Phishing Analysis & Typosquatting](#bagian-2-phishing-analysis--typosquatting)
- [Bagian 3: SQL Injection di PCAP](#bagian-3-sql-injection-di-pcap)
- [Bagian 4: Web Attack Patterns di PCAP](#bagian-4-web-attack-patterns-di-pcap)
- [Bagian 5: Data Exfiltration di PCAP](#bagian-5-data-exfiltration-di-pcap)
- [Bagian 6: Script & Boilerplate Siap Pakai](#bagian-6-scripts--boilerplate)
- [Bagian 7: Walkthrough Soal Bergaya LKS](#bagian-7-walkthrough-bergaya-lks)
- [Bagian 8: Cheat Sheet](#bagian-8-cheat-sheet)

---

# Bagian 1: Email Forensics

## Apa itu File .eml?

**EML** = format standar untuk menyimpan satu pesan email lengkap. Berisi header, body, dan attachment dalam bentuk teks.

```
File .eml pada dasarnya adalah TEXT FILE yang bisa dibuka dengan:
- Notepad / text editor apapun
- Thunderbird (email client)
- Outlook
- Browser (beberapa bisa render langsung)
- Python (parsing otomatis)
```

## Struktur File .eml

```
┌─────────────────────────────────────────────────────┐
│ HEADER                                               │
│ ├── From: sender@example.com                         │
│ ├── To: victim@example.com                           │
│ ├── Subject: Important Security Alert!               │
│ ├── Date: Mon, 15 Jan 2026 14:30:00 +0700           │
│ ├── Message-ID: <unique-id@mail.example.com>         │
│ ├── MIME-Version: 1.0                                │
│ ├── Content-Type: multipart/mixed; boundary="..."    │
│ ├── X-Mailer: Thunderbird 102.0                      │
│ ├── Received: from [...] (beberapa baris, chain)     │
│ ├── Return-Path: <real-sender@attacker.com>          │
│ ├── DKIM-Signature: ... (jika ada)                   │
│ ├── SPF: ... (jika ada)                              │
│ └── Reply-To: reply@attacker.com (BISA BEDA!)        │
│                                                       │
│ BODY (setelah baris kosong)                           │
│ ├── Text/Plain: pesan dalam plaintext                │
│ ├── Text/HTML: pesan dalam HTML (bisa ada link!)     │
│ └── Attachments: file terlampir (Base64 encoded)     │
└─────────────────────────────────────────────────────┘
```

## Cara Membaca .eml

### Metode 1: Buka dengan Text Editor

```bash
# Cara paling dasar — buka langsung!
$ cat suspicious.eml

# Output:
From: "Roman Bank Security" <security@roman-bank.idhello>
To: <bob@recipient.idhello>
Subject: Urgent: Unusual Login Detected
Date: Mon, 15 Jan 2026 10:00:00 +0700
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Return-Path: <zeno.vemtom@idhello>
Received: from mail.attacker.com (192.168.1.100)
    by mail.recipient.idhello; Mon, 15 Jan 2026 10:00:01 +0700
Message-ID: <abc123@mail.attacker.com>
X-Mailer: Python/smtplib

<html>
<body>
<p>Dear Bob,</p>
<p>We detected an unusual login to your account.</p>
<p>Please verify your identity: 
   <a href="http://romaո-bankverify.idhello/login?id=bo">Click here</a></p>
<p>Regards,<br>Roman Bank Security Team</p>
</body>
</html>
```

### Metode 2: Python Parser (Recommended!)

```python
#!/usr/bin/env python3
"""Parse file .eml dan extract informasi penting"""
import email
from email import policy
from email.parser import BytesParser
import base64, sys, re, os

eml_file = sys.argv[1] if len(sys.argv) > 1 else "suspicious.eml"

with open(eml_file, 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

print("=" * 60)
print("EMAIL FORENSICS REPORT")
print("=" * 60)

# ═══ HEADER ANALYSIS ═══
print("\n[1] BASIC HEADERS")
print(f"  From:        {msg['From']}")
print(f"  To:          {msg['To']}")
print(f"  Subject:     {msg['Subject']}")
print(f"  Date:        {msg['Date']}")
print(f"  Message-ID:  {msg['Message-ID']}")
print(f"  Reply-To:    {msg['Reply-To']}")
print(f"  Return-Path: {msg['Return-Path']}")
print(f"  X-Mailer:    {msg['X-Mailer']}")

# ═══ RECEIVED HEADERS (routing) ═══
print("\n[2] RECEIVED HEADERS (bottom = origin)")
received = msg.get_all('Received', [])
for i, r in enumerate(reversed(received)):
    r_clean = ' '.join(r.split())
    print(f"  Hop {i+1}: {r_clean[:120]}")

# ═══ SECURITY HEADERS ═══
print("\n[3] SECURITY HEADERS")
for hdr in ['DKIM-Signature', 'ARC-Authentication-Results',
            'Authentication-Results', 'X-Spam-Status', 'X-Spam-Score']:
    val = msg[hdr]
    if val:
        print(f"  {hdr}: {str(val)[:120]}")

# SPF/DKIM results from Authentication-Results
auth_result = msg.get('Authentication-Results', '')
if auth_result:
    if 'spf=pass' in str(auth_result).lower():
        print("  [✅] SPF PASS")
    elif 'spf=fail' in str(auth_result).lower():
        print("  [❌] SPF FAIL — possible spoofing!")
    if 'dkim=pass' in str(auth_result).lower():
        print("  [✅] DKIM PASS")
    elif 'dkim=fail' in str(auth_result).lower():
        print("  [❌] DKIM FAIL — possible spoofing!")

# ═══ BODY EXTRACTION ═══
print("\n[4] BODY CONTENT")
body_text = ""
body_html = ""

if msg.is_multipart():
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == 'text/plain':
            body_text = part.get_content()
        elif ctype == 'text/html':
            body_html = part.get_content()
else:
    ctype = msg.get_content_type()
    if ctype == 'text/plain':
        body_text = msg.get_content()
    elif ctype == 'text/html':
        body_html = msg.get_content()

if body_text:
    print(f"  [Text/Plain]:\n  {body_text[:500]}")
if body_html:
    print(f"  [Text/HTML]:\n  {body_html[:500]}")

# ═══ EXTRACT URLS ═══
print("\n[5] EXTRACTED URLs")
all_text = body_text + body_html
urls = re.findall(r'https?://[^\s<>"\']+', all_text)
for url in set(urls):
    print(f"  → {url}")
    # cek homoglyph / typosquatting
    for i, char in enumerate(url):
        if ord(char) > 127:
            print(f"    ⚠️  HOMOGLYPH at position {i}: '{char}' "
                  f"(U+{ord(char):04X}) — NOT ASCII!")

# Cek href vs display text mismatch
href_pattern = r'href=["\']([^"\']+)["\'][^>]*>([^<]+)'
mismatches = re.findall(href_pattern, all_text)
for href, display in mismatches:
    if href.replace('http://', '').replace('https://', '').split('/')[0] != \
       display.replace('http://', '').replace('https://', '').split('/')[0]:
        print(f"  ⚠️  HREF MISMATCH: link='{href}' display='{display}'")

# ═══ EXTRACT ATTACHMENTS ═══
print("\n[6] ATTACHMENTS")
for part in msg.walk() if msg.is_multipart() else [msg]:
    filename = part.get_filename()
    if filename:
        payload = part.get_payload(decode=True)
        print(f"  📎 {filename} ({len(payload)} bytes)")
        outpath = f"extracted_{filename}"
        with open(outpath, 'wb') as out:
            out.write(payload)
        print(f"     Saved to: {outpath}")

# ═══ FLAG SEARCH ═══
print("\n[7] FLAG SEARCH")
all_content = str(msg)
flags = re.findall(r'(?:flag|LKS|CTF)\{[^}]+\}', all_content, re.IGNORECASE)
if flags:
    for f in flags:
        print(f"  🏴 {f}")
else:
    print("  No flags found in raw content.")

# ═══ SUSPICIOUS INDICATORS ═══
print("\n[8] SUSPICIOUS INDICATORS")

# From vs Return-Path mismatch
from_addr = str(msg['From'])
return_path = str(msg['Return-Path'] or '')
if return_path and from_addr:
    from_email = re.findall(r'[\w.-]+@[\w.-]+', from_addr)
    return_email = re.findall(r'[\w.-]+@[\w.-]+', return_path)
    if from_email and return_email and from_email[0] != return_email[0]:
        print(f"  ⚠️  FROM ({from_email[0]}) ≠ RETURN-PATH ({return_email[0]})")

# Reply-To mismatch
reply_to = str(msg['Reply-To'] or '')
if reply_to and from_addr:
    reply_email = re.findall(r'[\w.-]+@[\w.-]+', reply_to)
    if from_email and reply_email and from_email[0] != reply_email[0]:
        print(f"  ⚠️  FROM ({from_email[0]}) ≠ REPLY-TO ({reply_email[0]})")

# Urgency keywords
subject = str(msg['Subject'] or '').lower()
urgency_words = ['urgent', 'immediately', 'suspend', 'verify', 'confirm',
                 'unusual', 'unauthorized', 'security', 'alert', 'warning']
found_urgency = [w for w in urgency_words if w in subject]
if found_urgency:
    print(f"  ⚠️  URGENCY keywords in subject: {found_urgency}")

print("\n" + "=" * 60)
```

### Metode 3: Thunderbird / Outlook

```
Thunderbird:
1. File → Open → pilih .eml
2. Email terbuka untuk dibaca
3. View → Message Source (Ctrl+U) → lihat raw headers

Outlook:
1. Drag .eml ke Outlook, atau double-click
2. File → Properties → Internet Headers (lihat raw headers)
```

### Metode 4: CLI Tools

```bash
# Lihat headers saja
$ grep -E "^(From|To|Subject|Date|Return-Path|Reply-To|Received|X-Mailer):" email.eml

# Extract semua URLs
$ grep -oP 'https?://[^\s<>"'"'"']+' email.eml

# Extract attachments dengan munpack
$ sudo apt install mpack
$ munpack email.eml
# File attachment di-extract ke current directory

# Atau ripmime
$ sudo apt install ripmime
$ ripmime -i email.eml -d extracted/
$ ls extracted/
```

## Header yang Penting untuk CTF

```
═══ IDENTIFIKASI PENGIRIM ═══
From:           → alamat yang DITAMPILKAN (bisa di-spoof!)
Return-Path:    → alamat ASLI pengirim (lebih reliable)
Reply-To:       → alamat balasan (jika beda dari From → SUSPICIOUS)
Received:       → rute email (dari bawah ke atas = asli ke tujuan)
X-Originating-IP: → IP asli pengirim (kadang ada)

═══ VERIFIKASI ═══  
DKIM-Signature:           → tanda tangan digital (validasi sender domain)
Authentication-Results:   → hasil pengecekan SPF/DKIM/DMARC
  spf=pass  → domain pengirim valid
  spf=fail  → domain DIPALSUKAN!
  dkim=pass → signature valid
  dkim=fail → signature INVALID!

═══ RED FLAGS ═══
✗ From ≠ Return-Path         → sender spoofing
✗ From ≠ Reply-To            → reply akan ke orang lain
✗ SPF/DKIM fail              → domain palsu
✗ Urgency di subject         → social engineering
✗ URL di body ≠ display text → phishing link
✗ Attachment .exe/.js/.vbs   → malware
✗ X-Mailer: Python           → automated/scripted email
```

---

# Bagian 2: Phishing Analysis & Typosquatting

## Apa itu Typosquatting?

**Typosquatting** = membuat domain yang MIRIP dengan domain asli untuk menipu korban.

```
Domain asli:    google.com
Typosquatting:  g00gle.com        ← angka 0 menggantikan huruf o
                gooogle.com       ← huruf tambahan
                googl.com         ← huruf hilang
                gogle.com         ← huruf ditukar
                gogole.com        ← urutan huruf dibalik
                google.corn       ← TLD mirip (.corn vs .com)
```

## Apa itu Homoglyph Attack?

**Homoglyph** = karakter Unicode yang TERLIHAT IDENTIK dengan karakter ASCII biasa, tapi sebenarnya BERBEDA.

Ini yang digunakan di soal LKS "VERIFIED"!

```
Contoh homoglyph:

ASCII    Unicode                  Terlihat Sama?
─────    ───────────────────────  ──────────────
a        а (Cyrillic а, U+0430)  YA!
e        е (Cyrillic е, U+0435)  YA!  
o        о (Cyrillic о, U+043E)  YA!
p        р (Cyrillic р, U+0440)  YA!
c        с (Cyrillic с, U+0441)  YA!
n        ո (Armenian ո, U+0578)  YA! ← digunakan di soal LKS!
n        ñ (Latin ñ, U+00F1)     Mirip tapi beda
l        І (Cyrillic І, U+0406)  YA!
i        і (Cyrillic і, U+0456)  YA!
d        ԁ (Cyrillic ԁ, U+0501)  YA!

URL asli:     roman-bankverify.idhello
URL phishing: romaո-bankverify.idhello
                  ↑ ini bukan "n" ASCII!
                  ini "ո" (Armenian, U+0578)
```

## Cara Mendeteksi Homoglyph

### Metode 1: Hex Dump (Paling Reliable!)

```bash
# ASCII "n" = 0x6E (1 byte)
# Armenian "ո" = 0xD5 0xB8 (2 bytes, UTF-8)

$ echo -n "romaո-bank" | xxd
00000000: 726f 6d61 d5b8 2d62 616e 6b              roma..-bank

# Lihat! "ո" jadi D5 B8 (2 bytes), bukan 6E (1 byte)!
# Karakter ASCII SELALU 1 byte (00-7F)
# Jika ada byte > 0x7F → bukan ASCII → kemungkinan homoglyph!
```

### Metode 2: Python Detector

```python
#!/usr/bin/env python3
"""Deteksi homoglyph / karakter non-ASCII di URL atau teks"""
import unicodedata, sys

text = sys.argv[1] if len(sys.argv) > 1 else "romaո-bankverify.idhello"

print(f"Analyzing: {text}")
print(f"Length: {len(text)} characters\n")

print(f"{'Pos':>4} {'Char':>5} {'Hex':>8} {'Unicode':>8} {'Name'}")
print("-" * 70)

suspicious = []
for i, char in enumerate(text):
    code = ord(char)
    name = unicodedata.name(char, 'UNKNOWN')
    category = unicodedata.category(char)
    
    is_sus = code > 127  # non-ASCII = suspicious!
    marker = " ⚠️ HOMOGLYPH!" if is_sus else ""
    
    print(f"{i:>4} {repr(char):>5} {code:#8x} {'U+'+format(code,'04X'):>8} {name}{marker}")
    
    if is_sus:
        suspicious.append((i, char, code, name))

if suspicious:
    print(f"\n{'='*70}")
    print(f"⚠️  FOUND {len(suspicious)} SUSPICIOUS CHARACTER(S):")
    for pos, char, code, name in suspicious:
        print(f"  Position {pos}: '{char}' → U+{code:04X} ({name})")
        # Cari kemungkinan ASCII equivalent
        ascii_look = {
            'ARMENIAN SMALL LETTER VO': 'n',
            'CYRILLIC SMALL LETTER A': 'a',
            'CYRILLIC SMALL LETTER IE': 'e',
            'CYRILLIC SMALL LETTER O': 'o',
            'CYRILLIC SMALL LETTER ER': 'p',
            'CYRILLIC SMALL LETTER ES': 'c',
            'CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I': 'I',
            'CYRILLIC SMALL LETTER UKRAINIAN I': 'i',
            'CYRILLIC SMALL LETTER KOMI DE': 'd',
            'LATIN SMALL LETTER N WITH TILDE': 'n',
        }
        likely = ascii_look.get(name, '?')
        print(f"    Intended to look like ASCII: '{likely}'")
else:
    print("\n✅ No homoglyphs detected — all characters are ASCII.")
```

### Metode 3: Quick CLI Check

```bash
# Cek apakah ada karakter non-ASCII di file
$ grep -P '[^\x00-\x7F]' suspicious.eml
# Jika ada output → ada karakter non-ASCII!

# Highlight karakter non-ASCII
$ cat suspicious.eml | LC_ALL=C grep --color='auto' -P '[\x80-\xFF]'

# Cek URL spesifik
$ echo -n "romaո-bankverify.idhello" | LC_ALL=C grep -cP '[^\x00-\x7F]'
# Output: 1 → ada 1 baris dengan karakter non-ASCII

# Lihat code point setiap karakter
$ echo -n "romaո-bank" | python3 -c "
import sys
for c in sys.stdin.read():
    print(f'{c!r:>6} = U+{ord(c):04X} ({ord(c):>5d})')
"
```

### Metode 4: CyberChef

```
1. Buka https://gchq.github.io/CyberChef/
2. Paste URL yang mencurigakan
3. Operasi: "To Hex" atau "To Charcode" 
4. Bandingkan: ASCII characters = 1 byte, homoglyphs = 2+ bytes
5. Atau: "Escape Unicode Characters" → menunjukkan \uXXXX untuk non-ASCII
```

## IDN Homograph Attack (Punycode)

```
Domain Unicode bisa di-convert ke Punycode:
  romaո-bank.com → xn--roma-bank-z06e.com

Browser modern menampilkan Punycode jika domain mengandung
mixed scripts (Latin + Cyrillic, dll.) → tapi tidak selalu!

Cek Punycode:
$ python3 -c "print('romaո-bank.com'.encode('idna'))"
# b'xn--roma-bank-z06e.com'

# Jika domain di-encode ke Punycode (xn--) → ada Unicode characters!
```

## Phishing Indicators — Checklist Lengkap

```
═══ EMAIL HEADER ═══
□ From address domain cocok dengan organisasi yang diklaim?
□ Return-Path sama dengan From?
□ Reply-To sama dengan From?
□ SPF pass?
□ DKIM pass?
□ X-Mailer mencurigakan? (Python, PHP, etc.)
□ Received headers konsisten?

═══ EMAIL BODY ═══
□ Urgency/pressure? ("Immediately", "Your account will be suspended")
□ Generic greeting? ("Dear Customer" instead of name)
□ Grammar/spelling errors?
□ Threats? ("If you don't verify, your account will be closed")
□ Request for credentials/personal info?
□ Too good to be true? ("You won $1,000,000!")

═══ URL/LINKS ═══
□ Hover link — actual URL matches displayed text?
□ Domain typosquatting? (g00gle vs google)
□ Homoglyph attack? (karakter non-ASCII)
□ Shortened URL? (bit.ly, tinyurl — hide real destination)
□ HTTP instead of HTTPS?
□ IP address instead of domain? (http://192.168.1.1/login)
□ Excessive subdomains? (login.google.com.attacker.com)
□ Suspicious TLD? (.xyz, .tk, .ml, .top)

═══ ATTACHMENTS ═══
□ Unexpected attachment?
□ Dangerous extension? (.exe, .js, .vbs, .bat, .ps1, .scr, .hta)
□ Double extension? (document.pdf.exe)
□ Password-protected archive? (bypass AV scanning)
□ Macro-enabled Office? (.docm, .xlsm)
```

---

# Bagian 3: SQL Injection di PCAP

## Apa itu SQL Injection?

**SQL Injection** = menyisipkan perintah SQL ke input yang dikirim ke server, sehingga server menjalankan query yang tidak seharusnya.

```
Normal request:
  GET /search?q=pizza HTTP/1.1
  → Server query: SELECT * FROM products WHERE name='pizza'

SQLi request:
  GET /search?q=pizza' OR 1=1-- HTTP/1.1
  → Server query: SELECT * FROM products WHERE name='pizza' OR 1=1--'
  → OR 1=1 selalu true → mengembalikan SEMUA data!
```

## Jenis SQLi yang Sering Muncul di CTF

### 1. Boolean-Based Blind SQLi (PALING SERING DI LKS!)

```
Attacker menebak data karakter per karakter:

Request 1: ' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='a' --
Server: false (status 200 tapi body "no results" / ukuran kecil)

Request 2: ' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='b' --
Server: false

...

Request 27: ' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='L' --
Server: TRUE! (status 200 dan body "results found" / ukuran besar)
→ Karakter pertama password = 'L'

Request selanjutnya:
' OR (SELECT substr(password,2,1) FROM users WHERE username='admin')='K' --
Server: TRUE!
→ Karakter kedua = 'K'

Dan seterusnya...
Password = L, K, S, {, X, f, !, l, t, r, ...
```

### 2. Union-Based SQLi

```
' UNION SELECT username, password FROM users--
→ Data dari tabel users digabung ke output normal
```

### 3. Error-Based SQLi

```
' AND 1=CONVERT(int, (SELECT @@version))--
→ Error message berisi informasi database
```

### 4. Time-Based Blind SQLi

```
' OR IF(substr(password,1,1)='a', SLEEP(5), 0)--
→ Jika benar, server delay 5 detik
→ Jika salah, response langsung
```

## Cara Mendeteksi SQLi di Wireshark

### Step 1: Filter HTTP Traffic

```
Filter Wireshark:
  http
  http.request.method == "GET" || http.request.method == "POST"
```

### Step 2: Cari SQL Patterns

```
Filter string-based:
  http.request.uri contains "'"
  http.request.uri contains "UNION"
  http.request.uri contains "SELECT"  
  http.request.uri contains "substr"
  http.request.uri contains "OR"
  http.request.uri contains "--"
  http.request.uri contains "SLEEP"
  frame contains "SELECT"
  frame contains "substr"
  frame contains "UNION"

Atau gabungan:
  http && (frame contains "SELECT" || frame contains "UNION" || frame contains "substr" || frame contains "OR 1=1")
```

### Step 3: Identifikasi True/False Response

```
Untuk Boolean-based SQLi:
- Filter request yang mengandung "substr" 
- Cek response masing-masing:
  - TRUE: ukuran response lebih besar / content berbeda / status code tertentu
  - FALSE: ukuran response lebih kecil / content berbeda

Di Wireshark:
1. Klik request → klik response (di "Request in frame XXX" / "Response in frame YYY")
2. Bandingkan Content-Length atau body
3. TRUE biasanya: ada "result", "found", content lebih panjang
4. FALSE biasanya: "no result", "not found", content lebih pendek
```

### Step 4: Extract Karakter yang Benar

```
Untuk setiap posisi (substr(password,N,1)):
1. Cari semua request dengan posisi N
2. Cek response masing-masing
3. Yang return TRUE → itulah karakter ke-N
4. Gabungkan semua karakter → password/flag!
```

## tshark — Extract SQLi dari PCAP via CLI

```bash
# ═══ CARI SEMUA REQUEST YANG MENGANDUNG SQL ═══
$ tshark -r challenge.pcap -Y 'http.request.uri contains "substr"' \
    -T fields -e frame.number -e http.request.uri

# ═══ CARI REQUEST + RESPONSE LENGTH ═══
$ tshark -r challenge.pcap -Y 'http.request.uri contains "substr"' \
    -T fields -e frame.number -e http.request.uri -e http.response.code \
    -e http.content_length

# ═══ FOLLOW SEMUA HTTP STREAMS ═══
$ tshark -r challenge.pcap -Y 'http' -T fields -e tcp.stream | sort -u
# Lalu follow satu per satu:
$ tshark -r challenge.pcap -z follow,tcp,ascii,<stream_number>

# ═══ EXPORT KE FILE UNTUK PROCESSING ═══
$ tshark -r challenge.pcap -Y 'http.request.uri contains "substr"' \
    -T fields -e http.request.uri > sqli_requests.txt
```

---

# Bagian 4: Web Attack Patterns di PCAP

## Pattern yang Sering Muncul

### Directory Bruteforce / Scanning

```
Ciri-ciri:
- Banyak request GET ke path berbeda-beda
- Banyak response 404 (Not Found) atau 403 (Forbidden)
- User-Agent: gobuster, dirbuster, nikto, wfuzz, sqlmap

Filter:
  http.response.code == 404 | stats count
  http.request && http.user_agent contains "gobuster"
```

### Command Injection

```
Ciri-ciri di URL:
  /page.php?cmd=whoami
  /page.php?cmd=cat+/etc/passwd
  /page.php?cmd=ls+-la
  /page.php?cmd=id;cat+/etc/shadow

  /page.php?file=../../../../etc/passwd   ← Path Traversal

Filter:
  http.request.uri contains "cmd="
  http.request.uri contains "exec="
  http.request.uri contains "../"
  frame contains "whoami" || frame contains "/etc/passwd"
```

### File Upload (Webshell)

```
Ciri-ciri:
- POST request ke /upload endpoint
- Setelah itu GET request ke file .php/.jsp di folder upload
- Parameter seperti ?cmd= atau ?c=

Timeline:
  1. POST /upload.php → upload shell.php
  2. GET /uploads/shell.php?cmd=whoami → RCE!

Filter:
  http.request.method == "POST" && http.request.uri contains "upload"
  http.request.uri contains "shell" || http.request.uri contains ".php?cmd"
```

### Cross-Site Scripting (XSS)

```
Ciri-ciri di URL/body:
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  javascript:alert(document.cookie)

Filter:
  frame contains "<script>"
  frame contains "alert("
  frame contains "onerror="
  http.request.uri contains "script"
```

---

# Bagian 5: Data Exfiltration di PCAP

## DNS Exfiltration

```
Attacker encode data → kirim sebagai subdomain DNS query:

Normal DNS:    www.google.com
Exfiltration:  ZmxhZ3t0ZXN0fQ.evil.com     ← Base64 encoded!
               666c61677b74657374.evil.com  ← Hex encoded!

Cara detect:
1. Filter: dns
2. Cari DNS query yang sangat panjang / subdomain aneh
3. Extract subdomain → decode (Base64/Hex/etc.)

Filter Wireshark:
  dns.qry.name contains "evil.com"
  dns && frame contains ".evil.com"
```

## ICMP Tunneling

```
Data disembunyikan di ICMP payload (ping):

Normal ping: payload = "abcdefghijklmnop..."
Exfil ping:  payload = "flag{hidden_data}"

Cara detect:
1. Filter: icmp
2. Cek payload setiap paket ICMP
3. Gabungkan payload → decode
```

## HTTP Exfiltration

```
Data dikirim via:
- HTTP POST body
- URL parameter
- HTTP headers (Cookie, User-Agent, X-Custom-Header)
- Base64 encoded di request

Filter:
  http.request.method == "POST"
  http && frame contains "base64"
```

---

# Bagian 6: Scripts & Boilerplate

## Script 1: Boolean SQLi Extractor dari PCAP

```python
#!/usr/bin/env python3
"""
Extract password dari Boolean-based Blind SQLi di PCAP.
Cocok untuk soal seperti "FoodJection" di LKS.

Cara kerja:
1. Parse semua HTTP request yang mengandung "substr"
2. Cek response — TRUE atau FALSE
3. Extract karakter yang correct
4. Gabungkan → flag/password

Jalankan: python3 sqli_extract.py capture.pcap
"""
from scapy.all import *
import re, sys
from urllib.parse import unquote
from collections import defaultdict

pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"

print(f"[*] Loading {pcap_file}...")
packets = rdpcap(pcap_file)

# ═══ CONFIG ═══
# Sesuaikan pattern ini berdasarkan soal!
SUBSTR_PATTERN = r"substr\((\w+),(\d+),(\d+)\).*?=.*?'([^']+)'"
# ↑ Match: substr(password,1,1)='a'
# Group 1: field name (password)
# Group 2: position
# Group 3: length
# Group 4: character being tested

# Cara menentukan TRUE response:
# Opsi 1: berdasarkan Content-Length (response TRUE biasanya lebih besar)
# Opsi 2: berdasarkan string di response body ("true", "found", "result")
# Opsi 3: berdasarkan HTTP status code
TRUE_INDICATORS = [b'true', b'found', b'result', b'success', b'1']
FALSE_INDICATORS = [b'false', b'not found', b'no result', b'fail', b'0']

# ═══ PARSE PACKETS ═══
# Bangun mapping: request frame → response
http_pairs = []  # (request_data, response_data)

# Pendekatan: parse TCP streams
streams = defaultdict(list)
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        stream_id = (
            min(str(pkt[IP].src), str(pkt[IP].dst)),
            max(str(pkt[IP].src), str(pkt[IP].dst)),
            min(pkt[TCP].sport, pkt[TCP].dport),
            max(pkt[TCP].sport, pkt[TCP].dport)
        ) if pkt.haslayer(IP) else None
        if stream_id:
            streams[stream_id].append(bytes(pkt[Raw]))

# Parse HTTP dari streams
results = {}  # {position: character}

for stream_id, payloads in streams.items():
    full_data = b''.join(payloads)
    
    # Split request & response
    parts = full_data.split(b'HTTP/')
    
    for i, part in enumerate(parts):
        decoded = part.decode(errors='ignore')
        decoded_unescaped = unquote(decoded)
        
        # Cari substr pattern
        matches = re.findall(SUBSTR_PATTERN, decoded_unescaped, re.IGNORECASE)
        
        for match in matches:
            field, pos, length, char = match
            pos = int(pos)
            
            # Cek apakah response = TRUE
            # Cari response part yang terkait
            response_part = parts[i+1] if i+1 < len(parts) else b''
            response_str = response_part if isinstance(response_part, bytes) else response_part.encode()
            
            is_true = any(indicator in response_str.lower() for indicator in TRUE_INDICATORS)
            
            if is_true:
                results[pos] = char
                print(f"  [+] Position {pos}: '{char}' → TRUE")

# ═══ ALTERNATIVE: Simpler approach — parse URI directly ═══
print("\n[*] Alternative extraction (URI-based)...")
results2 = {}

for pkt in packets:
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        continue
    
    payload = bytes(pkt[Raw]).decode(errors='ignore')
    payload = unquote(payload)
    
    # Cari substr pattern di request
    matches = re.findall(SUBSTR_PATTERN, payload, re.IGNORECASE)
    if not matches:
        continue
    
    for match in matches:
        field, pos, length, char = match
        pos = int(pos)
        
        # Heuristic: cek response di paket-paket berikutnya dari stream yang sama
        # Untuk soal CTF, kita bisa juga cek Content-Length
        
        # Track semua candidates
        if pos not in results2:
            results2[pos] = []
        results2[pos].append(char)

# ═══ OUTPUT ═══
print("\n" + "=" * 60)
print("EXTRACTED DATA:")
print("=" * 60)

if results:
    password = ''.join(results[i] for i in sorted(results.keys()))
    print(f"\n[+] Extracted (response-based): {password}")

if results2:
    print(f"\n[*] All candidates per position:")
    for pos in sorted(results2.keys()):
        chars = results2[pos]
        print(f"  Position {pos}: {chars}")

print("\n[!] NOTE: Jika hasil belum akurat, buka PCAP di Wireshark")
print("[!] Filter: http.request.uri contains \"substr\"")
print("[!] Lalu bandingkan response TRUE vs FALSE secara manual")
print("[!] TRUE response biasanya punya Content-Length lebih besar")
```

## Script 2: Boolean SQLi Extractor — Wireshark Export Version

```python
#!/usr/bin/env python3
"""
Versi SIMPEL: paste HTTP request URIs dari Wireshark.
Lebih reliable karena kamu tentukan sendiri mana yang TRUE.

CARA PAKAI:
1. Di Wireshark: filter `http.request.uri contains "substr"`
2. Cek response setiap request → tandai yang TRUE
3. Copy URI yang TRUE ke file true_requests.txt
4. Jalankan: python3 sqli_simple.py true_requests.txt
"""
import re, sys
from urllib.parse import unquote

input_file = sys.argv[1] if len(sys.argv) > 1 else "true_requests.txt"

print("[*] Reading TRUE request URIs...")
results = {}

with open(input_file, 'r') as f:
    for line in f:
        line = unquote(line.strip())
        
        # Match berbagai format substr
        # Format 1: substr(password,1,1)='X'
        m = re.search(r"substr\(\w+,(\d+),\d+\).*?=.*?'([^']+)'", line, re.IGNORECASE)
        if m:
            pos = int(m.group(1))
            char = m.group(2)
            results[pos] = char
            continue
        
        # Format 2: SUBSTRING(password FROM 1 FOR 1)='X'
        m = re.search(r"SUBSTRING\(\w+\s+FROM\s+(\d+)\s+FOR\s+\d+\).*?=.*?'([^']+)'", line, re.IGNORECASE)
        if m:
            pos = int(m.group(1))
            char = m.group(2)
            results[pos] = char
            continue
        
        # Format 3: MID(password,1,1)='X'
        m = re.search(r"MID\(\w+,(\d+),\d+\).*?=.*?'([^']+)'", line, re.IGNORECASE)
        if m:
            pos = int(m.group(1))
            char = m.group(2)
            results[pos] = char

if results:
    password = ''.join(results[i] for i in sorted(results.keys()))
    print(f"\n[+] Extracted password/flag: {password}")
    print(f"[+] Length: {len(password)} characters")
    print(f"\n[+] Per position:")
    for pos in sorted(results.keys()):
        print(f"    [{pos:>3}] = '{results[pos]}'")
else:
    print("[-] No data extracted. Check input file format.")
```

## Script 3: DNS Exfiltration Extractor

```python
#!/usr/bin/env python3
"""Extract data dari DNS exfiltration PCAP"""
from scapy.all import *
import base64, sys

pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
# Domain yang digunakan attacker (sesuaikan!)
EXFIL_DOMAIN = sys.argv[2] if len(sys.argv) > 2 else ""

packets = rdpcap(pcap_file)
subdomains = []

for pkt in packets:
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query only
        qname = pkt[DNS].qd.qname.decode().rstrip('.')
        
        if EXFIL_DOMAIN:
            if qname.endswith(EXFIL_DOMAIN):
                subdomain = qname.replace('.' + EXFIL_DOMAIN, '')
                subdomains.append(subdomain)
        else:
            # Collect all unique domains
            subdomains.append(qname)

print(f"[*] Found {len(subdomains)} DNS queries\n")

if EXFIL_DOMAIN:
    print(f"[*] Subdomains for {EXFIL_DOMAIN}:")
    for s in subdomains:
        print(f"  {s}")
    
    combined = ''.join(subdomains)
    print(f"\n[*] Combined: {combined}")
    
    # Try decode
    for encoding in ['base64', 'hex', 'ascii']:
        try:
            if encoding == 'base64':
                decoded = base64.b64decode(combined + '==').decode(errors='ignore')
            elif encoding == 'hex':
                decoded = bytes.fromhex(combined).decode(errors='ignore')
            else:
                decoded = combined
            print(f"[+] Decoded ({encoding}): {decoded}")
        except:
            pass
else:
    # Print all unique domains, sorted by frequency
    from collections import Counter
    counts = Counter(subdomains)
    print("[*] All DNS queries (sorted by frequency):")
    for domain, count in counts.most_common(30):
        print(f"  {count:>5}x  {domain}")
    print("\n[!] Specify exfil domain as 2nd argument: python3 dns_exfil.py pcap evil.com")
```

## Script 4: Email Analyzer (Quick)

```python
#!/usr/bin/env python3
"""Quick email (.eml) analyzer for CTF"""
import email, re, sys, unicodedata
from email import policy
from email.parser import BytesParser

eml_file = sys.argv[1] if len(sys.argv) > 1 else "email.eml"

with open(eml_file, 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

print(f"From:        {msg['From']}")
print(f"To:          {msg['To']}")
print(f"Subject:     {msg['Subject']}")
print(f"Return-Path: {msg['Return-Path']}")
print(f"Reply-To:    {msg['Reply-To']}")

# Extract body
body = ""
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() in ('text/plain', 'text/html'):
            body += str(part.get_content())
else:
    body = str(msg.get_content())

# Extract & check URLs
urls = re.findall(r'https?://[^\s<>"\']+', body)
print(f"\nURLs found: {len(urls)}")
for url in urls:
    print(f"  {url}")
    for i, c in enumerate(url):
        if ord(c) > 127:
            name = unicodedata.name(c, '?')
            print(f"  ⚠️  HOMOGLYPH at [{i}]: '{c}' = U+{ord(c):04X} ({name})")

# Flag search
flags = re.findall(r'(?:flag|LKS|CTF)\{[^}]+\}', str(msg), re.IGNORECASE)
for f in flags:
    print(f"\n🏴 FLAG: {f}")
```

## Script 5: PCAP Web Attack Summarizer

```python
#!/usr/bin/env python3
"""Summarize web attacks dari PCAP — detect SQLi, XSS, CMDi, LFI"""
from scapy.all import *
from urllib.parse import unquote
import re, sys
from collections import defaultdict

pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
packets = rdpcap(pcap_file)

attacks = defaultdict(list)  # {type: [details]}

PATTERNS = {
    'SQL Injection': [
        r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s",
        r"(?:substr|substring|mid|ascii|ord|char)\s*\(",
        r"(?:OR|AND)\s+[\d'\"]+\s*=\s*[\d'\"]+",
        r"--\s*$", r";\s*--",
        r"(?:SLEEP|BENCHMARK|WAITFOR)\s*\(",
        r"' OR '",
        r"1\s*=\s*1",
    ],
    'XSS': [
        r"<\s*script", r"javascript\s*:", r"on\w+\s*=",
        r"alert\s*\(", r"document\.\w+", r"eval\s*\(",
    ],
    'Command Injection': [
        r";\s*(?:cat|ls|id|whoami|uname|pwd|ifconfig|wget|curl)\b",
        r"\|\s*(?:cat|ls|id|whoami|bash|sh)\b",
        r"(?:cmd|exec|system|popen|passthru)\s*[=(]",
        r"`[^`]+`",
    ],
    'Path Traversal / LFI': [
        r"\.\./", r"\.\.\\\\",
        r"/etc/(?:passwd|shadow|hosts)",
        r"(?:C:\\|/var/|/tmp/|/proc/)",
        r"(?:%2e%2e|%252e)",
    ],
    'File Upload': [
        r"filename=\"[^\"]+\.(?:php|jsp|asp|exe|sh|py)\"|\.(?:php|jsp)\?(?:cmd|c|exec)=",
    ],
}

for pkt in packets:
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        continue
    
    raw = bytes(pkt[Raw]).decode(errors='ignore')
    decoded = unquote(unquote(raw))  # double decode
    
    for attack_type, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                # Extract first line (request line)
                first_line = decoded.split('\r\n')[0][:200]
                src = pkt[IP].src if pkt.haslayer(IP) else '?'
                attacks[attack_type].append({
                    'src': src,
                    'detail': first_line,
                    'frame': pkt.summary()
                })
                break  # satu match per paket per tipe cukup

print(f"{'='*70}")
print(f"WEB ATTACK SUMMARY — {pcap_file}")
print(f"{'='*70}")

for attack_type, instances in attacks.items():
    unique = list({i['detail'] for i in instances})
    print(f"\n[{attack_type}] — {len(instances)} packets, {len(unique)} unique")
    for detail in unique[:10]:
        print(f"  → {detail[:150]}")
    if len(unique) > 10:
        print(f"  ... and {len(unique)-10} more")

if not attacks:
    print("\n[*] No common web attack patterns detected.")
    print("[*] Try manual analysis in Wireshark.")
```

---

# Bagian 7: Walkthrough Bergaya LKS

## Soal 1: Email Phishing (Mirip "VERIFIED")

```
SOAL: Diberikan file suspicious.eml. Temukan nama victim dan teknik 
      typosquatting yang digunakan attacker.

═══ STEP 1: Buka file .eml ═══
$ cat suspicious.eml | head -20
From: "Security Team" <security@bankjaya.co.id>
To: <alice@company.co.id>
Subject: Urgent: Verify Your Account
Return-Path: <attacker@malicious.xyz>          ← RED FLAG #1!
...
<a href="http://bаnkjaya.co.id/verify">Click here</a>

═══ STEP 2: Identify victim ═══
To: alice@company.co.id → victim = alice

═══ STEP 3: Cek URL ═══
$ echo -n "bаnkjaya.co.id" | xxd
00000000: 62d0 b06e 6b6a 6179 612e 636f 2e69 64

# "а" = D0 B0 (2 bytes!) bukan ASCII "a" = 61 (1 byte)
# Ini Cyrillic а (U+0430) bukan Latin a (U+0061)!

═══ STEP 4: Confirm ═══
$ python3 -c "
for c in 'bаnkjaya':
    if ord(c) > 127:
        import unicodedata
        print(f'{c!r} = U+{ord(c):04X} ({unicodedata.name(c)})')
"
# 'а' = U+0430 (CYRILLIC SMALL LETTER A)

FLAG: LKS{alice_a}  (victim=alice, typosquatted char=a)
```

## Soal 2: SQLi di PCAP (Mirip "FoodJection")

```
SOAL: File capture.pcap berisi aktivitas Boolean SQLi.
      Temukan password yang berhasil di-extract attacker.

═══ STEP 1: Buka di Wireshark ═══
Filter: http.request.uri contains "substr"
→ Muncul banyak request dengan payload SQLi

═══ STEP 2: Identifikasi pattern ═══
Request: GET /search?q=' OR (SELECT substr(password,1,1) FROM users 
         WHERE username='admin')='a' -- HTTP/1.1
→ Attacker menebak karakter per posisi

═══ STEP 3: Filter yang TRUE ═══
Untuk setiap request, cek response:
- Follow TCP Stream
- Response TRUE: body berisi "found" / Content-Length > 500
- Response FALSE: body berisi "not found" / Content-Length < 100

═══ STEP 4: Extract (manual atau script) ═══

MANUAL METHOD:
1. Filter: http.request.uri contains "substr(password,1,1)" 
2. Satu per satu → cek response
3. Yang TRUE → catat karakter
4. Ulangi untuk posisi 2,3,4,...

Di Wireshark:
  Filter: frame contains "substr" && frame contains "true"
  Atau: http.request.uri contains "substr" && http.content_length > 200

Auto method — gunakan script dari Bagian 6!

═══ STEP 5: Gabungkan ═══
Position 1: 'L' (TRUE)
Position 2: 'K' (TRUE)
Position 3: 'S' (TRUE)
Position 4: '{' (TRUE)
...
Password: LKS{Xf!ltr4tr10n_SQLi_asique}

FLAG: LKS{Xf!ltr4tr10n_SQLi_asique}
```

## Soal 3: DNS Exfiltration

```
SOAL: File traffic.pcap — data rahasia dikirim via DNS. Temukan flag.

═══ STEP 1: Wireshark ═══
Filter: dns
Banyak DNS query ke: *.evil.com
  ZmxhZ3t.evil.com
  kRE5TX.evil.com
  2V4ZmlsX.evil.com
  0cmF0aW9.evil.com
  ufQ==.evil.com

═══ STEP 2: Extract subdomains ═══
$ tshark -r traffic.pcap -Y 'dns.qry.name contains ".evil.com"' \
    -T fields -e dns.qry.name | sed 's/.evil.com//' | sort -u

Output:
  ZmxhZ3t
  kRE5TX
  2V4ZmlsX
  0cmF0aW9
  ufQ==

═══ STEP 3: Decode ═══
$ echo "ZmxhZ3tkRE5TX2V4ZmlsdHJhdGlvbid=" | base64 -d
flag{dDNS_exfiltration}

FLAG: flag{dDNS_exfiltration}
```

## Soal 4: ICMP Data Hiding

```
SOAL: traffic.pcap — data tersembunyi di ICMP. Temukan flag.

Filter Wireshark: icmp
Cek payload setiap ICMP Echo Request → ada data di payload!

$ python3 -c "
from scapy.all import *
pkts = rdpcap('traffic.pcap')
data = b''
for p in pkts:
    if p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(Raw):
        data += bytes(p[Raw])
print(data)
"
# b'flag{icmp_tunnel_detected}'

FLAG: flag{icmp_tunnel_detected}
```

---

# Bagian 8: Cheat Sheet

## Email Forensics Quick Reference

```bash
# Baca headers
grep -E "^(From|To|Subject|Return-Path|Reply-To|Received):" email.eml

# Extract URLs
grep -oP 'https?://[^\s<>"'"'"']+' email.eml

# Cek homoglyph
echo -n "suspicious-url.com" | xxd     # cari byte > 7F
echo -n "suspicious-url.com" | python3 -c "
import sys
for c in sys.stdin.read():
    if ord(c)>127: print(f'⚠️ {c!r} U+{ord(c):04X}')
"

# Extract attachments
munpack email.eml
ripmime -i email.eml -d extracted/

# Flag search
grep -iE "flag\{|LKS\{|CTF\{" email.eml
```

## Homoglyph Quick Reference

```
ASCII → Homoglyph (Common)
  a → а (Cyrillic, U+0430)
  c → с (Cyrillic, U+0441)
  e → е (Cyrillic, U+0435)
  i → і (Cyrillic, U+0456)
  o → о (Cyrillic, U+043E)
  p → р (Cyrillic, U+0440)
  n → ո (Armenian, U+0578)
  d → ԁ (Cyrillic, U+0501)
  g → ɡ (Latin, U+0261)
  l → ⅼ (Roman numeral, U+217C)
  I → Ι (Greek, U+0399)
  
DETECTION: if ord(char) > 127 → NOT ASCII → possible homoglyph!
```

## SQLi in PCAP Quick Reference

```
# Wireshark filters
http.request.uri contains "substr"
http.request.uri contains "UNION"
http.request.uri contains "SELECT"
http.request.uri contains "OR 1=1"
frame contains "substr" && frame contains "true"

# tshark extract
tshark -r pcap -Y 'http.request.uri contains "substr"' -T fields -e http.request.uri

# Boolean SQLi logic:
# Request: substr(pass,N,1)='X' → Response TRUE → char at position N = X
# Collect all TRUE positions → join → password/flag!
```

## Web Attack Detection Quick Reference

```
SQL Injection:    ' OR 1=1--    UNION SELECT    substr(    SLEEP(
XSS:              <script>     alert(          onerror=   javascript:
Command Inj:      ;whoami      |cat /etc/      `id`       cmd=
Path Traversal:   ../../../    /etc/passwd     %2e%2e     ..\\
File Upload:      .php         .jsp            shell      webshell
```

---

> **🎯 Ringkasan untuk LKS:**
> 
> **Soal Email (seperti VERIFIED):**
> 1. Buka .eml → lihat headers → identifikasi victim (To:)
> 2. Extract URLs → cek setiap karakter dengan `xxd` atau Python
> 3. Karakter non-ASCII (byte > 0x7F) = homoglyph = typosquatted character
> 
> **Soal PCAP SQLi (seperti FoodJection):**
> 1. Filter: `http.request.uri contains "substr"`
> 2. Untuk setiap request → cek response TRUE/FALSE
> 3. Yang TRUE → catat karakter + posisi
> 4. Gabungkan urut posisi → flag!
> 
> **Jangan lupa:** Selalu coba `grep flag{` dan `strings | grep LKS{` pertama! 🏴
