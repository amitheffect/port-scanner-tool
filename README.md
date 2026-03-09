# 🔍 Port Scanner
![Alt text](PORTSC.png)
> An advanced TCP port scanner for cybersecurity testing, written in Python.

---

## Features

- **TCP Connect Scanning** — reliable SYN-style connection probing via `socket`
- **Multithreaded** — concurrent scanning with configurable thread count (default: 100)
- **Banner Grabbing** — pull live service banners from open ports with `--banner`
- **CIDR / Subnet Support** — scan entire networks like `192.168.1.0/24`
- **Top 100 Ports Mode** — quickly hit the most common ports with `--top-ports`
- **Flexible Port Input** — single ports, ranges, or comma-separated lists
- **Service Identification** — maps 60+ well-known ports to their service names
- **File Output** — save scan reports to a `.txt` file with `--output`
- **Color-coded Terminal UI** — clean, readable output with ANSI colors

---

## Requirements

- Python 3.10+
- No external dependencies — uses only the Python standard library

```bash
python --version  # must be 3.10 or higher
```

---

## Installation
# Clone the repository
```bash

git clone https://github.com/yourname/port-scanner.git
cd port-scanner


```
# No pip install needed — zero dependencies!
---

## Usage

```bash
python port_scanner.py -t <target> [options]
```

### Arguments

| Flag | Long Form | Description | Default |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target IP, hostname, or CIDR range | *(required)* |
| `-p` | `--ports` | Ports: `80`, `1-1000`, or `22,80,443` | `1-1024` |
| | `--top-ports` | Scan the top 100 most common ports | `False` |
| | `--timeout` | Connection timeout in seconds | `1.0` |
| | `--threads` | Number of concurrent threads | `100` |
| | `--banner` | Grab service banners from open ports | `False` |
| | `--output` | Save results to a file (e.g. `report.txt`) | `None` |

---

## Examples

**Basic scan (ports 1–1024):**
```bash
python port_scanner.py -t 192.168.1.1
```

**Scan a hostname with a custom port range:**
```bash
python port_scanner.py -t scanme.nmap.org -p 1-1000
```

**Scan specific ports with banner grabbing:**
```bash
python port_scanner.py -t 10.0.0.1 -p 22,80,443,8080 --banner
```

**Fast top-100 scan with aggressive timeout:**
```bash
python port_scanner.py -t 192.168.1.1 --top-ports --timeout 0.5
```

**Subnet scan with high thread count:**
```bash
python port_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 200
```

**Full scan with output saved to file:**
```bash
python port_scanner.py -t 192.168.1.1 -p 1-65535 --threads 500 --output results.txt
```

---

## Sample Output

```
  Target(s):  192.168.1.1
  Ports    :  1-1024 (1024 total)
  Timeout  :  1.0s
  Threads  :  100
  Banner   :  No
  Started  :  2026-03-07 14:32:01

[*] Scanning 192.168.1.1 ...

  ──────────────────────────────────────────────────────────────
  Scan Report for: 192.168.1.1
  Scanned 1024 port(s) in 3.87s
  ──────────────────────────────────────────────────────────────

  PORT    STATE     SERVICE
  ────────────────────────────
  22      OPEN      SSH
  80      OPEN      HTTP
  443     OPEN      HTTPS
  8080    OPEN      HTTP Proxy

  [+] 4 open port(s) found
  ──────────────────────────────────────────────────────────────
```

---

## Recognized Services

The scanner has built-in mappings for 60+ common services, including:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 3306 | MySQL |
| 22 | SSH | 3389 | RDP |
| 25 | SMTP | 5432 | PostgreSQL |
| 53 | DNS | 5900 | VNC |
| 80 | HTTP | 6379 | Redis |
| 443 | HTTPS | 8080 | HTTP Proxy |
| 445 | SMB | 27017 | MongoDB |
| 1433 | MSSQL | 9200 | Elasticsearch |

---

## Project Structure

```
port-scanner/
├── port_scanner.py   # Main scanner script
└── README.md         # This file
```

---

## How It Works

1. **Target Resolution** — hostnames are resolved to IPs via DNS; CIDR ranges are expanded to individual hosts
2. **Port Scanning** — a `ThreadPoolExecutor` fires TCP `connect_ex()` probes in parallel
3. **Service Detection** — open ports are matched against a built-in service dictionary, with fallback to `socket.getservbyport()`
4. **Banner Grabbing** — optional: reconnects to open ports and sends a probe to capture the service greeting
5. **Reporting** — results are sorted by port number and printed to the terminal (and optionally saved to disk)

---

## Limitations

- **TCP only** — does not support UDP scanning
- **No OS fingerprinting** — focuses on port/service discovery
- **No stealth mode** — uses full TCP connect (no raw socket SYN scan)
- **IPv4 only** — IPv6 targets are not currently supported

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
>
> Scanning networks or systems without explicit written permission from the owner is **illegal** in most jurisdictions and may violate laws such as the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and similar legislation worldwide.
>
> The author assumes **no liability** for misuse or damage caused by this tool. Always obtain proper authorization before scanning any target.

---
