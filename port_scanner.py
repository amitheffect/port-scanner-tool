#Only use this tool against systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. jk bud! xD
"""
╔══════════════════════════════════════════════════════════╗
║           PORT SCANNER - Cybersecurity Tool              ║
║         Scan open ports on target hosts/networks         ║
╚══════════════════════════════════════════════════════════╝

Usage:
  python port_scanner.py -t <target> [options]

Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t scanme.nmap.org -p 1-1000
  python port_scanner.py -t 192.168.1.1 -p 22,80,443,8080 --timeout 2
  python port_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 100
  python port_scanner.py -t 192.168.1.1 --top-ports --banner
"""

import socket
import argparse
import ipaddress
import concurrent.futures
import sys
import time
import struct
from datetime import datetime

# ─────────────────────────────────────────────
#  ANSI Color Codes
# ─────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ─────────────────────────────────────────────
#  Common Ports & Service Names
# ─────────────────────────────────────────────
COMMON_SERVICES = {
    20:   "FTP Data",
    21:   "FTP Control",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP Server",
    68:   "DHCP Client",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    119:  "NNTP",
    123:  "NTP",
    135:  "MS RPC",
    137:  "NetBIOS Name",
    138:  "NetBIOS Datagram",
    139:  "NetBIOS Session",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP Trap",
    179:  "BGP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    500:  "IKE/IPsec",
    514:  "Syslog",
    515:  "LPD Print",
    587:  "SMTP Submission",
    631:  "IPP Printing",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "ZooKeeper",
    2222: "SSH Alt",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    4567: "Sinatra",
    5000: "Flask",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    6881: "BitTorrent",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "Jupyter",
    9000: "SonarQube",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    27017:"MongoDB",
    27018:"MongoDB Shard",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 194, 443, 445,
    465, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2222, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5984, 6379, 6443,
    8000, 8080, 8443, 8888, 9000, 9200, 27017,
    # Additional commonly scanned
    20, 67, 68, 69, 119, 123, 137, 138, 161, 162, 179, 389, 500,
    514, 515, 1723, 4567, 6881, 9300, 27018
]

# ─────────────────────────────────────────────
#  Banner / Header
# ─────────────────────────────────────────────
def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗   ║
║   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝   ║
║   ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║        ║
║   ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║        ║
║   ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗   ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝   ║
║                                                              ║
║              Advanced Port Scanner v1.0                      ║
║          For authorized security testing only                ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}"""
    print(banner)

# ─────────────────────────────────────────────
#  Helper: Resolve hostname → IP
# ─────────────────────────────────────────────
def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{Color.RED}[!] Could not resolve host: {host}{Color.RESET}")
        sys.exit(1)

# ─────────────────────────────────────────────
#  Helper: Get service name
# ─────────────────────────────────────────────
def get_service(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"

# ─────────────────────────────────────────────
#  Helper: Grab banner from open port
# ─────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send a probe for HTTP ports
        if port in (80, 8080, 8000, 8888, 3000, 4567, 5000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            sock.close()
            return "SSL/TLS (HTTPS)"
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()
        # Truncate long banners
        first_line = banner.split("\n")[0].strip()
        return first_line[:80] if first_line else "No banner"
    except Exception:
        return ""

# ─────────────────────────────────────────────
#  Core: Scan a single port
# ─────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = get_service(port)
            banner = grab_banner(ip, port, timeout) if grab else ""
            return {
                "port":    port,
                "state":   "OPEN",
                "service": service,
                "banner":  banner,
            }
    except socket.error:
        pass
    return None

# ─────────────────────────────────────────────
#  Core: Scan all ports on a host
# ─────────────────────────────────────────────
def scan_host(ip: str, ports: list[int], timeout: float,
              threads: int, grab_banner_flag: bool) -> list[dict]:
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banner_flag): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])

# ─────────────────────────────────────────────
#  Output: Print results table
# ─────────────────────────────────────────────
def print_results(ip: str, hostname: str, open_ports: list[dict],
                  elapsed: float, total_ports: int, banner_mode: bool):

    host_display = f"{hostname} ({ip})" if hostname != ip else ip

    print(f"\n{Color.CYAN}{'─'*62}{Color.RESET}")
    print(f"{Color.BOLD}  Scan Report for: {Color.GREEN}{host_display}{Color.RESET}")
    print(f"  Scanned {Color.YELLOW}{total_ports}{Color.RESET} port(s) in "
          f"{Color.YELLOW}{elapsed:.2f}s{Color.RESET}")
    print(f"{Color.CYAN}{'─'*62}{Color.RESET}")

    if not open_ports:
        print(f"\n  {Color.RED}No open ports found.{Color.RESET}\n")
        return

    # Table header
    if banner_mode:
        print(f"\n  {Color.BOLD}{'PORT':<8}{'STATE':<10}{'SERVICE':<20}{'BANNER'}{Color.RESET}")
        print(f"  {'─'*8}{'─'*10}{'─'*20}{'─'*24}")
    else:
        print(f"\n  {Color.BOLD}{'PORT':<8}{'STATE':<10}{'SERVICE'}{Color.RESET}")
        print(f"  {'─'*8}{'─'*10}{'─'*20}")

    for entry in open_ports:
        port_str    = f"{Color.GREEN}{entry['port']}/tcp{Color.RESET}"
        state_str   = f"{Color.GREEN}OPEN{Color.RESET}"
        service_str = f"{Color.YELLOW}{entry['service']}{Color.RESET}"

        if banner_mode:
            banner_str = f"{Color.MAGENTA}{entry['banner'][:40]}{Color.RESET}" if entry["banner"] else ""
            print(f"  {entry['port']:<8}{'OPEN':<10}{entry['service']:<20}{entry['banner'][:40]}")
        else:
            print(f"  {entry['port']:<8}{'OPEN':<10}{entry['service']}")

    print(f"\n  {Color.GREEN}[+]{Color.RESET} {len(open_ports)} open port(s) found")
    print(f"{Color.CYAN}{'─'*62}{Color.RESET}\n")

# ─────────────────────────────────────────────
#  Parse port string  e.g. "22,80,100-200"
# ─────────────────────────────────────────────
def parse_ports(port_str: str) -> list[int]:
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ─────────────────────────────────────────────
#  Expand CIDR notation to list of IPs
# ─────────────────────────────────────────────
def expand_targets(target: str) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target]  # Single host / hostname

# ─────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="Advanced Port Scanner for Cybersecurity Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t scanme.nmap.org -p 1-1000
  python port_scanner.py -t 10.0.0.1 -p 22,80,443,8080 --banner
  python port_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 200
  python port_scanner.py -t 192.168.1.1 --top-ports --timeout 0.5
        """
    )
    parser.add_argument("-t", "--target",    required=True,
                        help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",     default="1-1024",
                        help="Ports to scan: single (80), range (1-1000), list (22,80,443) [default: 1-1024]")
    parser.add_argument("--top-ports",       action="store_true",
                        help="Scan the top 100 most common ports (overrides -p)")
    parser.add_argument("--timeout",         type=float, default=1.0,
                        help="Connection timeout in seconds [default: 1.0]")
    parser.add_argument("--threads",         type=int, default=100,
                        help="Number of concurrent threads [default: 100]")
    parser.add_argument("--banner",          action="store_true",
                        help="Attempt to grab service banners from open ports")
    parser.add_argument("--output",          type=str, default=None,
                        help="Save results to a text file")
    return parser

# ─────────────────────────────────────────────
#  Save results to file
# ─────────────────────────────────────────────
def save_results(filepath: str, target: str, results: list[dict], elapsed: float):
    with open(filepath, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Duration: {elapsed:.2f}s\n")
        f.write(f"{'='*60}\n")
        if results:
            f.write(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<20}{'BANNER'}\n")
            f.write(f"{'-'*60}\n")
            for r in results:
                f.write(f"{r['port']:<10}{'OPEN':<10}{r['service']:<20}{r['banner']}\n")
        else:
            f.write("No open ports found.\n")
    print(f"{Color.YELLOW}[*] Results saved to: {filepath}{Color.RESET}")

# ─────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────
def main():
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()

    # ── Determine port list ─────────────────
    if args.top_ports:
        ports = TOP_100_PORTS
        port_label = "Top 100 ports"
    else:
        ports = parse_ports(args.ports)
        port_label = args.ports

    # ── Expand target(s) ───────────────────
    targets = expand_targets(args.target)

    print(f"  {Color.BOLD}Target(s):{Color.RESET}  {Color.CYAN}{args.target}{Color.RESET}")
    print(f"  {Color.BOLD}Ports    :{Color.RESET}  {Color.CYAN}{port_label} ({len(ports)} total){Color.RESET}")
    print(f"  {Color.BOLD}Timeout  :{Color.RESET}  {Color.CYAN}{args.timeout}s{Color.RESET}")
    print(f"  {Color.BOLD}Threads  :{Color.RESET}  {Color.CYAN}{args.threads}{Color.RESET}")
    print(f"  {Color.BOLD}Banner   :{Color.RESET}  {Color.CYAN}{'Yes' if args.banner else 'No'}{Color.RESET}")
    print(f"  {Color.BOLD}Started  :{Color.RESET}  {Color.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")

    # ── Scan each target ────────────────────
    for target in targets:
        ip = resolve_host(target)
        hostname = target if target != ip else ip

        print(f"\n{Color.CYAN}[*]{Color.RESET} Scanning {Color.BOLD}{hostname}{Color.RESET} ...")

        start = time.time()
        open_ports = scan_host(
            ip=ip,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads,
            grab_banner_flag=args.banner,
        )
        elapsed = time.time() - start

        print_results(ip, hostname, open_ports, elapsed, len(ports), args.banner)

        if args.output:
            save_results(args.output, f"{hostname} ({ip})", open_ports, elapsed)

    print(f"{Color.GREEN}[✓] Scan complete.{Color.RESET}\n")


# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[!] Scan interrupted by user.{Color.RESET}\n")
        sys.exit(0)
