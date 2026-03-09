#Only use this tool against systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. jk bud! xD
"""
╔══════════════════════════════════════════════════════════╗
║           PORT SCANNER - Cybersecurity Tool              ║
║         Scan open ports on target hosts/networks         ║
║                      v2.0                                ║
╚══════════════════════════════════════════════════════════╝

Usage:
  python port_scanner.py -t <target> [options]

Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t scanme.nmap.org -p 1-1000
  python port_scanner.py -t 192.168.1.1 -p 22,80,443,8080 --timeout 2
  python port_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 100
  python port_scanner.py -t 192.168.1.1 --top-ports --banner
  python port_scanner.py -t 192.168.1.1 --udp -p 53,161,123
  python port_scanner.py -t ::1 --ipv6 -p 80,443
  python port_scanner.py -t 192.168.1.1 --os-detect
"""

import socket
import argparse
import ipaddress
import concurrent.futures
import sys
import time
import platform
import subprocess
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
    20:"FTP Data",21:"FTP Control",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",67:"DHCP Server",68:"DHCP Client",69:"TFTP",80:"HTTP",
    110:"POP3",111:"RPC",119:"NNTP",123:"NTP",135:"MS RPC",
    137:"NetBIOS Name",138:"NetBIOS Datagram",139:"NetBIOS Session",
    143:"IMAP",161:"SNMP",162:"SNMP Trap",179:"BGP",194:"IRC",
    389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",500:"IKE/IPsec",
    514:"Syslog",515:"LPD Print",587:"SMTP Submission",631:"IPP Printing",
    636:"LDAPS",993:"IMAPS",995:"POP3S",1080:"SOCKS Proxy",1194:"OpenVPN",
    1433:"MSSQL",1521:"Oracle DB",1723:"PPTP",2049:"NFS",2181:"ZooKeeper",
    2222:"SSH Alt",3000:"Dev Server",3306:"MySQL",3389:"RDP",4444:"Metasploit",
    4567:"Sinatra",5000:"Flask",5432:"PostgreSQL",5900:"VNC",5984:"CouchDB",
    6379:"Redis",6443:"Kubernetes API",6881:"BitTorrent",8000:"HTTP Alt",
    8080:"HTTP Proxy",8443:"HTTPS Alt",8888:"Jupyter",9000:"SonarQube",
    9200:"Elasticsearch",9300:"Elasticsearch Cluster",27017:"MongoDB",27018:"MongoDB Shard",
}

UDP_SERVICES = {
    53:"DNS",67:"DHCP Server",68:"DHCP Client",69:"TFTP",123:"NTP",
    137:"NetBIOS Name",138:"NetBIOS Datagram",161:"SNMP",162:"SNMP Trap",
    500:"IKE/IPsec",514:"Syslog",1194:"OpenVPN",1900:"UPnP/SSDP",
    4500:"IPSec NAT-T",5353:"mDNS",5355:"LLMNR",
}

TOP_100_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,194,443,445,465,587,631,636,
    993,995,1080,1194,1433,1521,1723,2049,2222,3000,3306,3389,4444,5000,
    5432,5900,5984,6379,6443,8000,8080,8443,8888,9000,9200,27017,
    20,67,68,69,119,123,137,138,161,162,179,389,500,514,515,4567,6881,9300,27018
]

TOP_UDP_PORTS = [53,67,68,69,123,137,138,161,162,500,514,1194,1900,4500,5353,5355]

# UDP probes for common services
UDP_PROBES = {
    53:  (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07version\x04bind\x00\x00\x10\x00\x03"),
    123: b"\x1b" + b"\x00" * 47,
    161: (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
          b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
          b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
}

# ─────────────────────────────────────────────
#  OS Fingerprinting via TTL heuristics
# ─────────────────────────────────────────────
TTL_OS_MAP = [
    (range(0,   65),  "Linux / Android",         "🐧"),
    (range(65,  129), "Windows",                  "🪟"),
    (range(129, 193), "Cisco / Network Device",   "🔌"),
    (range(193, 256), "Solaris / AIX / macOS",    "🍎"),
]

def get_ttl(host: str, ipv6: bool = False):
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "2000", host]
        elif ipv6:
            cmd = ["ping6", "-c", "1", "-W", "2", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr

        for token in output.split():
            clean = token.lower().replace("ttl=","").replace("ttl:","").strip(",.")
            if "ttl" in token.lower() and clean.isdigit():
                return int(clean)
    except Exception:
        pass
    return None

def fingerprint_os(host: str, ipv6: bool = False):
    ttl = get_ttl(host, ipv6)
    if ttl is None:
        return ("Unknown (no ping response)", "❓", None)
    for ttl_range, os_name, icon in TTL_OS_MAP:
        if ttl in ttl_range:
            return (os_name, icon, ttl)
    return ("Unknown", "❓", ttl)

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
def print_banner():
    print(f"""
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
║           Advanced Port Scanner v2.0                         ║
║    TCP · UDP · IPv6 · OS Fingerprinting · Banner Grab        ║
║         For authorized security testing only                 ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}""")

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def resolve_host(host: str, ipv6: bool = False) -> str:
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        results = socket.getaddrinfo(host, None, family)
        return results[0][4][0]
    except socket.gaierror:
        print(f"{Color.RED}[!] Could not resolve host: {host}{Color.RESET}")
        sys.exit(1)

def get_service(port: int, udp: bool = False) -> str:
    smap = UDP_SERVICES if udp else COMMON_SERVICES
    if port in smap:
        return smap[port]
    try:
        return socket.getservbyport(port, "udp" if udp else "tcp")
    except OSError:
        return "Unknown"

def grab_banner(ip: str, port: int, timeout: float = 2.0, ipv6: bool = False) -> str:
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (80,8080,8000,8888,3000,4567,5000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            sock.close()
            return "SSL/TLS (HTTPS)"
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()
        line = banner.split("\n")[0].strip()
        return line[:80] if line else "No banner"
    except Exception:
        return ""

# ─────────────────────────────────────────────
#  Scanners
# ─────────────────────────────────────────────
def scan_tcp_port(ip, port, timeout, grab, ipv6=False):
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return {
                "port":    port,
                "proto":   "TCP",
                "state":   "OPEN",
                "service": get_service(port),
                "banner":  grab_banner(ip, port, timeout, ipv6) if grab else "",
            }
    except socket.error:
        pass
    return None

def scan_udp_port(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        probe = UDP_PROBES.get(port, b"\x00" * 8)
        sock.sendto(probe, (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return {
                "port":    port,
                "proto":   "UDP",
                "state":   "OPEN",
                "service": get_service(port, udp=True),
                "banner":  data[:40].decode(errors="replace").strip() if data else "",
            }
        except socket.timeout:
            sock.close()
            return {
                "port":    port,
                "proto":   "UDP",
                "state":   "OPEN|FILTERED",
                "service": get_service(port, udp=True),
                "banner":  "",
            }
    except Exception:
        pass
    return None

def scan_host(ip, ports, timeout, threads, grab, udp=False, ipv6=False):
    results = []
    def worker(port):
        return scan_udp_port(ip, port, timeout) if udp else scan_tcp_port(ip, port, timeout, grab, ipv6)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r:
                results.append(r)
    return sorted(results, key=lambda x: x["port"])

# ─────────────────────────────────────────────
#  Output
# ─────────────────────────────────────────────
def print_results(ip, hostname, open_ports, elapsed, total_ports, banner_mode, os_info=None):
    host_display = f"{hostname} ({ip})" if hostname != ip else ip
    print(f"\n{Color.CYAN}{'─'*68}{Color.RESET}")
    print(f"{Color.BOLD}  Scan Report for: {Color.GREEN}{host_display}{Color.RESET}")
    print(f"  Scanned {Color.YELLOW}{total_ports}{Color.RESET} port(s) in {Color.YELLOW}{elapsed:.2f}s{Color.RESET}")
    if os_info:
        os_name, icon, ttl = os_info
        ttl_str = f" (TTL={ttl})" if ttl else ""
        print(f"  OS Guess  : {Color.MAGENTA}{icon}  {os_name}{ttl_str}{Color.RESET}")
    print(f"{Color.CYAN}{'─'*68}{Color.RESET}")

    if not open_ports:
        print(f"\n  {Color.RED}No open ports found.{Color.RESET}\n")
        return

    if banner_mode:
        print(f"\n  {Color.BOLD}{'PORT':<8}{'PROTO':<7}{'STATE':<16}{'SERVICE':<20}BANNER{Color.RESET}")
        print(f"  {'─'*7}  {'─'*6}  {'─'*15}  {'─'*19}  {'─'*12}")
    else:
        print(f"\n  {Color.BOLD}{'PORT':<8}{'PROTO':<7}{'STATE':<16}SERVICE{Color.RESET}")
        print(f"  {'─'*7}  {'─'*6}  {'─'*15}  {'─'*15}")

    for e in open_ports:
        sc = Color.GREEN if e["state"] == "OPEN" else Color.YELLOW
        if banner_mode:
            print(f"  {e['port']:<8}{e['proto']:<7}{sc}{e['state']:<16}{Color.RESET}{e['service']:<20}{e['banner'][:28]}")
        else:
            print(f"  {e['port']:<8}{e['proto']:<7}{sc}{e['state']:<16}{Color.RESET}{e['service']}")

    print(f"\n  {Color.GREEN}[+]{Color.RESET} {len(open_ports)} port(s) found")
    print(f"{Color.CYAN}{'─'*68}{Color.RESET}\n")

def save_results(filepath, target, results, elapsed, os_info=None):
    with open(filepath, "a") as f:
        f.write(f"\n{'='*65}\n")
        f.write(f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target  : {target}\n")
        f.write(f"Duration: {elapsed:.2f}s\n")
        if os_info:
            os_name, icon, ttl = os_info
            f.write(f"OS Guess: {icon} {os_name}" + (f" (TTL={ttl})\n" if ttl else "\n"))
        f.write(f"{'='*65}\n")
        if results:
            f.write(f"{'PORT':<10}{'PROTO':<8}{'STATE':<16}{'SERVICE':<20}BANNER\n")
            f.write(f"{'-'*65}\n")
            for r in results:
                f.write(f"{r['port']:<10}{r['proto']:<8}{r['state']:<16}{r['service']:<20}{r['banner']}\n")
        else:
            f.write("No open ports found.\n")
    print(f"{Color.YELLOW}[*] Results saved to: {filepath}{Color.RESET}")

# ─────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="Advanced Port Scanner v2.0 — TCP · UDP · IPv6 · OS Fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t scanme.nmap.org -p 1-1000 --banner
  python port_scanner.py -t 192.168.1.1 --udp -p 53,161,123
  python port_scanner.py -t ::1 --ipv6 -p 80,443
  python port_scanner.py -t 192.168.1.1 --top-ports --os-detect
  python port_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 200
        """
    )
    parser.add_argument("-t","--target",   required=True, help="Target IP, hostname, or CIDR range")
    parser.add_argument("-p","--ports",    default="1-1024", help="Ports: 80 | 1-1000 | 22,80,443 [default: 1-1024]")
    parser.add_argument("--top-ports",    action="store_true", help="Scan top 100 common ports (overrides -p)")
    parser.add_argument("--timeout",      type=float, default=1.0, help="Timeout in seconds [default: 1.0]")
    parser.add_argument("--threads",      type=int,   default=100, help="Concurrent threads [default: 100]")
    parser.add_argument("--banner",       action="store_true", help="Grab service banners (TCP only)")
    parser.add_argument("--udp",          action="store_true", help="Scan UDP ports instead of TCP")
    parser.add_argument("--ipv6",         action="store_true", help="Enable IPv6 scanning")
    parser.add_argument("--os-detect",    action="store_true", help="OS fingerprinting via TTL analysis")
    parser.add_argument("--output",       type=str,   default=None, help="Save results to a text file")
    return parser

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.top_ports:
        ports      = TOP_UDP_PORTS if args.udp else TOP_100_PORTS
        port_label = "Top UDP ports" if args.udp else "Top 100 ports"
    else:
        ports      = parse_ports(args.ports)
        port_label = args.ports

    def parse_ports(port_str):
        pts = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                s, e = part.split("-", 1)
                pts.update(range(int(s), int(e)+1))
            else:
                pts.add(int(part))
        return sorted(pts)

    if not args.top_ports:
        ports = parse_ports(args.ports)

    def expand_targets(target, ipv6=False):
        try:
            net = ipaddress.IPv6Network(target, strict=False) if ipv6 else ipaddress.IPv4Network(target, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 256:
                print(f"{Color.YELLOW}[!] Subnet has {len(hosts)} hosts — limiting to first 256.{Color.RESET}")
                hosts = hosts[:256]
            return [str(h) for h in hosts]
        except ValueError:
            return [target]

    targets     = expand_targets(args.target, args.ipv6)
    proto_label = "UDP" if args.udp else ("TCP/IPv6" if args.ipv6 else "TCP/IPv4")

    print(f"  {Color.BOLD}Target(s) :{Color.RESET}  {Color.CYAN}{args.target}{Color.RESET}")
    print(f"  {Color.BOLD}Protocol  :{Color.RESET}  {Color.CYAN}{proto_label}{Color.RESET}")
    print(f"  {Color.BOLD}Ports     :{Color.RESET}  {Color.CYAN}{port_label} ({len(ports)} total){Color.RESET}")
    print(f"  {Color.BOLD}Timeout   :{Color.RESET}  {Color.CYAN}{args.timeout}s{Color.RESET}")
    print(f"  {Color.BOLD}Threads   :{Color.RESET}  {Color.CYAN}{args.threads}{Color.RESET}")
    print(f"  {Color.BOLD}Banner    :{Color.RESET}  {Color.CYAN}{'Yes' if args.banner else 'No'}{Color.RESET}")
    print(f"  {Color.BOLD}OS Detect :{Color.RESET}  {Color.CYAN}{'Yes' if args.os_detect else 'No'}{Color.RESET}")
    print(f"  {Color.BOLD}Started   :{Color.RESET}  {Color.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")

    for target in targets:
        ip       = resolve_host(target, args.ipv6)
        hostname = target if target != ip else ip

        print(f"\n{Color.CYAN}[*]{Color.RESET} Scanning {Color.BOLD}{hostname}{Color.RESET} ({proto_label}) ...")

        os_info = None
        if args.os_detect:
            print(f"  {Color.CYAN}[~]{Color.RESET} Running OS fingerprint via TTL analysis ...")
            os_info = fingerprint_os(ip, args.ipv6)

        start      = time.time()
        open_ports = scan_host(ip, ports, args.timeout, args.threads, args.banner, args.udp, args.ipv6)
        elapsed    = time.time() - start

        print_results(ip, hostname, open_ports, elapsed, len(ports), args.banner, os_info)

        if args.output:
            save_results(args.output, f"{hostname} ({ip})", open_ports, elapsed, os_info)

    print(f"{Color.GREEN}[✓] Scan complete.{Color.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[!] Scan interrupted by user.{Color.RESET}\n")
        sys.exit(0)
