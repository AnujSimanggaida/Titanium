#!/usr/bin/env python3
"""
Titanium - A Python-based TCP port scanner
Currently supports: TCP Connect Scan (full three-way handshake), UDP Scan,
and SYN Scan (raw half-open scan via Scapy)

Usage:
    python3 titanium.py <target> -p <ports> [options]

Examples:
    python3 titanium.py 192.168.1.1 -p 1-1000
    python3 titanium.py scanme.nmap.org -p 22,80,443
    python3 titanium.py 10.0.0.5 -p 1-65535 -t 200
    sudo python3 titanium.py 10.0.0.5 -p 1-1000 -s syn
"""
import argparse
import os
import random
import re
import shutil
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Scapy is only needed for SYN scans, but we import it at module load time
# so failures are surfaced early with a clear message rather than deep in a thread.

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    from scapy.supersocket import L3RawSocket
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
    conf.verb = 0  # silence Scapy's own console output
    conf.L3socket = L3RawSocket  # send at layer 3 directly, skip ARP/MAC resolution
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---- Common port -> service name lookup (fallback if socket lookup fails) ----
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
}

print_lock = threading.Lock()
results_lock = threading.Lock()

GRAY = "\033[90m"
RESET = "\033[0m"

_ANSI_ESCAPE_RE = re.compile(r'\033\[[0-9;]*m')


def _truncate_to_width(text, width):
    """Truncate a string (which may contain ANSI color codes) to at most
    `width` *visible* characters. This is what makes resizing the terminal
    cut a line off instead of letting the terminal itself wrap it onto a
    second line, which would break the layout. Escape sequences are copied
    through in full and never counted toward the width; a reset code is
    always appended so color can't bleed onto the next line if a colored
    segment gets cut off mid-way.
    """
    if width <= 0:
        return ""
    visible = 0
    out = []
    i = 0
    while i < len(text):
        m = _ANSI_ESCAPE_RE.match(text, i)
        if m:
            out.append(m.group())
            i = m.end()
            continue
        if visible >= width:
            break
        out.append(text[i])
        visible += 1
        i += 1
    out.append(RESET)
    return "".join(out)


_builtin_print = print


def print(*args, sep=" ", end="\n", **kwargs):
    """Drop-in replacement for the built-in print() that truncates each
    line to the terminal's *current* width before printing. Every existing
    print(...) call in this file automatically gets this behavior, and the
    width is re-checked on every call, so resizing the window mid-scan is
    handled correctly without needing to touch every call site.
    """
    text = sep.join(str(a) for a in args)
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    _builtin_print(_truncate_to_width(text, width), end=end, **kwargs)


def parse_ports(port_string):
    """Parse a port string like '80,443,1000-1010' into a sorted list of ints."""
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def grab_banner(sock):
    """Attempt to read a short banner from an open socket. Best-effort only."""
    try:
        sock.settimeout(0.75)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        return ""


def tcp_scan_port(target, port, timeout, grab_banners, results):
    """Attempt a full TCP three-way handshake connect to a single port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock) if grab_banners else ""
            with results_lock:
                results.append((port, "open", banner))
            with print_lock:
                service = get_service_name(port)
                line = f"[+] Port {port:>5}/tcp  OPEN   ({service})"
                if banner:
                    line += f"  -> {banner}"
                print(line)
    except socket.error:
        pass
    finally:
        sock.close()


def udp_scan_port(target, port, timeout, grab_banners, results):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        sock.send(b"")
        data = sock.recv(1024)

        if grab_banners:
            banner = data.decode(errors="ignore").strip()[:80]
        else:
            banner = ""

        with results_lock:
            results.append((port, "open", banner))
        with print_lock:
            line = f"[+] Port {port:>5}/udp  OPEN"
            if banner:
                line += f"  -> {banner}"
            print(line)

    except socket.timeout:
        # No response at all — ambiguous: open|filtered
        pass
    except ConnectionRefusedError:
        # ICMP Port Unreachable — closed
        pass
    finally:
        sock.close()


def syn_scan_port(target, port, timeout, grab_banners, results):
    """
    Half-open SYN scan: send a raw SYN packet and classify the reply
    without ever completing the TCP handshake.

      SYN-ACK (flags 0x12)  -> port is open; we immediately send a RST
      RST-ACK (flags 0x14)  -> port is closed
      ICMP unreachable/none -> port is filtered
    """
    src_port = random.randint(1025, 65535)
    pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")

    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return  # filtered — nothing came back at all

    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK -> open
            # Tear down the half-open connection immediately.
            rst = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")
            sr1(rst, timeout=timeout, verbose=0)

            with results_lock:
                results.append((port, "open", ""))
            with print_lock:
                service = get_service_name(port)
                print(f"[+] Port {port:>5}/tcp  OPEN   ({service})  [SYN scan]")
        # flags == 0x14 (RST-ACK) -> closed; nothing to print
    elif resp.haslayer(ICMP):
        pass  # destination/port unreachable -> filtered


SCAN_FUNCTIONS = {
    "tcp": tcp_scan_port,
    "udp": udp_scan_port,
    "syn": syn_scan_port,
}


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


# Each entry is (plain_text_for_width_calc, colored_text_to_print).
# Keeping the plain version separate matters because ANSI escape codes are
# invisible characters that would otherwise throw off column alignment.
_LOGO_PLAIN = [
     r"______________  __                .__               ",
    r"\__    ___/|__|/  |______    ____ |__|__ __  _____  ",
    r"  |    |   |  \   __\__  \  /    \|  |  |  \/     \ ",
    r"  |    |   |  ||  |  / __ \|   |  \  |  |  /  Y Y  \ ",
    r"  |____|   |__||__| (____  /___|  /__|____/|__|_|  / ",
    r"                         \/     \/               \/ "
]
LOGO_LINES = [(line, f"{GRAY}{line}{RESET}") for line in _LOGO_PLAIN]


def print_logo():
    """Print the ASCII logo on its own, one line at a time."""
    for _plain, colored in LOGO_LINES:
        print(colored)


def print_banner(info_lines):
    """Print the logo on top, followed by the info text block below it."""
    print_logo()
    for line in info_lines:
        print(line)


def main():
    print("\n")
    parser = argparse.ArgumentParser(
        prog="titanium",
        description="Titanium - TCP Connect, UDP, and SYN port scanner"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-65535",
                         help="Ports to scan, e.g. '22,80,443' or '1-1000' (default: 1-65535)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Socket timeout in seconds per port (default: 1.0)")
    parser.add_argument("-b", "--banner", action="store_true",
                         help="Attempt basic banner grabbing on open ports (tcp scan only)")
    parser.add_argument("-s", "--scan", choices=["tcp", "udp", "syn"], default=None,
                         help="Scan type: 'tcp' (full handshake), 'udp', or 'syn' "
                              "(raw half-open scan via Scapy, requires root). "
                              "If omitted, you will be prompted.")
    args = parser.parse_args()

    if args.scan is None:
        while True:
            choice = input("Select scan type - (T)CP, (U)DP, or (S)YN: ").strip().lower()
            if choice in ("t", "tcp"):
                args.scan = "tcp"
                break
            elif choice in ("u", "udp"):
                args.scan = "udp"
                break
            elif choice in ("s", "syn"):
                args.scan = "syn"
                break
            else:
                print("[!] Invalid choice. Please enter 'T', 'U', or 'S'.")

    if args.scan == "syn":
        if not SCAPY_AVAILABLE:
            print("[!] SYN scan requires Scapy. Install it with:")
            print("    pip install scapy --break-system-packages")
            sys.exit(1)
        if os.geteuid() != 0:
            print("[!] SYN scan requires root privileges (raw sockets).")
            print("    Run with sudo, or grant cap_net_raw to your python3 binary, "
                  "or use -s tcp instead.")
            sys.exit(1)

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    scan_labels = {
        "tcp": "TCP Connect (full handshake)",
        "udp": "UDP Scan",
        "syn": "SYN Scan (half-open, raw sockets)",
    }
    scan_label = scan_labels.get(args.scan, "Unknown scan type")

    info_lines = [
        "Welcome to Titanium, a network port scanning tool",
        "=" * 50,
        
        f"Target      : {args.target} ({ip})",
        f"Ports       : {len(ports)} port(s)",
        f"Scan type   : {scan_label}",
        f"Started at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Scapy version: " + (f"{conf.version}" if SCAPY_AVAILABLE else "Not installed"),
        f"Tool Version: 1.3.2",
        f"Remember    : be responsible ;)",
        "=" * 50,
    ]
    print_banner(info_lines)

    results = []
    start_time = time.time()

    # SYN scans lean on raw sockets rather than per-connection kernel state,
    # but very high thread counts can still cause reply loss / kernel RST
    # interference. Cap it a bit lower by default for that mode.
    requested_threads = args.threads
    if args.scan == "syn" and requested_threads > 50:
        print(f"[i] Capping threads to 50 for SYN scan (requested {requested_threads}).")
        requested_threads = 50

    num_threads = min(requested_threads, len(ports)) or 1
    scan_fn = SCAN_FUNCTIONS[args.scan]

    # ThreadPoolExecutor keeps a fixed pool of worker threads alive and pulls
    # the next port off the internal queue the instant a thread finishes —
    # no thread ever sits idle waiting on Queue.get()/task_done() bookkeeping,
    # and a handful of slow/timed-out ports no longer stalls the whole batch.
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {
            executor.submit(scan_fn, ip, port, args.timeout, args.banner, results): port
            for port in ports
        }
        for future in as_completed(futures):
            # Surface unexpected errors per-port instead of letting one bad
            # port silently kill that thread for the rest of the scan.
            exc = future.exception()
            if exc is not None:
                port = futures[future]
                with print_lock:
                    print(f"[!] Error scanning port {port}: {exc}")

    elapsed = time.time() - start_time
    open_ports = sorted(results, key=lambda r: r[0])

    print("-" * 60)
    print(f" Scan complete. {len(open_ports)} open port(s) found.")
    print(f" Time elapsed: {elapsed:.2f} seconds")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(0)