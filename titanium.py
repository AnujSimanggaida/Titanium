#!/usr/bin/env python3
"""
Titanium - A Python-based TCP port scanner
Currently supports: TCP Connect Scan (full three-way handshake)

Usage:
    python3 titanium.py <target> -p <ports> [options]

Examples:
    python3 titanium.py 192.168.1.1 -p 1-1000
    python3 titanium.py scanme.nmap.org -p 22,80,443
    python3 titanium.py 10.0.0.5 -p 1-65535 -t 200
"""

import argparse
import socket
import sys
import threading
import time
from queue import Queue
from datetime import datetime

# ---- Common port -> service name lookup (fallback if socket lookup fails) ----
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
}

print_lock = threading.Lock()


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


def scan_port(target, port, timeout, grab_banners, results):
    """Attempt a full TCP three-way handshake connect to a single port"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port)) #this part need to not use sock.connect"
        if result == 0:
            banner = grab_banner(sock) if grab_banners else ""
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


def worker(target, timeout, grab_banners, results, q):
    while True:
        port = q.get()
        if port is None:
            q.task_done()
            break
        scan_port(target, port, timeout, grab_banners, results)
        q.task_done()


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="titanium",
        description="Titanium - TCP Connect (three-way handshake) port scanner"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan, e.g. '22,80,443' or '1-1000' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Socket timeout in seconds per port (default: 1.0)")
    parser.add_argument("-b", "--banner", action="store_true",
                         help="Attempt basic banner grabbing on open ports")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    print("=" * 60)
    print(f" Titanium Port Scanner")
    print(f" Target      : {args.target} ({ip})")
    print(f" Ports       : {len(ports)} port(s)")
    print(f" Scan type   : TCP Connect (full handshake)")
    print(f" Started at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []
    q = Queue()
    threads = []

    start_time = time.time()

    num_threads = min(args.threads, len(ports)) or 1
    for _ in range(num_threads):
        th = threading.Thread(target=worker, args=(ip, args.timeout, args.banner, results, q))
        th.start()
        threads.append(th)

    for port in ports:
        q.put(port)

    q.join()

    for _ in threads:
        q.put(None)
    for th in threads:
        th.join()

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