#!/usr/bin/env python3
"""
Simple TCP Network Port Scanner
Use only on systems/networks you own or are authorized to test.
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable


COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}


def resolve_target(target: str) -> str:
    """Resolve a hostname/IP and return its IPv4 address."""
    return socket.gethostbyname(target)


def scan_port(host: str, port: int, timeout: float = 0.5):
    """Check whether a TCP port is accepting connections."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return port, COMMON_PORTS.get(port, "Unknown")
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.5,
               workers: int = 50):
    """Scan ports concurrently and return sorted open ports."""
    found = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, host, p, timeout) for p in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return sorted(found)


def parse_ports(spec: str):
    """Parse '22,80,443' and ranges such as '1-100'."""
    ports = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start, end = item.split("-", 1)
            start, end = int(start), int(end)
            if not (1 <= start <= end <= 65535):
                raise ValueError("Port range must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        else:
            port = int(item)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            ports.add(port)
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner for authorized security testing."
    )
    parser.add_argument("target", help="Hostname or IPv4 address")
    parser.add_argument(
        "-p", "--ports", default="22,80,443",
        help="Ports, e.g. 22,80,443 or 1-1000"
    )
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=50)
    args = parser.parse_args()

    try:
        host = resolve_target(args.target)
        ports = parse_ports(args.ports)
    except (socket.gaierror, ValueError) as exc:
        parser.error(str(exc))

    print(f"Target: {args.target} ({host})")
    print(f"Scanning {len(ports)} TCP port(s)...\n")

    results = scan_ports(host, ports, args.timeout, args.workers)

    if not results:
        print("No open TCP ports found in the selected range.")
        return

    print("OPEN PORT   SERVICE")
    print("-" * 28)
    for port, service in results:
        print(f"{port:<11} {service}")


if __name__ == "__main__":
    main()
