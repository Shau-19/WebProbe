"""Opt-in TCP connect scan of the local machine (loopback only)."""

import socket
from urllib.parse import urlsplit

from .catalog import make_finding
from .guard import ensure_local

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


def scan_ports(base_url: str, timeout: float = 0.3):
    ensure_local(base_url)
    parts = urlsplit(base_url)
    host, own_port = parts.hostname, parts.port
    address = "127.0.0.1" if host.lower() == "localhost" else host
    family = socket.AF_INET6 if ":" in address else socket.AF_INET  # [::1] needs an IPv6 socket
    shown = f"[{host}]" if ":" in host else host
    findings = []
    for port, service in COMMON_PORTS.items():
        if port == own_port:
            continue
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                is_open = sock.connect_ex((address, port)) == 0
            except OSError:
                is_open = False
        if is_open:
            findings.append(
                make_finding(
                    "open_port",
                    f"tcp://{shown}:{port}",
                    parameter=str(port),
                    title=f"Open TCP port {port} ({service})",
                    evidence=f"TCP connect to {shown}:{port} succeeded.",
                )
            )
    return findings
