import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}


def is_private_or_reserved(ip_str):
    """Block scans targeting internal/private infrastructure."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        return False


def scan_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def scan(host):
    if not host:
        return None

    host = host.replace("https://", "").replace("http://", "").strip("/")

    # Block obviously internal hostnames outright
    blocked_hostnames = {"localhost", "0.0.0.0", "::1"}
    if host.lower() in blocked_hostnames:
        return {"error": "Scanning localhost or internal addresses is not allowed."}

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": f"Could not resolve host: '{host}'"}

    if is_private_or_reserved(resolved_ip):
        return {"error": "This host resolves to a private or internal IP address. Scanning internal infrastructure is not allowed."}

    open_ports   = []
    closed_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, resolved_ip, port): port
            for port in COMMON_PORTS
        }
        for future in futures:
            port, is_open = future.result()
            entry = {
                "port":    port,
                "service": COMMON_PORTS[port],
                "status":  "open" if is_open else "closed",
            }
            if is_open:
                open_ports.append(entry)
            else:
                closed_ports.append(entry)

    open_ports.sort(key=lambda x: x["port"])
    closed_ports.sort(key=lambda x: x["port"])

    return {
        "host":         host,
        "resolved_ip":  resolved_ip,
        "open_ports":   open_ports,
        "closed_ports": closed_ports,
        "total_open":   len(open_ports),
        "error":        None,
    }