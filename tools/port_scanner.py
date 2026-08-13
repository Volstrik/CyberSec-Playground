import socket
from concurrent.futures import ThreadPoolExecutor
from tools.network_safety import resolve_and_check

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

    safe, resolved_ip, reason = resolve_and_check(host)
    if not safe:
        return {"error": reason}

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