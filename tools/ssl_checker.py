import ssl
import socket
from datetime import datetime

def check(domain):
    if not domain:
        return None

    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

        # Parse dates
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")

        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(not_before_str, fmt)
        not_after  = datetime.strptime(not_after_str,  fmt)
        now        = datetime.utcnow()

        days_left = (not_after - now).days
        is_valid  = now < not_after and now > not_before

        if days_left > 30:
            status, color = "Valid", "ok"
        elif days_left > 0:
            status, color = "Expiring Soon", "warn"
        else:
            status, color = "Expired", "danger"

        # Subject / Issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        # SANs
        sans = []
        for entry in cert.get("subjectAltName", []):
            if entry[0] == "DNS":
                sans.append(entry[1])

        return {
            "domain":       domain,
            "status":       status,
            "color":        color,
            "is_valid":     is_valid,
            "days_left":    days_left,
            "not_before":   not_before.strftime("%Y-%m-%d"),
            "not_after":    not_after.strftime("%Y-%m-%d"),
            "common_name":  subject.get("commonName", "N/A"),
            "org":          subject.get("organizationName", "N/A"),
            "issuer_cn":    issuer.get("commonName", "N/A"),
            "issuer_org":   issuer.get("organizationName", "N/A"),
            "protocol":     protocol,
            "cipher":       cipher[0] if cipher else "N/A",
            "sans":         sans[:10],  # cap at 10
            "error":        None,
        }

    except ssl.SSLCertVerificationError as e:
        return {"error": f"SSL verification failed: {str(e)}"}
    except socket.gaierror:
        return {"error": f"Could not resolve domain: '{domain}'"}
    except socket.timeout:
        return {"error": "Connection timed out."}
    except ConnectionRefusedError:
        return {"error": f"Port 443 is closed on '{domain}' — no SSL detected."}
    except Exception as e:
        return {"error": str(e)}