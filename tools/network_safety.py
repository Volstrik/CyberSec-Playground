import socket
import ipaddress
import urllib.parse


def is_private_or_reserved(ip_str):
    """Returns True if the IP is private, loopback, link-local, reserved, or multicast."""
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


def resolve_and_check(hostname):
    """
    Resolves a hostname and checks whether it points to a private/internal address.
    Returns (is_safe: bool, resolved_ip: str|None, reason: str|None)
    """
    blocked_hostnames = {"localhost", "0.0.0.0", "::1"}
    if hostname.lower() in blocked_hostnames:
        return False, None, "Hostname is a blocked internal address."

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False, None, f"Could not resolve host: '{hostname}'"

    if is_private_or_reserved(resolved_ip):
        return False, resolved_ip, "Host resolves to a private or internal IP address."

    return True, resolved_ip, None


def is_url_safe(url):
    """
    Validates that a URL's hostname does not resolve to a private/internal address.
    Returns (is_safe: bool, reason: str|None)
    """
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Could not parse hostname from URL."

        safe, _, reason = resolve_and_check(hostname)
        return safe, reason

    except Exception as e:
        return False, str(e)