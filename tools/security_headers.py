import requests
from tools.network_safety import is_url_safe

HEADERS_INFO = {
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS connections to the server.",
        "risk": "Without this, users can be downgraded to HTTP.",
    },
    "Content-Security-Policy": {
        "desc": "Controls resources the browser is allowed to load.",
        "risk": "Without this, the site is vulnerable to XSS attacks.",
    },
    "X-Frame-Options": {
        "desc": "Prevents the page from being embedded in an iframe.",
        "risk": "Without this, clickjacking attacks are possible.",
    },
    "X-Content-Type-Options": {
        "desc": "Stops browsers from MIME-sniffing a response.",
        "risk": "Without this, browsers may misinterpret file types.",
    },
    "Referrer-Policy": {
        "desc": "Controls how much referrer info is sent with requests.",
        "risk": "Without this, sensitive URLs may leak to third parties.",
    },
    "Permissions-Policy": {
        "desc": "Controls access to browser features like camera/mic.",
        "risk": "Without this, embedded content may access device features.",
    },
}

MAX_REDIRECTS = 5


def check(url):
    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate the initial URL before making any request
    safe, reason = is_url_safe(url)
    if not safe:
        return {"error": f"Request blocked: {reason}"}

    try:
        current_url = url
        response = None

        # Manually follow redirects, validating each hop before following it.
        # This prevents an attacker using a safe public URL that 302s to an
        # internal address, which `requests`' default redirect handling
        # would otherwise follow blindly.
        for _ in range(MAX_REDIRECTS):
            response = requests.get(current_url, timeout=8, allow_redirects=False)

            if response.is_redirect or response.is_permanent_redirect:
                next_url = response.headers.get("Location")
                if not next_url:
                    break

                safe, reason = is_url_safe(next_url)
                if not safe:
                    return {"error": f"Redirect blocked: {reason}"}

                current_url = next_url
                continue

            break

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        results = []
        present_count = 0

        for header, info in HEADERS_INFO.items():
            found = header.lower() in response_headers
            if found:
                present_count += 1
            results.append({
                "name":    header,
                "present": found,
                "value":   response_headers.get(header.lower(), None),
                "desc":    info["desc"],
                "risk":    info["risk"],
            })

        score = round((present_count / len(HEADERS_INFO)) * 100)

        if score >= 80:
            grade, color = "A", "ok"
        elif score >= 60:
            grade, color = "B", "ok"
        elif score >= 40:
            grade, color = "C", "warn"
        elif score >= 20:
            grade, color = "D", "warn"
        else:
            grade, color = "F", "danger"

        return {
            "url":           current_url,
            "status_code":   response.status_code,
            "results":       results,
            "present_count": present_count,
            "total":         len(HEADERS_INFO),
            "score":         score,
            "grade":         grade,
            "color":         color,
            "error":         None,
        }

    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to '{url}'. Check the URL and try again."}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out. The server took too long to respond."}
    except Exception as e:
        return {"error": str(e)}