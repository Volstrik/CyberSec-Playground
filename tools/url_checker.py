import re
import time
import urllib.parse
import requests as http_requests
import config

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "wallet",
    "free", "lucky", "winner", "claim", "prize", "urgent",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".club", ".online", ".site", ".icu", ".buzz",
]

TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "wikipedia.org", "youtube.com",
]


def analyze(url):
    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed   = urllib.parse.urlparse(url)
        domain   = parsed.netloc.lower()
        path     = parsed.path.lower()
        fullurl  = url.lower()

        flags  = []
        score  = 0  # risk score, higher = more suspicious

        # ── Checks ──────────────────────────────────────────────────────
        # 1. HTTPS
        uses_https = url.startswith("https://")
        if not uses_https:
            flags.append({"label": "No HTTPS", "detail": "Connection is unencrypted.", "level": "danger"})
            score += 20

        # 2. IP address instead of domain
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
        if is_ip:
            flags.append({"label": "IP Address URL", "detail": "URL uses a raw IP instead of a domain name.", "level": "danger"})
            score += 25

        # 3. Suspicious TLD
        sus_tld = next((t for t in SUSPICIOUS_TLDS if domain.endswith(t)), None)
        if sus_tld:
            flags.append({"label": f"Suspicious TLD ({sus_tld})", "detail": "This TLD is commonly used in phishing.", "level": "warn"})
            score += 15

        # 4. Suspicious keywords in URL
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in fullurl]
        if found_keywords:
            flags.append({
                "label":  "Suspicious Keywords",
                "detail": f"Found: {', '.join(found_keywords)}",
                "level":  "warn",
            })
            score += len(found_keywords) * 5

        # 5. Excessive subdomains
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            flags.append({"label": "Excessive Subdomains", "detail": f"{subdomain_count} dots in domain — common in phishing URLs.", "level": "warn"})
            score += 15

        # 6. URL length
        if len(url) > 100:
            flags.append({"label": "Very Long URL", "detail": f"{len(url)} characters — long URLs are often used to obscure destinations.", "level": "warn"})
            score += 10

        # 7. @ symbol in URL
        if "@" in url:
            flags.append({"label": "@ Symbol in URL", "detail": "The @ symbol can redirect to a different host.", "level": "danger"})
            score += 25

        # 8. Double slash redirect
        if "//" in parsed.path:
            flags.append({"label": "Double Slash in Path", "detail": "May indicate a redirect trick.", "level": "warn"})
            score += 10

        # 9. Hex or percent encoding
        if re.search(r"%[0-9a-fA-F]{2}", url):
            flags.append({"label": "Encoded Characters", "detail": "URL contains encoded characters — sometimes used to disguise malicious links.", "level": "warn"})
            score += 10

        # 10. Trusted domain check
        is_trusted = any(domain == t or domain.endswith("." + t) for t in TRUSTED_DOMAINS)

        # ── Final verdict ────────────────────────────────────────────────
        score = min(score, 100)

        if is_trusted and score < 20:
            verdict, color = "Likely Safe", "ok"
        elif score == 0:
            verdict, color = "No Issues Found", "ok"
        elif score < 25:
            verdict, color = "Low Risk", "ok"
        elif score < 50:
            verdict, color = "Suspicious", "warn"
        elif score < 75:
            verdict, color = "High Risk", "danger"
        else:
            verdict, color = "Very High Risk", "danger"

        # ── VirusTotal check ─────────────────────────────────────────────
        vt_result = check_virustotal(url)

        return {
            "url":        url,
            "domain":     domain,
            "uses_https": uses_https,
            "is_trusted": is_trusted,
            "flags":      flags,
            "score":      score,
            "verdict":    verdict,
            "color":      color,
            "vt":         vt_result,
            "error":      None,
        }

    except Exception as e:
        return {"error": str(e)}


def check_virustotal(url):
    if not config.VT_API_KEY:
        return {"available": False, "reason": "No API key configured."}

    headers = {"x-apikey": config.VT_API_KEY}

    try:
        # Submit URL for analysis
        submit_resp = http_requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )

        if submit_resp.status_code != 200:
            return {"available": False, "reason": f"VirusTotal error: {submit_resp.status_code}"}

        analysis_id = submit_resp.json()["data"]["id"]

        # Poll for result (VT needs a moment to analyze)
        data = None
        for _ in range(6):
            time.sleep(2)
            result_resp = http_requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10,
            )
            data = result_resp.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                break

        if data is None:
            return {"available": False, "reason": "No response from VirusTotal."}

        stats = data["data"]["attributes"]["stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict, color = "Flagged Malicious", "danger"
        elif suspicious > 0:
            verdict, color = "Flagged Suspicious", "warn"
        else:
            verdict, color = "Clean", "ok"

        return {
            "available":  True,
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "total":      total,
            "verdict":    verdict,
            "color":      color,
        }

    except Exception as e:
        return {"available": False, "reason": str(e)}