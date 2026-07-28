import whois

def lookup(domain):
    if not domain:
        return None

    try:
        w = whois.whois(domain)

        def clean(val):
            if isinstance(val, list):
                val = val[0]
            return str(val).strip() if val else "N/A"

        def clean_date(val):
            if isinstance(val, list):
                val = val[0]
            if val is None:
                return "N/A"
            try:
                return val.strftime("%Y-%m-%d")
            except Exception:
                return str(val)

        return {
            "domain":      clean(w.domain_name),
            "registrar":   clean(w.registrar),
            "created":     clean_date(w.creation_date),
            "expires":     clean_date(w.expiration_date),
            "updated":     clean_date(w.updated_date),
            "status":      clean(w.status),
            "name_servers": ", ".join(w.name_servers) if isinstance(w.name_servers, list) else clean(w.name_servers),
            "emails":      clean(w.emails),
            "country":     clean(w.country),
            "error":       None,
        }

    except Exception as e:
        return {"error": str(e)}