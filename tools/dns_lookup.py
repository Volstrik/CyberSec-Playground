import dns.resolver

def lookup(domain):
    if not domain:
        return None

    record_types = ["A", "MX", "TXT", "NS"]
    results = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []

            for rdata in answers:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                else:
                    records.append(rdata.to_text())

            results[rtype] = records

        except dns.resolver.NoAnswer:
            results[rtype] = ["No records found"]
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain '{domain}' does not exist."}
        except Exception as e:
            results[rtype] = [f"Error: {str(e)}"]

    return {"domain": domain, "records": results, "error": None}