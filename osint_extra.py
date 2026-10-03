"""Later free feeds."""

import json

from osint_dns import TIMEOUT, ent, get, under


def ipinfo(ip: str) -> list[dict]:
    r = get(f"https://ipinfo.io/{ip}/json", timeout=15)
    if not r.ok:
        return []
    body = r.json()
    out = []
    if body.get("org"):
        out.append(ent("organization", body["org"], "ipinfo"))
    if body.get("city") or body.get("country"):
        out.append(ent("location", ", ".join(x for x in (body.get("city"), body.get("region"), body.get("country")) if x), "ipinfo"))
    if body.get("hostname"):
        out.append(ent("dns", body["hostname"], "ipinfo"))
    return out


def networkcalc(domain: str) -> list[dict]:
    out = []
    r = get(f"https://networkcalc.com/api/dns/lookup/{domain}", timeout=20)
    if r.ok and r.json().get("status") == "OK":
        records = r.json().get("records") or {}
        for row in records.get("A") or []:
            if row.get("address"):
                out.append(ent("ipv4", row["address"], "networkcalc"))
        for row in records.get("MX") or []:
            if row.get("exchange"):
                out.append(ent("mx", row["exchange"].rstrip("."), "networkcalc"))
        for row in records.get("NS") or []:
            if row.get("nameserver"):
                out.append(ent("ns", row["nameserver"].rstrip("."), "networkcalc"))
    c = get(f"https://networkcalc.com/api/security/certificate/{domain}", timeout=20)
    if c.ok and (c.json().get("status") == "OK" or c.json().get("certificate")):
        cert = c.json().get("certificate") or c.json()
        names = cert.get("subject_alt_names") or cert.get("san") or []
        if isinstance(names, str):
            names = [n.strip() for n in names.split(",")]
        for name in names:
            name = str(name).lower().lstrip("*.")
            if under(name, domain):
                out.append(ent("subdomain", name, "networkcalc"))
    return out


def wikidata_org(domain: str) -> list[dict]:
    query = domain.split(".")[0]
    r = get(
        "https://www.wikidata.org/w/api.php",
        params={"action": "wbsearchentities", "search": query, "language": "en", "format": "json", "limit": 3},
        timeout=20,
    )
    if not r.ok:
        return []
    out = []
    for hit in r.json().get("search") or []:
        out.append(ent("organization", hit.get("label") or hit.get("id"), "wikidata", qid=hit.get("id"), description=hit.get("description")))
        if hit.get("id"):
            out.append(ent("url", f"https://www.wikidata.org/wiki/{hit['id']}", "wikidata"))
    return out


def hibp_domain(domain: str) -> list[dict]:
    r = get("https://haveibeenpwned.com/api/v3/breaches", timeout=40)
    r.raise_for_status()
    out = []
    for row in r.json():
        if str(row.get("Domain") or "").lower() == domain:
            out.append(ent(
                "phrase",
                row.get("Title") or row.get("Name"),
                "hibp",
                breach=row.get("Name"),
                date=row.get("BreachDate"),
                pwncount=row.get("PwnCount"),
                dataclass=",".join(row.get("DataClasses") or [])[:240],
            ))
    return out


def common_crawl(domain: str) -> list[dict]:
    info = get("https://index.commoncrawl.org/collinfo.json", timeout=25)
    info.raise_for_status()
    colls = info.json()
    if not colls:
        return []
    coll = colls[0]["id"]
    r = get(
        f"https://index.commoncrawl.org/{coll}-index",
        params={"url": f"{domain}/*", "output": "json", "fl": "url,timestamp,status", "limit": "12"},
        timeout=30,
    )
    if not r.ok:
        return []
    out = []
    for line in r.text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("url"):
            out.append(ent("url", row["url"], "commoncrawl", timestamp=row.get("timestamp"), status=row.get("status"), index=coll))
    return out


def sslabs(domain: str) -> list[dict]:
    r = get(
        "https://api.ssllabs.com/api/v3/analyze",
        params={"host": domain, "fromCache": "on", "maxAge": "48"},
        timeout=25,
    )
    if not r.ok:
        return []
    body = r.json()
    out = []
    for endpoint in body.get("endpoints") or []:
        if endpoint.get("ipAddress"):
            out.append(ent("ipv4", endpoint["ipAddress"], "ssllabs", grade=endpoint.get("grade")))
        if endpoint.get("grade"):
            out.append(ent("phrase", f"SSL Labs {endpoint.get('grade')}", "ssllabs", ip=endpoint.get("ipAddress")))
    if body.get("status") and not out:
        out.append(ent("phrase", f"SSL Labs {body.get('status')}", "ssllabs"))
    return out
