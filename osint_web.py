"""Site, archive and urlscan pivots."""
import re
from urllib.parse import urljoin, urlparse

import requests

from osint_dns import CONTACT_HINTS, HOST_RE, LinkParser, emails_in, ent, get, phones_in, under


def site_contacts(domain: str, region: str, page_limit: int = 6) -> list[dict]:
    out = []
    seeds = [
        f"https://{domain}/",
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/robots.txt",
    ]
    try:
        sm = get(f"https://{domain}/sitemap.xml")
        if sm.status_code == 200:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm.text or "", re.I):
                if any(h in loc.lower() for h in CONTACT_HINTS):
                    seeds.append(loc)
    except Exception:
        pass
    seen = set()
    queue = list(dict.fromkeys(seeds))
    fetched = 0
    while queue and fetched < page_limit:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = get(url, headers={"Accept": "text/html,text/plain"})
        except Exception:
            continue
        fetched += 1
        text = r.text or ""
        out.append(ent("url", r.url, "site", status=r.status_code))
        for addr in emails_in(text):
            out.append(ent("email", addr, "site", page=r.url))
        for num in phones_in(text, region):
            out.append(ent("phone", num, "site", page=r.url))
        if "robots.txt" in r.url and r.status_code == 200:
            for line in text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        out.append(ent("url", f"https://{domain}{path}", "robots"))
        parser = LinkParser()
        try:
            parser.feed(text)
        except Exception:
            continue
        for href in parser.links:
            absolute = urljoin(r.url, href).split("#")[0]
            host = (urlparse(absolute).hostname or "").lower()
            if (host == domain or host.endswith("." + domain)) and any(h in urlparse(absolute).path.lower() for h in CONTACT_HINTS):
                if absolute not in seen:
                    queue.append(absolute)
    return out


def archived_urls(domain: str, region: str = "US") -> list[dict]:
    out = []
    r = get(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": "25",
        },
        timeout=35,
    )
    r.raise_for_status()
    rows = r.json()
    if not rows or len(rows) < 2:
        return out
    contact_fetches = 0
    for original, timestamp, _status in rows[1:]:
        archived = f"https://web.archive.org/web/{timestamp}/{original}"
        out.append(ent("url", original, "wayback", archived=archived))
        if contact_fetches < 2 and any(h in original.lower() for h in CONTACT_HINTS):
            contact_fetches += 1
            try:
                page = get(f"https://web.archive.org/web/{timestamp}id_/{original}", timeout=20)
            except Exception:
                continue
            for addr in emails_in(page.text or ""):
                out.append(ent("email", addr, "wayback", page=original))
            for num in phones_in(page.text or "", region):
                out.append(ent("phone", num, "wayback", page=original))
    return out


def urlscan(domain: str) -> list[dict]:
    r = get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": "15"}, timeout=25)
    r.raise_for_status()
    out = []
    for hit in r.json().get("results") or []:
        page = hit.get("page") or {}
        task = hit.get("task") or {}
        if page.get("domain"):
            out.append(ent("subdomain", page["domain"], "urlscan"))
        if page.get("ip"):
            out.append(ent("ipv4", page["ip"], "urlscan"))
        if page.get("asn"):
            out.append(ent("asn", str(page["asn"]).replace("AS", ""), "urlscan", name=page.get("asnname")))
        if task.get("url"):
            out.append(ent("url", task["url"], "urlscan"))
    return out


def dorks(domain: str) -> list[dict]:
    queries = [
        f"site:{domain}",
        f"site:{domain} (contact OR email OR phone OR tel)",
        f\"@{domain}\"",
        f"site:{domain} filetype:pdf",
    ]
    return [ent("phrase", q, "google", url="https://www.google.com/search?q=" + requests.utils.quote(q)) for q in queries]
