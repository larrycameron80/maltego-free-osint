"""Free passive sources shared by the Maltego transforms."""

from osint_dns import (
    apex, certificates, dns_records, emails_in, ent, get, passive_subdomains, phones_in, rdap, under,
)
from osint_extra import common_crawl, hibp_domain, networkcalc, sslabs, wikidata_org
from osint_ip import dedupe, email_identity, ip_infra, phone_details, reverse_dns, run_labeled
from osint_web import archived_urls, dorks, site_contacts, urlscan

GH = {"Accept": "application/vnd.github+json", "User-Agent": "maltego-free-osint"}


def github_public(query: str) -> list[dict]:
    out = []
    users = get("https://api.github.com/search/users", params={"q": query, "per_page": 5}, headers=GH, timeout=20)
    if users.ok:
        for item in (users.json().get("items") or []):
            out.append(ent("alias", item.get("login"), "github", url=item.get("html_url"), kind=item.get("type")))
            if item.get("html_url"):
                out.append(ent("url", item["html_url"], "github"))
    repos = get("https://api.github.com/search/repositories", params={"q": query, "per_page": 5}, headers=GH, timeout=20)
    if repos.ok:
        for item in (repos.json().get("items") or []):
            out.append(ent("phrase", item.get("full_name"), "github", url=item.get("html_url"), description=item.get("description")))
            if item.get("html_url"):
                out.append(ent("url", item["html_url"], "github"))
    return out


def emit(response, rows, limit: int, errors=None):
    from maltego_trx.entities import (
        ASNumber, Alias, DNS, Domain, Email, IPAddress, Location, MX, NS, Netblock,
        Organization, Person, PhoneNumber, Phrase, Port, URL, Website,
    )
    from maltego_trx.maltego import UIM_TYPES
    from maltego_trx.overlays import OverlayPosition, OverlayType

    type_map = {
        "domain": Domain, "subdomain": DNS, "dns": DNS, "email": Email, "phone": PhoneNumber,
        "ipv4": IPAddress, "ipv6": "maltego.IPv6Address", "asn": ASNumber, "ns": NS, "mx": MX,
        "url": URL, "website": Website, "phrase": Phrase, "port": Port, "location": Location,
        "organization": Organization, "person": Person, "alias": Alias, "netblock": Netblock,
    }
    link_color = {
        "email": "#c0392b", "phone": "#8e44ad", "ipv4": "#2471a3", "ipv6": "#1a5276",
        "subdomain": "#0e6655", "url": "#b9770e", "asn": "#1c2833", "phrase": "#7f8c8d",
        "alias": "#1a5276",
    }
    shown = 0
    cap = limit or 12
    for row in rows:
        if shown >= cap:
            break
        labels = row.get("labels") or []
        entity = response.addEntity(type_map.get(row["type"], Phrase), row["value"])
        entity.setLinkLabel(", ".join(labels)[:80])
        entity.setLinkColor(link_color.get(row["type"], "#34495e"))
        entity.setLinkThickness(2 if len(labels) > 1 else 1)
        entity.setWeight(min(100, 20 * len(labels)))
        entity.addProperty("sources", "Sources", "loose", str(len(labels)))
        entity.addOverlay("sources", OverlayPosition.NORTH_WEST, OverlayType.TEXT)
        if len(labels) >= 3:
            entity.setBookmark("4")
        elif len(labels) == 2:
            entity.setBookmark("1")
        bits = "".join(f"<li>{k}: {v}</li>" for k, v in list((row.get("props") or {}).items())[:8])
        entity.addDisplayInformation(
            f"<p><b>{row['type']}</b> from {', '.join(labels)}</p><ul>{bits}</ul>",
            "Free OSINT",
        )
        entity.setNote(", ".join(labels))
        if row["type"] in {"domain", "subdomain", "dns"}:
            entity.setIconURL(f"https://www.google.com/s2/favicons?domain={row['value']}&sz=64")
        for key, value in (row.get("props") or {}).items():
            entity.addProperty(key, key, "loose", str(value)[:500])
        shown += 1
    if len(rows) > cap:
        response.addUIMessage(f"Slider capped output at {cap} of {len(rows)}. Raise the slider for more.", UIM_TYPES["partial"])
    for err in errors or []:
        response.addUIMessage(err, UIM_TYPES["partial"])
    return shown


def collect(domain: str, region: str = "US") -> tuple[list[dict], list[str]]:
    rows, errors = run_labeled({
        "dns": lambda: dns_records(domain),
        "rdap": lambda: rdap(domain),
        "certs": lambda: certificates(domain),
        "subs": lambda: passive_subdomains(domain),
        "site": lambda: site_contacts(domain, region),
        "wayback": lambda: archived_urls(domain, region),
        "urlscan": lambda: urlscan(domain),
        "dorks": lambda: dorks(domain),
        "github": lambda: github_public(domain),
        "networkcalc": lambda: networkcalc(domain),
        "wikidata": lambda: wikidata_org(domain),
        "hibp": lambda: hibp_domain(domain),
        "commoncrawl": lambda: common_crawl(domain),
        "ssllabs": lambda: sslabs(domain),
    })
    return dedupe(rows), errors
