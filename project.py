import sys
from pathlib import Path

import transforms
from extensions import registry
from flask import jsonify, request
from maltego_trx.handler import handle_run
from maltego_trx.registry import register_transform_classes
from maltego_trx.server import app as application

from osintlib import (
    apex, certificates, collect, common_crawl, dedupe, dns_records, hibp_domain,
    ip_infra, passive_subdomains, reverse_dns, run_labeled, site_contacts, wikidata_org,
)

register_transform_classes(transforms)
registry.write_transforms_config(include_output_entities=True)
registry.write_settings_config()

UI = Path(__file__).with_name("ui.html").read_text(encoding="utf-8")


@application.route("/ui")
def ui():
    return UI


@application.route("/api/run", methods=["POST"])
def api_run():
    body = request.get_json(force=True, silent=True) or {}
    raw = (body.get("q") or "").strip()
    kind = body.get("kind") or "all"
    if not raw:
        return jsonify({"entities": [], "errors": ["empty input"]}), 400
    errors = []
    try:
        if kind == "all":
            rows, errors = collect(apex(raw), "US")
        elif kind == "dns":
            rows = dedupe(dns_records(apex(raw)))
        elif kind == "contacts":
            rows = [r for r in dedupe(site_contacts(apex(raw), "US")) if r["type"] in {"email", "phone"}]
        elif kind == "subs":
            found, errors = run_labeled({
                "certs": lambda: certificates(apex(raw)),
                "passive": lambda: passive_subdomains(apex(raw)),
            })
            rows = dedupe(found)
        elif kind == "breaches":
            rows = dedupe(hibp_domain(apex(raw)))
        elif kind == "org":
            rows = dedupe(wikidata_org(apex(raw)))
        elif kind == "crawl":
            rows = dedupe(common_crawl(apex(raw)))
        elif kind == "ip":
            found, errors = run_labeled({"infra": lambda: ip_infra(raw), "ptr": lambda: reverse_dns(raw)})
            rows = dedupe(found)
        else:
            rows, errors = collect(apex(raw), "US")
    except Exception as exc:
        return jsonify({"entities": [], "errors": [f"{type(exc).__name__}: {exc}"]}), 200
    return jsonify({"entities": rows[:200], "errors": errors})


if __name__ == "__main__":
    handle_run(__name__, sys.argv, application)
