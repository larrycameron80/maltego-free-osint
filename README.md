# Free OSINT transforms for Maltego

Passive, keyless transforms built on the official `maltego-trx` SDK. Entity types are the desktop types (`maltego.Domain`, `maltego.EmailAddress`, `maltego.IPv4Address`, `maltego.AS`, and the rest). The registry writes `transforms.csv`, which is the file an iTDS or a Transform Distribution Server import expects.

Public listing on Transform Hub is a Maltego partner step. This package is the SDK and config format that hub and local installs consume.

## Install

```
pip install -r requirements.txt
python project.py list
```

## Local transforms

In Maltego: Transforms > New Local Transform Set, then point each command at:

```
python project.py local <name>
```

Names from `python project.py list`:

- domaintoall
- domaintodns
- domaintordap
- domaintosubdomains
- domaintocontacts
- domaintourls
- domaintodorks
- domaintobreaches
- domaintoorg
- domaintocrawl
- iptoinfr
- emailtoidentity
- phonetodetails
- dnstoip
- urltoarchive

Raise the result slider. The default cap is 12, matching Maltego Basic.

## Browser UI

```
python project.py runserver
```

Open http://localhost:8080/ui. The page runs the same feeds and groups entities by type.

## Maltego SDK features in this set

- Official entity types and a Transform Set named Free OSINT
- Popup transform setting for phone region on Domain to all free OSINT
- Display information panel, source-count overlay, bookmark, link color, link thickness, note, favicon icon
- `transforms.csv` for an iTDS import

## Feeds

Google DNS, rdap.org, crt.sh, Cert Spotter, subdomain.center, RapidDNS, the site itself, Wayback CDX, urlscan, ip-api, RIPEstat, ipwho.is, iptoasn, ipinfo.io, NetworkCalc, Wikidata, the public HIBP breach catalog, Common Crawl, SSL Labs cache, Shodan InternetDB, URLhaus, Gravatar, GitHub public profiles, libphonenumber.
