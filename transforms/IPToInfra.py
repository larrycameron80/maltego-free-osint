from extensions import FREE_OSINT, registry
from maltego_trx.entities import ASNumber, DNS, IPAddress, Location, Netblock, Organization, Phrase, Port, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import dedupe, emit, ip_infra, reverse_dns, run_labeled


@registry.register_transform(
    display_name="To infrastructure",
    input_entity="maltego.IPv4Address",
    description="ip-api, RIPEstat, ipwho.is, iptoasn, Shodan InternetDB, URLhaus and reverse DNS.",
    output_entities=[Location, Organization, ASNumber, Netblock, DNS, Port, Phrase, URL],
    transform_set=FREE_OSINT,
)
class IPToInfra(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        ip = request.Value.strip()
        rows, errors = run_labeled({
            "infra": lambda: ip_infra(ip),
            "ptr": lambda: reverse_dns(ip),
        })
        emit(response, dedupe(rows), request.Slider or 12, errors)
