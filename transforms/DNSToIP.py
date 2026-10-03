from extensions import FREE_OSINT, registry
from maltego_trx.entities import DNS, IPAddress, Phrase
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, dns_records, emit


@registry.register_transform(
    display_name="To IP addresses",
    input_entity="maltego.DNSName",
    description="Resolve a DNS name through Google Public DNS. Does not query the target resolver.",
    output_entities=[IPAddress, DNS, Phrase],
    transform_set=FREE_OSINT,
)
class DNSToIP(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        rows = [r for r in dedupe(dns_records(apex(request.Value))) if r["type"] in {"ipv4", "ipv6", "ns", "mx"}]
        emit(response, rows, request.Slider or 12)
