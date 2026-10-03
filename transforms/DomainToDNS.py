from extensions import FREE_OSINT, registry
from maltego_trx.entities import DNS, IPAddress, MX, NS, Phrase
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, dns_records, emit


@registry.register_transform(
    display_name="To DNS records",
    input_entity="maltego.Domain",
    description="A, AAAA, MX, NS, TXT, SPF includes and DMARC via Google DNS.",
    output_entities=[IPAddress, DNS, NS, MX, Phrase],
    transform_set=FREE_OSINT,
)
class DomainToDNS(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        rows = dedupe(dns_records(apex(request.Value)))
        emit(response, rows, request.Slider or 12)
