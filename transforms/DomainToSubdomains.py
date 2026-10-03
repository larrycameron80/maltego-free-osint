from extensions import FREE_OSINT, registry
from maltego_trx.entities import DNS, Email
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, certificates, dedupe, emit, passive_subdomains, run_labeled


@registry.register_transform(
    display_name="To subdomains",
    input_entity="maltego.Domain",
    description="Certificate Transparency, Cert Spotter, subdomain.center and RapidDNS.",
    output_entities=[DNS, Email],
    transform_set=FREE_OSINT,
)
class DomainToSubdomains(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        domain = apex(request.Value)
        rows, errors = run_labeled({
            "certs": lambda: certificates(domain),
            "passive": lambda: passive_subdomains(domain),
        })
        emit(response, dedupe(rows), request.Slider or 12, errors)
