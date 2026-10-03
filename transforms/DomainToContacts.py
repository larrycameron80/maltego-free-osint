from extensions import FREE_OSINT, registry
from maltego_trx.entities import Email, PhoneNumber, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, archived_urls, certificates, dedupe, emit, run_labeled, site_contacts


@registry.register_transform(
    display_name="To emails and phones",
    input_entity="maltego.Domain",
    description="Published addresses and numbers from the site, security.txt, certificates and Wayback.",
    output_entities=[Email, PhoneNumber, URL],
    transform_set=FREE_OSINT,
)
class DomainToContacts(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        domain = apex(request.Value)
        region = "US"
        rows, errors = run_labeled({
            "site": lambda: site_contacts(domain, region),
            "certs": lambda: certificates(domain),
            "wayback": lambda: archived_urls(domain, region),
        })
        wanted = [r for r in dedupe(rows) if r["type"] in {"email", "phone", "url"}]
        emit(response, wanted, request.Slider or 12, errors)
