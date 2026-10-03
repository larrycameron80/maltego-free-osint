from extensions import FREE_OSINT, registry
from maltego_trx.entities import ASNumber, DNS, IPAddress, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, archived_urls, dedupe, emit, run_labeled, urlscan


@registry.register_transform(
    display_name="To URLs and urlscan",
    input_entity="maltego.Domain",
    description="Wayback CDX captures and urlscan.io observations.",
    output_entities=[URL, DNS, IPAddress, ASNumber],
    transform_set=FREE_OSINT,
)
class DomainToURLs(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        domain = apex(request.Value)
        rows, errors = run_labeled({
            "wayback": lambda: archived_urls(domain),
            "urlscan": lambda: urlscan(domain),
        })
        emit(response, dedupe(rows), request.Slider or 12, errors)
