from extensions import FREE_OSINT, registry
from maltego_trx.entities import Domain, Phrase, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, emit, ent


@registry.register_transform(
    display_name="To domain and archive",
    input_entity="maltego.URL",
    description="Host from the URL, plus a Wayback capture link.",
    output_entities=[Domain, URL, Phrase],
    transform_set=FREE_OSINT,
)
class URLToArchive(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        raw = request.Value.strip()
        domain = apex(raw)
        rows = dedupe([
            ent("domain", domain, "url"),
            ent("url", f"https://web.archive.org/web/*/{raw}", "wayback"),
            ent("phrase", f"site:{domain}", "google", url=f"https://www.google.com/search?q=site:{domain}"),
        ])
        emit(response, rows, request.Slider or 12)
