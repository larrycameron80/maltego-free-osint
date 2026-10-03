from extensions import FREE_OSINT, registry
from maltego_trx.entities import URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, common_crawl, dedupe, emit


@registry.register_transform(
    display_name="To Common Crawl URLs",
    input_entity="maltego.Domain",
    description="URLs from the latest Common Crawl index.",
    output_entities=[URL],
    transform_set=FREE_OSINT,
)
class DomainToCrawl(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(common_crawl(apex(request.Value)))
        except Exception as exc:
            response.addUIMessage(f"commoncrawl: {exc}", UIM_TYPES["partial"])
            return
        emit(response, rows, request.Slider or 12)
