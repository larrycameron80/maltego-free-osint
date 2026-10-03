from extensions import FREE_OSINT, registry
from maltego_trx.entities import Organization, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, emit, wikidata_org


@registry.register_transform(
    display_name="To organization",
    input_entity="maltego.Domain",
    description="Wikidata entity search from the registrable label.",
    output_entities=[Organization, URL],
    transform_set=FREE_OSINT,
)
class DomainToOrg(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(wikidata_org(apex(request.Value)))
        except Exception as exc:
            response.addUIMessage(str(exc), UIM_TYPES["partial"])
            return
        emit(response, rows, request.Slider or 12)
