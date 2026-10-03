from extensions import FREE_OSINT, registry
from maltego_trx.entities import Domain, NS, Organization
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, emit, rdap


@registry.register_transform(
    display_name="To RDAP registration",
    input_entity="maltego.Domain",
    description="Registrar, dates, status and nameservers from rdap.org.",
    output_entities=[Domain, NS, Organization],
    transform_set=FREE_OSINT,
)
class DomainToRDAP(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(rdap(apex(request.Value)))
        except Exception as exc:
            response.addUIMessage(f"rdap: {exc}", UIM_TYPES["fatal"])
            return
        emit(response, rows, request.Slider or 12)
