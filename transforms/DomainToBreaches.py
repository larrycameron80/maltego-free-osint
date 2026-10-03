from extensions import FREE_OSINT, registry
from maltego_trx.entities import Phrase
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, emit, hibp_domain


@registry.register_transform(
    display_name="To known breaches",
    input_entity="maltego.Domain",
    description="Match the domain against the public Have I Been Pwned breach catalog. Not an email search.",
    output_entities=[Phrase],
    transform_set=FREE_OSINT,
)
class DomainToBreaches(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(hibp_domain(apex(request.Value)))
        except Exception as exc:
            response.addUIMessage(f"hibp: {exc}", UIM_TYPES["partial"])
            return
        if not rows:
            response.addUIMessage("No breach in the public catalog lists this domain.", UIM_TYPES["inform"])
        emit(response, rows, request.Slider or 12)
