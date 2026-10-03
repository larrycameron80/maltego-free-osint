from extensions import FREE_OSINT, registry
from maltego_trx.entities import Location, PhoneNumber
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import dedupe, emit, phone_details


@registry.register_transform(
    display_name="To phone details",
    input_entity="maltego.PhoneNumber",
    description="E.164, region, carrier and line type from libphonenumber. No subscriber lookup.",
    output_entities=[PhoneNumber, Location],
    transform_set=FREE_OSINT,
)
class PhoneToDetails(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(phone_details(request.Value, "US"))
        except Exception as exc:
            response.addUIMessage(str(exc), UIM_TYPES["fatal"])
            return
        emit(response, rows, request.Slider or 12)
