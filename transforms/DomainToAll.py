from extensions import FREE_OSINT, registry
from maltego_trx.decorator_registry import TransformSetting
from maltego_trx.entities import DNS, Domain, Email, IPAddress, MX, NS, Phrase, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, collect, emit

region_setting = TransformSetting(
    name="region",
    display_name="Phone region",
    setting_type="string",
    default_value="US",
    optional=True,
    popup=True,
)


@registry.register_transform(
    display_name="To all free OSINT",
    input_entity="maltego.Domain",
    description="Run every keyless passive feed and return a mixed entity graph.",
    output_entities=[DNS, Email, IPAddress, NS, MX, URL, Phrase, Domain],
    settings=[region_setting],
    transform_set=FREE_OSINT,
)
class DomainToAll(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        region = request.getTransformSetting("region") or "US"
        rows, errors = collect(apex(request.Value), region)
        emit(response, rows, request.Slider or 12, errors)
