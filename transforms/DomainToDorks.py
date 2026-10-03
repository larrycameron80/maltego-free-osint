from extensions import FREE_OSINT, registry
from maltego_trx.entities import Phrase
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, dorks, emit


@registry.register_transform(
    display_name="To search dorks",
    input_entity="maltego.Domain",
    description="Google dork phrases for documents and published contact pages.",
    output_entities=[Phrase],
    transform_set=FREE_OSINT,
)
class DomainToDorks(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        emit(response, dedupe(dorks(apex(request.Value))), request.Slider or 12)
