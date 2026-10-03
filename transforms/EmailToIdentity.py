from extensions import FREE_OSINT, registry
from maltego_trx.entities import Alias, Domain, Person, Phrase, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import dedupe, email_identity, emit


@registry.register_transform(
    display_name="To identity pivots",
    input_entity="maltego.EmailAddress",
    description="Gravatar, mail domain, local-part alias and a public GitHub profile if the local part matches.",
    output_entities=[Domain, Alias, Person, URL, Phrase],
    transform_set=FREE_OSINT,
)
class EmailToIdentity(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        try:
            rows = dedupe(email_identity(request.Value))
        except Exception as exc:
            response.addUIMessage(str(exc), UIM_TYPES["partial"])
            return
        emit(response, rows, request.Slider or 12)
