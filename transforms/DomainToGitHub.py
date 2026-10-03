from extensions import FREE_OSINT, registry
from maltego_trx.entities import Alias, Phrase, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_TYPES
from maltego_trx.transform import DiscoverableTransform

from osintlib import apex, dedupe, emit, github_public


@registry.register_transform(
    display_name="To public GitHub",
    input_entity="maltego.Domain",
    description="Public GitHub user and repository search for the domain. No token. Rate limited.",
    output_entities=[Alias, URL, Phrase],
    transform_set=FREE_OSINT,
)
class DomainToGitHub(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        domain = apex(request.Value)
        try:
            rows = dedupe(github_public(f"{domain} in:name,description,login"))
        except Exception as exc:
            response.addUIMessage(f"github: {exc}", UIM_TYPES["partial"])
            return
        if not rows:
            response.addUIMessage("No public GitHub user or repository matched.", UIM_TYPES["inform"])
        emit(response, rows, request.Slider or 12)
