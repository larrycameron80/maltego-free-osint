from maltego_trx.decorator_registry import TransformRegistry, TransformSet

registry = TransformRegistry(
    owner="Free OSINT",
    author="osint-super-transform",
    host_url="https://localhost:8080",
    seed_ids=["free-osint"],
)
registry.version = "1.0"
registry.display_name_suffix = " [Free OSINT]"

FREE_OSINT = TransformSet(name="Free OSINT", description="Keyless passive reconnaissance transforms")
