from app.services.base import ProviderError
from app.services.otx import fetch_otx
from app.services.virustotal import fetch_virustotal


async def query_provider(
    provider: str,
    indicator_type: str,
    indicator: str,
) -> dict:
    provider = provider.lower()

    if provider == "otx":
        return await fetch_otx(indicator_type, indicator)

    if provider == "virustotal":
        return await fetch_virustotal(indicator_type, indicator)

    raise ProviderError(
        "Provedor não suportado. Use otx ou virustotal.",
        400,
    )