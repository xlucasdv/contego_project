import httpx

from app.config import settings
from app.services.base import ProviderError


OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


async def fetch_otx(indicator_type: str, indicator: str) -> dict:
    if indicator_type == "ip":
        path_type = "IPv6" if ":" in indicator else "IPv4"
        url = f"{OTX_BASE_URL}/{path_type}/{indicator}/general"
    elif indicator_type == "domain":
        url = f"{OTX_BASE_URL}/domain/{indicator}/general"
    elif indicator_type == "hash":
        url = f"{OTX_BASE_URL}/file/{indicator}/general"
    else:
        raise ProviderError("Tipo de indicador não suportado pelo OTX.", 400)

    headers = {
        "User-Agent": "contego-threat-dashboard/1.0",
        "Accept": "application/json",
    }

    if settings.otx_api_key:
        headers["X-OTX-API-KEY"] = settings.otx_api_key

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            response = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            raise ProviderError(
                f"Falha de rede ao consultar o OTX: {exc}"
            ) from exc

    if response.status_code == 404:
        raise ProviderError("Indicador não encontrado no OTX.", 404)

    if response.status_code >= 400:
        raise ProviderError(
            f"OTX respondeu com status {response.status_code}.",
            response.status_code,
            _safe_json(response),
        )

    return _normalize_otx(response.json(), indicator, indicator_type)


def _safe_json(response: httpx.Response) -> dict:
    try:
        return response.json()
    except Exception:
        return {}


def _normalize_otx(data: dict, indicator: str, indicator_type: str) -> dict:
    pulse_info = data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count") or 0)

    pulses = []
    for pulse in (pulse_info.get("pulses") or [])[:10]:
        pulses.append(
            {
                "name": pulse.get("name"),
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "tlp": pulse.get("TLP"),
                "tags": (pulse.get("tags") or [])[:20],
            }
        )

    if pulse_count == 0:
        risk_level = "baixo"
        verdict = "Nenhum pulse público conhecido no OTX."
    elif pulse_count <= 5:
        risk_level = "médio"
        verdict = f"{pulse_count} pulse(s) públicos associados no OTX."
    else:
        risk_level = "alto"
        verdict = f"{pulse_count} pulse(s) públicos associados no OTX."

    additional = {}

    for key in (
        "country_name",
        "city_name",
        "asn",
        "hostname",
        "alexa",
        "type",
        "base_indicator",
    ):
        if data.get(key) is not None:
            additional[key] = data.get(key)

    analysis = data.get("analysis") or {}
    if analysis:
        additional["analysis"] = {
            "malware_family": analysis.get("malware_family"),
            "sha1": analysis.get("sha1"),
            "sha256": analysis.get("sha256"),
            "file_class": analysis.get("file_class"),
        }

    return {
        "provider": "otx",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "risk_level": risk_level,
        "verdict": verdict,
        "reputation": {
            "pulse_count": pulse_count,
            "pulses": pulses,
            "references": (data.get("references") or [])[:10],
        },
        "additional": additional,
    }