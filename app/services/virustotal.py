import httpx

from app.config import settings
from app.services.base import ProviderError


VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch_virustotal(indicator_type: str, indicator: str) -> dict:
    if not settings.virustotal_api_key:
        raise ProviderError(
            "Defina VIRUSTOTAL_API_KEY para usar o VirusTotal.",
            401,
        )

    paths = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files",
    }

    if indicator_type not in paths:
        raise ProviderError(
            "Tipo de indicador não suportado pelo VirusTotal.",
            400,
        )

    url = f"{VIRUSTOTAL_BASE_URL}/{paths[indicator_type]}/{indicator}"

    headers = {
        "x-apikey": settings.virustotal_api_key,
        "accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            response = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            raise ProviderError(
                f"Falha de rede ao consultar o VirusTotal: {exc}"
            ) from exc

    if response.status_code == 404:
        raise ProviderError(
            "Indicador não encontrado no VirusTotal.",
            404,
        )

    if response.status_code == 429:
        raise ProviderError(
            "Limite de consultas do VirusTotal atingido. Aguarde alguns instantes.",
            429,
        )

    if response.status_code >= 400:
        raise ProviderError(
            f"VirusTotal respondeu com status {response.status_code}.",
            response.status_code,
        )

    return _normalize_virustotal(response.json(), indicator, indicator_type)


def _normalize_virustotal(data: dict, indicator: str, indicator_type: str) -> dict:
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    timeout = int(stats.get("timeout") or 0)

    total = malicious + suspicious + harmless + undetected + timeout

    if malicious > 0:
        risk_level = "alto"
    elif suspicious > 0:
        risk_level = "médio"
    else:
        risk_level = "baixo"

    if total:
        verdict = f"{malicious}/{total} engines classificam como malicioso."
    else:
        verdict = "Sem análise pública recente."

    additional = {}

    if indicator_type == "ip":
        for key in (
            "country",
            "as_owner",
            "asn",
            "network",
            "regional_internet_registry",
            "reputation",
        ):
            if attrs.get(key) is not None:
                additional[key] = attrs[key]

    elif indicator_type == "domain":
        for key in (
            "registrar",
            "creation_date",
            "last_modification_date",
            "reputation",
            "categories",
        ):
            if attrs.get(key) is not None:
                additional[key] = attrs[key]

        dns_records = attrs.get("last_dns_records") or []
        if dns_records:
            additional["last_dns_records"] = dns_records[:10]

    elif indicator_type == "hash":
        for key in (
            "meaningful_name",
            "type_description",
            "magic",
            "size",
            "md5",
            "sha1",
            "sha256",
            "reputation",
        ):
            if attrs.get(key) is not None:
                additional[key] = attrs[key]

    return {
        "provider": "virustotal",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "risk_level": risk_level,
        "verdict": verdict,
        "reputation": {
            "last_analysis_stats": stats,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "total_engines": total,
        },
        "additional": additional,
    }