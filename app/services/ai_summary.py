import json

import httpx

from app.config import settings


SYSTEM_PROMPT = (
    "Você é um analista de segurança da Contego. "
    "Resuma dados técnicos em um briefing curto, objetivo e em português "
    "para um cliente não técnico. Não invente informações."
)


async def generate_summary(result: dict) -> str:
    heuristic = _heuristic_summary(result)

    if not settings.openai_api_key:
        return heuristic

    compact_result = {
        "provider": result.get("provider"),
        "indicator": result.get("indicator"),
        "indicator_type": result.get("indicator_type"),
        "risk_level": result.get("risk_level"),
        "verdict": result.get("verdict"),
        "reputation": result.get("reputation"),
        "additional": result.get("additional"),
    }

    payload = {
        "model": settings.openai_model,
        "temperature": 0.2,
        "max_tokens": 300,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": (
                    "Gere um briefing com base nestes dados: "
                    f"{json.dumps(compact_result, ensure_ascii=False)[:8000]}"
                ),
            },
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                },
                json=payload,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return heuristic


def _heuristic_summary(result: dict) -> str:
    provider = result.get("provider", "desconhecido")
    indicator = result.get("indicator", "indicador")
    risk = result.get("risk_level", "indefinido")
    verdict = result.get("verdict", "")

    if provider == "otx":
        pulses = (result.get("reputation") or {}).get("pulse_count", 0)

        if pulses == 0:
            return (
                f"Consulta OTX para {indicator}: nenhum pulse público conhecido. "
                f"Risco classificado como {risk}. "
                "Recomenda-se manter monitoramento contínuo."
            )

        tags = []
        for pulse in ((result.get("reputation") or {}).get("pulses") or [])[:3]:
            tags.extend(pulse.get("tags") or [])

        tags = ", ".join(sorted(set(tag.lower() for tag in tags))[:8])
        extra = f" Tags observadas: {tags}." if tags else ""

        return (
            f"Consulta OTX para {indicator}: {pulses} pulse(s) públicos associados. "
            f"Risco {risk}.{extra} "
            "Sugere-se investigação adicional e bloqueio cautelar se o ativo for crítico."
        )

    if provider == "virustotal":
        stats = (result.get("reputation") or {}).get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious:
            return (
                f"Consulta VirusTotal para {indicator}: "
                f"{malicious} motor(es) detectam como malicioso e "
                f"{suspicious} como suspeito. "
                f"Risco {risk}. "
                "Recomenda-se bloqueio imediato e análise de eventos correlacionados."
            )

        if suspicious:
            return (
                f"Consulta VirusTotal para {indicator}: "
                "nenhum motor detecta como malicioso, mas há "
                f"{suspicious} detecção(ões) suspeita(s). "
                f"Risco {risk}. "
                "Recomenda-se monitorar e validar contexto."
            )

        return (
            f"Consulta VirusTotal para {indicator}: "
            "nenhuma detecção maliciosa relevante no último scan. "
            f"Risco {risk}. "
            "Manter monitoramento."
        )

    return f"Consulta para {indicator} finalizada com risco {risk}. {verdict}".strip()