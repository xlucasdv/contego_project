from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.config import settings
from app.database import get_lookup, init_db, list_lookups, save_lookup
from app.indicator import classify_indicator, normalize_value
from app.services.ai_summary import generate_summary
from app.services.base import ProviderError
from app.services.lookup import query_provider


BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Contego Threat Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)


class LookupRequest(BaseModel):
    value: str = Field(..., min_length=3, max_length=255)
    provider: str | None = None


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/api/lookup")
async def lookup(payload: LookupRequest):
    provider = (payload.provider or settings.default_provider or "otx").lower()

    try:
        indicator = normalize_value(payload.value)
        indicator_type = classify_indicator(indicator)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = await query_provider(provider, indicator_type, indicator)
        summary = await generate_summary(result)
        result["summary"] = summary

        lookup_id = save_lookup(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=provider,
            success=True,
            risk_level=result.get("risk_level"),
            summary=summary,
            payload=result,
        )

        return {
            "id": lookup_id,
            "success": True,
            "result": result,
        }

    except ProviderError as exc:
        error_payload = {
            "provider": provider,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "error": str(exc),
            "status_code": exc.status_code,
            "details": exc.payload,
        }

        lookup_id = save_lookup(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=provider,
            success=False,
            risk_level=None,
            summary=f"Erro na consulta: {exc}",
            payload=error_payload,
            error=str(exc),
        )

        status_code = (
            exc.status_code
            if exc.status_code in (400, 401, 403, 404, 429)
            else 502
        )

        return JSONResponse(
            status_code=status_code,
            content={
                "id": lookup_id,
                "success": False,
                "error": str(exc),
            },
        )

    except Exception:
        error_payload = {
            "provider": provider,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "error": "Erro interno não esperado.",
        }

        lookup_id = save_lookup(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=provider,
            success=False,
            risk_level=None,
            summary="Erro interno ao processar consulta.",
            payload=error_payload,
            error="internal_error",
        )

        return JSONResponse(
            status_code=500,
            content={
                "id": lookup_id,
                "success": False,
                "error": "Erro interno ao processar consulta.",
            },
        )


@app.get("/api/history")
async def history(limit: int = 50):
    limit = min(max(limit, 1), 200)
    return {"items": list_lookups(limit)}


@app.get("/api/history/{lookup_id}")
async def history_detail(lookup_id: int):
    item = get_lookup(lookup_id)

    if not item:
        raise HTTPException(status_code=404, detail="Consulta não encontrada.")

    return item