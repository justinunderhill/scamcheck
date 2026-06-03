"""FastAPI application entrypoint.

Run with:  uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routes import check_router, report_router
from app.services.limits import guard

settings = get_settings()

app = FastAPI(
    title="ScamCheck API",
    version="0.1.0",
    description="Paste a URL, get a plain-language risk verdict.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.include_router(check_router)
app.include_router(report_router)


@app.get("/api/health")
async def health() -> dict[str, object]:
    """Liveness + which detection sources are configured (no secrets leaked)."""
    return {
        "status": "ok",
        "sources": {
            "web_risk": settings.web_risk_enabled,
            "virustotal": settings.virustotal_enabled,
            "ai": settings.ai_enabled,
        },
        # Abuse-protection state. AI only activates when the budget is durable
        # (or explicitly allowed for local dev).
        "durable_limits": guard.is_durable,
        "ai_active": settings.ai_enabled
        and (guard.is_durable or settings.ai_allow_without_durable_budget),
    }
