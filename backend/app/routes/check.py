"""POST /api/check — the single public endpoint.

Validates input, applies abuse protection + tier gating, runs the detection
pipeline, and returns the verdict. The request/response shapes are the frozen
public contract (CLAUDE.md).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.config import FREE_TIER_CHECKS_PER_DAY, get_settings
from app.core.tiers import features_for, resolve_tier
from app.core.urls import InvalidURLError
from app.models import CheckRequest, CheckResponse
from app.services.limits import guard
from app.services.pipeline import analyze

router = APIRouter(prefix="/api", tags=["check"])

_RATE_MSG = "You're checking links a little too quickly. Please wait a few seconds and try again."
_DAILY_MSG = (
    f"You've used all {FREE_TIER_CHECKS_PER_DAY} of today's free checks. "
    "Please come back tomorrow, or upgrade for unlimited checks."
)


def _client_ip(request: Request) -> str:
    # Respect a single proxy hop if present; otherwise the socket peer.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/check", response_model=CheckResponse)
async def check(request: CheckRequest, http_request: Request) -> CheckResponse:
    settings = get_settings()
    ip = _client_ip(http_request)
    tier = resolve_tier(http_request)
    features = features_for(tier)

    # Short-window per-IP rate limit (all tiers) — friendly message, not a bare 429.
    if not guard.allow_request(ip):
        raise HTTPException(status_code=429, detail=_RATE_MSG)

    # Daily free-tier cap (paid/business have unlimited checks).
    if not features.unlimited_checks and not guard.allow_daily_check(ip):
        raise HTTPException(status_code=429, detail=_DAILY_MSG)

    # Global daily AI budget: once exhausted, fall back to deterministic-only so
    # scripted abuse can't run up the AI bill. Only consume when AI is usable.
    allow_ai = settings.ai_enabled and guard.try_consume_ai_budget()

    try:
        return await analyze(
            request.url,
            message=request.message,
            allow_message_analysis=features.message_analysis,
            allow_ai_summary=allow_ai,
        )
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
