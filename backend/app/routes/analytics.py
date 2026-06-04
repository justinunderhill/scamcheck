"""Analytics endpoints.

Two routes, both reading the same aggregate counters (see docs/ANALYTICS.md):

  GET /api/admin/analytics  — full internal snapshot. Admin-only: requires the
      secret `admin_api_token`. Disabled (404) when no token is configured, so
      the numbers are never exposed by accident.

  GET /api/stats/public     — the public "links checked / scams flagged" pair.
      Behind the `public_stats_enabled` feature flag, which is OFF for now, so
      the route 404s until it's deliberately turned on.

Neither route can return anything user-identifying — the store holds only
category counters.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Header, HTTPException, Request

from app.config import get_settings
from app.services.analytics import analytics

router = APIRouter(prefix="/api", tags=["analytics"])

# 404 (not 401/403) when the route is disabled, so we don't advertise that an
# admin surface even exists on this deployment.
_DISABLED = HTTPException(status_code=404, detail="Not Found")


def _require_admin(request: Request, x_admin_token: str | None) -> None:
    settings = get_settings()
    if not settings.admin_analytics_enabled:
        raise _DISABLED
    # Accept the token from a dedicated header or an Authorization: Bearer header.
    presented = x_admin_token
    if presented is None:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
    # Constant-time comparison; a missing/blank token must never match.
    if not presented or not hmac.compare_digest(presented, settings.admin_api_token):
        raise HTTPException(status_code=401, detail="Invalid or missing admin token.")


@router.get("/admin/analytics")
async def admin_analytics(
    request: Request,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> dict:
    """Full aggregate analytics snapshot. Admin token required."""
    _require_admin(request, x_admin_token)
    return await analytics.snapshot()


@router.get("/stats/public")
async def public_stats() -> dict:
    """Public counters. 404 while the `public_stats_enabled` flag is off."""
    if not get_settings().public_stats_enabled:
        raise _DISABLED
    return await analytics.public_counters()
