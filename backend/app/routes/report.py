"""POST /api/report — submit a suspected scam link.

v1: validates and acknowledges; storage is stubbed (no DB). The endpoint exists
now so the contract and client are ready; v2 adds durable storage + moderation.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.core.urls import InvalidURLError
from app.models.reports import ScamReportAck, ScamReportRequest
from app.routes.check import _RATE_MSG, _client_ip
from app.services.limits import guard
from app.services.reports import submit_report

router = APIRouter(prefix="/api", tags=["report"])


@router.post("/report", response_model=ScamReportAck)
async def report(request: ScamReportRequest, http_request: Request) -> ScamReportAck:
    if not await guard.allow_request(_client_ip(http_request)):
        raise HTTPException(status_code=429, detail=_RATE_MSG)
    try:
        return await submit_report(request)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
