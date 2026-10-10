"""POST /api/extract — read the link and message text from a screenshot.

The screenshot is transcribed by the AI layer and the result is handed back to
the client, which then runs a normal POST /api/check on it. Reading never
produces a verdict, so the deterministic sources still own every verdict. The
image is held in memory for this request only: never stored, never logged.
"""
from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, HTTPException, Request

from app.config import (
    SCREENSHOT_MAX_BYTES,
    SCREENSHOT_MEDIA_TYPES,
    SCREENSHOT_READS_PER_DAY,
    get_settings,
)
from app.core.urls import InvalidURLError, normalize_url
from app.models import ScreenshotRequest, ScreenshotResponse
from app.routes.check import _RATE_MSG, _client_ip
from app.services import ai
from app.services.ai.client import AIUnavailable
from app.services.limits import guard

router = APIRouter(prefix="/api", tags=["extract"])

_UNAVAILABLE_MSG = (
    "We can't read screenshots right now. Please type or paste the message instead."
)
_DAILY_MSG = (
    f"You've read {SCREENSHOT_READS_PER_DAY} screenshots today, which is the daily limit. "
    "You can still paste the message or link as text."
)
_BAD_IMAGE_MSG = "That file doesn't look like a picture. Please choose a screenshot (JPG, PNG or WebP)."
_TOO_BIG_MSG = "That picture is too large. Please try a smaller screenshot."
_NOTHING_MSG = (
    "We couldn't find a message or link in that picture. "
    "Try a clearer screenshot, or paste the text instead."
)

# Leading bytes of each accepted format, so a mislabelled upload is rejected.
_MAGIC = {
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/webp": (b"RIFF",),
}


@router.post("/extract", response_model=ScreenshotResponse)
async def extract(request: ScreenshotRequest, http_request: Request) -> ScreenshotResponse:
    settings = get_settings()
    ip = _client_ip(http_request)

    _validate_image(request)

    # Same AI interlock as /api/check: no durable budget store, no AI.
    if not (settings.ai_enabled and (guard.is_durable or settings.ai_allow_without_durable_budget)):
        raise HTTPException(status_code=503, detail=_UNAVAILABLE_MSG)

    if not settings.dev_unlimited:
        if not await guard.allow_request(ip):
            raise HTTPException(status_code=429, detail=_RATE_MSG)
        if not await guard.allow_screenshot_read(ip):
            raise HTTPException(status_code=429, detail=_DAILY_MSG)
    if not await guard.try_consume_ai_budget():
        raise HTTPException(status_code=503, detail=_UNAVAILABLE_MSG)

    try:
        url, message = await ai.read_screenshot(request.image, request.media_type)
    except AIUnavailable as exc:
        raise HTTPException(status_code=503, detail=_UNAVAILABLE_MSG) from exc

    # A link we can't parse (cut off, garbled) is dropped; it's still part of the
    # message text, which message analysis reads.
    if url:
        try:
            normalize_url(url)
        except InvalidURLError:
            url = None
    if not (url or message):
        raise HTTPException(status_code=422, detail=_NOTHING_MSG)
    return ScreenshotResponse(url=url, message=message)


def _validate_image(request: ScreenshotRequest) -> None:
    if request.media_type not in SCREENSHOT_MEDIA_TYPES:
        raise HTTPException(status_code=400, detail=_BAD_IMAGE_MSG)
    # Cheap length check before decoding: base64 is ~4/3 the raw size.
    if len(request.image) > SCREENSHOT_MAX_BYTES * 4 // 3 + 4:
        raise HTTPException(status_code=413, detail=_TOO_BIG_MSG)
    try:
        raw = base64.b64decode(request.image, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=_BAD_IMAGE_MSG) from exc
    if not raw.startswith(_MAGIC[request.media_type]):
        raise HTTPException(status_code=400, detail=_BAD_IMAGE_MSG)
    if request.media_type == "image/webp" and raw[8:12] != b"WEBP":
        raise HTTPException(status_code=400, detail=_BAD_IMAGE_MSG)
