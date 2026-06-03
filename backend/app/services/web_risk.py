"""Google Web Risk detection source.

Web Risk is Google's current URL-blocklist API (the modern replacement for the
legacy Safe Browsing v4 lookup). Uses the Lookup `uris:search` endpoint: a GET
with the URL and the threat types we care about. A hit is a strong signal and
maps to a high-severity finding.
"""
from __future__ import annotations

import httpx

from app.config import get_settings
from app.core.urls import NormalizedURL
from app.models import Finding, Severity
from app.models.schemas import SOURCE_WEB_RISK
from app.services.base import SourceUnavailable

NAME = SOURCE_WEB_RISK
_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"

_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
_THREAT_LABELS = {
    "MALWARE": "harmful software (malware)",
    "SOCIAL_ENGINEERING": "phishing or deception",
    "UNWANTED_SOFTWARE": "unwanted software",
}


def is_configured() -> bool:
    return get_settings().web_risk_enabled


async def check(url: NormalizedURL, client: httpx.AsyncClient) -> list[Finding]:
    settings = get_settings()
    if not settings.web_risk_enabled:
        raise SourceUnavailable(NAME, "no API key configured")

    params = [("key", settings.web_risk_effective_key), ("uri", url.url)]
    params += [("threatTypes", t) for t in _THREAT_TYPES]
    try:
        resp = await client.get(_ENDPOINT, params=params)
    except httpx.HTTPError as exc:
        raise SourceUnavailable(NAME, type(exc).__name__) from exc

    if resp.status_code == 429:
        raise SourceUnavailable(NAME, "rate limited")
    if resp.status_code in (401, 403):
        raise SourceUnavailable(NAME, "auth rejected or API not enabled")
    if resp.status_code >= 500:
        raise SourceUnavailable(NAME, f"server error {resp.status_code}")
    if resp.status_code != 200:
        raise SourceUnavailable(NAME, f"unexpected status {resp.status_code}")

    threat = resp.json().get("threat")
    if not threat:
        return []  # checked, nothing found

    types = threat.get("threatTypes", []) or []
    labels = sorted({_THREAT_LABELS.get(t, "a known threat") for t in types})
    label_text = " and ".join(labels) if labels else "a known threat"
    return [
        Finding(
            source=NAME,
            severity=Severity.HIGH,
            title="Listed on Google's danger list",
            detail=f"Google Web Risk lists this link for {label_text}.",
            tip="Google actively tracks dangerous sites. A listing here is a serious warning — don't open it.",
        )
    ]
