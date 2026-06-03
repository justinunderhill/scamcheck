"""Google Safe Browsing detection source.

Checks the URL against Google's phishing/malware/unwanted-software lists via the
Safe Browsing v4 `threatMatches:find` endpoint. A match is a strong signal and
maps to a high-severity finding.
"""
from __future__ import annotations

import httpx

from app.config import get_settings
from app.core.urls import NormalizedURL
from app.models import Finding, Severity
from app.models.schemas import SOURCE_GOOGLE
from app.services.base import SourceUnavailable

NAME = SOURCE_GOOGLE
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Map Safe Browsing threat types to plain language for non-technical users.
_THREAT_LABELS = {
    "MALWARE": "harmful software (malware)",
    "SOCIAL_ENGINEERING": "phishing or deception",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful app",
}


def is_configured() -> bool:
    return get_settings().google_safe_browsing_enabled


async def check(url: NormalizedURL, client: httpx.AsyncClient) -> list[Finding]:
    settings = get_settings()
    if not settings.google_safe_browsing_enabled:
        raise SourceUnavailable(NAME, "no API key configured")

    payload = {
        "client": {"clientId": "scamcheck", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": list(_THREAT_LABELS.keys()),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url.url}],
        },
    }
    try:
        resp = await client.post(
            _ENDPOINT, params={"key": settings.google_safe_browsing_key}, json=payload
        )
    except httpx.HTTPError as exc:
        raise SourceUnavailable(NAME, type(exc).__name__) from exc

    if resp.status_code == 429:
        raise SourceUnavailable(NAME, "rate limited")
    if resp.status_code >= 500:
        raise SourceUnavailable(NAME, f"server error {resp.status_code}")
    if resp.status_code != 200:
        raise SourceUnavailable(NAME, f"unexpected status {resp.status_code}")

    matches = resp.json().get("matches", [])
    if not matches:
        return []  # checked, nothing found

    threat_types = {m.get("threatType") for m in matches if m.get("threatType")}
    labels = sorted({_THREAT_LABELS.get(t, "a known threat") for t in threat_types})
    label_text = " and ".join(labels) if labels else "a known threat"
    return [
        Finding(
            source=NAME,
            severity=Severity.HIGH,
            title="Listed on Google's danger list",
            detail=f"Google Safe Browsing lists this link for {label_text}.",
            tip="Google actively tracks dangerous sites. A listing here is a serious warning — don't open it.",
        )
    ]
