"""VirusTotal detection source.

Reads VirusTotal's aggregated engine verdicts for the URL (v3 API). We look up
the existing report by URL id; if VirusTotal hasn't seen the URL yet, we submit
it for future analysis and report no verdict this time (rather than blocking the
user on a fresh scan). Many engines flagging = push hard toward dangerous.
"""
from __future__ import annotations

import base64

import httpx

from app.config import get_settings
from app.core.urls import NormalizedURL
from app.models import Finding, Severity
from app.models.schemas import SOURCE_VIRUSTOTAL
from app.services.base import SourceUnavailable

NAME = SOURCE_VIRUSTOTAL
_BASE = "https://www.virustotal.com/api/v3"

# Engine counts at/above which we raise severity.
_MALICIOUS_HIGH = 2     # >=2 engines call it malicious -> high
_MALICIOUS_MEDIUM = 1   # 1 engine malicious, or suspicious only -> medium


def is_configured() -> bool:
    return get_settings().virustotal_enabled


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def check(url: NormalizedURL, client: httpx.AsyncClient) -> list[Finding]:
    settings = get_settings()
    if not settings.virustotal_enabled:
        raise SourceUnavailable(NAME, "no API key configured")

    headers = {"x-apikey": settings.virustotal_key}
    try:
        resp = await client.get(f"{_BASE}/urls/{_url_id(url.url)}", headers=headers)
    except httpx.HTTPError as exc:
        raise SourceUnavailable(NAME, type(exc).__name__) from exc

    if resp.status_code == 404:
        # Not seen before — submit for analysis so it's ready next time, then
        # report no verdict for now. Submission failure is non-fatal.
        try:
            await client.post(f"{_BASE}/urls", headers=headers, data={"url": url.url})
        except httpx.HTTPError:
            pass
        return []

    if resp.status_code in (401, 403):
        raise SourceUnavailable(NAME, "auth rejected")
    if resp.status_code == 429:
        raise SourceUnavailable(NAME, "rate limited")
    if resp.status_code >= 500:
        raise SourceUnavailable(NAME, f"server error {resp.status_code}")
    if resp.status_code != 200:
        raise SourceUnavailable(NAME, f"unexpected status {resp.status_code}")

    stats = (
        resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    )
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious == 0 and suspicious == 0:
        return []

    flagged = malicious + suspicious
    if malicious >= _MALICIOUS_HIGH:
        severity = Severity.HIGH
    elif malicious >= _MALICIOUS_MEDIUM or suspicious >= 1:
        severity = Severity.MEDIUM
    else:  # pragma: no cover - covered by the early return above
        return []

    vendor_word = "security vendor" if flagged == 1 else "security vendors"
    return [
        Finding(
            source=NAME,
            severity=severity,
            title="Flagged by security vendors",
            detail=f"{flagged} {vendor_word} on VirusTotal flagged this link as harmful.",
            tip="VirusTotal pools dozens of security engines. Several flags mean you should stay away.",
        )
    ]
