"""Tests for the external detection sources. All HTTP is mocked via respx."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.config import get_settings
from app.core.urls import normalize_url
from app.models import Severity
from app.services import google_safe_browsing as gsb
from app.services import virustotal as vt
from app.services import web_risk
from app.services.base import SourceUnavailable


@pytest.fixture
def with_keys(monkeypatch):
    """Configure both API keys and reset the settings cache."""
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "test-gsb-key")
    monkeypatch.setenv("VIRUSTOTAL_KEY", "test-vt-key")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def no_keys(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_KEY", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --- Google Safe Browsing ------------------------------------------------

@respx.mock
async def test_gsb_match_is_high(with_keys):
    respx.route(method="POST", host="safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    )
    async with httpx.AsyncClient() as client:
        findings = await gsb.check(normalize_url("https://evil.example"), client)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "google_safe_browsing"


@respx.mock
async def test_gsb_clean_is_empty(with_keys):
    respx.route(method="POST", host="safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json={})
    )
    async with httpx.AsyncClient() as client:
        findings = await gsb.check(normalize_url("https://example.com"), client)
    assert findings == []


@respx.mock
async def test_gsb_rate_limited_raises(with_keys):
    respx.route(method="POST", host="safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(429)
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceUnavailable):
            await gsb.check(normalize_url("https://example.com"), client)


async def test_gsb_unconfigured_raises(no_keys):
    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceUnavailable):
            await gsb.check(normalize_url("https://example.com"), client)


# --- Google Web Risk -----------------------------------------------------

@respx.mock
async def test_web_risk_threat_is_high(with_keys):
    respx.route(method="GET", host="webrisk.googleapis.com").mock(
        return_value=httpx.Response(200, json={"threat": {"threatTypes": ["MALWARE"]}})
    )
    async with httpx.AsyncClient() as client:
        findings = await web_risk.check(normalize_url("https://evil.example"), client)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "web_risk"


@respx.mock
async def test_web_risk_clean_is_empty(with_keys):
    respx.route(method="GET", host="webrisk.googleapis.com").mock(
        return_value=httpx.Response(200, json={})
    )
    async with httpx.AsyncClient() as client:
        findings = await web_risk.check(normalize_url("https://example.com"), client)
    assert findings == []


@respx.mock
async def test_web_risk_403_raises(with_keys):
    # API not enabled / key restricted -> unavailable, never crashes the request.
    respx.route(method="GET", host="webrisk.googleapis.com").mock(
        return_value=httpx.Response(403)
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceUnavailable):
            await web_risk.check(normalize_url("https://example.com"), client)


async def test_web_risk_uses_safe_browsing_key_fallback(monkeypatch):
    # Only the Safe Browsing key is set; Web Risk should still be configured.
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "shared-google-key")
    monkeypatch.delenv("WEB_RISK_KEY", raising=False)
    get_settings.cache_clear()
    try:
        assert web_risk.is_configured() is True
    finally:
        get_settings.cache_clear()


# --- VirusTotal ----------------------------------------------------------

@respx.mock
async def test_vt_many_malicious_is_high(with_keys):
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}}}},
        )
    )
    async with httpx.AsyncClient() as client:
        findings = await vt.check(normalize_url("https://evil.example"), client)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "6" in findings[0].detail  # 5 malicious + 1 suspicious flagged


@respx.mock
async def test_vt_suspicious_only_is_medium(with_keys):
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 2}}}}
        )
    )
    async with httpx.AsyncClient() as client:
        findings = await vt.check(normalize_url("https://example.com"), client)
    assert findings[0].severity == Severity.MEDIUM


@respx.mock
async def test_vt_clean_is_empty(with_keys):
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}}}
        )
    )
    async with httpx.AsyncClient() as client:
        findings = await vt.check(normalize_url("https://example.com"), client)
    assert findings == []


@respx.mock
async def test_vt_unseen_submits_and_returns_empty(with_keys):
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(404)
    )
    submit = respx.post("https://www.virustotal.com/api/v3/urls").mock(
        return_value=httpx.Response(200, json={"data": {"id": "x"}})
    )
    async with httpx.AsyncClient() as client:
        findings = await vt.check(normalize_url("https://brand-new.example"), client)
    assert findings == []
    assert submit.called


@respx.mock
async def test_vt_auth_rejected_raises(with_keys):
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(401)
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(SourceUnavailable):
            await vt.check(normalize_url("https://example.com"), client)
