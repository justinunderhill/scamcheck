"""Smoke tests: the app boots and the /api/check contract holds its shape.

Network is stubbed: heuristics' WHOIS/cert lookups are replaced, and with no
API keys set the external sources report themselves unavailable without any HTTP.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.services import heuristics

client = TestClient(app)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # Heuristics network providers -> safe no-ops (no WHOIS / no TLS dial-out).
    monkeypatch.setattr(heuristics, "lookup_registration_date", lambda domain: None)
    monkeypatch.setattr(
        heuristics,
        "get_cert_info",
        lambda url: heuristics.CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    # No API keys -> external sources are cleanly unavailable, no HTTP attempted.
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_KEY", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_health_ok():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "sources" in body


def test_check_returns_contract_shape():
    resp = client.post("/api/check", json={"url": "https://example.com/login"})
    assert resp.status_code == 200
    body = resp.json()

    for key in (
        "input_url",
        "final_url",
        "verdict",
        "score",
        "summary",
        "findings",
        "sources_checked",
        "sources_unavailable",
    ):
        assert key in body, f"missing contract field: {key}"

    assert body["verdict"] in {"safe", "suspicious", "dangerous"}
    assert 0 <= body["score"] <= 100
    assert "heuristics" in body["sources_checked"]
    # No keys in tests -> external sources + AI summary unavailable; request still succeeds.
    assert set(body["sources_unavailable"]) == {"web_risk", "virustotal", "ai"}
    for finding in body["findings"]:
        assert set(finding) >= {"source", "severity", "title", "detail", "tip"}
        assert finding["severity"] in {"low", "medium", "high"}


def test_check_rejects_missing_url():
    resp = client.post("/api/check", json={})
    assert resp.status_code == 422


def test_check_rejects_malformed_url():
    resp = client.post("/api/check", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 400
    assert resp.json()["detail"]
