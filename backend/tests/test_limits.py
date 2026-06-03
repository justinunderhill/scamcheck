"""Tests for abuse protection (rate limit, daily cap, AI budget) and tier gating."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.services import heuristics
from app.services.limits import AbuseGuard, guard

client = TestClient(app)


@pytest.fixture(autouse=True)
def stub_heuristics_network(monkeypatch):
    monkeypatch.setattr(heuristics, "lookup_registration_date", lambda domain: None)
    monkeypatch.setattr(
        heuristics,
        "get_cert_info",
        lambda url: heuristics.CertInfo(checked=True, present=True, valid=True, expired=False),
    )


# --- AbuseGuard unit -----------------------------------------------------

def test_rate_limit_sliding_window(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 3)
    monkeypatch.setattr(config, "RATE_LIMIT_WINDOW_SECONDS", 60)
    g = AbuseGuard()
    assert all(g.allow_request("1.2.3.4", now=1000.0 + i) for i in range(3))
    assert g.allow_request("1.2.3.4", now=1003.0) is False  # 4th in window
    assert g.allow_request("1.2.3.4", now=1100.0) is True   # window has slid


def test_rate_limit_is_per_ip(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 1)
    g = AbuseGuard()
    assert g.allow_request("a", now=1.0) is True
    assert g.allow_request("a", now=1.0) is False
    assert g.allow_request("b", now=1.0) is True  # different IP unaffected


def test_daily_cap(monkeypatch):
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 2)
    g = AbuseGuard()
    assert g.allow_daily_check("ip") is True
    assert g.allow_daily_check("ip") is True
    assert g.allow_daily_check("ip") is False


def test_ai_budget(monkeypatch):
    monkeypatch.setattr(config, "AI_DAILY_CALL_CAP", 1)
    g = AbuseGuard()
    assert g.try_consume_ai_budget() is True
    assert g.try_consume_ai_budget() is False


# --- Route-level enforcement --------------------------------------------

def test_daily_cap_returns_friendly_429(monkeypatch):
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 2)
    guard.reset()
    for _ in range(2):
        assert client.post("/api/check", json={"url": "https://example.com"}).status_code == 200
    resp = client.post("/api/check", json={"url": "https://example.com"})
    assert resp.status_code == 429
    assert "free checks" in resp.json()["detail"].lower()


def test_rate_limit_returns_friendly_429(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 1000)  # don't trip the daily cap
    guard.reset()
    for _ in range(2):
        assert client.post("/api/check", json={"url": "https://example.com"}).status_code == 200
    resp = client.post("/api/check", json={"url": "https://example.com"})
    assert resp.status_code == 429
    assert "too quickly" in resp.json()["detail"].lower()


def test_paid_tier_bypasses_daily_cap(monkeypatch):
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 1)
    guard.reset()
    headers = {"X-ScamCheck-Tier": "paid"}
    # Well beyond the free daily cap, all allowed for paid.
    for _ in range(4):
        assert client.post("/api/check", json={"url": "https://example.com"}, headers=headers).status_code == 200


def test_free_tier_ignores_message(monkeypatch):
    guard.reset()
    resp = client.post("/api/check", json={"url": "https://example.com", "message": "hi"})
    body = resp.json()
    assert "ai_message_analysis" not in body["sources_checked"]
    assert "ai_message_analysis" not in body["sources_unavailable"]


def test_paid_tier_attempts_message_analysis(monkeypatch):
    guard.reset()
    # Paid tier enables message analysis, but with no ANTHROPIC key it's recorded
    # as unavailable (gating worked; the call just couldn't run).
    resp = client.post(
        "/api/check",
        json={"url": "https://example.com", "message": "Pay now!"},
        headers={"X-ScamCheck-Tier": "paid"},
    )
    body = resp.json()
    assert "ai_message_analysis" in body["sources_unavailable"]
