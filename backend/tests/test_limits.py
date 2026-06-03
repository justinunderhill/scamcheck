"""Tests for abuse protection (rate limit, daily cap, AI budget) and tier gating."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import httpx
import respx

from app import config
from app.main import app
from app.services import heuristics
from app.services.limits import AbuseGuard, MemoryAbuseStore, RedisAbuseStore, guard

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

async def test_rate_limit_blocks_over_threshold(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 3)
    g = AbuseGuard(MemoryAbuseStore())
    # All within the same fixed window (same second).
    assert all([await g.allow_request("1.2.3.4") for _ in range(3)])
    assert await g.allow_request("1.2.3.4") is False  # 4th over the limit


async def test_rate_limit_is_per_ip(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 1)
    g = AbuseGuard(MemoryAbuseStore())
    assert await g.allow_request("a") is True
    assert await g.allow_request("a") is False
    assert await g.allow_request("b") is True  # different IP unaffected


async def test_daily_cap(monkeypatch):
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 2)
    g = AbuseGuard(MemoryAbuseStore())
    assert await g.allow_daily_check("ip") is True
    assert await g.allow_daily_check("ip") is True
    assert await g.allow_daily_check("ip") is False


async def test_ai_budget(monkeypatch):
    monkeypatch.setattr(config, "AI_DAILY_CALL_CAP", 1)
    g = AbuseGuard(MemoryAbuseStore())
    assert await g.try_consume_ai_budget() is True
    assert await g.try_consume_ai_budget() is False


async def test_memory_store_expiry(monkeypatch):
    import app.services.limits as limits

    store = MemoryAbuseStore()
    monkeypatch.setattr(limits.time, "time", lambda: 1000.0)
    assert await store.incr("k", 60) == 1
    assert await store.incr("k", 60) == 2
    monkeypatch.setattr(limits.time, "time", lambda: 1100.0)  # past ttl
    assert await store.incr("k", 60) == 1  # counter reset after expiry


def test_memory_guard_is_not_durable():
    assert AbuseGuard(MemoryAbuseStore()).is_durable is False
    assert AbuseGuard(RedisAbuseStore("https://x", "t")).is_durable is True


# --- RedisAbuseStore (Upstash REST, mocked) ------------------------------

@respx.mock
async def test_redis_store_incr_pipeline():
    route = respx.post("https://redis.example/pipeline").mock(
        return_value=httpx.Response(200, json=[{"result": 7}, {"result": 1}])
    )
    store = RedisAbuseStore("https://redis.example", "tok")
    assert await store.incr("ai:2026-06-03", 86400) == 7
    assert route.called


async def test_ai_budget_fails_closed_on_store_error():
    class BrokenStore:
        async def incr(self, key, ttl_seconds):
            raise RuntimeError("redis down")

        def reset(self):
            pass

    g = AbuseGuard(BrokenStore())
    # AI budget must fail CLOSED (protect the bill); rate/daily fail OPEN.
    assert await g.try_consume_ai_budget() is False
    assert await g.allow_request("ip") is True
    assert await g.allow_daily_check("ip") is True


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


def test_ai_interlock_off_without_durable_store(monkeypatch):
    # Key present but no durable store + interlock not overridden -> AI stays off.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    config.get_settings.cache_clear()
    guard.configure(MemoryAbuseStore())  # not durable
    resp = client.post("/api/check", json={"url": "https://example.com"})
    body = resp.json()
    assert "ai" in body["sources_unavailable"]  # AI not active -> template summary


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
