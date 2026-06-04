"""Tests for internal analytics: the recorder, the store, and the routes.

The store is mocked everywhere — `MemoryAnalyticsStore` for inspection, a tiny
broken store for the best-effort guarantee, and `respx` for the Redis REST
transport. No test ever touches a real network or KV.
"""
from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.services import analytics as analytics_mod
from app.services import heuristics
from app.services.analytics import (
    Analytics,
    K_AI_RAN,
    K_AI_TEMPLATE,
    K_CAP_AI,
    K_CAP_FREE,
    K_CHECKS_TOTAL,
    MemoryAnalyticsStore,
    RedisAnalyticsStore,
    analytics,
    checks_day_key,
    heuristic_key,
    source_key,
    verdict_key,
)
from app.models.schemas import SOURCE_AI, SOURCE_VIRUSTOTAL, SOURCE_WEB_RISK

client = TestClient(app)


# --- Recorder (Analytics) -----------------------------------------------

async def test_record_check_counts_every_dimension():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_check(
        verdict="dangerous",
        heuristic_codes=["raw_ip", "no_https"],
        sources_checked=[SOURCE_WEB_RISK, "heuristics"],
        sources_unavailable=[SOURCE_VIRUSTOTAL],
        ai_cap_hit=False,
    )
    c = store.counts
    assert c[K_CHECKS_TOTAL] == 1
    assert c[checks_day_key(analytics_mod._today())] == 1
    assert c[verdict_key("dangerous")] == 1
    assert c[heuristic_key("raw_ip")] == 1
    assert c[heuristic_key("no_https")] == 1
    # External source availability tracked from the checked/unavailable lists.
    assert c[source_key(SOURCE_WEB_RISK, True)] == 1
    assert c[source_key(SOURCE_VIRUSTOTAL, False)] == 1
    # AI ran (the `ai` source was NOT in sources_unavailable).
    assert c[K_AI_RAN] == 1
    assert K_AI_TEMPLATE not in c


async def test_record_check_template_fallback_and_ai_cap():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_check(
        verdict="safe",
        heuristic_codes=[],
        sources_checked=["heuristics"],
        sources_unavailable=[SOURCE_AI],  # AI summary fell back to a template
        ai_cap_hit=True,
    )
    c = store.counts
    assert c[K_AI_TEMPLATE] == 1
    assert K_AI_RAN not in c
    assert c[K_CAP_AI] == 1


async def test_record_check_dedupes_repeated_heuristic_codes():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_check(
        verdict="suspicious",
        heuristic_codes=["embedded_credentials", "embedded_credentials"],
        sources_checked=["heuristics"],
        sources_unavailable=[],
        ai_cap_hit=False,
    )
    assert store.counts[heuristic_key("embedded_credentials")] == 1


async def test_record_free_cap_hit():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_free_cap_hit()
    await rec.record_free_cap_hit()
    assert store.counts[K_CAP_FREE] == 2


async def test_recording_is_best_effort_on_store_error():
    class BrokenStore:
        async def apply(self, increments):
            raise RuntimeError("kv down")

        async def get_many(self, keys):
            raise RuntimeError("kv down")

        def reset(self):
            pass

    rec = Analytics(BrokenStore())
    # Must not raise — a dead store can never break the user's result.
    await rec.record_check(
        verdict="safe",
        heuristic_codes=["raw_ip"],
        sources_checked=["heuristics"],
        sources_unavailable=[],
        ai_cap_hit=False,
    )
    await rec.record_free_cap_hit()
    assert await rec.snapshot()  # snapshot also swallows the error, returns zeros
    assert (await rec.public_counters())["links_checked"] == 0


async def test_count_dont_log_no_url_or_message_in_keys():
    # The recorder is only ever handed categories, never the URL/message. Assert
    # every key written is from the fixed namespace and contains no free text.
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_check(
        verdict="dangerous",
        heuristic_codes=list(heuristics.HEURISTIC_CODES),
        sources_checked=[SOURCE_WEB_RISK],
        sources_unavailable=[SOURCE_VIRUSTOTAL, SOURCE_AI],
        ai_cap_hit=True,
    )
    # Every key must be a known category counter — built only from fixed tokens
    # (verdicts, heuristic codes, source names), never free text from the input.
    allowed = {
        K_CHECKS_TOTAL,
        checks_day_key(analytics_mod._today()),
        K_AI_RAN,
        K_AI_TEMPLATE,
        K_CAP_AI,
        K_CAP_FREE,
        *(verdict_key(v) for v in ("safe", "suspicious", "dangerous")),
        *(heuristic_key(c) for c in heuristics.HEURISTIC_CODES),
        *(source_key(n, a) for n in (SOURCE_WEB_RISK, SOURCE_VIRUSTOTAL) for a in (True, False)),
    }
    for key in store.counts:
        assert key.startswith(config.ANALYTICS_KEY_PREFIX)
        assert key in allowed  # no URL/host/message fragment can ever appear
        assert "://" not in key


# --- Snapshot / public counters -----------------------------------------

async def test_snapshot_shape_and_values():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    await rec.record_check(
        verdict="suspicious",
        heuristic_codes=["lookalike"],
        sources_checked=[SOURCE_WEB_RISK, SOURCE_VIRUSTOTAL],
        sources_unavailable=[],
        ai_cap_hit=False,
    )
    snap = await rec.snapshot()
    assert snap["checks"]["total"] == 1
    assert snap["checks"]["today"] == 1
    assert snap["verdicts"] == {"safe": 0, "suspicious": 1, "dangerous": 0}
    assert snap["heuristics"]["lookalike"] == 1
    # Every heuristic name is present (zero when it never fired).
    assert set(snap["heuristics"]) == set(heuristics.HEURISTIC_CODES)
    assert snap["sources"][SOURCE_WEB_RISK]["available"] == 1
    assert snap["ai"]["ran"] == 1


async def test_public_counters_derived_from_same_data():
    store = MemoryAnalyticsStore()
    rec = Analytics(store)
    for verdict in ("safe", "suspicious", "dangerous", "dangerous"):
        await rec.record_check(
            verdict=verdict,
            heuristic_codes=[],
            sources_checked=["heuristics"],
            sources_unavailable=[],
            ai_cap_hit=False,
        )
    pub = await rec.public_counters()
    assert pub["links_checked"] == 4
    assert pub["scams_flagged"] == 3  # 1 suspicious + 2 dangerous


# --- RedisAnalyticsStore (Upstash REST, mocked) -------------------------

@respx.mock
async def test_redis_store_pipelines_incrby_and_expire():
    route = respx.post("https://kv.example/pipeline").mock(
        return_value=httpx.Response(200, json=[{"result": 1}, {"result": 1}, {"result": 5}])
    )
    store = RedisAnalyticsStore("https://kv.example", "tok")
    await store.apply(
        [
            (K_CHECKS_TOTAL, 1, None),               # all-time -> no EXPIRE
            (checks_day_key("2026-06-04"), 1, 999),  # day key -> INCRBY + EXPIRE NX
        ]
    )
    assert route.called
    sent = route.calls.last.request
    body = sent.content.decode()
    assert "INCRBY" in body and "EXPIRE" in body


@respx.mock
async def test_redis_store_get_many_reads_values():
    respx.post("https://kv.example/pipeline").mock(
        return_value=httpx.Response(200, json=[{"result": "7"}, {"result": None}])
    )
    store = RedisAnalyticsStore("https://kv.example", "tok")
    out = await store.get_many([K_CHECKS_TOTAL, K_CAP_FREE])
    assert out[K_CHECKS_TOTAL] == 7
    assert out[K_CAP_FREE] == 0  # missing key -> 0


# --- Admin route ---------------------------------------------------------

def test_admin_route_disabled_without_token(monkeypatch):
    # No admin token configured -> route is 404 (existence not advertised).
    resp = client.get("/api/admin/analytics")
    assert resp.status_code == 404


def test_admin_route_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "s3cret")
    config.get_settings.cache_clear()
    assert client.get("/api/admin/analytics").status_code == 401
    assert client.get(
        "/api/admin/analytics", headers={"X-Admin-Token": "nope"}
    ).status_code == 401


def test_admin_route_accepts_correct_token(monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "s3cret")
    config.get_settings.cache_clear()
    # Header form.
    resp = client.get("/api/admin/analytics", headers={"X-Admin-Token": "s3cret"})
    assert resp.status_code == 200
    assert "checks" in resp.json() and "verdicts" in resp.json()
    # Bearer form also works.
    resp2 = client.get(
        "/api/admin/analytics", headers={"Authorization": "Bearer s3cret"}
    )
    assert resp2.status_code == 200


# --- Public stats route (feature-flagged) -------------------------------

def test_public_stats_404_when_flag_off():
    # Default config has the flag off.
    assert client.get("/api/stats/public").status_code == 404


def test_public_stats_200_when_flag_on(monkeypatch):
    monkeypatch.setenv("PUBLIC_STATS_ENABLED", "true")
    config.get_settings.cache_clear()
    resp = client.get("/api/stats/public")
    assert resp.status_code == 200
    assert set(resp.json()) == {"links_checked", "scams_flagged"}


# --- Route-level integration --------------------------------------------

def test_successful_check_increments_counters(monkeypatch):
    monkeypatch.setattr(heuristics, "lookup_registration_date", lambda d: None)
    monkeypatch.setattr(
        heuristics,
        "get_cert_info",
        lambda url: heuristics.CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    store = MemoryAnalyticsStore()
    analytics.configure(store)
    assert client.post("/api/check", json={"url": "https://example.com"}).status_code == 200
    c = store.counts
    assert c[K_CHECKS_TOTAL] == 1
    assert c[verdict_key("safe")] == 1
    # No external keys configured in tests -> both blocklists recorded unavailable.
    assert c[source_key(SOURCE_WEB_RISK, False)] == 1
    assert c[source_key(SOURCE_VIRUSTOTAL, False)] == 1
    # No AI key -> template fallback.
    assert c[K_AI_TEMPLATE] == 1


def test_free_cap_hit_is_counted(monkeypatch):
    monkeypatch.setattr(config, "FREE_TIER_CHECKS_PER_DAY", 1)
    monkeypatch.setattr(heuristics, "lookup_registration_date", lambda d: None)
    monkeypatch.setattr(
        heuristics,
        "get_cert_info",
        lambda url: heuristics.CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    store = MemoryAnalyticsStore()
    analytics.configure(store)
    assert client.post("/api/check", json={"url": "https://example.com"}).status_code == 200
    assert client.post("/api/check", json={"url": "https://example.com"}).status_code == 429
    assert store.counts[K_CAP_FREE] == 1
    assert store.counts[K_CHECKS_TOTAL] == 1  # the rejected request wasn't counted


def test_invalid_input_not_counted(monkeypatch):
    store = MemoryAnalyticsStore()
    analytics.configure(store)
    assert client.post("/api/check", json={"url": "not a url"}).status_code == 400
    assert store.counts.get(K_CHECKS_TOTAL, 0) == 0
