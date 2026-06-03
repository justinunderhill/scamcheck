"""Unit tests for the AI layer. The Anthropic SDK is never called: we monkeypatch
the `complete` wrapper. Covers caching, escalate-only output handling, JSON
parsing robustness, graceful fallback, and v2 stubs.
"""
from __future__ import annotations

import pytest

from app.models import Finding, Severity, Verdict
from app.services import ai
from app.services.ai.client import AIUnavailable


@pytest.fixture(autouse=True)
def clear_cache():
    ai._explain_cache.clear()
    yield
    ai._explain_cache.clear()


def finding(source="heuristics", severity=Severity.MEDIUM, title="Very new website"):
    return Finding(source=source, severity=severity, title=title, detail="d", tip="t")


# --- explain -------------------------------------------------------------

async def test_explain_returns_text(monkeypatch):
    async def fake_complete(**_kwargs):
        return "This link looks risky. Be careful."

    monkeypatch.setattr(ai, "complete", fake_complete)
    out = await ai.explain(Verdict.SUSPICIOUS, 40, [finding()])
    assert "risky" in out


async def test_explain_is_cached(monkeypatch):
    calls = {"n": 0}

    async def fake_complete(**_kwargs):
        calls["n"] += 1
        return "summary text"

    monkeypatch.setattr(ai, "complete", fake_complete)
    findings = [finding()]
    await ai.explain(Verdict.SUSPICIOUS, 40, findings)
    await ai.explain(Verdict.SUSPICIOUS, 40, findings)  # identical -> cached
    assert calls["n"] == 1


async def test_explain_cache_key_varies_by_verdict(monkeypatch):
    calls = {"n": 0}

    async def fake_complete(**_kwargs):
        calls["n"] += 1
        return "s"

    monkeypatch.setattr(ai, "complete", fake_complete)
    await ai.explain(Verdict.SAFE, 0, [])
    await ai.explain(Verdict.DANGEROUS, 90, [])
    assert calls["n"] == 2


async def test_explain_propagates_unavailable(monkeypatch):
    async def boom(**_kwargs):
        raise AIUnavailable("down")

    monkeypatch.setattr(ai, "complete", boom)
    with pytest.raises(AIUnavailable):
        await ai.explain(Verdict.SAFE, 0, [])


# --- analyze_message -----------------------------------------------------

async def test_analyze_message_parses_findings(monkeypatch):
    async def fake_complete(**_kwargs):
        return (
            '[{"severity":"high","title":"Fake urgency",'
            '"detail":"The message says your account closes in 24 hours.",'
            '"tip":"Real companies rarely demand instant action."}]'
        )

    monkeypatch.setattr(ai, "complete", fake_complete)
    findings = await ai.analyze_message("Your account closes in 24h!", "https://x.example")
    assert len(findings) == 1
    assert findings[0].source == "ai_message_analysis"
    assert findings[0].severity == Severity.HIGH


async def test_analyze_message_tolerates_prose_around_json(monkeypatch):
    async def fake_complete(**_kwargs):
        return 'Here are the findings:\n[{"severity":"medium","title":"Payment pressure","detail":"Asks for gift cards.","tip":"Never pay with gift cards."}]\nDone.'

    monkeypatch.setattr(ai, "complete", fake_complete)
    findings = await ai.analyze_message("pay in gift cards", "https://x.example")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


async def test_analyze_message_caps_count(monkeypatch):
    async def fake_complete(**_kwargs):
        items = ",".join(
            '{"severity":"low","title":"t%d","detail":"d","tip":"x"}' % i for i in range(20)
        )
        return f"[{items}]"

    monkeypatch.setattr(ai, "complete", fake_complete)
    findings = await ai.analyze_message("blah", "https://x.example")
    from app.config import AI_MESSAGE_MAX_FINDINGS

    assert len(findings) == AI_MESSAGE_MAX_FINDINGS


async def test_analyze_message_empty_input_skips(monkeypatch):
    async def fake_complete(**_kwargs):  # pragma: no cover - should not be called
        raise AssertionError("should not call the model for empty input")

    monkeypatch.setattr(ai, "complete", fake_complete)
    assert await ai.analyze_message("   ", "https://x.example") == []


async def test_analyze_message_degrades_to_empty_on_failure(monkeypatch):
    async def boom(**_kwargs):
        raise AIUnavailable("rate limited")

    monkeypatch.setattr(ai, "complete", boom)
    assert await ai.analyze_message("something", "https://x.example") == []


async def test_analyze_message_garbage_output_is_empty(monkeypatch):
    async def fake_complete(**_kwargs):
        return "I could not analyze this."

    monkeypatch.setattr(ai, "complete", fake_complete)
    assert await ai.analyze_message("something", "https://x.example") == []


# --- v2 stubs ------------------------------------------------------------

async def test_v2_stubs_not_implemented():
    with pytest.raises(NotImplementedError):
        await ai.analyze_page(object())
    with pytest.raises(NotImplementedError):
        await ai.followup("what now?", object())
