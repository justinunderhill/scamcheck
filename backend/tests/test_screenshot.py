"""Screenshot reading (POST /api/extract) and message-only checks.

The AI layer is stubbed throughout; nothing here calls Anthropic.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import config
from app.config import get_settings
from app.main import app
from app.models import CheckRequest, Finding, Severity, Verdict
from app.services import ai, pipeline
from app.services.ai.client import AIUnavailable
from app.services.limits import guard

client = TestClient(app)

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode()
JPEG = base64.b64encode(b"\xff\xd8\xff\xe0" + b"\x00" * 64).decode()


@pytest.fixture
def with_ai(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("AI_ALLOW_WITHOUT_DURABLE_BUDGET", "true")
    get_settings.cache_clear()
    guard.reset()
    yield
    guard.reset()
    get_settings.cache_clear()


def _fake_reader(url, message):
    async def fake(image_b64, media_type):
        return url, message

    return fake


# --- request contract -------------------------------------------------------

def test_check_request_needs_a_link_or_a_message():
    with pytest.raises(ValidationError):
        CheckRequest(url="  ", message="")
    assert CheckRequest(url="example.com").message is None
    assert CheckRequest(message="Hi Mum, new number").url is None


def test_message_only_floor_matches_suspicious_threshold():
    assert config.MESSAGE_ONLY_MIN_SCORE == config.SCORE_SUSPICIOUS_THRESHOLD


# --- message-only pipeline ---------------------------------------------------

async def test_message_only_clean_wording_is_never_safe(with_ai, monkeypatch):
    async def no_findings(message, final_url):
        assert final_url is None
        return []

    async def fake_explain(verdict, score, findings, **kwargs):
        assert kwargs.get("message_only") is True
        return "summary"

    monkeypatch.setattr(pipeline.ai, "analyze_message", no_findings)
    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)

    result = await pipeline.analyze(None, message="Dinner at 7?", allow_message_analysis=True)

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == config.MESSAGE_ONLY_MIN_SCORE
    assert result.input_url is None and result.final_url is None
    assert result.sources_checked == ["ai_message_analysis"]
    assert [f.title for f in result.findings] == ["We could only check the wording"]


async def test_message_only_scam_escalates_without_scope_note(with_ai, monkeypatch):
    async def scam(message, final_url):
        return [
            Finding(source="ai_message_analysis", severity=Severity.HIGH, title=t, detail="d", tip="t")
            for t in ("Impersonating family", "Asks for money")
        ]

    async def fake_explain(verdict, score, findings, **kwargs):
        return "summary"

    monkeypatch.setattr(pipeline.ai, "analyze_message", scam)
    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)

    result = await pipeline.analyze(None, message="Hi Mum, pay this", allow_message_analysis=True)

    assert result.verdict is Verdict.DANGEROUS
    assert all(f.title != "We could only check the wording" for f in result.findings)


async def test_message_only_with_ai_down_says_nothing_was_checked(with_ai, monkeypatch):
    async def down(message, final_url):
        raise AIUnavailable("down")

    monkeypatch.setattr(pipeline.ai, "analyze_message", down)

    result = await pipeline.analyze(None, message="Hi Mum", allow_message_analysis=True)

    assert result.verdict is not Verdict.SAFE
    assert "ai_message_analysis" in result.sources_unavailable
    assert "ai" in result.sources_unavailable
    assert any(f.title == "We couldn't check your message" for f in result.findings)


def test_check_endpoint_accepts_message_only(with_ai, monkeypatch):
    async def no_findings(message, final_url):
        return []

    async def fake_explain(verdict, score, findings, **kwargs):
        return "summary"

    monkeypatch.setattr(pipeline.ai, "analyze_message", no_findings)
    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)

    resp = client.post("/api/check", json={"message": "Hi Mum, new number"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["input_url"] is None
    assert body["verdict"] == "suspicious"


def test_check_endpoint_rejects_empty_request():
    assert client.post("/api/check", json={}).status_code == 422


# --- screenshot reading ------------------------------------------------------

async def test_read_screenshot_parses_json_and_passes_image(monkeypatch):
    seen = {}

    async def fake_complete(**kwargs):
        seen.update(kwargs)
        return 'Here you go: {"url": "https://paypa1.com/login", "message": "Your account is locked", "x": 1}'

    monkeypatch.setattr(ai, "complete", fake_complete)
    url, message = await ai.read_screenshot("QUJD", "image/png")

    assert (url, message) == ("https://paypa1.com/login", "Your account is locked")
    assert seen["images"] == [("image/png", "QUJD")]


async def test_read_screenshot_treats_null_and_blank_as_missing(monkeypatch):
    async def fake_complete(**kwargs):
        return '{"url": "null", "message": "  "}'

    monkeypatch.setattr(ai, "complete", fake_complete)
    assert await ai.read_screenshot("QUJD", "image/png") == (None, None)


def test_extract_returns_what_was_read(with_ai, monkeypatch):
    monkeypatch.setattr(ai, "read_screenshot", _fake_reader("https://example.com/x", "Pay now"))
    resp = client.post("/api/extract", json={"image": PNG, "media_type": "image/png"})
    assert resp.status_code == 200
    assert resp.json() == {"url": "https://example.com/x", "message": "Pay now"}


def test_extract_drops_an_unparseable_link(with_ai, monkeypatch):
    monkeypatch.setattr(ai, "read_screenshot", _fake_reader("http://", "Tap the link"))
    resp = client.post("/api/extract", json={"image": JPEG, "media_type": "image/jpeg"})
    assert resp.status_code == 200
    assert resp.json() == {"url": None, "message": "Tap the link"}


def test_extract_with_nothing_readable_is_a_friendly_error(with_ai, monkeypatch):
    monkeypatch.setattr(ai, "read_screenshot", _fake_reader(None, None))
    resp = client.post("/api/extract", json={"image": PNG, "media_type": "image/png"})
    assert resp.status_code == 422
    assert "couldn't find" in resp.json()["detail"]


@pytest.mark.parametrize(
    "payload",
    [
        {"image": PNG, "media_type": "image/gif"},  # type not accepted
        {"image": JPEG, "media_type": "image/png"},  # label doesn't match bytes
        {"image": "not base64!!", "media_type": "image/png"},
    ],
)
def test_extract_rejects_bad_images(with_ai, monkeypatch, payload):
    monkeypatch.setattr(ai, "read_screenshot", _fake_reader("https://example.com", None))
    assert client.post("/api/extract", json=payload).status_code == 400


def test_extract_rejects_oversized_images(with_ai):
    big = "A" * (config.SCREENSHOT_MAX_BYTES * 2)
    assert client.post("/api/extract", json={"image": big, "media_type": "image/png"}).status_code == 413


def test_extract_unavailable_when_ai_fails(with_ai, monkeypatch):
    async def down(image_b64, media_type):
        raise AIUnavailable("down")

    monkeypatch.setattr(ai, "read_screenshot", down)
    resp = client.post("/api/extract", json={"image": PNG, "media_type": "image/png"})
    assert resp.status_code == 503


def test_extract_unavailable_without_ai_interlock(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("AI_ALLOW_WITHOUT_DURABLE_BUDGET", raising=False)
    get_settings.cache_clear()
    try:
        resp = client.post("/api/extract", json={"image": PNG, "media_type": "image/png"})
    finally:
        get_settings.cache_clear()
    assert resp.status_code == 503


def test_extract_daily_cap(with_ai, monkeypatch):
    monkeypatch.setattr(ai, "read_screenshot", _fake_reader("https://example.com", None))
    monkeypatch.setattr(config, "RATE_LIMIT_REQUESTS", 1000)
    payload = {"image": PNG, "media_type": "image/png"}
    for _ in range(config.SCREENSHOT_READS_PER_DAY):
        assert client.post("/api/extract", json=payload).status_code == 200
    assert client.post("/api/extract", json=payload).status_code == 429
