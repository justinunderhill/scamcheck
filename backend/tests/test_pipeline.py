"""End-to-end pipeline tests: concurrency, aggregation, graceful degradation.

All network is mocked (respx) or stubbed (heuristics providers monkeypatched).
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.config import get_settings
from app.models import Verdict
from app.services import heuristics
from app.services import pipeline


@pytest.fixture(autouse=True)
def stub_heuristics_network(monkeypatch):
    monkeypatch.setattr(heuristics, "lookup_registration_date", lambda domain: None)
    monkeypatch.setattr(
        heuristics,
        "get_cert_info",
        lambda url: heuristics.CertInfo(checked=True, present=True, valid=True, expired=False),
    )


@pytest.fixture
def with_keys(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "k")
    monkeypatch.setenv("VIRUSTOTAL_KEY", "k")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _mock_web_risk(matches: bool):
    body = {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}} if matches else {}
    respx.route(method="GET", host="webrisk.googleapis.com").mock(
        return_value=httpx.Response(200, json=body)
    )


def _mock_vt_clean():
    respx.route(method="GET", url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
        )
    )


@respx.mock
async def test_web_risk_hit_makes_verdict_dangerous(with_keys):
    _mock_web_risk(True)
    _mock_vt_clean()

    result = await pipeline.analyze("https://totally-legit-bank.example/login")

    assert result.verdict is Verdict.DANGEROUS
    assert result.score >= 70
    assert set(result.sources_checked) == {"heuristics", "web_risk", "virustotal"}
    # No ANTHROPIC key in `with_keys` -> AI summary falls back to template.
    assert result.sources_unavailable == ["ai"]
    assert any(f.source == "web_risk" for f in result.findings)


@respx.mock
async def test_graceful_degradation_one_source_down(with_keys):
    # Web Risk errors; VT still answers. Request must still succeed.
    respx.route(method="GET", host="webrisk.googleapis.com").mock(
        return_value=httpx.Response(503)
    )
    _mock_vt_clean()

    result = await pipeline.analyze("https://example.com")

    assert "web_risk" in result.sources_unavailable
    assert "virustotal" in result.sources_checked
    assert "heuristics" in result.sources_checked


async def test_no_keys_both_external_unavailable(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    monkeypatch.delenv("WEB_RISK_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_KEY", raising=False)
    get_settings.cache_clear()
    try:
        result = await pipeline.analyze("https://example.com")
    finally:
        get_settings.cache_clear()

    assert set(result.sources_unavailable) == {"web_risk", "virustotal", "ai"}
    assert result.sources_checked == ["heuristics"]


@respx.mock
async def test_shortener_is_expanded_and_flagged(with_keys):
    final = "https://destination.example/page"
    respx.head("https://bit.ly/abc").mock(
        return_value=httpx.Response(301, headers={"location": final})
    )
    respx.head(final).mock(return_value=httpx.Response(200))
    _mock_web_risk(False)
    _mock_vt_clean()

    result = await pipeline.analyze("https://bit.ly/abc")

    assert result.final_url == final
    assert any(f.title == "Shortened link" for f in result.findings)


@respx.mock
async def test_dangerous_summary_is_template_without_ai(with_keys):
    _mock_web_risk(True)
    _mock_vt_clean()
    # No ANTHROPIC key in `with_keys` -> AI summary falls back to template.
    result = await pipeline.analyze("https://evil.example")
    assert result.summary
    assert result.verdict is Verdict.DANGEROUS
    assert "ai" in result.sources_unavailable


@respx.mock
async def test_email_input_checks_domain_and_labels_summary(with_keys):
    _mock_web_risk(False)
    _mock_vt_clean()

    result = await pipeline.analyze("security@mail.instagram.com")

    # Input is echoed back as the email; we report the domain we actually checked.
    assert result.input_url == "security@mail.instagram.com"
    assert result.final_url == "https://mail.instagram.com"
    # Template summary (no AI key) must label this as an email-domain check and be
    # honest that a clean domain doesn't make the email safe.
    assert "mail.instagram.com" in result.summary
    assert "email" in result.summary.lower()


@pytest.fixture
def with_ai(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "k")
    monkeypatch.setenv("VIRUSTOTAL_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@respx.mock
async def test_ai_summary_used_when_available(with_ai, monkeypatch):
    _mock_web_risk(False)
    _mock_vt_clean()

    async def fake_explain(verdict, score, findings):
        return "An AI-written calm explanation."

    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)

    result = await pipeline.analyze("https://example.com")
    assert result.summary == "An AI-written calm explanation."
    assert "ai" not in result.sources_unavailable


@respx.mock
async def test_ai_summary_falls_back_on_failure(with_ai, monkeypatch):
    _mock_web_risk(False)
    _mock_vt_clean()

    async def boom(verdict, score, findings):
        raise pipeline.AIUnavailable("down")

    monkeypatch.setattr(pipeline.ai, "explain", boom)

    result = await pipeline.analyze("https://example.com")
    assert result.summary  # template
    assert "ai" in result.sources_unavailable


@respx.mock
async def test_message_analysis_adds_findings_and_escalates(with_ai, monkeypatch):
    _mock_web_risk(False)
    _mock_vt_clean()

    async def fake_explain(verdict, score, findings):
        return "summary"

    async def fake_analyze_message(message, final_url):
        from app.models import Finding, Severity

        return [Finding(source="ai_message_analysis", severity=Severity.HIGH,
                        title="Fake urgency", detail="d", tip="t")]

    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)
    monkeypatch.setattr(pipeline.ai, "analyze_message", fake_analyze_message)

    # A clean URL becomes suspicious purely from the message finding.
    result = await pipeline.analyze(
        "https://example.com", message="Pay now or your account closes!",
        allow_message_analysis=True,
    )
    assert "ai_message_analysis" in result.sources_checked
    assert any(f.source == "ai_message_analysis" for f in result.findings)
    assert result.verdict is Verdict.SUSPICIOUS


@respx.mock
async def test_message_ignored_on_free_tier(with_ai, monkeypatch):
    _mock_web_risk(False)
    _mock_vt_clean()

    async def fake_explain(verdict, score, findings):
        return "summary"

    async def should_not_run(message, final_url):  # pragma: no cover
        raise AssertionError("message analysis must not run when not allowed")

    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)
    monkeypatch.setattr(pipeline.ai, "analyze_message", should_not_run)

    result = await pipeline.analyze(
        "https://example.com", message="something", allow_message_analysis=False
    )
    assert "ai_message_analysis" not in result.sources_checked


@respx.mock
async def test_unavailable_message_layer_blocks_safe_allclear(with_ai, monkeypatch):
    # The real-world miss: user pastes a scam message, but the message layer is
    # down. A clean URL must NOT come back "safe" — we flag that we couldn't
    # check the message and hold the verdict out of the green all-clear band.
    _mock_web_risk(False)
    _mock_vt_clean()

    async def fake_explain(verdict, score, findings):
        return "summary"

    async def boom(message, final_url):
        raise pipeline.AIUnavailable("message layer down")

    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)
    monkeypatch.setattr(pipeline.ai, "analyze_message", boom)

    result = await pipeline.analyze(
        "https://example.com",
        message="Your account is suspended! Update payment within 48 hours.",
        allow_message_analysis=True,
    )

    assert "ai_message_analysis" in result.sources_unavailable
    assert "ai_message_analysis" not in result.sources_checked
    # The gap is surfaced as a finding, and the verdict is no longer "safe".
    assert any(
        f.source == "ai_message_analysis" and "couldn't check" in f.title.lower()
        for f in result.findings
    )
    assert result.verdict is not Verdict.SAFE


@respx.mock
async def test_slow_whois_is_bounded_and_does_not_block_message(with_ai, monkeypatch):
    # The real production failure: a hanging WHOIS lookup (typical of the dead/new
    # domains scams use) serialized in front of message analysis and squeezed it
    # into timing out. WHOIS must be hard-bounded, and message analysis must run
    # concurrently — so a slow WHOIS neither delays the response nor starves the
    # message check.
    import time

    _mock_web_risk(False)
    _mock_vt_clean()

    monkeypatch.setattr(pipeline, "HEURISTIC_WHOIS_TIMEOUT_SECONDS", 0.1)

    def hanging_whois(domain):
        time.sleep(1.0)  # far longer than the 0.1s bound above
        return None

    monkeypatch.setattr(heuristics, "lookup_registration_date", hanging_whois)

    async def fake_explain(verdict, score, findings):
        return "summary"

    async def fake_analyze_message(message, final_url):
        from app.models import Finding, Severity

        return [Finding(source="ai_message_analysis", severity=Severity.HIGH,
                        title="Fake urgency", detail="d", tip="t")]

    monkeypatch.setattr(pipeline.ai, "explain", fake_explain)
    monkeypatch.setattr(pipeline.ai, "analyze_message", fake_analyze_message)

    start = time.perf_counter()
    result = await pipeline.analyze(
        "https://example.com", message="pay now", allow_message_analysis=True,
    )
    elapsed = time.perf_counter() - start

    assert elapsed < 0.9  # bounded by the 0.1s WHOIS timeout, not the 1s hang
    # Message analysis ran (concurrently) despite the slow WHOIS, and the verdict
    # reflects its finding rather than a starved "couldn't check".
    assert "ai_message_analysis" in result.sources_checked
    assert any(f.title == "Fake urgency" for f in result.findings)


@respx.mock
async def test_no_unchecked_finding_when_no_message(with_ai, monkeypatch):
    # The unchecked-message finding must only appear when a message was actually
    # pasted — a URL-only check with the AI layer down stays clean of it.
    _mock_web_risk(False)
    _mock_vt_clean()

    async def boom(verdict, score, findings):
        raise pipeline.AIUnavailable("down")

    monkeypatch.setattr(pipeline.ai, "explain", boom)

    result = await pipeline.analyze("https://example.com", allow_message_analysis=True)
    assert not any(f.source == "ai_message_analysis" for f in result.findings)
    assert result.verdict is Verdict.SAFE
