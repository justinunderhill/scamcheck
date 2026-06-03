"""Tests for score aggregation, verdict thresholds, and the template summary."""
from __future__ import annotations

from app.models import Finding, Severity, Verdict
from app.services.scoring import score_findings, template_summary, verdict_for_score


def f(source: str, severity: Severity, title: str = "x") -> Finding:
    return Finding(source=source, severity=severity, title=title, detail="d", tip="t")


def test_gsb_hit_is_dangerous_alone():
    score = score_findings([f("google_safe_browsing", Severity.HIGH)])
    assert score >= 70
    assert verdict_for_score(score) is Verdict.DANGEROUS


def test_virustotal_medium_is_suspicious():
    score = score_findings([f("virustotal", Severity.MEDIUM)])
    assert verdict_for_score(score) is Verdict.SUSPICIOUS


def test_single_heuristic_medium_is_safe():
    score = score_findings([f("heuristics", Severity.MEDIUM)])
    assert verdict_for_score(score) is Verdict.SAFE


def test_heuristics_compound_to_dangerous():
    # lookalike(high) + new domain(high) + suspicious tld(low)
    score = score_findings([
        f("heuristics", Severity.HIGH),
        f("heuristics", Severity.HIGH),
        f("heuristics", Severity.LOW),
    ])
    assert verdict_for_score(score) is Verdict.DANGEROUS


def test_score_capped_at_100():
    score = score_findings([f("google_safe_browsing", Severity.HIGH)] * 5)
    assert score == 100


def test_ai_findings_only_add():
    base = score_findings([f("heuristics", Severity.MEDIUM)])
    with_ai = score_findings([
        f("heuristics", Severity.MEDIUM),
        f("ai_message_analysis", Severity.HIGH),
    ])
    assert with_ai > base  # AI can only escalate


def test_no_findings_is_safe():
    assert verdict_for_score(score_findings([])) is Verdict.SAFE


def test_template_summary_is_honest_when_safe():
    summary = template_summary(Verdict.SAFE, [])
    assert "guarantee" in summary.lower()
    assert "this is safe" not in summary.lower()


def test_template_summary_mentions_reasons_when_risky():
    findings = [f("virustotal", Severity.HIGH, title="Flagged by security vendors")]
    summary = template_summary(Verdict.DANGEROUS, findings)
    assert "flagged by security vendors" in summary.lower()
