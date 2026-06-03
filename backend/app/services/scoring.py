"""Aggregate findings into a single 0-100 risk score, verdict, and (fallback)
summary.

The score is the capped sum of per-finding weights (config.SCORE_WEIGHTS).
Because every weight is non-negative and AI findings are weighted like any other
source, adding AI findings can only raise the score — never lower it. This is
how the escalate-only rule is enforced mechanically rather than by trust.
"""
from __future__ import annotations

from app.config import (
    SCORE_DANGEROUS_THRESHOLD,
    SCORE_DEFAULT_WEIGHTS,
    SCORE_SUSPICIOUS_THRESHOLD,
    SCORE_WEIGHTS,
)
from app.models import Finding, Verdict


def score_findings(findings: list[Finding]) -> int:
    total = 0
    for f in findings:
        weight = SCORE_WEIGHTS.get(
            (f.source, f.severity.value),
            SCORE_DEFAULT_WEIGHTS.get(f.severity.value, 0),
        )
        total += weight
    return min(100, total)


def verdict_for_score(score: int) -> Verdict:
    if score >= SCORE_DANGEROUS_THRESHOLD:
        return Verdict.DANGEROUS
    if score >= SCORE_SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def template_summary(verdict: Verdict, findings: list[Finding]) -> str:
    """Deterministic, honest summary used when the AI layer is unavailable.

    Honest about uncertainty: a clean result says "no known threats found",
    never "this is safe" (CLAUDE.md ethics rule).
    """
    if verdict is Verdict.SAFE:
        return (
            "We didn't find any known threats for this link. That isn't a "
            "guarantee it's safe, so stay alert — especially if it arrived "
            "unexpectedly or asks for personal details."
        )

    # Lead with the most serious concerns.
    ordered = sorted(findings, key=_severity_rank)
    top = [f.title.lower() for f in ordered[:3]]
    reasons = _join(top)

    if verdict is Verdict.DANGEROUS:
        return (
            f"This link shows strong signs of being dangerous ({reasons}). "
            "We'd strongly recommend not opening it and not entering any "
            "personal or payment details."
        )
    return (
        f"This link has some warning signs ({reasons}). Treat it with caution: "
        "don't enter passwords or payment details unless you're certain it's genuine."
    )


def _severity_rank(f: Finding) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(f.severity.value, 3)


def _join(items: list[str]) -> str:
    if not items:
        return "several warning signs"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]
