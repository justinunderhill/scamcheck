"""The detection pipeline: turn a raw URL into a CheckResponse.

Flow:
  1. normalize + validate the URL (raises InvalidURLError on bad input)
  2. safely expand shorteners (HEAD-follow only)
  3. run deterministic sources CONCURRENTLY against the final URL:
       - heuristics  (local, pure; run in a thread so it doesn't block the loop)
       - Google Safe Browsing + VirusTotal (async HTTP)
  4. (paid + allowed) AI message analysis -> may ADD findings
  5. aggregate findings -> score -> verdict
  6. AI explanation summary (falls back to a deterministic template, noting `ai`
     in sources_unavailable)

The AI layer can only ADD findings (raising the score) and rewrite the summary;
it can never lower the score or soften the verdict. A source that's down,
rate-limited, or unconfigured is recorded in `sources_unavailable` and never
fails the whole request.
"""
from __future__ import annotations

import asyncio

import httpx

from app.config import URL_FETCH_USER_AGENT, get_settings
from app.core.urls import expand_url, normalize_url
from app.models import CheckResponse, Finding, Severity
from app.models.schemas import SOURCE_AI, SOURCE_AI_MESSAGE, SOURCE_HEURISTICS
from app.services import ai
from app.services import heuristics
from app.services import virustotal as vt
from app.services import web_risk
from app.services.ai.client import AIUnavailable
from app.services.base import SourceUnavailable
from app.services.scoring import score_findings, template_summary, verdict_for_score

# External (HTTP) sources, in the order they appear in sources_checked.
# Web Risk is Google's current blocklist API; it replaces the legacy Safe
# Browsing v4 source (`google_safe_browsing.py` is kept for reference/fallback).
_EXTERNAL_SOURCES = (web_risk, vt)


async def analyze(
    raw_url: str,
    message: str | None = None,
    *,
    allow_message_analysis: bool = False,
    allow_ai_summary: bool = True,
) -> CheckResponse:
    """Run the full pipeline.

    `allow_message_analysis` is set by tier gating (paid-only). `allow_ai_summary`
    is set False by the daily AI-cap fallback. Both default to the deterministic-
    safe behaviour.
    """
    settings = get_settings()

    normalized = normalize_url(raw_url)
    expansion = await expand_url(normalized)
    final = normalize_url(expansion.final_url) if expansion.expanded else normalized

    # If the user pasted an email address, we checked its sender domain. The
    # summary must label that scope (a clean domain doesn't make the email safe).
    email_domain = final.host if final.is_email else None

    findings: list[Finding] = []
    sources_checked: list[str] = []
    sources_unavailable: list[str] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0),
        headers={"User-Agent": URL_FETCH_USER_AGENT},
    ) as client:
        heuristics_task = asyncio.to_thread(
            heuristics.check, final, was_shortener=expansion.was_shortener
        )
        external_tasks = [_run_source(mod, final, client) for mod in _EXTERNAL_SOURCES]
        heuristic_findings, *external_results = await asyncio.gather(
            heuristics_task, *external_tasks
        )

    findings.extend(heuristic_findings)
    sources_checked.append(SOURCE_HEURISTICS)

    for name, source_findings, error in external_results:
        if error is not None:
            sources_unavailable.append(name)
        else:
            sources_checked.append(name)
            findings.extend(source_findings)

    # --- AI message analysis (free for all tiers; can only add findings) ---
    if message and allow_message_analysis:
        if settings.ai_enabled and allow_ai_summary:
            try:
                findings.extend(await ai.analyze_message(message, final.url))
                sources_checked.append(SOURCE_AI_MESSAGE)
            except AIUnavailable:
                # Failed mid-call — treat as unavailable, not a clean "checked".
                sources_unavailable.append(SOURCE_AI_MESSAGE)
        else:
            sources_unavailable.append(SOURCE_AI_MESSAGE)

        # The user pasted a message expressly so we'd scan it for scam wording.
        # If that layer couldn't run, we did NOT inspect the single most
        # important signal — and a brand-new scam URL no blocklist knows yet
        # will otherwise sail through the deterministic sources as "safe". A
        # calm green all-clear here is the exact falsely-reassuring failure the
        # free message analysis exists to prevent (CLAUDE.md). Record the gap as
        # a finding so the user sees it, and let its weight hold the verdict out
        # of the "safe" band rather than silently downgrading.
        if SOURCE_AI_MESSAGE in sources_unavailable:
            findings.append(_message_unchecked_finding())

    # --- Aggregate (after any AI-added findings) ---
    score = score_findings(findings)
    verdict = verdict_for_score(score)

    # --- AI explanation summary, with deterministic fallback ---
    summary: str | None = None
    if allow_ai_summary and settings.ai_enabled:
        # Only pass email_domain when relevant so existing call sites/tests that
        # stub explain(verdict, score, findings) keep working for normal URLs.
        explain_extra = {"email_domain": email_domain} if email_domain else {}
        try:
            summary = await ai.explain(verdict, score, findings, **explain_extra)
        except AIUnavailable:
            summary = None
    if summary is None:
        summary = template_summary(verdict, findings, email_domain=email_domain)
        sources_unavailable.append(SOURCE_AI)

    return CheckResponse(
        input_url=normalized.input_url,
        final_url=final.url,
        verdict=verdict,
        score=score,
        summary=summary,
        findings=findings,
        sources_checked=sources_checked,
        sources_unavailable=sources_unavailable,
    )


def _message_unchecked_finding() -> Finding:
    """Surface that a pasted message went un-analyzed (AI layer unavailable).

    Medium severity is deliberate: on its own it weighs enough to lift an
    otherwise-clean link out of the "safe" band into "suspicious", so the user
    never sees a green all-clear for a message we couldn't actually scan. We'd
    rather over-warn than reassure someone about an unchecked scam message.
    """
    return Finding(
        source=SOURCE_AI_MESSAGE,
        severity=Severity.MEDIUM,
        title="We couldn't check the message you pasted",
        detail=(
            "Our message analysis was temporarily unavailable, so we couldn't scan the "
            "text you pasted for scam wording. This result is based only on the link "
            "itself — treat it as incomplete, not as an all-clear."
        ),
        tip=(
            "Be wary of messages that pressure you to act fast, threaten to suspend or "
            "delete your account, or ask for payment or passwords. Try checking again in "
            "a little while."
        ),
    )


async def _run_source(module, url, client) -> tuple[str, list[Finding], Exception | None]:
    """Run one external source, converting failures into a recorded unavailability."""
    try:
        result = await module.check(url, client)
        return module.NAME, result, None
    except SourceUnavailable as exc:
        return module.NAME, [], exc
    except Exception as exc:  # noqa: BLE001 - never let one source break the request
        return module.NAME, [], exc
