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

from app.config import (
    CERT_CHECK_TIMEOUT_SECONDS,
    HEURISTIC_WHOIS_TIMEOUT_SECONDS,
    URL_FETCH_USER_AGENT,
    get_settings,
)
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

    # Everything that needs the network runs concurrently so the user waits only
    # as long as the slowest source — never the sum (CLAUDE.md). The AI message
    # analysis joins this batch rather than running after it: it depends only on
    # the message and the final URL, so making it wait behind a slow WHOIS lookup
    # was what squeezed it into timing out on exactly the dead/new domains scams
    # use. The two blocking heuristic lookups (WHOIS, cert) are each hard-bounded
    # so a stalled server can't delay or break the request.
    message_wanted = bool(message) and allow_message_analysis
    ai_active = settings.ai_enabled and allow_ai_summary
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0),
        headers={"User-Agent": URL_FETCH_USER_AGENT},
    ) as client:
        reg_date, cert, external_results, message_outcome = await asyncio.gather(
            _whois_registration_date(final),
            _cert_info(final),
            _gather_external(final, client),
            _run_message_analysis(final.url, message, message_wanted, ai_active),
        )

    # Heuristics is now pure (both network lookups were resolved above) — run it
    # directly with the gathered data injected.
    findings.extend(
        heuristics.check(
            final,
            was_shortener=expansion.was_shortener,
            registration_date_fn=lambda _domain: reg_date,
            cert_info_fn=lambda _url: cert,
        )
    )
    sources_checked.append(SOURCE_HEURISTICS)

    for name, source_findings, error in external_results:
        if error is not None:
            sources_unavailable.append(name)
        else:
            sources_checked.append(name)
            findings.extend(source_findings)

    # --- AI message analysis result (free for all tiers; can only add findings) ---
    message_state, message_findings = message_outcome
    if message_state == "ran":
        findings.extend(message_findings)
        sources_checked.append(SOURCE_AI_MESSAGE)
    elif message_state == "unavailable":
        sources_unavailable.append(SOURCE_AI_MESSAGE)

    # The user pasted a message expressly so we'd scan it for scam wording. If
    # that layer couldn't run, we did NOT inspect the single most important
    # signal — and a brand-new scam URL no blocklist knows yet will otherwise
    # sail through the deterministic sources as "safe". A calm green all-clear
    # here is the exact falsely-reassuring failure the free message analysis
    # exists to prevent (CLAUDE.md). Record the gap as a finding so the user
    # sees it, and let its weight hold the verdict out of the "safe" band rather
    # than silently downgrading.
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


async def _gather_external(url, client) -> list[tuple[str, list[Finding], Exception | None]]:
    """Run all external blocklist sources concurrently."""
    return list(await asyncio.gather(*(_run_source(mod, url, client) for mod in _EXTERNAL_SOURCES)))


async def _whois_registration_date(url):
    """Bounded WHOIS lookup. Returns the creation date, or None on timeout/error.

    `lookup_registration_date` already pins a socket timeout; wrapping it in
    `wait_for` is the hard ceiling on how long a stalled whois server can hold up
    the request, independent of whether the orphaned worker thread has returned.
    """
    if url.is_ip:
        return None
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(heuristics.lookup_registration_date, url.registered_domain),
            timeout=HEURISTIC_WHOIS_TIMEOUT_SECONDS,
        )
    except Exception:  # noqa: BLE001 - timeout/error both degrade to "unknown age"
        return None


async def _cert_info(url):
    """Bounded TLS certificate check. Returns CertInfo, or None to skip/degrade."""
    if url.scheme != "https":
        return None
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(heuristics.get_cert_info, url),
            timeout=CERT_CHECK_TIMEOUT_SECONDS + 2.0,  # outer bound; the socket has its own
        )
    except Exception:  # noqa: BLE001 - timeout/error: don't raise a false alarm
        return None


async def _run_message_analysis(
    final_url: str, message: str | None, wanted: bool, ai_active: bool
) -> tuple[str, list[Finding]]:
    """Run message analysis concurrently with the other sources.

    Returns (state, findings) where state is "ran", "unavailable", or "skipped".
    "unavailable" distinguishes a genuine failure-to-run (so the caller can warn
    the user) from "skipped" (no message supplied / not permitted).
    """
    if not wanted:
        return "skipped", []
    if not ai_active:
        return "unavailable", []
    try:
        return "ran", await ai.analyze_message(message or "", final_url)
    except AIUnavailable:
        return "unavailable", []
