"""AI layer — human-friendly reasoning ON TOP OF deterministic detection.

Public surface:
  v1: explain(verdict, score, findings)        -> summary string  (cached)
      analyze_message(message_text, final_url)  -> list[Finding]   (paid-gated upstream)
  v2 (stubbed): analyze_page(...), followup(...)

Escalate-only is enforced upstream by scoring (AI findings only add weight) and
here by the prompts. The pasted message is never persisted or logged.
"""
from __future__ import annotations

import hashlib
import json
from collections import OrderedDict

from app.config import (
    AI_ANALYSIS_MAX_TOKENS,
    AI_ANALYSIS_MODEL,
    AI_EXPLAIN_CACHE_SIZE,
    AI_EXPLAIN_MAX_TOKENS,
    AI_EXPLAIN_MODEL,
    AI_MESSAGE_MAX_FINDINGS,
)
from app.models import Finding, Severity, Verdict
from app.models.schemas import SOURCE_AI_MESSAGE
from app.services.ai import prompts
from app.services.ai.client import AIUnavailable, complete

__all__ = ["explain", "analyze_message", "analyze_page", "followup", "AIUnavailable"]

# Simple in-process LRU cache for explanations, keyed by (verdict, findings).
# Identical deterministic results reuse the same summary and don't re-bill.
_explain_cache: "OrderedDict[str, str]" = OrderedDict()


def _explain_cache_key(
    verdict: Verdict, findings: list[Finding], email_domain: str | None
) -> str:
    payload = {
        "verdict": verdict.value,
        "findings": sorted(
            (f.source, f.severity.value, f.title) for f in findings
        ),
        "email_domain": email_domain,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


async def explain(
    verdict: Verdict,
    score: int,
    findings: list[Finding],
    *,
    email_domain: str | None = None,
) -> str:
    """Plain-language summary of the result. Cached; raises AIUnavailable on failure.

    `email_domain`, when set, tells the model the input was an email address and
    only its domain was checked, so the summary can be honest about that scope.
    """
    key = _explain_cache_key(verdict, findings, email_domain)
    if key in _explain_cache:
        _explain_cache.move_to_end(key)
        return _explain_cache[key]

    user = _render_explain_input(verdict, score, findings, email_domain)
    summary = await complete(
        model=AI_EXPLAIN_MODEL,
        system=prompts.EXPLAIN_SYSTEM,
        user=user,
        max_tokens=AI_EXPLAIN_MAX_TOKENS,
    )

    _explain_cache[key] = summary
    _explain_cache.move_to_end(key)
    while len(_explain_cache) > AI_EXPLAIN_CACHE_SIZE:
        _explain_cache.popitem(last=False)
    return summary


def _render_explain_input(
    verdict: Verdict, score: int, findings: list[Finding], email_domain: str | None
) -> str:
    if findings:
        lines = "\n".join(f"- [{f.severity.value}] {f.title}: {f.detail}" for f in findings)
    else:
        lines = "- (no specific warning signs were detected)"
    scope = ""
    if email_domain:
        scope = (
            "Input type: the user pasted an EMAIL ADDRESS; we checked only its "
            f"domain ({email_domain}). Make clear we checked the sender's domain, "
            "and that a clean domain does not mean the email is safe (display-name "
            "spoofing, lookalike domains, and hijacked accounts all exist).\n"
        )
    # Findings are our own trusted strings, but we still frame them as data.
    return (
        f"{scope}Verdict: {verdict.value}\nRisk score: {score}/100\n"
        f"Findings:\n{lines}\n\n"
        "Write the summary for the user now."
    )


async def analyze_message(message_text: str, final_url: str) -> list[Finding]:
    """Detect social-engineering patterns in a pasted message.

    Returns normalized ai_message_analysis findings; an empty list means the
    analysis RAN and found nothing (or returned nothing parseable). A genuine
    failure to run raises `AIUnavailable` — the caller must distinguish "checked,
    clean" from "couldn't check" so it never presents an unscanned message as a
    reassuring all-clear (see pipeline). Never persists the message.
    """
    message_text = (message_text or "").strip()
    if not message_text:
        return []

    # The message and URL are untrusted: clearly delimit them as data.
    user = (
        "Analyze the message below. The link it contained resolves to: "
        f"{final_url}\n\n"
        "<<<USER_MESSAGE_START>>>\n"
        f"{message_text}\n"
        "<<<USER_MESSAGE_END>>>\n\n"
        "Return only the JSON array of findings."
    )
    # AIUnavailable propagates: the pipeline records the message layer as
    # unavailable rather than silently treating a failed call as "checked".
    raw = await complete(
        model=AI_ANALYSIS_MODEL,
        system=prompts.MESSAGE_ANALYSIS_SYSTEM,
        user=user,
        max_tokens=AI_ANALYSIS_MAX_TOKENS,
    )

    return _parse_message_findings(raw)


def _parse_message_findings(raw: str) -> list[Finding]:
    data = _extract_json_array(raw)
    findings: list[Finding] = []
    for item in data[:AI_MESSAGE_MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "")).lower()
        if severity not in {"low", "medium", "high"}:
            severity = "medium"
        title = str(item.get("title", "")).strip()
        detail = str(item.get("detail", "")).strip()
        tip = str(item.get("tip", "")).strip()
        if not (title and detail):
            continue
        findings.append(
            Finding(
                source=SOURCE_AI_MESSAGE,
                severity=Severity(severity),
                title=title,
                detail=detail,
                tip=tip or "Be cautious with messages that pressure you to act quickly.",
            )
        )
    return findings


def _extract_json_array(raw: str) -> list:
    raw = raw.strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        pass
    # Be tolerant of stray prose around the array.
    start, end = raw.find("["), raw.rfind("]")
    if 0 <= start < end:
        try:
            parsed = json.loads(raw[start : end + 1])
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


# ---------------------------------------------------------------------------
# v2 — interfaces defined now, bodies stubbed (see backend/app/services/AI_SPEC.md)
# ---------------------------------------------------------------------------

async def analyze_page(safe_capture: object) -> list[Finding]:
    """v2: vision/text analysis of a SAFELY captured destination page.

    Will detect brand-impersonation login pages and pressure tactics on sites
    too new for any blocklist. Input is a safe capture (screenshot + extracted
    text) — never a live-rendered page. Stubbed for v1.
    """
    raise NotImplementedError("analyze_page is a v2 feature")


async def followup(question: str, prior_result: object) -> str:
    """v2: grounded Q&A after a verdict ("what do I do now?").

    Must stay within the established verdict and give practical safety steps.
    Stubbed for v1.
    """
    raise NotImplementedError("followup is a v2 feature")
