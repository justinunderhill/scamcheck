"""Thin wrapper around the Anthropic SDK.

Isolated here so the rest of the AI layer (and tests) depend on one small
`complete()` function rather than the SDK directly. Tests monkeypatch this.
"""
from __future__ import annotations

import logging

from app.config import AI_MAX_RETRIES, AI_REQUEST_TIMEOUT_SECONDS, get_settings

logger = logging.getLogger(__name__)


class AIUnavailable(Exception):
    """The AI layer couldn't produce a result (no key, timeout, error, rate limit)."""


async def complete(*, model: str, system: str, user: str, max_tokens: int) -> str:
    """Send one message to Claude and return the text response.

    Raises AIUnavailable on any failure so callers can fall back deterministically.
    The system prompt holds the fixed guardrails; `user` is untrusted data.
    """
    settings = get_settings()
    if not settings.ai_enabled:
        raise AIUnavailable("no API key configured")

    try:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            timeout=AI_REQUEST_TIMEOUT_SECONDS,
            max_retries=AI_MAX_RETRIES,
        )
        message = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
    except Exception as exc:  # noqa: BLE001 - SDK raises many types; all -> fallback
        # Log the failure reason so a silent fallback is diagnosable. SDK error
        # text carries status/type/request-id only — never the key, the user's
        # message or URL (we don't include the exception's request body).
        logger.warning("AI call failed (model=%s): %s: %.300s", model, type(exc).__name__, exc)
        raise AIUnavailable(f"{type(exc).__name__}: {exc}") from exc

    parts = [block.text for block in message.content if getattr(block, "type", None) == "text"]
    text = "".join(parts).strip()
    if not text:
        raise AIUnavailable("empty response")
    return text
