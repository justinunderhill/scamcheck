"""Pydantic models for the public API contract.

This contract is documented in CLAUDE.md and must stay stable. The frontend and
any future clients depend on these exact field names and value sets.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Canonical source identifiers used in `findings[].source`, `sources_checked`,
# and `sources_unavailable`. Kept as plain string constants (not an enum) so a
# new detection module can register its own name without editing this file.
SOURCE_HEURISTICS = "heuristics"
SOURCE_GOOGLE = "google_safe_browsing"
SOURCE_WEB_RISK = "web_risk"
SOURCE_VIRUSTOTAL = "virustotal"
SOURCE_AI_MESSAGE = "ai_message_analysis"
SOURCE_AI = "ai"  # the explanation layer; appears in sources_unavailable on fallback


class Finding(BaseModel):
    """One human-readable reason contributing to the verdict."""

    source: str = Field(..., examples=[SOURCE_HEURISTICS])
    severity: Severity
    title: str = Field(..., description="Short plain-language label. No jargon.")
    detail: str = Field(..., description="One sentence explaining what was found.")
    tip: str = Field(..., description="One sentence teaching the general lesson.")
    # Stable internal identifier for the specific check that produced this
    # finding (e.g. "domain_age"). Used only for aggregate analytics counters;
    # excluded from the API response so the public contract is unchanged. The
    # user-facing wording above may change freely without breaking stats.
    code: str | None = Field(default=None, exclude=True)


class CheckRequest(BaseModel):
    url: str | None = Field(
        default=None,
        description="The URL the user wants checked. Optional when a message is given.",
    )
    message: str | None = Field(
        default=None,
        description=(
            "Optional full message the link arrived in. Analyzed for "
            "social-engineering patterns (available on all tiers). On its own, "
            "with no url, it makes a message-only check."
        ),
    )

    @model_validator(mode="after")
    def _require_url_or_message(self) -> "CheckRequest":
        self.url = (self.url or "").strip() or None
        self.message = (self.message or "").strip() or None
        if not (self.url or self.message):
            raise ValueError("Paste a link or a message to check.")
        return self


class CheckResponse(BaseModel):
    # Both are null for a message-only check (no link was given).
    input_url: str | None
    final_url: str | None
    verdict: Verdict
    score: int = Field(..., ge=0, le=100, description="0-100, higher = riskier.")
    summary: str = Field(
        ...,
        description="Plain-language overview. AI-written, or a template on fallback.",
    )
    findings: list[Finding] = Field(default_factory=list)
    sources_checked: list[str] = Field(default_factory=list)
    sources_unavailable: list[str] = Field(default_factory=list)


class ScreenshotRequest(BaseModel):
    """POST /api/extract: a screenshot to read (never stored or logged)."""

    image: str = Field(..., description="Base64-encoded image bytes (no data: prefix).")
    media_type: str = Field(..., examples=["image/jpeg"])


class ScreenshotResponse(BaseModel):
    """What was read from the screenshot. The client then runs a normal check."""

    url: str | None = None
    message: str | None = None
