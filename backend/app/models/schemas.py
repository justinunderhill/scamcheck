"""Pydantic models for the public API contract.

This contract is documented in CLAUDE.md and must stay stable. The frontend and
any future clients depend on these exact field names and value sets.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


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


class CheckRequest(BaseModel):
    url: str = Field(..., description="The URL the user wants checked.")
    message: str | None = Field(
        default=None,
        description=(
            "Optional full message the link arrived in. Paid-tier feature: "
            "analyzed for social-engineering patterns when the tier allows."
        ),
    )


class CheckResponse(BaseModel):
    input_url: str
    final_url: str
    verdict: Verdict
    score: int = Field(..., ge=0, le=100, description="0-100, higher = riskier.")
    summary: str = Field(
        ...,
        description="Plain-language overview. AI-written, or a template on fallback.",
    )
    findings: list[Finding] = Field(default_factory=list)
    sources_checked: list[str] = Field(default_factory=list)
    sources_unavailable: list[str] = Field(default_factory=list)
