"""Data shapes for the "report a scam" feature.

v1 designs the shape and stubs storage (no DB). v2 wires a real datastore +
moderation and feeds confirmed reports into an internal blocklist (see ROADMAP).

Privacy: we deliberately do NOT persist full URLs with query strings (they may
carry tokens/personal data — CLAUDE.md). The stored record keeps only the
scheme/host/path, and the reporter's contact is optional.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ScamReportCategory(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    FAKE_SHOP = "fake_shop"
    SCAM_MESSAGE = "scam_message"
    OTHER = "other"


class ScamReportRequest(BaseModel):
    """What a user submits when reporting a scam link."""

    url: str = Field(..., description="The scam link being reported.")
    category: ScamReportCategory | None = Field(
        default=None, description="What kind of scam the reporter thinks it is."
    )
    message: str | None = Field(
        default=None, description="Optional: the message the link arrived in."
    )
    note: str | None = Field(
        default=None, description="Optional: anything the reporter wants to add."
    )
    contact_email: str | None = Field(
        default=None, description="Optional: only if the reporter wants follow-up."
    )


class ScamReportRecord(BaseModel):
    """The privacy-reduced record we would persist (storage stubbed in v1)."""

    id: str
    reported_url: str = Field(..., description="Scheme/host/path only — query stripped.")
    category: ScamReportCategory | None = None
    had_message: bool = False
    note: str | None = None
    contact_email: str | None = None
    created_at: datetime


class ScamReportAck(BaseModel):
    """The response a reporter gets back."""

    report_id: str
    status: str = "received"
    message: str
