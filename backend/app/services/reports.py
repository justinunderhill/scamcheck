"""Scam-report intake with stubbed storage.

The `ScamReportStore` interface is real so v2 can drop in a database +
moderation queue without changing call sites. `StubScamReportStore` does NOT
persist anything durably — it just mints an id (and keeps a small, bounded
in-memory list for the running process, clearly non-durable).
"""
from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Protocol

from app.core.urls import normalize_url
from app.models.reports import ScamReportAck, ScamReportRecord, ScamReportRequest


class ScamReportStore(Protocol):
    async def save(self, record: ScamReportRecord) -> str:
        """Persist a report and return its id. (v2 implements durably.)"""
        ...


class StubScamReportStore:
    """v1 stub: no durable storage. Keeps the last N reports in memory only."""

    def __init__(self, capacity: int = 100) -> None:
        self._recent: deque[ScamReportRecord] = deque(maxlen=capacity)

    async def save(self, record: ScamReportRecord) -> str:
        # Intentionally not written to disk/DB in v1.
        self._recent.append(record)
        return record.id


# Process-wide stub instance. Swap for a real store in v2.
report_store: ScamReportStore = StubScamReportStore()


def _privacy_reduced_url(raw_url: str) -> str:
    """Normalize and strip the query string before storage (CLAUDE.md privacy)."""
    n = normalize_url(raw_url)
    host = n.host if n.port is None else f"{n.host}:{n.port}"
    return f"{n.scheme}://{host}{n.path}"


async def submit_report(request: ScamReportRequest) -> ScamReportAck:
    """Validate, privacy-reduce, and hand the report to the (stubbed) store."""
    record = ScamReportRecord(
        id=uuid.uuid4().hex,
        reported_url=_privacy_reduced_url(request.url),
        category=request.category,
        had_message=bool(request.message and request.message.strip()),
        note=request.note,
        contact_email=request.contact_email,
        created_at=datetime.now(timezone.utc),
    )
    report_id = await report_store.save(record)
    return ScamReportAck(
        report_id=report_id,
        status="received",
        message=(
            "Thanks for reporting this. We've logged it for review. Reporting "
            "scams helps protect other people from the same trap."
        ),
    )
