"""Tests for the (stubbed-storage) scam-report feature."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models.reports import ScamReportCategory, ScamReportRequest
from app.services import reports

client = TestClient(app)


async def test_submit_report_strips_query_string():
    # Query strings may carry tokens/PII -> must not be stored.
    req = ScamReportRequest(
        url="https://evil.example/login?token=secret123&user=alice",
        category=ScamReportCategory.PHISHING,
        message="Your account is locked!",
    )
    ack = await reports.submit_report(req)
    assert ack.report_id
    assert ack.status == "received"

    stored = reports.report_store._recent[-1]  # stub keeps recent in memory
    assert stored.reported_url == "https://evil.example/login"
    assert "token" not in stored.reported_url
    assert stored.had_message is True
    assert stored.category is ScamReportCategory.PHISHING


def test_report_endpoint_acknowledges():
    resp = client.post(
        "/api/report",
        json={"url": "https://scam.example/pay", "category": "fake_shop"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "received"
    assert body["report_id"]


def test_report_endpoint_rejects_bad_url():
    resp = client.post("/api/report", json={"url": "not a url with spaces"})
    assert resp.status_code == 400
