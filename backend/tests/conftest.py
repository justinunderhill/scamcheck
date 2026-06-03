"""Test isolation.

Production Settings load the repo `.env` (so the app picks up real keys at
runtime). Tests must NOT read that file — otherwise real API keys leak in and
trigger real network calls. This autouse fixture forces Settings to ignore the
`.env` file so only explicitly-set environment variables take effect, keeping
the suite hermetic.
"""
from __future__ import annotations

import pytest

from app import config
from app.services.limits import MemoryAbuseStore, guard


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch):
    cfg = dict(config.Settings.model_config)
    cfg["env_file"] = None
    monkeypatch.setattr(config.Settings, "model_config", cfg)
    # Ensure no leftover keys/store config from the developer's shell unless a
    # test sets them.
    for var in (
        "GOOGLE_SAFE_BROWSING_KEY", "WEB_RISK_KEY", "VIRUSTOTAL_KEY", "ANTHROPIC_API_KEY",
        "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN",
        "KV_REST_API_URL", "KV_REST_API_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    config.get_settings.cache_clear()
    # The abuse guard is a process-wide singleton; give each test a clean,
    # in-memory store (independent of whatever the dev shell has configured).
    guard.configure(MemoryAbuseStore())
    yield
    config.get_settings.cache_clear()
    guard.configure(MemoryAbuseStore())
