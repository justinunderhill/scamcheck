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
from app.services.limits import guard


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch):
    cfg = dict(config.Settings.model_config)
    cfg["env_file"] = None
    monkeypatch.setattr(config.Settings, "model_config", cfg)
    # Ensure no leftover keys from the developer's shell unless a test sets them.
    for var in ("GOOGLE_SAFE_BROWSING_KEY", "WEB_RISK_KEY", "VIRUSTOTAL_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    config.get_settings.cache_clear()
    # The abuse guard is a process-wide singleton; start each test clean.
    guard.reset()
    yield
    config.get_settings.cache_clear()
    guard.reset()
