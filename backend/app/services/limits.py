"""Abuse protection: per-IP rate limiting, daily free-tier cap, and a global
daily ceiling on AI calls.

Counters live behind an `AbuseStore` so they can be durable across serverless
invocations:
  - `MemoryAbuseStore`  — per-process dict (local dev / tests / single instance)
  - `RedisAbuseStore`   — Upstash Redis over its REST API (works on Vercel)

All windows are fixed-window counters (INCR + EXPIRE NX), which are cheap and
correct over a stateless REST store. Thresholds read from `config` at call time
so they stay tunable (and monkeypatchable in tests).

Failure policy: if the store errors, rate/daily checks FAIL OPEN (don't block
real users on an outage), but the AI budget FAILS CLOSED (protect the bill).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Protocol

import httpx

from app import config
from app.config import get_settings


class AbuseStore(Protocol):
    async def incr(self, key: str, ttl_seconds: int) -> int:
        """Increment `key`, setting `ttl_seconds` on first creation; return the count."""
        ...

    def reset(self) -> None:
        """Clear all counters (tests / single-process)."""
        ...


class MemoryAbuseStore:
    """Per-process counters with expiry. Correct only within a single instance."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._expiry: dict[str, float] = {}

    async def incr(self, key: str, ttl_seconds: int) -> int:
        now = time.time()
        if key in self._expiry and self._expiry[key] <= now:
            self._counts.pop(key, None)
            self._expiry.pop(key, None)
        self._counts[key] = self._counts.get(key, 0) + 1
        if self._counts[key] == 1:
            self._expiry[key] = now + ttl_seconds
        return self._counts[key]

    def reset(self) -> None:
        self._counts.clear()
        self._expiry.clear()


class RedisAbuseStore:
    """Upstash Redis via its REST API — a single pipelined round trip per incr."""

    def __init__(self, url: str, token: str) -> None:
        self._url = url.rstrip("/")
        self._token = token

    async def incr(self, key: str, ttl_seconds: int) -> int:
        headers = {"Authorization": f"Bearer {self._token}"}
        # Pipeline: INCR, then set expiry only if not already set (NX).
        body = [["INCR", key], ["EXPIRE", key, str(ttl_seconds), "NX"]]
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), headers=headers) as client:
            resp = await client.post(f"{self._url}/pipeline", json=body)
            resp.raise_for_status()
            data = resp.json()
        return int(data[0]["result"])

    def reset(self) -> None:  # pragma: no cover - no-op in production
        pass


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class AbuseGuard:
    def __init__(self, store: AbuseStore) -> None:
        self._store = store

    def configure(self, store: AbuseStore) -> None:
        self._store = store

    @property
    def is_durable(self) -> bool:
        return isinstance(self._store, RedisAbuseStore)

    async def allow_request(self, ip: str) -> bool:
        """Fixed-window per-IP rate limit. Fails OPEN on store error."""
        window = config.RATE_LIMIT_WINDOW_SECONDS
        bucket = int(time.time()) // window
        try:
            count = await self._store.incr(f"rl:{ip}:{bucket}", window)
        except Exception:  # noqa: BLE001
            return True
        return count <= config.RATE_LIMIT_REQUESTS

    async def allow_daily_check(self, ip: str) -> bool:
        """Per-IP daily free-tier cap. Fails OPEN on store error."""
        try:
            count = await self._store.incr(f"daily:{ip}:{_today()}", 86_400)
        except Exception:  # noqa: BLE001
            return True
        return count <= config.FREE_TIER_CHECKS_PER_DAY

    async def try_consume_ai_budget(self) -> bool:
        """Global daily AI-call budget. Fails CLOSED on store error (protect the bill)."""
        try:
            count = await self._store.incr(f"ai:{_today()}", 86_400)
        except Exception:  # noqa: BLE001
            return False
        return count <= config.AI_DAILY_CALL_CAP

    def reset(self) -> None:
        self._store.reset()


def _make_store() -> AbuseStore:
    settings = get_settings()
    if settings.redis_enabled:
        return RedisAbuseStore(settings.redis_rest_url, settings.redis_rest_token)
    return MemoryAbuseStore()


# Process-wide singleton, built from the current settings.
guard = AbuseGuard(_make_store())
