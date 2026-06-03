"""Abuse protection: per-IP rate limiting, daily free-tier cap, and a global
daily ceiling on AI calls.

In-memory and per-process — fine for v1's stateless single-instance deployment.
A shared store (e.g. Redis) is the obvious upgrade when scaling to multiple
workers; the interface here stays the same. All thresholds read from `config`
at call time so they're tunable (and monkeypatchable in tests).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from app import config


class AbuseGuard:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)   # ip -> request timestamps
        self._daily: dict[tuple[str, str], int] = defaultdict(int)  # (ip, day) -> count
        self._ai_calls: dict[str, int] = defaultdict(int)           # day -> count

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def allow_request(self, ip: str, *, now: float | None = None) -> bool:
        """Sliding-window per-IP rate limit. True if the request may proceed."""
        now = time.monotonic() if now is None else now
        window = config.RATE_LIMIT_WINDOW_SECONDS
        limit = config.RATE_LIMIT_REQUESTS
        with self._lock:
            hits = self._hits[ip]
            cutoff = now - window
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def allow_daily_check(self, ip: str) -> bool:
        """Per-IP daily free-tier cap. True (and consumes one) if under the cap."""
        key = (ip, self._today())
        with self._lock:
            if self._daily[key] >= config.FREE_TIER_CHECKS_PER_DAY:
                return False
            self._daily[key] += 1
            return True

    def try_consume_ai_budget(self) -> bool:
        """Global daily AI-call budget. True (and consumes one) if under the cap."""
        day = self._today()
        with self._lock:
            if self._ai_calls[day] >= config.AI_DAILY_CALL_CAP:
                return False
            self._ai_calls[day] += 1
            return True

    def reset(self) -> None:
        """Clear all counters (used by tests)."""
        with self._lock:
            self._hits.clear()
            self._daily.clear()
            self._ai_calls.clear()


# Process-wide singleton.
guard = AbuseGuard()
