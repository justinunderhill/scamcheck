"""Internal analytics: aggregate integer counters, nothing else.

The absolute rule (see docs/ANALYTICS.md): **count, don't log.** We only ever
store integer counters keyed by *category* — a verdict, a heuristic name, a
source's availability. We never persist a URL, a domain, a message, or anything
that could identify a user or their input.

Counters live behind an `AnalyticsStore` so they can be durable across
serverless invocations (the same idea as the abuse store in `limits.py`):
  - `MemoryAnalyticsStore` — per-process dict (local dev / tests / inspection)
  - `RedisAnalyticsStore`  — Upstash Redis over its REST API (works on Vercel)

Recording is **best-effort**: every write is wrapped so a store outage can never
block or fail the user's result. A check is counted only once it has already
succeeded, so a failed/invalid request never moves the numbers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Protocol

import httpx

from app import config
from app.config import get_settings
from app.models.schemas import (
    SOURCE_AI,
    SOURCE_AI_MESSAGE,
    SOURCE_GOOGLE,
    SOURCE_VIRUSTOTAL,
    SOURCE_WEB_RISK,
)
from app.services.heuristics import HEURISTIC_CODES

# External (network) detection sources whose availability we track. Heuristics
# are local and always run, so they aren't in this set.
_EXTERNAL_SOURCES: tuple[str, ...] = (SOURCE_WEB_RISK, SOURCE_VIRUSTOTAL, SOURCE_GOOGLE)


# ---------------------------------------------------------------------------
# Counter keys — every key is an aggregate integer (see docs/ANALYTICS.md)
# ---------------------------------------------------------------------------
def _k(*parts: str) -> str:
    return config.ANALYTICS_KEY_PREFIX + ":".join(parts)


K_CHECKS_TOTAL = _k("checks", "total")                       # all-time successful checks
K_CAP_FREE = _k("cap", "free_tier")                          # free daily cap rejections
K_CAP_AI = _k("cap", "ai_hardcap")                           # AI budget exhausted (fell back)
K_AI_RAN = _k("ai", "ran")                                   # AI summary produced
K_AI_TEMPLATE = _k("ai", "template")                         # template fallback used
# Message-analysis layer, tracked separately from the summary layer above. Only
# moved when the user actually submitted a message (so it measures the message
# detector's own health, not how often people paste a message). "found" is the
# subset of "ran" that flagged at least one social-engineering pattern.
K_MSG_RAN = _k("message", "ran")                             # message analysis ran
K_MSG_UNAVAILABLE = _k("message", "unavailable")             # supplied but couldn't run
K_MSG_FOUND = _k("message", "found")                         # ran AND flagged something


def checks_day_key(day: str) -> str:
    return _k("checks", "day", day)


def verdict_key(verdict: str) -> str:
    return _k("verdict", verdict)


def heuristic_key(code: str) -> str:
    return _k("heuristic", code)


def source_key(name: str, available: bool) -> str:
    return _k("source", name, "available" if available else "unavailable")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
# One increment to apply: (key, amount, ttl_seconds). ttl_seconds is None for
# all-time counters that must never expire, or a number for day-bucketed keys.
Increment = tuple[str, int, "int | None"]


class AnalyticsStore(Protocol):
    async def apply(self, increments: list[Increment]) -> None:
        """Apply a batch of increments atomically-ish. Raises on transport error."""
        ...

    async def get_many(self, keys: Iterable[str]) -> dict[str, int]:
        """Return current values for `keys` (0 for any missing/expired key)."""
        ...

    def reset(self) -> None:
        """Clear all counters (tests / single-process)."""
        ...


class MemoryAnalyticsStore:
    """Per-process counters. Correct only within a single instance.

    TTLs are ignored (a dev/test process is short-lived); the point of the
    in-memory store is local development, tests, and direct inspection via
    `counts`.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    async def apply(self, increments: list[Increment]) -> None:
        for key, amount, _ttl in increments:
            self._counts[key] = self._counts.get(key, 0) + amount

    async def get_many(self, keys: Iterable[str]) -> dict[str, int]:
        return {key: self._counts.get(key, 0) for key in keys}

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def reset(self) -> None:
        self._counts.clear()


class RedisAnalyticsStore:
    """Upstash Redis via its REST API — one pipelined round trip per batch."""

    def __init__(self, url: str, token: str) -> None:
        self._url = url.rstrip("/")
        self._token = token

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def apply(self, increments: list[Increment]) -> None:
        if not increments:
            return
        # INCRBY each key; for day-bucketed keys also set the TTL once (EXPIRE NX
        # only sets it when the key has no expiry yet, so all-time counters that
        # share a name never get an accidental TTL).
        commands: list[list[str]] = []
        for key, amount, ttl in increments:
            commands.append(["INCRBY", key, str(amount)])
            if ttl is not None:
                commands.append(["EXPIRE", key, str(ttl), "NX"])
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), headers=self._headers) as client:
            resp = await client.post(f"{self._url}/pipeline", json=commands)
            resp.raise_for_status()

    async def get_many(self, keys: Iterable[str]) -> dict[str, int]:
        keys = list(keys)
        if not keys:
            return {}
        commands = [["GET", key] for key in keys]
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), headers=self._headers) as client:
            resp = await client.post(f"{self._url}/pipeline", json=commands)
            resp.raise_for_status()
            results = resp.json()
        out: dict[str, int] = {}
        for key, item in zip(keys, results):
            value = item.get("result") if isinstance(item, dict) else None
            out[key] = int(value) if value is not None else 0
        return out

    def reset(self) -> None:  # pragma: no cover - no-op in production
        pass


# ---------------------------------------------------------------------------
# Recorder / reader
# ---------------------------------------------------------------------------
class Analytics:
    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def configure(self, store: AnalyticsStore) -> None:
        self._store = store

    async def _safe_apply(self, increments: list[Increment]) -> None:
        """Best-effort write: a store error is swallowed so it never affects the
        user's response (we'd rather under-count than fail)."""
        try:
            await self._store.apply(increments)
        except Exception:  # noqa: BLE001
            pass

    async def record_check(
        self,
        *,
        verdict: str,
        heuristic_codes: Iterable[str],
        sources_checked: Iterable[str],
        sources_unavailable: Iterable[str],
        ai_cap_hit: bool,
        message_findings: int = 0,
    ) -> None:
        """Count one successful, valid check across every tracked dimension.

        Called only after a check has already succeeded, so invalid/failed
        requests never move the numbers. AI-ran vs template fallback is derived
        from whether the `ai` source landed in `sources_unavailable`.

        `message_findings` is the number of message-analysis findings produced
        (used only when that layer actually ran, to count the "flagged
        something" subset). It is ignored when no message was submitted.
        """
        day_ttl = config.ANALYTICS_DAILY_TTL_SECONDS
        checked = set(sources_checked)
        unavailable = set(sources_unavailable)

        increments: list[Increment] = [
            (K_CHECKS_TOTAL, 1, None),
            (checks_day_key(_today()), 1, day_ttl),
            (verdict_key(verdict), 1, None),
        ]
        # Which heuristics fired (by stable name). De-dupe in case a code repeats.
        for code in set(heuristic_codes):
            increments.append((heuristic_key(code), 1, None))
        # External source availability.
        for name in _EXTERNAL_SOURCES:
            if name in checked:
                increments.append((source_key(name, True), 1, None))
            elif name in unavailable:
                increments.append((source_key(name, False), 1, None))
        # AI ran vs template fallback (the `ai` summary source is the signal).
        if SOURCE_AI in unavailable:
            increments.append((K_AI_TEMPLATE, 1, None))
        else:
            increments.append((K_AI_RAN, 1, None))
        # AI hard-cap hit: the global daily AI budget was exhausted this request.
        if ai_cap_hit:
            increments.append((K_CAP_AI, 1, None))
        # Message-analysis layer health (only when a message was submitted, i.e.
        # the source landed in one of the lists). Separating this from the
        # summary counters is what makes a "it said safe on a scam message"
        # report answerable: was the message scanned at all, and did it flag
        # anything? When it ran, the synthetic "couldn't check" finding is never
        # present, so `message_findings` here only counts real scam signals.
        if SOURCE_AI_MESSAGE in checked:
            increments.append((K_MSG_RAN, 1, None))
            if message_findings > 0:
                increments.append((K_MSG_FOUND, 1, None))
        elif SOURCE_AI_MESSAGE in unavailable:
            increments.append((K_MSG_UNAVAILABLE, 1, None))

        await self._safe_apply(increments)

    async def record_free_cap_hit(self) -> None:
        """Count one request rejected by the per-IP daily free-tier cap."""
        await self._safe_apply([(K_CAP_FREE, 1, None)])

    # --- Reads (admin + public) ------------------------------------------
    async def snapshot(self) -> dict:
        """Full aggregate snapshot for the admin route. Read-only; no user data."""
        verdicts = ["safe", "suspicious", "dangerous"]
        keys: list[str] = [
            K_CHECKS_TOTAL,
            checks_day_key(_today()),
            K_AI_RAN,
            K_AI_TEMPLATE,
            K_MSG_RAN,
            K_MSG_UNAVAILABLE,
            K_MSG_FOUND,
            K_CAP_FREE,
            K_CAP_AI,
        ]
        keys += [verdict_key(v) for v in verdicts]
        keys += [heuristic_key(c) for c in HEURISTIC_CODES]
        for name in _EXTERNAL_SOURCES:
            keys += [source_key(name, True), source_key(name, False)]

        try:
            values = await self._store.get_many(keys)
        except Exception:  # noqa: BLE001
            values = {}

        def g(key: str) -> int:
            return int(values.get(key, 0))

        return {
            "checks": {
                "total": g(K_CHECKS_TOTAL),
                "today": g(checks_day_key(_today())),
            },
            "verdicts": {v: g(verdict_key(v)) for v in verdicts},
            "heuristics": {c: g(heuristic_key(c)) for c in HEURISTIC_CODES},
            "sources": {
                name: {
                    "available": g(source_key(name, True)),
                    "unavailable": g(source_key(name, False)),
                }
                for name in _EXTERNAL_SOURCES
            },
            "ai": {"ran": g(K_AI_RAN), "template_fallback": g(K_AI_TEMPLATE)},
            "message_analysis": {
                "ran": g(K_MSG_RAN),
                "unavailable": g(K_MSG_UNAVAILABLE),
                "found": g(K_MSG_FOUND),
            },
            "caps": {"free_tier_hit": g(K_CAP_FREE), "ai_hardcap_hit": g(K_CAP_AI)},
        }

    async def public_counters(self) -> dict:
        """The two public numbers, derived from the same counters.

        `links_checked` = all-time successful checks. `scams_flagged` = checks
        that came back suspicious or dangerous (anything not `safe`).
        """
        keys = [K_CHECKS_TOTAL, verdict_key("suspicious"), verdict_key("dangerous")]
        try:
            values = await self._store.get_many(keys)
        except Exception:  # noqa: BLE001
            values = {}
        flagged = int(values.get(verdict_key("suspicious"), 0)) + int(
            values.get(verdict_key("dangerous"), 0)
        )
        return {
            "links_checked": int(values.get(K_CHECKS_TOTAL, 0)),
            "scams_flagged": flagged,
        }

    def reset(self) -> None:
        self._store.reset()


def _make_store() -> AnalyticsStore:
    settings = get_settings()
    if settings.redis_enabled:
        return RedisAnalyticsStore(settings.redis_rest_url, settings.redis_rest_token)
    return MemoryAnalyticsStore()


# Process-wide singleton, built from the current settings (mirrors `limits.guard`).
analytics = Analytics(_make_store())
