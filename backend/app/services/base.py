"""Shared types for detection sources.

Each source module exposes an async `check(url, client)` returning a normalized
list[Finding], and may raise SourceUnavailable to signal graceful degradation.
The orchestrator catches it, records the source under `sources_unavailable`, and
returns results from the sources that did work (CLAUDE.md fail-gracefully rule).
"""
from __future__ import annotations


class SourceUnavailable(Exception):
    """A detection source couldn't produce a result (down, rate-limited, unconfigured)."""

    def __init__(self, source: str, reason: str) -> None:
        super().__init__(f"{source} unavailable: {reason}")
        self.source = source
        self.reason = reason
