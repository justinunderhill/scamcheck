"""User tiers and feature gating (stubbed account system).

v1 has no real accounts. Tier is resolved from a request header so the gating
logic is real and exercised now; swapping in a proper account/auth lookup later
means changing only `resolve_tier`. Flipping a user's tier unlocks the paid
features without touching call sites — they all read `Features`.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from fastapi import Request


class Tier(str, Enum):
    FREE = "free"
    PAID = "paid"
    BUSINESS = "business"


@dataclass(frozen=True)
class Features:
    unlimited_checks: bool   # bypass the daily free-tier cap
    message_analysis: bool   # analyze the pasted `message` field
    followup: bool           # v2 conversational follow-up
    history: bool            # saved check history


_FEATURES: dict[Tier, Features] = {
    Tier.FREE: Features(unlimited_checks=False, message_analysis=False, followup=False, history=False),
    Tier.PAID: Features(unlimited_checks=True, message_analysis=True, followup=True, history=True),
    Tier.BUSINESS: Features(unlimited_checks=True, message_analysis=True, followup=True, history=True),
}

# Header used by the stub to simulate a logged-in tier. Replaced by real auth.
TIER_HEADER = "X-ScamCheck-Tier"


def features_for(tier: Tier) -> Features:
    return _FEATURES[tier]


def resolve_tier(request: Request) -> Tier:
    """Determine the caller's tier. STUB: trusts a header; default FREE.

    Real implementation will resolve an authenticated account here. Anything
    unrecognised falls back to FREE (fail safe — never grant paid features).
    """
    raw = (request.headers.get(TIER_HEADER) or "").strip().lower()
    try:
        return Tier(raw)
    except ValueError:
        return Tier.FREE
