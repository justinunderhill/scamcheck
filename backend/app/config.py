"""Central configuration for ScamCheck.

Every tunable knob lives here so limits, weights, and thresholds can be tuned
with real-world data without hunting through the codebase. Secrets come from the
environment (never hardcoded); everything else has a sensible default.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings, loaded from environment / .env.

    Only secrets and deployment-specific values are read from the environment.
    Behavioural constants (limits, weights, thresholds) are class attributes
    below so they are visible and reviewable in one place.
    """

    model_config = SettingsConfigDict(
        # The .env lives at the repo root, one level above backend/.
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Secrets (backend only; never sent to the frontend) ---
    google_safe_browsing_key: str = ""
    virustotal_key: str = ""
    anthropic_api_key: str = ""

    # --- Server ---
    port: int = 8000
    # Origins allowed to call the API (the Vite dev server by default).
    cors_allow_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @property
    def google_safe_browsing_enabled(self) -> bool:
        return bool(self.google_safe_browsing_key)

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.virustotal_key)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()


# ---------------------------------------------------------------------------
# Tiers & abuse protection (see docs/PRICING.md)
# ---------------------------------------------------------------------------

# Free tier: a few frictionless, account-free checks per IP per day.
FREE_TIER_CHECKS_PER_DAY = 5

# Per-IP rate limit on POST /api/check (short-window throttle, separate from the
# daily free-tier cap above). Protects against bursts/scraping.
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60

# Hard global ceiling on AI calls per day across ALL users. Once exceeded we
# fall back to deterministic-only results so scripted abuse can't run up the
# AI bill. The verdict + findings are unaffected — only the AI summary is.
AI_DAILY_CALL_CAP = 2000


# ---------------------------------------------------------------------------
# Scoring (see docs/DECISIONS.md for rationale)
# ---------------------------------------------------------------------------
# Verdict thresholds on the 0-100 risk score (higher = riskier).
SCORE_SUSPICIOUS_THRESHOLD = 30
SCORE_DANGEROUS_THRESHOLD = 70

# Risk points contributed by one finding, keyed by (source, severity). The score
# is the capped sum of all findings' weights. External blocklist hits are heavy
# enough to reach `dangerous` on their own; heuristics are lighter and compound.
# AI findings only ever ADD weight, so the AI layer can only escalate (never
# soften) the deterministic verdict — see the escalate-only rule in CLAUDE.md.
SCORE_WEIGHTS: dict[tuple[str, str], int] = {
    ("google_safe_browsing", "high"): 90,
    ("google_safe_browsing", "medium"): 60,
    ("virustotal", "high"): 80,
    ("virustotal", "medium"): 45,
    ("ai_message_analysis", "high"): 50,
    ("ai_message_analysis", "medium"): 30,
    ("ai_message_analysis", "low"): 15,
    ("heuristics", "high"): 35,
    ("heuristics", "medium"): 20,
    ("heuristics", "low"): 8,
}
# Fallback if a source/severity pair isn't in the table above.
SCORE_DEFAULT_WEIGHTS: dict[str, int] = {"high": 35, "medium": 18, "low": 8}


# ---------------------------------------------------------------------------
# Heuristics thresholds (see backend/app/services/HEURISTICS_SPEC.md)
# ---------------------------------------------------------------------------
# Domain age: newer = riskier.
HEURISTIC_DOMAIN_AGE_DANGER_DAYS = 7    # < this -> high severity
HEURISTIC_DOMAIN_AGE_WARN_DAYS = 30     # < this -> medium severity
# Subdomains: more than this many sub-labels (excluding the registered domain)
# is "excessive" — a common trick to hide the real domain.
HEURISTIC_MAX_SUBDOMAIN_LABELS = 3
# Lookalike: max edit distance from a brand to count as a typo-squat.
HEURISTIC_LOOKALIKE_MAX_EDIT_DISTANCE = 1
# Cert check network timeout.
CERT_CHECK_TIMEOUT_SECONDS = 5.0


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------
# Safe shortener expansion: HEAD-follow redirects only, never render content.
SHORTENER_EXPAND_TIMEOUT_SECONDS = 5.0
SHORTENER_MAX_REDIRECTS = 5
# A neutral UA so we aren't mistaken for a browser fetching the page.
URL_FETCH_USER_AGENT = "ScamCheck/0.1 (+https://scamcheck.example; link-safety-checker)"


# ---------------------------------------------------------------------------
# AI model selection (see backend/app/services/AI_SPEC.md)
# ---------------------------------------------------------------------------
# Fast, cheap model for the per-request explanation layer.
AI_EXPLAIN_MODEL = "claude-haiku-4-5-20251001"
AI_EXPLAIN_MAX_TOKENS = 400
# Stronger model reserved for message analysis (and v2 page analysis).
AI_ANALYSIS_MODEL = "claude-sonnet-4-6"
AI_ANALYSIS_MAX_TOKENS = 700
# Network timeout for any single AI call.
AI_REQUEST_TIMEOUT_SECONDS = 12.0
# explain() outputs are cached on a hash of (verdict, findings) so identical
# results don't re-bill (see docs/PRICING.md cost control).
AI_EXPLAIN_CACHE_SIZE = 512
# Cap how many findings message analysis may add (keeps output bounded).
AI_MESSAGE_MAX_FINDINGS = 5
