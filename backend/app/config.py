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
    # Web Risk is Google's current blocklist API (replacement for Safe Browsing
    # v4). Defaults to the Safe Browsing key so a single Google API key can serve
    # both — set separately only if you use a different key.
    web_risk_key: str = ""
    virustotal_key: str = ""
    anthropic_api_key: str = ""

    # --- Durable abuse store (Upstash Redis REST; serverless-friendly) ---
    # Accept both the Upstash integration's vars and the legacy Vercel KV vars.
    upstash_redis_rest_url: str = ""
    upstash_redis_rest_token: str = ""
    kv_rest_api_url: str = ""
    kv_rest_api_token: str = ""

    # Safety interlock: the AI layer only activates when a durable budget store
    # is configured (so the AI bill can't be exposed on serverless without a
    # working cap). Set true for single-process local dev to use AI without Redis.
    ai_allow_without_durable_budget: bool = False

    # --- Internal analytics ---
    # Secret token guarding GET /api/admin/analytics. When empty the admin route
    # is disabled entirely (responds 404), so analytics are never exposed by
    # accident. Set it to a long random string in production.
    admin_api_token: str = ""
    # Feature flag for the PUBLIC "links checked / scams flagged" counter
    # (GET /api/stats/public). OFF by default — the route 404s until this is
    # turned on. The numbers come from the same aggregate counters as the admin
    # view; no per-user data is involved either way.
    public_stats_enabled: bool = False

    # --- Development ---
    # Bypass abuse limits (per-IP short-window rate limit AND the daily free-tier
    # cap) so you can test freely on your own machine. Defaults OFF; never set in
    # production — it would remove all per-IP throttling. Does NOT touch the global
    # AI budget cap (that protects the bill regardless).
    dev_unlimited: bool = False

    # --- Server ---
    port: int = 8000
    # Origins allowed to call the API (the Vite dev server by default).
    cors_allow_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @property
    def redis_rest_url(self) -> str:
        return self.upstash_redis_rest_url or self.kv_rest_api_url

    @property
    def redis_rest_token(self) -> str:
        return self.upstash_redis_rest_token or self.kv_rest_api_token

    @property
    def redis_enabled(self) -> bool:
        return bool(self.redis_rest_url and self.redis_rest_token)

    @property
    def google_safe_browsing_enabled(self) -> bool:
        return bool(self.google_safe_browsing_key)

    @property
    def web_risk_effective_key(self) -> str:
        # Fall back to the Safe Browsing key (same Google project) if unset.
        return self.web_risk_key or self.google_safe_browsing_key

    @property
    def web_risk_enabled(self) -> bool:
        return bool(self.web_risk_effective_key)

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.virustotal_key)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def admin_analytics_enabled(self) -> bool:
        return bool(self.admin_api_token)


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
# Internal analytics (see docs/ANALYTICS.md)
# ---------------------------------------------------------------------------
# All analytics counter keys are aggregate integers under this namespace. We
# count categories only — never URLs or message text (see the "count, don't log"
# rule in docs/ANALYTICS.md). Counters share the durable Redis store with abuse
# protection but live under their own prefix so the two never collide.
ANALYTICS_KEY_PREFIX = "stats:"
# Per-day counters (e.g. checks on a given date) expire after this many seconds
# so day-bucketed keys don't accumulate forever; all-time totals never expire.
ANALYTICS_DAILY_TTL_SECONDS = 60 * 60 * 24 * 120  # ~120 days of daily history


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
    ("web_risk", "high"): 90,
    ("web_risk", "medium"): 60,
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
# WHOIS (domain-age) lookup timeout. python-whois has NO timeout of its own and
# blocks on the socket; a slow or unresponsive whois server (common for the
# dead/new domains scammers use) would otherwise stall the whole request for
# tens of seconds and squeeze the AI calls that run alongside it. Bounded hard
# at both the socket level and the orchestration level (see pipeline).
HEURISTIC_WHOIS_TIMEOUT_SECONDS = 4.0


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
# Stronger model reserved for message analysis (and v2 page analysis). Sonnet is
# kept for its false-positive discrimination (a measured win over Haiku on
# legitimate-but-urgent messages — see docs/DECISIONS.md 2026-06-06). The latency
# cost is its output volume, so the prompt asks for terse findings and the token
# ceiling is tight; that ~halves the call without changing the model.
AI_ANALYSIS_MODEL = "claude-sonnet-4-6"
AI_ANALYSIS_MAX_TOKENS = 400
# Network timeout for any single AI call.
AI_REQUEST_TIMEOUT_SECONDS = 12.0
# explain() outputs are cached on a hash of (verdict, findings) so identical
# results don't re-bill (see docs/PRICING.md cost control).
AI_EXPLAIN_CACHE_SIZE = 512
# Cap how many findings message analysis may add. Also bounds output volume
# (latency): a real scam trips the same few patterns, so the 4 strongest say
# everything the verdict needs without making the model write a long array.
AI_MESSAGE_MAX_FINDINGS = 4
