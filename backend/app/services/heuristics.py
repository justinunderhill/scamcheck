"""In-house heuristics detection source.

Pure logic (the easiest source to get wrong, so the most heavily tested). The
two checks that need the network — domain age (WHOIS) and the TLS certificate —
take their gathered data as arguments, so every check is unit-testable offline.

Public entry point:  check(url, ...) -> list[Finding]
matching the shared one-`check`-per-source convention.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable

from app.config import (
    HEURISTIC_DOMAIN_AGE_DANGER_DAYS,
    HEURISTIC_DOMAIN_AGE_WARN_DAYS,
    HEURISTIC_LOOKALIKE_MAX_EDIT_DISTANCE,
    HEURISTIC_MAX_SUBDOMAIN_LABELS,
)
from app.core.urls import NormalizedURL
from app.models import Finding, Severity
from app.models.schemas import SOURCE_HEURISTICS

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Leetspeak / number-for-letter substitutions used to disguise brand names.
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})

# Words that, combined with a brand name, strongly signal credential phishing.
_SCAM_KEYWORDS = frozenset({
    "secure", "security", "login", "signin", "logon", "verify", "verification",
    "account", "accounts", "update", "confirm", "confirmation", "support",
    "service", "billing", "payment", "alert", "suspended", "recovery", "unlock",
    "reset", "helpdesk", "customer", "auth",
    # Parcel/redelivery scam vocabulary (very common impersonation of couriers).
    "delivery", "redelivery", "parcel", "package", "fee", "fees", "shipping",
    "customs", "tracking",
})


def _finding(severity: Severity, title: str, detail: str, tip: str) -> Finding:
    return Finding(source=SOURCE_HEURISTICS, severity=severity, title=title, detail=detail, tip=tip)


@lru_cache(maxsize=1)
def _load_list(filename: str) -> frozenset[str]:
    path = _DATA_DIR / filename
    items: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            items.add(line)
    return frozenset(items)


def load_brands() -> frozenset[str]:
    return _load_list("brands.txt")


def load_suspicious_tlds() -> frozenset[str]:
    return _load_list("suspicious_tlds.txt")


# ---------------------------------------------------------------------------
# Pure checks
# ---------------------------------------------------------------------------

def check_raw_ip(url: NormalizedURL) -> Finding | None:
    if not url.is_ip:
        return None
    return _finding(
        Severity.HIGH,
        "Uses a numeric address instead of a name",
        "This link points straight to a numeric server address rather than a normal website name.",
        "Real companies use names like example.com, not raw numbers. Treat numeric links with suspicion.",
    )


def check_excessive_subdomains(url: NormalizedURL) -> Finding | None:
    if url.is_ip or not url.subdomain:
        return None
    sub_labels = [p for p in url.subdomain.split(".") if p]
    # "www" alone is normal and shouldn't count toward suspicion.
    meaningful = [p for p in sub_labels if p != "www"]
    if len(meaningful) <= HEURISTIC_MAX_SUBDOMAIN_LABELS:
        return None
    return _finding(
        Severity.MEDIUM,
        "Unusually complicated web address",
        "This address stacks many parts before the real site name, which can hide where it really goes.",
        "Scam links often bury a trustworthy-looking name in a long address. Check the part right before the first single slash.",
    )


def check_shortener(url: NormalizedURL, was_shortener: bool) -> Finding | None:
    if not was_shortener:
        return None
    return _finding(
        Severity.LOW,
        "Shortened link",
        "This was a shortened link that hides its real destination until you open it.",
        "Shortened links aren't bad by themselves, but they hide where you're going. Prefer links that show the full address.",
    )


def check_suspicious_tld(url: NormalizedURL) -> Finding | None:
    if url.is_ip or not url.suffix:
        return None
    # For multi-label suffixes (e.g. co.uk) the final label is what matters.
    final_label = url.suffix.rsplit(".", 1)[-1]
    if final_label not in load_suspicious_tlds():
        return None
    return _finding(
        Severity.LOW,
        f"Unusual website ending (.{final_label})",
        f"This site ends in .{final_label}, an ending that scammers use far more often than legitimate businesses.",
        "Be extra careful with uncommon endings, especially when you expected a well-known company.",
    )


def check_punycode_homograph(url: NormalizedURL) -> Finding | None:
    if url.is_ip:
        return None
    host = url.host

    if "xn--" in host:
        return _finding(
            Severity.HIGH,
            "Disguised web address",
            "This address uses encoded characters that can make a fake site look like a real one.",
            "Lookalike letters are a common trick. If you didn't type the address yourself, don't trust it.",
        )

    if any(ord(c) > 127 for c in host):
        try:
            from confusable_homoglyphs import confusables

            dangerous = confusables.is_dangerous(host)
        except Exception:  # noqa: BLE001 - never let the dependency break a check
            dangerous = True  # non-ASCII host we couldn't vet -> err toward caution
        if dangerous:
            return _finding(
                Severity.HIGH,
                "Lookalike characters in the address",
                "This address mixes in characters that look like ordinary letters but aren't, a trick used to imitate real sites.",
                "A web address that looks right but uses odd characters is a red flag. Type known addresses yourself.",
            )
    return None


def check_lookalike(url: NormalizedURL) -> Finding | None:
    """Detect domains imitating a known brand without being it.

    Deliberately conservative to avoid flagging legitimate domains that merely
    contain a brand word. Signals, strongest first:
      1. Brand name appears in a SUBDOMAIN while the real domain is unrelated.
      2. Leet/number-substituted domain that normalizes exactly to a brand.
      3. Domain within edit-distance 1 of a brand (typo-squat).
      4. Brand + a phishing keyword joined by hyphens.
    """
    if url.is_ip or not url.registered_domain:
        return None

    brands = load_brands()
    suffix_dot = f".{url.suffix}" if url.suffix else ""
    domain_label = url.registered_domain.removesuffix(suffix_dot) if suffix_dot else url.registered_domain
    domain_label = domain_label.lower()

    # If the domain label IS a brand, assume the brand owns it -> not a lookalike.
    if domain_label in brands:
        return None

    def lookalike_finding(brand: str, why: str) -> Finding:
        return _finding(
            Severity.HIGH,
            "Pretends to be a known brand",
            f"This address looks like it belongs to {brand.capitalize()} ({why}), but it isn't their real website.",
            "Scammers register addresses that resemble trusted brands. When in doubt, type the company's address yourself.",
        )

    # 1. Brand hiding in a subdomain (e.g. paypal.com.account-verify.ru).
    sub_tokens = {t for label in url.subdomain.split(".") for t in label.split("-") if t}
    for brand in brands:
        if brand in sub_tokens and domain_label != brand:
            return lookalike_finding(brand, "the brand name is in the address but isn't the real site")

    # 2. Leet/number substitution that resolves to a brand (paypa1 -> paypal).
    normalized = domain_label.translate(_LEET_MAP)
    if normalized != domain_label and normalized in brands:
        return lookalike_finding(normalized, "letters swapped for lookalike numbers or symbols")

    # 3. Edit-distance typo-squat (amaz0n already caught above; amazn / paypall here).
    for brand in brands:
        if len(brand) < 5:
            continue
        if abs(len(domain_label) - len(brand)) > 1:
            continue
        dist = _levenshtein(domain_label, brand)
        if 0 < dist <= HEURISTIC_LOOKALIKE_MAX_EDIT_DISTANCE:
            return lookalike_finding(brand, "a tiny misspelling of the real name")

    # 4. Brand + phishing keyword joined by hyphens (paypal-secure, amazon-support).
    tokens = [t for t in domain_label.split("-") if t]
    if len(tokens) > 1:
        token_set = set(tokens)
        brand_hit = next((b for b in brands if b in token_set), None)
        if brand_hit and (token_set & _SCAM_KEYWORDS):
            return lookalike_finding(brand_hit, "the brand name bundled with words like 'secure' or 'login'")

    return None


# ---------------------------------------------------------------------------
# Network-backed checks (data is passed in; gathering is injectable)
# ---------------------------------------------------------------------------

def check_domain_age(url: NormalizedURL, registration_date: datetime | None) -> Finding | None:
    if url.is_ip or registration_date is None:
        return None
    reg = registration_date
    if reg.tzinfo is None:
        reg = reg.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - reg).days
    if age_days < 0:
        return None  # clock skew / bad data — ignore rather than mislead

    if age_days < HEURISTIC_DOMAIN_AGE_DANGER_DAYS:
        severity = Severity.HIGH
    elif age_days < HEURISTIC_DOMAIN_AGE_WARN_DAYS:
        severity = Severity.MEDIUM
    else:
        return None

    when = "today" if age_days == 0 else f"{age_days} day{'s' if age_days != 1 else ''} ago"
    return _finding(
        severity,
        "Very new website",
        f"This website's address was first registered {when}. Scam sites are often brand new.",
        "Legitimate companies usually own their addresses for years. Be cautious with very new sites.",
    )


@dataclass(frozen=True)
class CertInfo:
    checked: bool          # did we attempt/obtain a result?
    present: bool          # a certificate was presented
    valid: bool            # presented AND validated (hostname + chain + dates)
    expired: bool
    error: str | None = None


def check_https_cert(url: NormalizedURL, cert: CertInfo | None) -> Finding | None:
    if url.scheme == "http":
        return _finding(
            Severity.MEDIUM,
            "Connection isn't private (no HTTPS)",
            "This site doesn't use a secure connection, so anything you type could be seen by others.",
            "Look for https and a padlock before entering passwords or payment details.",
        )
    # https
    if cert is None or not cert.checked:
        return None  # couldn't check — don't raise a false alarm
    if cert.valid and not cert.expired:
        return None
    if cert.expired:
        detail = "This site's security certificate has expired, so its identity can't be confirmed."
    elif not cert.present:
        detail = "This site claims to be secure but didn't provide a valid security certificate."
    else:
        detail = "This site's security certificate didn't check out, so its identity can't be confirmed."
    return _finding(
        Severity.MEDIUM,
        "Security certificate problem",
        detail,
        "A broken certificate can mean the site is misconfigured — or impersonating someone. Don't enter personal details.",
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def check(
    url: NormalizedURL,
    *,
    was_shortener: bool = False,
    registration_date_fn: Callable[[str], datetime | None] | None = None,
    cert_info_fn: Callable[[NormalizedURL], CertInfo | None] | None = None,
) -> list[Finding]:
    """Run every heuristic and return the findings that fired.

    `registration_date_fn` and `cert_info_fn` gather network data; they default
    to the real implementations and are injected with fakes in tests. Each is
    wrapped so a failure degrades to "no finding" rather than erroring the request.
    """
    registration_date_fn = registration_date_fn or lookup_registration_date
    cert_info_fn = cert_info_fn or get_cert_info

    try:
        reg_date = registration_date_fn(url.registered_domain) if not url.is_ip else None
    except Exception:  # noqa: BLE001
        reg_date = None
    try:
        cert = cert_info_fn(url) if url.scheme == "https" else None
    except Exception:  # noqa: BLE001
        cert = None

    candidates = [
        check_raw_ip(url),
        check_excessive_subdomains(url),
        check_shortener(url, was_shortener),
        check_suspicious_tld(url),
        check_punycode_homograph(url),
        check_lookalike(url),
        check_domain_age(url, reg_date),
        check_https_cert(url, cert),
    ]
    return [f for f in candidates if f is not None]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


# ---------------------------------------------------------------------------
# Real network providers (blocking; orchestrator runs check() in a thread).
# Never hit in tests — always mocked / injected.
# ---------------------------------------------------------------------------

def lookup_registration_date(registered_domain: str) -> datetime | None:
    """Best-effort WHOIS creation date. Returns None on any failure."""
    if not registered_domain:
        return None
    try:
        import whois  # python-whois

        data = whois.whois(registered_domain)
        created = data.creation_date if data else None
        if isinstance(created, list):
            created = next((d for d in created if isinstance(d, datetime)), None)
        return created if isinstance(created, datetime) else None
    except Exception:  # noqa: BLE001
        return None


def get_cert_info(url: NormalizedURL) -> CertInfo:
    """Validate the TLS certificate without fetching page content."""
    import socket
    import ssl

    from app.config import CERT_CHECK_TIMEOUT_SECONDS

    host = url.host
    port = url.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CERT_CHECK_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # A returned cert dict from a default context means the chain, hostname,
        # and validity window all passed.
        return CertInfo(checked=True, present=bool(cert), valid=True, expired=False)
    except ssl.SSLCertVerificationError as exc:
        expired = "expired" in str(exc).lower()
        return CertInfo(checked=True, present=True, valid=False, expired=expired, error="verify")
    except (socket.timeout, OSError) as exc:
        # Couldn't connect — don't assert anything about the cert.
        return CertInfo(checked=False, present=False, valid=False, expired=False, error=type(exc).__name__)
