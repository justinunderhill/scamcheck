"""URL validation, normalization, and safe shortener expansion.

Shared plumbing used before any detection runs. NOT a detection source — it
lives in core/, not services/. Two jobs:

  1. normalize_url(raw)  -> NormalizedURL  (validate + parse, pure/sync)
  2. expand_url(url)     -> ExpandResult   (follow shortener redirects SAFELY)

Safety: expansion uses HEAD requests and never executes or renders page
content (CLAUDE.md ethics rule). We only read the redirect chain's final URL.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx
import tldextract

from app.config import (
    SHORTENER_EXPAND_TIMEOUT_SECONDS,
    SHORTENER_MAX_REDIRECTS,
    URL_FETCH_USER_AGENT,
)
from app.seedlists import SHORTENERS

ALLOWED_SCHEMES = {"http", "https"}

# A bare email address: localpart@domain, no scheme, no path/port/query/fragment,
# and a domain with at least one dot. Used to tell "check this email's sender
# domain" apart from a URL — see docs/DECISIONS.md (email-input handling).
_EMAIL_RE = re.compile(r"^[^\s@/:?#]+@[^\s@/:?#]+\.[^\s@/:?#]+$")

# Offline extractor: use the bundled public-suffix snapshot, never fetch from
# the network (keeps tests/CI hermetic). Refresh the snapshot via a dep bump.
_extract = tldextract.TLDExtract(suffix_list_urls=())


class InvalidURLError(ValueError):
    """Raised when input can't be understood as an http(s) URL."""


@dataclass(frozen=True)
class NormalizedURL:
    input_url: str          # exactly what the user submitted (trimmed)
    url: str                # normalized, with scheme
    scheme: str
    host: str               # hostname, lowercased (no port)
    port: int | None
    path: str
    subdomain: str          # e.g. "login.secure" for login.secure.example.com
    registered_domain: str  # e.g. "example.com" (eTLD+1)
    suffix: str             # e.g. "com", "co.uk"
    is_ip: bool             # host is a raw IP literal
    # The userinfo portion before any '@' in the authority (e.g. "instagram.com"
    # in instagram.com@evil.com). Kept separate from the true host so the @-in-URL
    # heuristic can flag it; "" when absent. The normalized `url` never includes it.
    userinfo: str = ""
    # Set when the input was a bare email address; we then check `host` (the
    # email's domain) and label the result accordingly. `email_address` is the
    # original address, echoed back to the user.
    is_email: bool = False
    email_address: str | None = None

    @property
    def labels(self) -> list[str]:
        """Dot-separated host labels (for subdomain-count heuristics)."""
        return [p for p in self.host.split(".") if p]


def looks_like_email(raw: str) -> bool:
    """True if the input is a bare email address rather than a URL.

    An email is `localpart@domain` with no scheme and no path. We classify before
    normalising so `name@domain` is checked as its DOMAIN — never coerced into
    `https://name@domain`, which would bury the real domain in userinfo and could
    yield a misleading "safe". See docs/DECISIONS.md (email-input handling).
    """
    candidate = raw.strip()
    if "://" in candidate:
        return False  # a real URL (possibly with userinfo), not an email
    return bool(_EMAIL_RE.match(candidate))


def normalize_url(raw: str) -> NormalizedURL:
    """Validate and normalize a user-supplied URL (or email address).

    - Trims whitespace; rejects empty input.
    - Detects a bare email address and checks its DOMAIN instead (never rewrites
      it into a userinfo URL).
    - Adds an https:// scheme when none is present.
    - Accepts only http/https; rejects javascript:, file:, ftp:, etc.
    - Requires a host. Lowercases the host. Detects raw-IP hosts.
    - Strips any userinfo before an '@' from the normalized URL so every
      downstream check and blocklist lookup runs against the TRUE host.
    """
    if raw is None:
        raise InvalidURLError("Please enter a link to check.")

    input_url = raw.strip()
    if not input_url:
        raise InvalidURLError("Please enter a link to check.")
    if any(c.isspace() for c in input_url):
        raise InvalidURLError("That doesn't look like a single link. Remove any spaces and try again.")

    # Email input: peel off the localpart and check the sender's domain. Doing
    # this first means the '@' is never interpreted as URL userinfo.
    email_address: str | None = None
    candidate = input_url
    if looks_like_email(candidate):
        email_address = candidate
        candidate = candidate.rpartition("@")[2]  # the domain we'll actually check

    # If there's no scheme, assume https. We detect a scheme by the "://"
    # marker; a bare "example.com/path" has none. Reject non-web schemes early.
    if "://" not in candidate:
        if ":" in candidate.split("/", 1)[0]:
            # Looks like "scheme:something" without "//", e.g. javascript:...
            scheme_guess = candidate.split(":", 1)[0].lower()
            if scheme_guess not in ALLOWED_SCHEMES:
                raise InvalidURLError("Only http and https links can be checked.")
        candidate = "https://" + candidate

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError("Only http and https links can be checked.")

    host = (parts.hostname or "").lower()
    if not host:
        raise InvalidURLError("That doesn't look like a valid web address.")

    # Userinfo is everything before the LAST '@' in the authority; the real host
    # is what follows it (browsers honour this). We keep userinfo only to flag it
    # and never let it into the normalized URL handed to blocklists.
    userinfo = parts.netloc.rpartition("@")[0]

    is_ip = _is_ip_literal(host)

    if is_ip:
        subdomain = registered_domain = suffix = ""
    else:
        ext = _extract(host)
        subdomain = ext.subdomain
        registered_domain = ext.top_domain_under_public_suffix or ""
        suffix = ext.suffix
        # A hostname with no recognised public suffix and no IP is malformed
        # (e.g. "localhost" or a typo'd bare word). Reject clearly.
        if not suffix and "." not in host:
            raise InvalidURLError("That doesn't look like a complete web address.")

    port = parts.port
    path = parts.path or "/"
    normalized = urlunsplit((scheme, _authority(host, port, is_ip), parts.path, parts.query, ""))

    return NormalizedURL(
        input_url=input_url,
        url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        subdomain=subdomain,
        registered_domain=registered_domain,
        suffix=suffix,
        is_ip=is_ip,
        userinfo=userinfo,
        is_email=email_address is not None,
        email_address=email_address,
    )


def _authority(host: str, port: int | None, is_ip: bool) -> str:
    """Rebuild the authority from the true host only (no userinfo).

    IPv6 literals need bracketing; an explicit port is preserved.
    """
    h = f"[{host}]" if is_ip and ":" in host else host
    return f"{h}:{port}" if port is not None else h


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip("[]")  # IPv6 literals arrive bracketed
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def load_shorteners() -> frozenset[str]:
    """The known-shortener domains (see app/seedlists.py)."""
    return SHORTENERS


def is_shortener(host: str) -> bool:
    """True if the host (or its registered domain) is a known shortener."""
    host = host.lower()
    if host in load_shorteners():
        return True
    ext = _extract(host)
    return (ext.top_domain_under_public_suffix or "") in load_shorteners()


@dataclass(frozen=True)
class ExpandResult:
    final_url: str
    was_shortener: bool   # input host was a known shortener
    expanded: bool        # we successfully resolved to a different final URL
    error: str | None = None


async def expand_url(normalized: NormalizedURL) -> ExpandResult:
    """If the URL is a known shortener, safely resolve its destination.

    Uses HEAD and follows the redirect chain; never downloads or renders the
    page body. On any failure we degrade gracefully and return the original URL
    so the rest of the pipeline can still run.
    """
    if not is_shortener(normalized.host):
        return ExpandResult(final_url=normalized.url, was_shortener=False, expanded=False)

    headers = {"User-Agent": URL_FETCH_USER_AGENT}
    timeout = httpx.Timeout(SHORTENER_EXPAND_TIMEOUT_SECONDS)
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=SHORTENER_MAX_REDIRECTS,
            timeout=timeout,
            headers=headers,
        ) as client:
            resp = await client.head(normalized.url)
            # Some shorteners reject HEAD; retry as a streamed GET but never
            # read the body (we only want the resolved final URL).
            if resp.status_code in (403, 405, 501):
                async with client.stream("GET", normalized.url) as streamed:
                    final_url = str(streamed.url)
            else:
                final_url = str(resp.url)
    except httpx.HTTPError as exc:
        return ExpandResult(
            final_url=normalized.url,
            was_shortener=True,
            expanded=False,
            error=type(exc).__name__,
        )

    return ExpandResult(
        final_url=final_url,
        was_shortener=True,
        expanded=final_url != normalized.url,
    )
