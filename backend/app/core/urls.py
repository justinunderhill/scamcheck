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

    @property
    def labels(self) -> list[str]:
        """Dot-separated host labels (for subdomain-count heuristics)."""
        return [p for p in self.host.split(".") if p]


def normalize_url(raw: str) -> NormalizedURL:
    """Validate and normalize a user-supplied URL.

    - Trims whitespace; rejects empty input.
    - Adds an https:// scheme when none is present.
    - Accepts only http/https; rejects javascript:, file:, ftp:, etc.
    - Requires a host. Lowercases the host. Detects raw-IP hosts.
    """
    if raw is None:
        raise InvalidURLError("Please enter a link to check.")

    candidate = raw.strip()
    if not candidate:
        raise InvalidURLError("Please enter a link to check.")
    if any(c.isspace() for c in candidate):
        raise InvalidURLError("That doesn't look like a single link. Remove any spaces and try again.")

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
    normalized = urlunsplit((scheme, parts.netloc.lower(), parts.path, parts.query, ""))

    return NormalizedURL(
        input_url=raw.strip(),
        url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        subdomain=subdomain,
        registered_domain=registered_domain,
        suffix=suffix,
        is_ip=is_ip,
    )


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
