"""Seed lists for detection (shorteners, impersonated brands, abused TLDs).

Kept as Python constants rather than loose data files so they bundle reliably
into serverless functions (no runtime file I/O). Still trivial to extend — just
edit the relevant set. Documented in docs/DECISIONS.md.
"""
from __future__ import annotations

# Known URL-shortener domains — expanded (via safe HEAD redirects) before checks.
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in",
    "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "t.ly", "tiny.cc",
    "tinyurl.com", "trib.al", "v.gd",
})

# Commonly impersonated brands (token only, lowercase) for lookalike detection.
# Keep these distinctive — short common words cause false positives.
BRANDS: frozenset[str] = frozenset({
    "amazon", "americanexpress", "apple", "bankofamerica", "binance", "chase",
    "citibank", "coinbase", "docusign", "dhl", "dropbox", "ebay", "facebook",
    "fedex", "google", "hmrc", "hsbc", "instagram", "irs", "linkedin",
    "mastercard", "metamask", "microsoft", "netflix", "outlook", "paypal",
    "royalmail", "santander", "steamcommunity", "tiktok", "ups", "usps",
    "verizon", "visa", "walmart", "wellsfargo", "whatsapp",
})

# TLDs disproportionately abused in phishing/scams (weak signal; compounds).
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "bid", "cam", "cf", "click", "country", "cricket", "date", "download",
    "faith", "ga", "gdn", "gq", "icu", "kim", "link", "loan", "men", "ml",
    "mov", "online", "party", "quest", "racing", "review", "rest", "science",
    "stream", "support", "surf", "tk", "top", "trade", "webcam", "win", "work",
    "xyz", "zip",
})
