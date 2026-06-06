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

# Free domain registries that hand out names under a shared second level. The
# visible TLD (e.g. ".ua", ".org") is legitimate, so the SUSPICIOUS_TLDS check
# (which only inspects the final label) never sees them — but the *full* suffix
# is a free, abuse-heavy space scammers favour because a host costs nothing and
# looks official. Matched against the host's ENDING (e.g. "biz.ua", "eu.org"),
# not the final label. Kept deliberately tight to the clearly-free spaces:
# regulated/paid second levels like com.ua, org.ua, net.ua, gov.ua, edu.ua are
# EXCLUDED to avoid flagging legitimate businesses.
#
# eu.org: a free subdomain service (run by a nonprofit) under the real .org TLD.
# tldextract parses "x.eu.org" with registered domain "eu.org" and suffix "org",
# so — like the .ua spaces — only host-ending matching catches it. It's a heavy
# home for throwaway phishing hosts (e.g. strw-v1-cl1.gogomailbali.it.eu.org).
ABUSED_HOST_SUFFIXES: frozenset[str] = frozenset({
    "biz.ua", "pp.ua", "co.ua", "in.ua", "eu.org",
})
