"""Unit tests for the heuristics source. Pure logic — no network."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.urls import normalize_url
from app.models import Severity, Verdict
from app.services import heuristics as h
from app.services.heuristics import CertInfo


def sev(finding):
    return finding.severity if finding else None


# --- raw IP --------------------------------------------------------------

def test_raw_ip_flagged_high():
    f = h.check_raw_ip(normalize_url("http://203.0.113.5/login"))
    assert sev(f) == Severity.HIGH


def test_normal_domain_not_ip():
    assert h.check_raw_ip(normalize_url("https://example.com")) is None


# --- subdomains ----------------------------------------------------------

def test_excessive_subdomains_flagged():
    url = normalize_url("https://login.secure.verify.account.example.com")
    assert sev(h.check_excessive_subdomains(url)) == Severity.MEDIUM


def test_www_does_not_count():
    assert h.check_excessive_subdomains(normalize_url("https://www.example.com")) is None


def test_few_subdomains_ok():
    assert h.check_excessive_subdomains(normalize_url("https://api.example.com")) is None


# --- shortener -----------------------------------------------------------

def test_shortener_flagged_low_when_flagged():
    assert sev(h.check_shortener(normalize_url("https://bit.ly/x"), True)) == Severity.LOW


def test_shortener_silent_when_not():
    assert h.check_shortener(normalize_url("https://example.com"), False) is None


# --- suspicious TLD ------------------------------------------------------

def test_suspicious_tld_flagged():
    assert sev(h.check_suspicious_tld(normalize_url("https://login-paypal.zip"))) == Severity.LOW


def test_normal_tld_ok():
    assert h.check_suspicious_tld(normalize_url("https://example.com")) is None


# --- punycode / homograph ------------------------------------------------

def test_punycode_flagged_high():
    assert sev(h.check_punycode_homograph(normalize_url("https://xn--pple-43d.com"))) == Severity.HIGH


def test_unicode_homograph_flagged_high():
    # Cyrillic 'е' in place of latin 'e'.
    f = h.check_punycode_homograph(normalize_url("https://appе.com"))
    assert sev(f) == Severity.HIGH


def test_plain_ascii_not_homograph():
    assert h.check_punycode_homograph(normalize_url("https://example.com")) is None


# --- lookalike -----------------------------------------------------------

def test_legit_brand_domain_not_flagged():
    assert h.check_lookalike(normalize_url("https://paypal.com")) is None
    assert h.check_lookalike(normalize_url("https://amazon.co.uk")) is None


def test_leet_substitution_flagged():
    assert sev(h.check_lookalike(normalize_url("https://paypa1.com"))) == Severity.HIGH


def test_number_substitution_flagged():
    assert sev(h.check_lookalike(normalize_url("https://amaz0n.com"))) == Severity.HIGH


def test_typo_squat_flagged():
    assert sev(h.check_lookalike(normalize_url("https://paypall.com"))) == Severity.HIGH


def test_brand_in_subdomain_flagged():
    url = normalize_url("https://paypal.account-verify.ru")
    assert sev(h.check_lookalike(url)) == Severity.HIGH


def test_brand_plus_keyword_hyphen_flagged():
    assert sev(h.check_lookalike(normalize_url("https://paypal-secure.com"))) == Severity.HIGH
    assert sev(h.check_lookalike(normalize_url("https://amazon-support.net"))) == Severity.HIGH


def test_parcel_redelivery_scam_flagged():
    # Classic courier-impersonation parcel scam: brand + delivery/fee keywords.
    url = normalize_url("https://royalmail-redelivery-fee.online/pay")
    assert sev(h.check_lookalike(url)) == Severity.HIGH


def test_online_tld_is_suspicious():
    assert sev(h.check_suspicious_tld(normalize_url("https://royalmail-redelivery-fee.online"))) == Severity.LOW


def test_parcel_scam_compounds_to_dangerous():
    # Free-tier (heuristics-only) should reach a non-safe verdict on this pattern.
    from app.services.scoring import score_findings, verdict_for_score

    url = normalize_url("https://royalmail-redelivery-fee.online/pay")
    findings = h.check(
        url,
        registration_date_fn=lambda d: None,
        cert_info_fn=lambda u: CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    titles = {f.title for f in findings}
    assert "Pretends to be a known brand" in titles
    assert any("Unusual website ending" in t for t in titles)
    assert verdict_for_score(score_findings(findings)) != Verdict.SAFE


def test_brand_word_alone_not_flagged():
    # Contains a brand word but no phishing keyword and isn't a near-miss.
    assert h.check_lookalike(normalize_url("https://amazonbooks-fanclub.com")) is None


def test_unrelated_domain_not_flagged():
    assert h.check_lookalike(normalize_url("https://my-cool-startup.com")) is None


# --- domain age ----------------------------------------------------------

def test_brand_new_domain_high():
    reg = datetime.now(timezone.utc) - timedelta(days=2)
    assert sev(h.check_domain_age(normalize_url("https://example.com"), reg)) == Severity.HIGH


def test_recent_domain_medium():
    reg = datetime.now(timezone.utc) - timedelta(days=20)
    assert sev(h.check_domain_age(normalize_url("https://example.com"), reg)) == Severity.MEDIUM


def test_old_domain_silent():
    reg = datetime.now(timezone.utc) - timedelta(days=900)
    assert h.check_domain_age(normalize_url("https://example.com"), reg) is None


def test_unknown_age_silent():
    assert h.check_domain_age(normalize_url("https://example.com"), None) is None


def test_naive_datetime_handled():
    reg = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)  # naive
    assert sev(h.check_domain_age(normalize_url("https://example.com"), reg)) == Severity.HIGH


# --- HTTPS / cert --------------------------------------------------------

def test_http_flagged_medium():
    assert sev(h.check_https_cert(normalize_url("http://example.com"), None)) == Severity.MEDIUM


def test_valid_cert_silent():
    cert = CertInfo(checked=True, present=True, valid=True, expired=False)
    assert h.check_https_cert(normalize_url("https://example.com"), cert) is None


def test_expired_cert_flagged():
    cert = CertInfo(checked=True, present=True, valid=False, expired=True)
    assert sev(h.check_https_cert(normalize_url("https://example.com"), cert)) == Severity.MEDIUM


def test_uncheckable_cert_silent():
    cert = CertInfo(checked=False, present=False, valid=False, expired=False, error="timeout")
    assert h.check_https_cert(normalize_url("https://example.com"), cert) is None


# --- orchestration -------------------------------------------------------

def test_check_aggregates_and_injects_providers():
    url = normalize_url("https://paypa1.zip")
    findings = h.check(
        url,
        was_shortener=False,
        registration_date_fn=lambda d: datetime.now(timezone.utc) - timedelta(days=1),
        cert_info_fn=lambda u: CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    titles = {f.title for f in findings}
    # lookalike (paypa1 -> paypal), suspicious tld (.zip), brand-new domain.
    assert "Pretends to be a known brand" in titles
    assert any("Unusual website ending" in t for t in titles)
    assert "Very new website" in titles
    # All come from heuristics.
    assert all(f.source == "heuristics" for f in findings)


def test_check_survives_provider_errors():
    def boom(*_args, **_kwargs):
        raise RuntimeError("network down")

    url = normalize_url("https://example.com")
    # Should not raise; just yields no network-based findings.
    findings = h.check(url, registration_date_fn=boom, cert_info_fn=boom)
    assert isinstance(findings, list)


def test_clean_domain_yields_no_findings():
    url = normalize_url("https://github.com")
    findings = h.check(
        url,
        registration_date_fn=lambda d: datetime(2008, 1, 1, tzinfo=timezone.utc),
        cert_info_fn=lambda u: CertInfo(checked=True, present=True, valid=True, expired=False),
    )
    assert findings == []
