"""Tests for URL normalization, validation, and safe shortener expansion."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.core.urls import (
    InvalidURLError,
    expand_url,
    is_shortener,
    normalize_url,
)


# --- normalization -------------------------------------------------------

def test_adds_https_when_scheme_missing():
    n = normalize_url("example.com/login")
    assert n.url == "https://example.com/login"
    assert n.scheme == "https"
    assert n.host == "example.com"
    assert n.registered_domain == "example.com"
    assert n.suffix == "com"
    assert n.is_ip is False


def test_lowercases_host_keeps_path_case():
    n = normalize_url("HTTPS://Example.COM/MyPath")
    assert n.host == "example.com"
    assert n.path == "/MyPath"


def test_parses_subdomain_and_registered_domain():
    n = normalize_url("https://login.secure.example.co.uk/x")
    assert n.registered_domain == "example.co.uk"
    assert n.subdomain == "login.secure"
    assert n.suffix == "co.uk"
    # login . secure . example . co . uk
    assert len(n.labels) == 5


def test_detects_raw_ipv4_host():
    n = normalize_url("http://192.168.0.1/admin")
    assert n.is_ip is True
    assert n.host == "192.168.0.1"
    assert n.registered_domain == ""


def test_detects_ipv6_host():
    n = normalize_url("http://[2001:db8::1]/")
    assert n.is_ip is True


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_rejects_empty(bad):
    with pytest.raises(InvalidURLError):
        normalize_url(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "file:///etc/passwd", "ftp://host/x"])
def test_rejects_non_web_schemes(bad):
    with pytest.raises(InvalidURLError):
        normalize_url(bad)


def test_rejects_input_with_spaces():
    with pytest.raises(InvalidURLError):
        normalize_url("http://exam ple.com")


def test_rejects_bare_word():
    with pytest.raises(InvalidURLError):
        normalize_url("localhost")


# --- shortener detection -------------------------------------------------

def test_is_shortener_known():
    assert is_shortener("bit.ly") is True
    assert is_shortener("tinyurl.com") is True


def test_is_shortener_false_for_normal_domain():
    assert is_shortener("example.com") is False
    assert is_shortener("github.com") is False


# --- safe expansion ------------------------------------------------------

@respx.mock
async def test_expand_resolves_shortener_via_head():
    final = "https://real-destination.example.org/landing"
    respx.head("https://bit.ly/abc123").mock(
        return_value=httpx.Response(301, headers={"location": final})
    )
    respx.head(final).mock(return_value=httpx.Response(200))

    n = normalize_url("https://bit.ly/abc123")
    result = await expand_url(n)

    assert result.was_shortener is True
    assert result.expanded is True
    assert result.final_url == final


@respx.mock
async def test_expand_non_shortener_is_noop():
    n = normalize_url("https://example.com/page")
    result = await expand_url(n)
    assert result.was_shortener is False
    assert result.expanded is False
    assert result.final_url == "https://example.com/page"


@respx.mock
async def test_expand_degrades_gracefully_on_error():
    respx.head("https://bit.ly/dead").mock(side_effect=httpx.ConnectError("boom"))
    n = normalize_url("https://bit.ly/dead")
    result = await expand_url(n)
    # Falls back to the original URL; never raises.
    assert result.was_shortener is True
    assert result.expanded is False
    assert result.final_url == "https://bit.ly/dead"
    assert result.error is not None
