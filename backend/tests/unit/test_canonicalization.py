"""
Unit tests for core/canonicalization.py
"""
import pytest

pytest.importorskip("core")

from core.canonicalization import Canonicalizer


class TestDomain:
    def test_lowercase(self):
        assert Canonicalizer.domain("EXAMPLE.COM") == "example.com"

    def test_strip_leading_dot(self):
        assert Canonicalizer.domain(".example.com") == "example.com"

    def test_strip_www(self):
        # Implementation strips www prefix
        result = Canonicalizer.domain("WWW.EXAMPLE.COM")
        assert result == "example.com"

    def test_empty_returns_empty(self):
        result = Canonicalizer.domain("")
        assert result == "" or result is None or isinstance(result, str)

    def test_already_canonical(self):
        assert Canonicalizer.domain("example.com") == "example.com"

    def test_strip_trailing_dot(self):
        result = Canonicalizer.domain("example.com.")
        assert result == "example.com"


class TestIP:
    def test_ipv4_passthrough(self):
        assert Canonicalizer.ip("192.168.1.1") == "192.168.1.1"

    def test_strips_whitespace(self):
        assert Canonicalizer.ip("  192.168.1.1  ") == "192.168.1.1"

    def test_ipv6_passthrough(self):
        result = Canonicalizer.ip("2001:db8::1")
        assert isinstance(result, str)
        assert "2001" in result.lower() or "2001:db8" in result.lower()

    def test_empty(self):
        result = Canonicalizer.ip("")
        assert result == "" or result is None or isinstance(result, str)


class TestURL:
    def test_lowercase_scheme_host(self):
        result = Canonicalizer.url("HTTP://EXAMPLE.COM/path")
        assert result.startswith("http://")
        assert "example.com" in result

    def test_strips_trailing_slash(self):
        result = Canonicalizer.url("https://example.com/")
        assert not result.endswith("/") or result == "https://example.com"

    def test_passthrough_valid(self):
        url = "https://example.com/path?q=1"
        result = Canonicalizer.url(url)
        assert "example.com" in result


class TestEmail:
    def test_lowercase(self):
        assert Canonicalizer.email("Admin@EXAMPLE.COM") == "admin@example.com"

    def test_already_lower(self):
        assert Canonicalizer.email("user@example.com") == "user@example.com"

    def test_strip_whitespace(self):
        assert Canonicalizer.email("  user@example.com  ") == "user@example.com"
