"""
Tests for core/identity.py — Canonical identity system.
"""
from core.identity import (
    normalize_domain,
    normalize_subdomain,
    normalize_ip,
    normalize_url,
    normalize_email,
    normalize_asn,
    normalize_org,
    normalize_value,
    make_entity_id,
    make_relationship_id,
    infer_entity_type,
)


class TestNormalizeDomain:
    def test_lowercase_and_strip(self):
        assert normalize_domain("  EXAMPLE.COM.  ") == "example.com"

    def test_trailing_dot_removed(self):
        assert normalize_domain("hcmute.edu.vn.") == "hcmute.edu.vn"

    def test_idna_passthrough(self):
        result = normalize_domain("example.com")
        assert result == "example.com"


class TestNormalizeSubdomain:
    def test_preserves_www(self):
        assert normalize_subdomain("WWW.example.com") == "www.example.com"

    def test_lowercase(self):
        assert normalize_subdomain("Api.HCMUTE.EDU.VN") == "api.hcmute.edu.vn"


class TestNormalizeIP:
    def test_valid_ipv4(self):
        assert normalize_ip("  203.113.147.181  ") == "203.113.147.181"

    def test_invalid_returns_stripped(self):
        assert normalize_ip("  not_an_ip  ") == "not_an_ip"


class TestNormalizeUrl:
    def test_lowercase_scheme_host(self):
        result = normalize_url("HTTPS://Example.COM/Path?q=1")
        assert result == "https://example.com/Path?q=1"

    def test_strip_trailing_slash(self):
        result = normalize_url("https://example.com/page/")
        assert result == "https://example.com/page"

    def test_root_path_kept(self):
        result = normalize_url("https://example.com/")
        assert result == "https://example.com/"


class TestNormalizeEmail:
    def test_lowercase(self):
        assert normalize_email("  Admin@HCMUTE.edu.vn ") == "admin@hcmute.edu.vn"


class TestNormalizeASN:
    def test_prepend_as(self):
        assert normalize_asn("45899") == "AS45899"

    def test_already_prefixed(self):
        assert normalize_asn("as45899") == "AS45899"

    def test_uppercase(self):
        assert normalize_asn("AS12345") == "AS12345"


class TestNormalizeOrg:
    def test_strip_suffixes(self):
        result = normalize_org("Acme Corp.")
        assert "corp" not in result
        assert result == "acme"

    def test_spaces_to_hyphens(self):
        result = normalize_org("Ho Chi Minh City University")
        assert " " not in result
        assert result == "ho-chi-minh-city-university"


class TestNormalizeValue:
    def test_routes_domain(self):
        assert normalize_value("domain", "EXAMPLE.COM") == "example.com"

    def test_routes_ip(self):
        assert normalize_value("ip_address", "10.0.0.1") == "10.0.0.1"

    def test_unknown_type_lowered(self):
        assert normalize_value("random_type", "  FOO  ") == "foo"


class TestMakeEntityId:
    def test_domain(self):
        assert make_entity_id("domain", "EXAMPLE.COM") == "domain:example.com"

    def test_subdomain(self):
        assert make_entity_id("subdomain", "Api.Example.com") == "subdomain:api.example.com"

    def test_ip_address_short_prefix(self):
        assert make_entity_id("ip_address", "10.0.0.1") == "ip:10.0.0.1"

    def test_email_short_prefix(self):
        assert make_entity_id("email_address", "A@B.COM") == "email:a@b.com"

    def test_asn(self):
        assert make_entity_id("asn", "12345") == "asn:AS12345"

    def test_stable_across_calls(self):
        id1 = make_entity_id("subdomain", "WWW.example.com")
        id2 = make_entity_id("subdomain", "www.EXAMPLE.com")
        assert id1 == id2


class TestMakeRelationshipId:
    def test_format(self):
        rid = make_relationship_id("ip:10.0.0.1", "resolves_to", "subdomain:a.example.com")
        assert rid == "rel:ip:10.0.0.1--resolves_to--subdomain:a.example.com"


class TestInferEntityType:
    def test_url(self):
        assert infer_entity_type("https://example.com/page") == "url"

    def test_ip(self):
        assert infer_entity_type("192.168.1.1") == "ip_address"

    def test_service_ip_port(self):
        assert infer_entity_type("10.0.0.1:443") == "service"

    def test_asn(self):
        assert infer_entity_type("AS45899") == "asn"

    def test_email(self):
        assert infer_entity_type("admin@example.com") == "email_address"

    def test_domain(self):
        assert infer_entity_type("example.com") == "domain"

    def test_subdomain(self):
        assert infer_entity_type("api.example.com") == "subdomain"

    def test_unknown(self):
        assert infer_entity_type("???") == "unknown"
