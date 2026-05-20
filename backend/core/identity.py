"""
core/identity.py — Canonical identity for all MINA entities.

All entity IDs follow the pattern: {type}:{normalized_value}
Examples:
  domain:hcmute.edu.vn
  subdomain:dkmh.hcmute.edu.vn
  ip:203.113.147.181
  service:203.113.147.181:443
  url:https://dkmh.hcmute.edu.vn/login
  asn:AS45899
  email:admin@hcmute.edu.vn
  org:ho-chi-minh-city-university-of-technology-and-education
  repo:github.com/hcmute/repo
  doc:https://hcmute.edu.vn/document.pdf

Rules:
  - entity_id is STABLE — never changes once emitted
  - entity_id = make_entity_id(type, canonical_value)
  - normalize before making ID (lowercase domain, strip spaces)
  - never use uuid for entities that have a real identity
"""

import re
import socket
from urllib.parse import urlparse


# ── Type normalizers ────────────────────────────────────────────────────────

def normalize_domain(value: str) -> str:
    """Lowercase, strip dots, strip www, IDNA-safe."""
    v = value.strip().lower().rstrip(".")
    # DO NOT strip www — keep as is for subdomains, only strip for root domain type
    try:
        v = v.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return v


def normalize_subdomain(value: str) -> str:
    """Same as domain — subdomains are domains too."""
    return normalize_domain(value)


def normalize_ip(value: str) -> str:
    """Validate and normalize IPv4 address."""
    v = value.strip()
    try:
        return socket.inet_ntoa(socket.inet_aton(v))
    except socket.error:
        return v


def normalize_url(value: str) -> str:
    """Normalize URL: lowercase scheme+host, preserve path/query."""
    try:
        parsed = urlparse(value.strip())
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        result = f"{scheme}://{netloc}{path}"
        if parsed.query:
            result += f"?{parsed.query}"
        return result
    except Exception:
        return value.strip().lower()


def normalize_service(host: str, port: int) -> str:
    """Canonical service ID: normalized_ip:port"""
    return f"{normalize_ip(host)}:{port}"


def normalize_email(value: str) -> str:
    return value.strip().lower()


def normalize_org(value: str) -> str:
    v = value.strip().lower()
    for suffix in [", inc", ", ltd", ", llc", " inc.", " ltd.", " corp.", " corporation", " co."]:
        v = v.replace(suffix, "")
    # Replace spaces/special chars with hyphens for stable ID
    v = re.sub(r"[^a-z0-9]+", "-", v).strip("-")
    return v


def normalize_asn(value: str) -> str:
    """Normalize ASN: AS12345"""
    v = value.strip().upper()
    if not v.startswith("AS"):
        # Might be just the number
        if v.isdigit():
            v = f"AS{v}"
    return v


def normalize_repo(value: str) -> str:
    """Normalize repo URL: strip scheme, lowercase."""
    v = value.strip().lower()
    for prefix in ("https://", "http://", "git://", "ssh://"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.rstrip("/")


def normalize_value(entity_type: str, value: str) -> str:
    """Route to correct normalizer by type."""
    handlers = {
        "domain":         normalize_domain,
        "subdomain":      normalize_subdomain,
        "ip_address":     normalize_ip,
        "ip":             normalize_ip,
        "url":            normalize_url,
        "endpoint":       normalize_url,
        "email_address":  normalize_email,
        "email":          normalize_email,
        "organization":   normalize_org,
        "asn":            normalize_asn,
        "repository":     normalize_repo,
        "repo":           normalize_repo,
    }
    fn = handlers.get(entity_type, lambda v: v.strip().lower())
    return fn(value)


# ── Canonical entity ID ─────────────────────────────────────────────────────

def make_entity_id(entity_type: str, value: str) -> str:
    """
    Create a stable, canonical entity ID.

    Pattern: {type}:{normalized_value}

    Examples:
      make_entity_id("subdomain", "DKMH.hcmute.edu.vn") → "subdomain:dkmh.hcmute.edu.vn"
      make_entity_id("ip_address", "203.113.147.181") → "ip:203.113.147.181"
      make_entity_id("service", "203.113.147.181:443") → "service:203.113.147.181:443"
    """
    # Normalize entity type for ID prefix (use short forms)
    type_prefix_map = {
        "ip_address":     "ip",
        "ip":             "ip",
        "email_address":  "email",
        "email":          "email",
        "organization":   "org",
        "endpoint":       "url",
        "repository":     "repo",
    }
    prefix = type_prefix_map.get(entity_type, entity_type)
    norm = normalize_value(entity_type, value)
    return f"{prefix}:{norm}"


def make_relationship_id(from_entity_id: str, relation_type: str, to_entity_id: str) -> str:
    """Stable relationship ID based on canonical entity IDs."""
    return f"rel:{from_entity_id}--{relation_type}--{to_entity_id}"


def infer_entity_type(value: str) -> str:
    """
    Infer entity type from value format.
    Used when type context is not available.
    """
    v = value.strip().lower()

    # URL
    if v.startswith(("http://", "https://", "ftp://")):
        return "url"

    # IP
    try:
        socket.inet_aton(v)
        return "ip_address"
    except socket.error:
        pass

    # IP:port
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", v):
        return "service"

    # host:port
    if re.match(r"^[a-z0-9._-]+:\d+$", v):
        return "service"

    # ASN
    if re.match(r"^as\d+$", v):
        return "asn"

    # Email
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email_address"

    # Domain/subdomain (has dots, no spaces)
    if re.match(r"^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$", v):
        parts = v.split(".")
        if len(parts) > 2:
            return "subdomain"
        return "domain"

    return "unknown"
