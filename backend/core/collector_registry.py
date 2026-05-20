"""
core/collector_registry.py — Collector family registry.

Maps every tool name used in the planner baseline matrices to
a named intelligence domain (collector family).  This lets agents,
reporters, and analysts group observations by *what kind of
intelligence* they represent, independent of which agent ran them.

Families:
  dns           — Zone, records, WHOIS, dumpster, SPF/DMARC
  cert          — TLS/SSL certificates, crt.sh, cert details
  subdomain     — Subdomain enumeration and discovery
  web           — Live web surface, crawl, headers, tech, robots
  infrastructure— IP, ASN, BGP, Shodan, Nmap, port scanning
  vuln_scan     — Vulnerability templating (Nuclei, CVE lookup)
  karma         — Karma V2 threat-intel feeds
  osint         — OSINT / passive intel (Wayback, email, docs, repos)
  other         — Fallback for unregistered tools
"""
from __future__ import annotations

from typing import Dict

# ── Tool → collector family mapping ──────────────────────────────

COLLECTOR_FAMILIES: Dict[str, str] = {
    # DNS / Zone
    "dns":                  "dns",
    "whois":                "dns",
    "reverse_dns":          "dns",
    "spf_dmarc":            "dns",
    "zone_transfer":        "dns",
    "dns_dumpster":         "dns",
    # Certificates
    "crt_sh":               "cert",
    "ssl":                  "cert",
    "cert_detail":          "cert",
    # Subdomain enumeration
    "subfinder":            "subdomain",
    "subdomain_discovery":  "subdomain",
    # Web surface
    "httpx":                "web",
    "headers":              "web",
    "tech":                 "web",
    "robots":               "web",
    "http_methods":         "web",
    "waf":                  "web",
    "web_surface":          "web",
    "dirs":                 "web",
    "crawl":                "web",
    "favicon":              "web",
    "params":               "web",
    "banner":               "web",
    "cloud":                "web",
    # Infrastructure / Ports
    "nmap":                 "infrastructure",
    "shodan":               "infrastructure",
    "asn":                  "infrastructure",
    "infra_asn_enrich":     "infrastructure",
    "bgp_range":            "infrastructure",
    "org_ip_range":         "infrastructure",
    "reverse_ip":           "infrastructure",
    # Vulnerability scanning
    "nuclei":               "vuln_scan",
    "cve_lookup":           "vuln_scan",
    # Karma V2 threat-intel
    "karma_ip":             "karma",
    "karma_leaks":          "karma",
    "karma_cve":            "karma",
    "smap":                 "karma",
    # OSINT / passive intel
    "email_harvest":        "osint",
    "wayback":              "osint",
    "js_endpoints":         "osint",
    "company_profile":      "osint",
    "repo_discovery":       "osint",
    "public_doc_discovery": "osint",
    "reverse_whois":        "osint",
    "google_analytics_id":  "osint",
    "public_contact":       "osint",
    "credential_signal":    "osint",
    "service_metadata":     "osint",
    "vhost":                "osint",
}

_FAMILY_DESCRIPTIONS: Dict[str, str] = {
    "dns":            "DNS zone, records, WHOIS, SPF/DMARC analysis",
    "cert":           "TLS/SSL certificate intelligence",
    "subdomain":      "Subdomain enumeration and discovery",
    "web":            "Live web surface, crawl, headers, technology",
    "infrastructure": "IP ranges, ASN, BGP, Shodan, port scanning",
    "vuln_scan":      "Vulnerability template scanning (Nuclei, CVE)",
    "karma":          "Karma V2 threat-intel feeds",
    "osint":          "OSINT / passive intel (Wayback, email, docs, repos)",
    "other":          "Unclassified tools",
}


def get_collector_family(tool_name: str) -> str:
    """Return the collector family for a given tool name."""
    return COLLECTOR_FAMILIES.get(tool_name, "other")


def describe_family(family: str) -> str:
    """Return a human-readable description for a collector family."""
    return _FAMILY_DESCRIPTIONS.get(family, "Unknown collector family")
