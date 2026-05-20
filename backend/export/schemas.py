"""
Shared table schema definitions — single source of truth.

Both table_exporter and reporter MUST use these field names.
Never guess column names; always read from TABLE_SCHEMAS.
"""

TABLE_SCHEMAS: dict[str, list[str]] = {
    # === 10 Primary tables ===
    "assets_table": [
        "entity_id", "type", "canonical_value", "display_value",
        "confidence", "status", "source_collectors", "tags",
        "first_seen", "last_seen",
    ],
    "domains_subdomains_table": [
        "root_domain", "subdomain", "status", "resolved_ips",
        "source_collectors", "confidence", "evidence_count",
    ],
    "ip_asn_table": [
        "ip", "asn", "cidr", "org", "country",
        "related_domains", "source_collectors", "confidence",
    ],
    "services_table": [
        "host", "ip", "port", "protocol", "service",
        "product", "version", "tls", "confidence",
    ],
    "web_surface_table": [
        "host", "url", "path", "title", "status_code",
        "technologies", "parameters", "source", "confidence",
    ],
    "digital_assets_table": [
        "type", "value", "url", "description",
        "source_collectors", "confidence",
    ],
    "documents_repos_table": [
        "type", "name", "url", "language", "description",
        "source_collectors", "confidence",
    ],
    "relationships_table": [
        "from_entity", "relationship_type", "to_entity",
        "confidence", "source_collectors", "evidence_refs",
    ],
    "impact_priority_table": [
        "entity_value", "entity_type", "priority_score",
        "exposure_score", "impact_score", "confidence_score",
        "impact_category", "top_reason", "suggested_action",
    ],
    "findings_table": [
        "finding_id", "severity", "category", "title",
        "evidence_source", "cvss_score", "priority_score",
        "confidence", "affected_asset", "affected_url",
        "description", "impact", "recommendation", "references",
    ],
    # === 4 Supplementary tables ===
    "endpoints_table": [
        "url", "host", "path", "status_code", "parameters",
        "source", "confidence",
    ],
    "dns_email_security_table": [
        "type", "domain", "value", "severity",
        "source", "confidence",
    ],
    "certificate_table": [
        "host", "issuer", "subject", "tls_version",
        "expiry_days", "self_signed", "wildcard", "san_domains", "grade",
    ],
    "collector_coverage_table": [
        "collector", "runs", "success", "failures",
        "total_events", "total_leads", "success_rate",
    ],
}


def get_fields(table_name: str) -> list[str]:
    """Return field list for a table, or empty list if unknown."""
    return TABLE_SCHEMAS.get(table_name, [])
