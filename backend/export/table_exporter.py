"""
table_exporter.py — Structured inventory table exports (JSON + CSV).

V6: Standardized schemas from export.schemas.TABLE_SCHEMAS.
Generates 10 primary + 4 supplementary tables.
"""
import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from core.state import MINAState
from export.schemas import TABLE_SCHEMAS

logger = logging.getLogger(__name__)

# Entity type classification
_DOMAIN_TYPES = {"domain", "subdomain"}
_IP_ASN_TYPES = {"ip_address", "asn", "ip_range"}
_SERVICE_TYPES = {"service"}
_DIGITAL_ASSET_TYPES = {"repository", "document", "certificate"}
_DOCUMENT_REPO_TYPES = {"repository", "document"}
_WEB_ASSET_TYPES = {"endpoint", "webapp"}
_PEOPLE_TYPES = {"person", "email_address"}
_ORG_TYPES = {"organization"}
_TECH_TYPES = {"technology"}


def export_all_tables(state: MINAState, output_dir: str | Path) -> dict[str, Path]:
    """
    Export all structured inventory tables to output_dir.
    Returns dict mapping table_name -> JSON file path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    entities = state.get("entities", [])
    relationships = state.get("relationships", [])
    findings = state.get("findings", [])
    impact_insights = state.get("impact_insights", [])
    observations = state.get("observations", [])

    ent_dicts = [_to_dict(e) for e in entities]
    rel_dicts = [_to_dict(r) for r in relationships]
    find_dicts = [_to_dict(f) for f in findings]
    insight_dicts = [_to_dict(i) for i in impact_insights]
    obs_dicts = [_to_dict(o) for o in observations]

    paths: dict[str, Path] = {}

    # --- 10 primary tables ---
    builders: dict[str, Any] = {
        "assets_table": lambda: _build_assets_table(ent_dicts),
        "domains_subdomains_table": lambda: _build_domains_subdomains_table(ent_dicts, rel_dicts, obs_dicts),
        "ip_asn_table": lambda: _build_ip_asn_table(ent_dicts, rel_dicts),
        "services_table": lambda: _build_services_table(ent_dicts, rel_dicts),
        "web_surface_table": lambda: _build_web_surface_table(ent_dicts, rel_dicts, obs_dicts),
        "digital_assets_table": lambda: _build_digital_assets_table(ent_dicts),
        "documents_repos_table": lambda: _build_documents_repos_table(ent_dicts),
        "relationships_table": lambda: _build_relationships_table(rel_dicts, ent_dicts),
        "impact_priority_table": lambda: _build_impact_priority_table(insight_dicts, ent_dicts),
        "findings_table": lambda: _build_findings_table(find_dicts, obs_dicts),
    }

    # --- 4 supplementary tables ---
    builders.update({
        "endpoints_table": lambda: _build_endpoints_table(ent_dicts, obs_dicts),
        "dns_email_security_table": lambda: _build_dns_email_security_table(obs_dicts),
        "certificate_table": lambda: _build_certificate_table(obs_dicts),
        "collector_coverage_table": lambda: _build_collector_coverage_table(state),
    })

    for name, builder in builders.items():
        rows = builder()
        paths[name] = _write_table(output_dir, name, rows)

    # Tool health snapshot (JSON-only)
    health_snap = state.get("tool_health_snapshot", {})
    health_path = output_dir / "tool_health_snapshot.json"
    health_path.write_text(json.dumps(health_snap, indent=2, default=str), encoding="utf-8")
    paths["tool_health_snapshot"] = health_path

    logger.info("[TableExporter] Exported %d tables to %s", len(paths), output_dir)
    return paths


# ---------------------------------------------------------------------------
# Primary table builders — schemas match export.schemas.TABLE_SCHEMAS
# ---------------------------------------------------------------------------

def _build_assets_table(entities: list[dict]) -> list[dict]:
    """One row per entity — full asset inventory."""
    rows = []
    for e in entities:
        rows.append({
            "entity_id": e.get("entity_id", ""),
            "type": e.get("type", ""),
            "canonical_value": e.get("canonical_value", ""),
            "display_value": e.get("display_value", ""),
            "confidence": e.get("confidence", 0),
            "status": e.get("status", "unknown"),
            "source_collectors": ", ".join(e.get("source_collectors", [])),
            "tags": ", ".join(e.get("tags", [])),
            "first_seen": e.get("first_seen", ""),
            "last_seen": e.get("last_seen", ""),
        })
    return sorted(rows, key=lambda r: (r["type"], r["canonical_value"]))


def _build_domains_subdomains_table(
    entities: list[dict], rels: list[dict], observations: list[dict]
) -> list[dict]:
    """Schema: root_domain, subdomain, status, resolved_ips,
              source_collectors, confidence, evidence_count"""
    id_to_val = {e["entity_id"]: e.get("canonical_value", "")
                 for e in entities if e.get("entity_id")}

    # resolves_to map
    resolves: dict[str, list[str]] = {}
    for r in rels:
        if r.get("type") == "resolves_to":
            src = r.get("from_entity_id", r.get("source_entity_id", ""))
            tgt = r.get("to_entity_id", r.get("target_entity_id", ""))
            resolves.setdefault(src, []).append(tgt)

    # evidence count per entity
    evidence_count: dict[str, int] = {}
    for obs in observations:
        eid = obs.get("entity_id", "")
        if eid:
            evidence_count[eid] = evidence_count.get(eid, 0) + 1

    rows = []
    for e in entities:
        etype = e.get("type", "")
        if etype not in _DOMAIN_TYPES:
            continue
        eid = e.get("entity_id", "")
        val = e.get("canonical_value", "")

        if etype == "domain":
            root_domain = val
            subdomain = ""
        else:
            parts = val.rsplit(".", 2)
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else val
            subdomain = val

        ip_ids = resolves.get(eid, [])
        ip_vals = [id_to_val.get(ip_id, ip_id) for ip_id in ip_ids]

        rows.append({
            "root_domain": root_domain,
            "subdomain": subdomain,
            "status": e.get("status", "unknown"),
            "resolved_ips": ", ".join(ip_vals),
            "source_collectors": ", ".join(e.get("source_collectors", [])),
            "confidence": e.get("confidence", 0),
            "evidence_count": evidence_count.get(eid, 0),
        })
    return sorted(rows, key=lambda r: (r["root_domain"], r["subdomain"]))


def _build_ip_asn_table(entities: list[dict], rels: list[dict]) -> list[dict]:
    """Schema: ip, asn, cidr, org, country,
              related_domains, source_collectors, confidence"""
    id_to_val = {e["entity_id"]: e.get("canonical_value", "")
                 for e in entities if e.get("entity_id")}

    # IP -> ASN via announced_by
    ip_to_asn: dict[str, str] = {}
    # IP -> domains via resolves_to (reverse: domain resolves_to IP)
    ip_to_domains: dict[str, list[str]] = {}
    for r in rels:
        rtype = r.get("type", "")
        src = r.get("from_entity_id", r.get("source_entity_id", ""))
        tgt = r.get("to_entity_id", r.get("target_entity_id", ""))
        if rtype == "announced_by":
            ip_to_asn[src] = id_to_val.get(tgt, tgt)
        elif rtype == "resolves_to":
            src_val = id_to_val.get(src, src)
            ip_to_domains.setdefault(tgt, []).append(src_val)

    rows = []
    for e in entities:
        if e.get("type") not in _IP_ASN_TYPES:
            continue
        eid = e.get("entity_id", "")
        attrs = e.get("attributes", {})
        val = e.get("canonical_value", "")

        rows.append({
            "ip": val,
            "asn": ip_to_asn.get(eid, attrs.get("asn", "")),
            "cidr": attrs.get("cidr", attrs.get("ip_range", "")),
            "org": attrs.get("org", attrs.get("organization", "")),
            "country": attrs.get("country", attrs.get("geo_country", "")),
            "related_domains": ", ".join(ip_to_domains.get(eid, [])),
            "source_collectors": ", ".join(e.get("source_collectors", [])),
            "confidence": e.get("confidence", 0),
        })
    return sorted(rows, key=lambda r: r["ip"])


def _build_services_table(entities: list[dict], rels: list[dict]) -> list[dict]:
    """Schema: host, ip, port, protocol, service,
              product, version, tls, confidence"""
    id_to_val = {e["entity_id"]: e.get("canonical_value", "")
                 for e in entities if e.get("entity_id")}

    # Service -> IP via hosts_service (IP hosts_service Service)
    svc_to_ip: dict[str, str] = {}
    for r in rels:
        if r.get("type") == "hosts_service":
            src = r.get("from_entity_id", r.get("source_entity_id", ""))
            tgt = r.get("to_entity_id", r.get("target_entity_id", ""))
            svc_to_ip[tgt] = id_to_val.get(src, src)

    rows = []
    for e in entities:
        if e.get("type") not in _SERVICE_TYPES:
            continue
        eid = e.get("entity_id", "")
        attrs = e.get("attributes", {})
        ip = svc_to_ip.get(eid, "")

        rows.append({
            "host": attrs.get("host", ip),
            "ip": ip,
            "port": attrs.get("port", ""),
            "protocol": attrs.get("protocol", "tcp"),
            "service": attrs.get("service", e.get("canonical_value", "")),
            "product": attrs.get("product", ""),
            "version": attrs.get("version", ""),
            "tls": attrs.get("tls", attrs.get("ssl", False)),
            "confidence": e.get("confidence", 0),
        })
    return sorted(rows, key=lambda r: (str(r["host"]), str(r["port"])))


def _build_web_surface_table(
    entities: list[dict], rels: list[dict], observations: list[dict]
) -> list[dict]:
    """Schema: host, url, path, title, status_code,
              technologies, parameters, source, confidence"""
    host_meta: dict[str, dict] = {}

    for obs in observations:
        obs_type = obs.get("type", "")
        attrs = obs.get("attributes", {})
        host = attrs.get("host", "")
        url = attrs.get("url", "")

        if not host and url:
            from urllib.parse import urlparse
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                host = ""
        if not host:
            val = obs.get("value", "")
            if "://" in val:
                from urllib.parse import urlparse
                try:
                    host = urlparse(val).hostname or val
                except Exception:
                    host = val.split(":")[0] if ":" in val else val
            else:
                host = val.split(":")[0] if ":" in val else val
        if not host:
            continue
        host = host.lower().strip()

        if host not in host_meta:
            host_meta[host] = {
                "url": url or f"https://{host}",
                "path": "/",
                "title": "",
                "status_code": "",
                "technologies": [],
                "parameters": [],
                "sources": set(),
                "confidence": 0,
            }

        m = host_meta[host]
        m["sources"].add(obs.get("source", ""))
        m["confidence"] = max(m["confidence"], obs.get("confidence", 0))

        if obs_type == "webapp_alive":
            m["status_code"] = attrs.get("status_code", m["status_code"])
            m["title"] = attrs.get("title", m["title"]) or m["title"]
            m["url"] = url or m["url"]
            m["path"] = attrs.get("path", m["path"]) or m["path"]
        elif obs_type == "technology_found":
            tech_val = obs.get("value", "")
            if tech_val and tech_val not in m["technologies"]:
                m["technologies"].append(tech_val)
        elif obs_type == "parameter_found":
            param = attrs.get("parameter", obs.get("value", ""))
            if param and param not in m["parameters"]:
                m["parameters"].append(param)

    rows = []
    for host, meta in sorted(host_meta.items()):
        rows.append({
            "host": host,
            "url": meta["url"],
            "path": meta["path"],
            "title": meta["title"],
            "status_code": meta["status_code"],
            "technologies": ", ".join(meta["technologies"]),
            "parameters": ", ".join(meta["parameters"]),
            "source": ", ".join(s for s in meta["sources"] if s),
            "confidence": meta["confidence"],
        })
    return rows


def _build_digital_assets_table(entities: list[dict]) -> list[dict]:
    """Schema: type, value, url, description,
              source_collectors, confidence"""
    rows = []
    for e in entities:
        if e.get("type") not in _DIGITAL_ASSET_TYPES:
            continue
        attrs = e.get("attributes", {})
        rows.append({
            "type": e.get("type", ""),
            "value": e.get("canonical_value", ""),
            "url": attrs.get("url", ""),
            "description": attrs.get("description", "")[:200],
            "source_collectors": ", ".join(e.get("source_collectors", [])),
            "confidence": e.get("confidence", 0),
        })
    return sorted(rows, key=lambda r: (r["type"], r["value"]))


def _build_documents_repos_table(entities: list[dict]) -> list[dict]:
    """Schema: type, name, url, language, description,
              source_collectors, confidence"""
    rows = []
    for e in entities:
        if e.get("type") not in _DOCUMENT_REPO_TYPES:
            continue
        attrs = e.get("attributes", {})
        rows.append({
            "type": e.get("type", ""),
            "name": e.get("canonical_value", ""),
            "url": attrs.get("url", ""),
            "language": attrs.get("language", ""),
            "description": attrs.get("description", "")[:200],
            "source_collectors": ", ".join(e.get("source_collectors", [])),
            "confidence": e.get("confidence", 0),
        })
    return sorted(rows, key=lambda r: (r["type"], r["name"]))


def _build_relationships_table(rels: list[dict], entities: list[dict]) -> list[dict]:
    """Schema: from_entity, relationship_type, to_entity,
              confidence, source_collectors, evidence_refs"""
    id_to_val = {e["entity_id"]: e.get("canonical_value", "")
                 for e in entities if e.get("entity_id")}
    rows = []
    for r in rels:
        src_id = r.get("from_entity_id", r.get("source_entity_id", ""))
        tgt_id = r.get("to_entity_id", r.get("target_entity_id", ""))
        rows.append({
            "from_entity": id_to_val.get(src_id, src_id),
            "relationship_type": r.get("type", ""),
            "to_entity": id_to_val.get(tgt_id, tgt_id),
            "confidence": r.get("confidence", 0),
            "source_collectors": ", ".join(r.get("source_collectors", [])),
            "evidence_refs": ", ".join(r.get("evidence_refs", [])),
        })
    return sorted(rows, key=lambda r: r["relationship_type"])


def _build_impact_priority_table(
    insights: list[dict], entities: list[dict]
) -> list[dict]:
    """Schema: entity_value, entity_type, priority_score,
              exposure_score, impact_score, confidence_score,
              impact_category, top_reason, suggested_action"""
    id_to_ent = {e["entity_id"]: e for e in entities if e.get("entity_id")}
    rows = []
    for ins in sorted(insights, key=lambda x: -x.get("priority_score", 0)):
        eid = ins.get("entity_id", "")
        ent = id_to_ent.get(eid, {})
        reasons = ins.get("reasons", [])
        rows.append({
            "entity_value": ent.get("canonical_value", eid),
            "entity_type": ent.get("type", ""),
            "priority_score": ins.get("priority_score", 0),
            "exposure_score": ins.get("exposure_score", 0),
            "impact_score": ins.get("impact_score", 0),
            "confidence_score": ins.get("confidence_score", 0),
            "impact_category": ins.get("impact_category", ""),
            "top_reason": reasons[0] if reasons else "",
            "suggested_action": ins.get("suggested_action", ""),
        })
    return rows


def _build_findings_table(
    findings: list[dict], observations: list[dict]
) -> list[dict]:
    """Schema: finding_id, severity, category, title, evidence_source,
              cvss_score, priority_score, confidence, affected_asset,
              affected_url, description, impact, recommendation, references"""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = []

    for f in findings:
        ev_refs = f.get("evidence_refs", f.get("evidence_ref", ""))
        if isinstance(ev_refs, list):
            ev_refs = ", ".join(ev_refs)

        impact_items = f.get("impact_items", [])
        affected_asset = (
            ", ".join(impact_items) if isinstance(impact_items, list) else str(impact_items or "")
        )

        refs = f.get("references", f.get("cve_refs", []))
        if isinstance(refs, list):
            refs = ", ".join(refs)

        sev = str(f.get("severity", f.get("risk_level", "medium"))).lower()
        rows.append({
            "finding_id": "",          # filled after sort
            "severity": sev.capitalize(),
            "category": f.get("category", f.get("impact_category", "")),
            "title": f.get("title", f.get("vulnerability", "")),
            "evidence_source": (f.get("source_agent") or f.get("source_tool") or ev_refs)[:120],
            "cvss_score": f.get("cvss_score", "N/A"),
            "priority_score": round(float(f.get("priority_score", 0) or 0), 1),
            "confidence": round(float(f.get("confidence", f.get("confidence_score", 0)) or 0), 2),
            "affected_asset": affected_asset,
            "affected_url": f.get("url", f.get("affected_url", "")),
            "description": f.get("description", "")[:500],
            "impact": f.get("impact", "")[:300],
            "recommendation": f.get("recommendation", "")[:300],
            "references": refs[:200] if isinstance(refs, str) else "",
        })

    # Include vulnerability observations not in formal findings
    for obs in observations:
        if obs.get("type") in ("vulnerability_found", "credential_signal_found"):
            attrs = obs.get("attributes", {})
            val = obs.get("value", "")
            sev = str(attrs.get("severity", obs.get("rate", "medium"))).lower()
            rows.append({
                "finding_id": "",
                "severity": sev.capitalize(),
                "category": obs.get("type", ""),
                "title": obs.get("context", "")[:100],
                "evidence_source": obs.get("evidence_ref", obs.get("source", "")),
                "cvss_score": "N/A",
                "priority_score": 0.0,
                "confidence": round(float(obs.get("confidence", 0) or 0), 2),
                "affected_asset": attrs.get("host", val.split("/")[0] if "/" in val else val),
                "affected_url": attrs.get("url", val if "/" in val else ""),
                "description": obs.get("context", "")[:500],
                "impact": "",
                "recommendation": "",
                "references": "",
            })

    rows.sort(key=lambda r: (sev_order.get(r["severity"].lower(), 5),
                              -r["priority_score"]))

    # Assign deterministic IDs after sorting
    for i, row in enumerate(rows, 1):
        row["finding_id"] = f"FIND-{i:03d}"

    return rows


# ---------------------------------------------------------------------------
# Supplementary table builders
# ---------------------------------------------------------------------------

def _build_endpoints_table(
    entities: list[dict], observations: list[dict]
) -> list[dict]:
    """Schema: url, host, path, status_code, parameters, source, confidence"""
    rows = []
    for e in entities:
        if e.get("type") not in ("endpoint",):
            continue
        attrs = e.get("attributes", {})
        url = e.get("canonical_value", "")
        host = ""
        path = ""
        if url:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                path = parsed.path or "/"
            except Exception:
                pass

        params = attrs.get("parameters", [])
        if isinstance(params, list):
            params = ", ".join(params)

        rows.append({
            "url": url,
            "host": host,
            "path": path,
            "status_code": attrs.get("status_code", ""),
            "parameters": params,
            "source": ", ".join(e.get("source_collectors", [])),
            "confidence": e.get("confidence", 0),
        })
    return sorted(rows, key=lambda r: r["url"])


def _build_dns_email_security_table(observations: list[dict]) -> list[dict]:
    """Schema: type, domain, value, severity, source, confidence"""
    rows = []
    for obs in observations:
        obs_type = obs.get("type", "")
        if obs_type in ("header_found", "domain_found", "spf_record",
                        "dmarc_record", "dkim_record"):
            attrs = obs.get("attributes", {})
            rows.append({
                "type": obs_type,
                "domain": attrs.get("domain", attrs.get("host", "")),
                "value": obs.get("value", ""),
                "severity": attrs.get("severity", obs.get("rate", "Low")),
                "source": obs.get("source", ""),
                "confidence": obs.get("confidence", 0),
            })
    return sorted(rows, key=lambda r: r["type"])


def _build_certificate_table(observations: list[dict]) -> list[dict]:
    """Schema: host, issuer, subject, tls_version,
              expiry_days, self_signed, wildcard, san_domains, grade"""
    rows = []
    for obs in observations:
        if obs.get("type") in ("cert_found",):
            attrs = obs.get("attributes", {})
            rows.append({
                "host": attrs.get("host", obs.get("value", "")),
                "issuer": attrs.get("cert_issuer", ""),
                "subject": attrs.get("cert_subject", ""),
                "tls_version": attrs.get("tls_version", ""),
                "expiry_days": attrs.get("cert_expiry_days", ""),
                "self_signed": attrs.get("self_signed", False),
                "wildcard": attrs.get("wildcard_cert", False),
                "san_domains": ", ".join(attrs.get("san_domains", [])),
                "grade": attrs.get("grade", ""),
            })
    return sorted(rows, key=lambda r: r.get("host", ""))


def _build_collector_coverage_table(state: MINAState) -> list[dict]:
    """Schema: collector, runs, success, failures,
              total_events, total_leads, success_rate"""
    stats = state.get("collector_stats", {})
    rows = []
    for collector, data in sorted(stats.items()):
        if isinstance(data, dict):
            runs = max(data.get("runs", 0), 1)
            rows.append({
                "collector": collector,
                "runs": data.get("runs", 0),
                "success": data.get("success", 0),
                "failures": data.get("failures", 0),
                "total_events": data.get("total_events", 0),
                "total_leads": data.get("total_leads", 0),
                "success_rate": f"{(data.get('success', 0) / runs) * 100:.0f}%",
            })
    return rows


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _write_table(output_dir: Path, name: str, rows: list[dict]) -> Path:
    """Write table as both JSON and CSV. Returns JSON path."""
    json_path = output_dir / f"{name}.json"
    csv_path = output_dir / f"{name}.csv"

    # JSON
    json_path.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")

    # CSV
    if rows:
        fieldnames = list(rows[0].keys())
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        csv_path.write_text(buf.getvalue(), encoding="utf-8")

    logger.debug("[TableExporter] %s: %d rows", name, len(rows))
    return json_path


def _to_dict(obj: Any) -> dict:
    """Convert Pydantic model or dict to dict."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return vars(obj)
