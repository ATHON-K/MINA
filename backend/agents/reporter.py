"""
Reporter Agent — V7: Deterministic intelligence report with 8 professional sections.

Renders from standardized exported tables (TABLE_SCHEMAS).
No data is invented — missing sections say "Không phát hiện trong đợt scan này".

Sections:
  1. Executive Summary
  2. Scope & Methodology
  3. Attack Surface Overview
  4. Findings Summary
  5. Detailed Technical Findings
  6. Risk Matrix
  7. Remediation Roadmap
  8. Appendix
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.state import MINAState
from export.table_exporter import export_all_tables
from export.schemas import TABLE_SCHEMAS

logger = logging.getLogger(__name__)

RISK_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🟢", "info": "⚪",
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_HIGH_INTEREST_KEYWORDS = {
    "admin", "login", "signin", "dashboard", "manage", "api", "graphql",
    "swagger", "openapi", "internal", "dev", "test", "backup", "export",
    "config", "upload", "webhook", "auth", "token",
}


def _is_high_interest(url: str) -> bool:
    return any(kw in url.lower() for kw in _HIGH_INTEREST_KEYWORDS)


def _attr(obj, key, default=None):
    """Get attribute from object or dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ===================================================================
# Main node
# ===================================================================

def reporter_node(state: MINAState) -> MINAState:
    """LangGraph node: Generate V7 intelligence report with 8 sections."""
    spec = state["engagement_spec"]
    session_dir = Path(f"backend/output/sessions/{spec['session_id']}")
    session_dir.mkdir(parents=True, exist_ok=True)

    # 1. Export deterministic tables first
    tables_dir = session_dir / "tables"
    table_paths = export_all_tables(state, tables_dir)

    # 2. Load tables back as dicts for report rendering
    tables = _load_tables(tables_dir)

    findings = state.get("findings", [])
    impact_insights = state.get("impact_insights", [])
    observations = state.get("observations", [])

    findings_sorted = sorted(
        findings,
        key=lambda f: (
            RISK_ORDER.get(_attr(f, "risk_level", "info"), 9),
            -(_attr(f, "priority_score", 0) or 0),
        ),
    )

    coverage = _build_coverage_stats(state)
    limitations = _build_limitations(state)

    # 3. Render 8-section markdown
    md_report = _render_report_markdown(
        spec, findings_sorted, observations,
        coverage, limitations, impact_insights, tables, state,
    )

    html_report = _render_html(md_report, spec, findings_sorted)

    # Write files
    report_md_path = session_dir / "report.md"
    report_html_path = session_dir / "report.html"
    intel_json_path = session_dir / "intel.json"

    report_md_path.write_text(md_report, encoding="utf-8")
    report_html_path.write_text(html_report, encoding="utf-8")

    intel = _build_intel_json(state, findings_sorted, coverage)
    intel_json_path.write_text(
        json.dumps(intel, indent=2, default=str), encoding="utf-8"
    )

    _symlink_latest(session_dir)

    state["report_paths"] = {
        "markdown": str(report_md_path),
        "html": str(report_html_path),
        "intel_json": str(intel_json_path),
        "tables": {name: str(p) for name, p in table_paths.items()},
    }
    state["report"] = md_report
    state["report_html"] = str(report_html_path)

    logger.info("[Reporter] V7 report written to %s", session_dir)
    return state


# ===================================================================
# Table loading
# ===================================================================

def _load_tables(tables_dir: Path) -> dict[str, list[dict]]:
    """Load all exported JSON tables into memory."""
    tables: dict[str, list[dict]] = {}
    if not tables_dir.exists():
        return tables
    for json_file in tables_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                tables[json_file.stem] = data
            elif isinstance(data, dict):
                tables[json_file.stem] = [data] if data else []
        except Exception as e:
            logger.warning("[Reporter] Failed to load table %s: %s", json_file.name, e)
    return tables


# ===================================================================
# Coverage & Limitations
# ===================================================================

def _build_coverage_stats(state: MINAState) -> dict:
    """Build coverage stats from REAL counts."""
    stats = state.get("collector_stats", {})
    return {
        "total_raw_events": sum(
            s.get("total_events", 0) for s in stats.values() if isinstance(s, dict)
        ),
        "total_observations": len(state.get("observations", [])),
        "total_entities": len(state.get("entities", [])),
        "total_relationships": len(state.get("relationships", [])),
        "total_findings": len(state.get("findings", [])),
        "collectors_run": list(stats.keys()),
        "lead_queue_at_stop": len(state.get("lead_queue", [])),
        "stop_reason": (
            state.get("stop_reason")
            or (state.get("phase_log", [{}])[-1].get("stop_reason", "unknown")
                if state.get("phase_log") else "unknown")
        ),
        "iterations": len(state.get("phase_log", [])),
        "per_collector": {
            tool: {
                "runs": s.get("runs", 0),
                "success_rate": round(
                    s.get("success", 0) / max(s.get("runs", 1), 1) * 100, 1
                ),
                "total_events": s.get("total_events", 0),
                "total_leads": s.get("total_leads", 0),
            }
            for tool, s in stats.items() if isinstance(s, dict)
        },
    }


def _build_limitations(state: MINAState) -> list:
    """Build honest limitations list."""
    spec = state["engagement_spec"]
    limitations = []
    features = spec.get("features", {})

    if not spec.get("active_recon_enabled", False):
        limitations.append("Active reconnaissance was disabled — port scans and direct probes not performed.")
    if not features.get("nuclei", False):
        limitations.append("Nuclei vulnerability scanner not enabled — CVE detection limited.")
    if not features.get("shodan", False):
        limitations.append("Shodan lookup disabled — internet-facing exposure data may be incomplete.")
    if not features.get("crawler", False):
        limitations.append("Web crawler disabled — dynamic paths and JS-rendered endpoints may be missed.")

    health = state.get("tool_health_snapshot", {})
    unavailable = [t for t, v in health.items()
                   if isinstance(v, dict) and not v.get("ready", True)]
    if unavailable:
        limitations.append(f"Tools unavailable at scan start: {', '.join(unavailable)}")

    errors = state.get("error_log", [])
    if errors:
        tools_with_errors = list({e.get("tool", "unknown") for e in errors})
        limitations.append(
            f"Collectors with errors (possibly incomplete): {', '.join(tools_with_errors)}"
        )
    return limitations


# ===================================================================
# Markdown helpers
# ===================================================================

def _md_table(fields: list[str], rows: list[dict], limit: int | None = None) -> list[str]:
    """Render a list of dicts as markdown table lines using given fields."""
    if not rows:
        return ["_No data._", ""]
    lines = []
    header = "| " + " | ".join(fields) + " |"
    sep = "| " + " | ".join("---" for _ in fields) + " |"
    lines += [header, sep]
    for i, row in enumerate(rows):
        if limit and i >= limit:
            remaining = len(rows) - limit
            lines.append(
                f"| ... | _{remaining} more rows — see exported tables_ |"
                + " |" * max(0, len(fields) - 2)
            )
            break
        cells = []
        for f in fields:
            v = str(row.get(f, "")).replace("|", "\\|").replace("\n", " ")
            cells.append(v[:120])
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _get_schema(table_name: str) -> list[str]:
    """Get field names from shared TABLE_SCHEMAS."""
    return TABLE_SCHEMAS.get(table_name, [])


# ===================================================================
# V6 Markdown renderer — 16 mandatory sections
# ===================================================================

def _render_report_markdown(
    spec: dict, findings: list, observations: list,
    coverage: dict, limitations: list, impact_insights: list,
    tables: dict, state: MINAState,
) -> str:
    target = spec.get("target", "Unknown")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    session_id = spec.get("session_id", "")

    lines: list[str] = [
        f"# MINA Intelligence Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Generated:** {date}  ",
        f"**Session:** `{session_id}`  ",
        f"",
        f"---",
        f"",
    ]

    # 8 professional sections
    lines += _s01_executive_summary(target, coverage, findings, tables, spec)
    lines += _s02_scope_methodology(spec, state, limitations)
    lines += _s03_attack_surface_overview(tables, coverage)
    lines += _s04_findings_summary(findings, tables)
    lines += _s05_detailed_findings(findings, tables)
    lines += _s06_risk_matrix(findings)
    lines += _s07_remediation_roadmap(findings, tables)
    lines += _s08_appendix(spec, coverage, tables, state)

    lines += [
        "", "---",
        "*MINA v7.0 — Multi Intelligence Network Agent | Red Team Recon System*",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section builders — each reads ONLY standardized TABLE_SCHEMAS fields
# No data is invented. Missing data → "Không phát hiện trong đợt scan này"
# ---------------------------------------------------------------------------

def _s01_executive_summary(
    target: str, coverage: dict, findings: list, tables: dict, spec: dict
) -> list[str]:
    """Section 1 — Executive Summary (deterministic, tiếng Việt)."""
    dom_table   = tables.get("domains_subdomains_table", [])
    ip_table    = tables.get("ip_asn_table", [])
    svc_table   = tables.get("services_table", [])
    web_table   = tables.get("web_surface_table", [])
    ep_table    = tables.get("endpoints_table", [])

    root_domains = [r for r in dom_table if not r.get("subdomain")]
    subdomains   = [r for r in dom_table if r.get("subdomain")]
    unique_ips   = len({r.get("ip", "") for r in ip_table if r.get("ip")})
    unique_asns  = len({r.get("asn", "") for r in ip_table if r.get("asn")})

    risk_counts: dict[str, int] = {r: 0 for r in RISK_ORDER}
    for f in findings:
        sev = str(_attr(f, "severity", _attr(f, "risk_level", "info"))).lower()
        risk_counts[sev] = risk_counts.get(sev, 0) + 1
    # Also count from findings_table if present
    find_table = tables.get("findings_table", [])
    if find_table and not findings:
        for row in find_table:
            sev = str(row.get("severity", "Info")).lower()
            risk_counts[sev] = risk_counts.get(sev, 0) + 1

    total_findings = sum(risk_counts.values()) or coverage.get("total_findings", 0)

    lines = [f"## 1. Executive Summary", ""]

    # Quantitative overview paragraph
    lines += [
        f"Đợt đánh giá tự động trên **{target}** đã thu thập "
        f"**{coverage['total_raw_events']}** sự kiện thô, "
        f"**{coverage['total_observations']}** quan sát, "
        f"**{coverage['total_entities']}** thực thể và "
        f"**{total_findings}** phát hiện bảo mật "
        f"qua **{coverage['iterations']}** vòng lặp.",
        "",
        f"**Bề mặt tấn công tổng quan:**",
    ]

    # Asset summary table
    lines += [
        "| Hạng mục | Số lượng |",
        "|---|---|",
        f"| Root domains | {len(root_domains) or 'Không phát hiện'} |",
        f"| Subdomains | {len(subdomains) or 'Không phát hiện'} |",
        f"| Địa chỉ IP | {unique_ips or 'Không phát hiện'} |",
        f"| ASN | {unique_asns or 'Không phát hiện'} |",
        f"| Services/Ports | {len(svc_table) or 'Không phát hiện'} |",
        f"| Web hosts | {len(web_table) or 'Không phát hiện'} |",
        f"| Endpoints | {len(ep_table) or 'Không phát hiện'} |",
        "",
    ]

    # Risk summary table
    lines += [
        "**Phân loại phát hiện theo mức độ nghiêm trọng:**", "",
        "| Mức độ | Số phát hiện |",
        "|---|---|",
    ]
    for risk in ["critical", "high", "medium", "low", "info"]:
        count = risk_counts.get(risk, 0)
        emoji = RISK_EMOJI.get(risk, "")
        lines.append(f"| {emoji} {risk.capitalize()} | {count} |")

    lines += ["", "---", ""]
    return lines


def _s02_scope_methodology(
    spec: dict, state: MINAState, limitations: list
) -> list[str]:
    """Section 2 — Scope & Methodology."""
    features     = spec.get("features", {})
    health       = state.get("tool_health_snapshot", {})
    allowed_scope = spec.get("allowed_scope", [])
    blocked_scope = spec.get("blocked_scope", [])

    lines = [f"## 2. Scope & Methodology", ""]

    # Scope
    lines += [
        "### Scope", "",
        f"- **Target chính:** `{spec.get('target', 'N/A')}`",
        f"- **Company:** {spec.get('company', spec.get('company_name', 'N/A'))}",
        f"- **Scan Profile:** {spec.get('profile', 'balanced')}",
        f"- **Active Recon:** {'Bật' if spec.get('active_recon_enabled') else 'Tắt'}",
    ]
    if allowed_scope:
        lines.append(f"- **Phạm vi được phép:** {', '.join(f'`{s}`' for s in allowed_scope)}")
    if blocked_scope:
        lines.append(f"- **Loại trừ:** {', '.join(f'`{s}`' for s in blocked_scope)}")
    lines += [""]

    # Methodology
    lines += [
        "### Methodology", "",
        "Pipeline MINA thực thi theo 5 pha liên tiếp:",
        "",
        "| Pha | Tên | Mô tả |",
        "|---|---|---|",
        "| 0 | Setup & Policy Gate | Khởi tạo session, kiểm tra ROE/scope |",
        "| 1 | Collection Loop | Director điều phối các agent thu thập: RootDomain → SubdomainIntel → InfraNetwork → CompanyIntel → PeopleIntel → CredentialsAccess → KarmaPassive → OSINTDeepDive → ServiceSurface → WebSurface → AttachProvenance |",
        "| 2 | Normalize | Chuẩn hóa, dedup, canonical entity |",
        "| 3 | Correlate & Conflict Resolution | Xây dựng graph quan hệ, giải quyết conflict |",
        "| 4 | Impact & TableCompose | Phân tích impact, xuất bảng deterministic |",
        "| 5 | Report | Sinh báo cáo Markdown + HTML + intel.json |",
        "",
        "_Tất cả thu thập là passive/OSINT hoặc active verification có giới hạn — "
        "không exploit, không xâm nhập sâu._",
        "",
    ]

    # Tool health
    if health:
        not_ready = [(t, info) for t, info in sorted(health.items())
                     if isinstance(info, dict) and not info.get("ready", True)]
        ready = [(t, info) for t, info in sorted(health.items())
                 if isinstance(info, dict) and info.get("ready", True)]
        lines += [
            "**Tool health tại thời điểm scan:**", "",
            f"- Ready: {', '.join(t for t, _ in ready) or 'không có'}",
        ]
        if not_ready:
            details = "; ".join(
                f"{t} ({info.get('error', 'not ready')})" for t, info in not_ready
            )
            lines.append(f"- Không sẵn sàng: {details}")
        lines.append("")

    # Limitations
    lines += ["### Limitations", ""]
    if limitations:
        for lim in limitations:
            lines.append(f"- {lim}")
    else:
        lines.append("- Không có giới hạn đáng kể.")
    lines += [
        "",
        "> ⚠️ Báo cáo được tạo tự động. Chỉ dùng cho kiểm tra bảo mật được ủy quyền.",
        "",
        "---", "",
    ]
    return lines


def _s03_attack_surface_overview(tables: dict, coverage: dict) -> list[str]:
    """Section 3 — Attack Surface Overview."""
    dom_table  = tables.get("domains_subdomains_table", [])
    ip_table   = tables.get("ip_asn_table", [])
    svc_table  = tables.get("services_table", [])
    web_table  = tables.get("web_surface_table", [])
    da_table   = tables.get("digital_assets_table", [])
    dr_table   = tables.get("documents_repos_table", [])

    root_domains = [r for r in dom_table if not r.get("subdomain")]
    subdomains   = [r for r in dom_table if r.get("subdomain")]

    lines = [f"## 3. Attack Surface Overview", ""]

    # 3.1 Domains & Subdomains
    lines += [f"### 3.1 Domains & Subdomains", ""]
    if dom_table:
        lines.append(
            f"Phát hiện **{len(root_domains)}** root domain(s) và "
            f"**{len(subdomains)}** subdomain(s)."
        )
        lines.append("")
        # Mini table — up to 30 rows
        lines += _md_table(
            ["root_domain", "subdomain", "status", "resolved_ips", "confidence"],
            dom_table,
            limit=30,
        )
    else:
        lines += ["_Không phát hiện trong đợt scan này._", ""]

    # 3.2 IP / ASN Footprint
    lines += [f"### 3.2 IP / ASN Footprint", ""]
    if ip_table:
        unique_ips  = len({r.get("ip", "") for r in ip_table if r.get("ip")})
        unique_asns = len({r.get("asn", "") for r in ip_table if r.get("asn")})
        lines.append(f"**{unique_ips}** địa chỉ IP duy nhất, **{unique_asns}** ASN.")
        lines.append("")
        lines += _md_table(
            ["ip", "asn", "org", "country", "related_domains", "confidence"],
            ip_table,
            limit=25,
        )
    else:
        lines += ["_Không phát hiện trong đợt scan này._", ""]

    # 3.3 Open Ports & Services
    lines += [f"### 3.3 Open Ports & Services", ""]
    if svc_table:
        lines.append(f"**{len(svc_table)}** service(s) xác định.")
        lines.append("")
        lines += _md_table(
            ["host", "port", "protocol", "service", "product", "version", "confidence"],
            svc_table,
            limit=30,
        )
    else:
        lines += ["_Không phát hiện trong đợt scan này._", ""]

    # 3.4 Web Surface / Endpoints
    lines += [f"### 3.4 Web Surface / Endpoints", ""]
    if web_table:
        hi = sum(1 for r in web_table if _is_high_interest(r.get("url", "")))
        lines.append(
            f"**{len(web_table)}** web host(s)/URL(s)"
            + (f", **{hi}** high-interest endpoints." if hi else ".")
        )
        lines.append("")
        lines += _md_table(
            ["host", "url", "title", "status_code", "technologies", "confidence"],
            web_table,
            limit=25,
        )
    else:
        lines += ["_Không phát hiện trong đợt scan này._", ""]

    # 3.5 Digital Assets
    if da_table or dr_table:
        lines += [f"### 3.5 Digital Assets / Repos / Documents", ""]
        if da_table:
            lines += _md_table(_get_schema("digital_assets_table"), da_table, limit=20)
        if dr_table:
            lines += _md_table(_get_schema("documents_repos_table"), dr_table, limit=20)

    lines += ["---", ""]
    return lines


def _s04_findings_summary(findings: list, tables: dict) -> list[str]:
    """Section 4 — Findings Summary (6-column visible table, deterministic IDs)."""
    lines = [f"## 4. Findings Summary", ""]

    find_table = tables.get("findings_table", [])

    # If no exported findings_table, build from raw findings list
    if not find_table and findings:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows = sorted(
            findings,
            key=lambda f: (
                sev_order.get(
                    str(_attr(f, "severity", _attr(f, "risk_level", "info"))).lower(), 5
                ),
                -float(_attr(f, "priority_score", 0) or 0),
            ),
        )
        find_table = []
        for i, f in enumerate(rows, 1):
            sev = str(_attr(f, "severity", _attr(f, "risk_level", "info"))).capitalize()
            cvss = _attr(f, "cvss_score", "N/A") or "N/A"
            ev_refs = _attr(f, "evidence_refs", "")
            if isinstance(ev_refs, list):
                ev_refs = ", ".join(ev_refs)
            find_table.append({
                "finding_id": f"FIND-{i:03d}",
                "severity": sev,
                "category": _attr(f, "category", ""),
                "title": _attr(f, "title", ""),
                "evidence_source": _attr(f, "source_agent", ev_refs or "")[:80],
                "cvss_score": cvss,
            })

    if not find_table:
        lines += ["_Không phát hiện trong đợt scan này._", "", "---", ""]
        return lines

    # Count by severity
    sev_counts: dict[str, int] = {}
    for row in find_table:
        sev = str(row.get("severity", "Info")).lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    summary_parts = []
    for s in ["critical", "high", "medium", "low", "info"]:
        c = sev_counts.get(s, 0)
        if c:
            summary_parts.append(f"{RISK_EMOJI.get(s, '')} {c} {s.capitalize()}")
    lines.append(f"**Tổng cộng {len(find_table)} phát hiện:** {' | '.join(summary_parts)}")
    lines.append("")

    # Visible 6-column table
    lines += _md_table(
        ["finding_id", "severity", "category", "title", "evidence_source", "cvss_score"],
        find_table,
    )
    lines += ["---", ""]
    return lines


def _s05_detailed_findings(findings: list, tables: dict) -> list[str]:
    """Section 5 — Detailed Technical Findings (one block per finding)."""
    lines = [f"## 5. Detailed Technical Findings", ""]

    find_table = tables.get("findings_table", [])

    # Merge: prefer find_table (has finding_id) but fall back to raw findings
    if find_table:
        # find_table has all fields including description, impact, recommendation
        source = find_table
        use_table = True
    elif findings:
        source = findings
        use_table = False
    else:
        lines += ["_Không phát hiện trong đợt scan này._", "", "---", ""]
        return lines

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    MAX_FULL = 20

    total = len(source)
    if total > MAX_FULL:
        # Full: critical + high; top medium by priority; rest truncated
        critical_high = [r for r in source
                         if str((r.get("severity") if use_table else
                                 _attr(r, "severity", _attr(r, "risk_level", "info")))
                                ).lower() in ("critical", "high")]
        medium = [r for r in source
                  if str((r.get("severity") if use_table else
                          _attr(r, "severity", _attr(r, "risk_level", "info")))
                         ).lower() == "medium"]
        medium = medium[:10]
        display = critical_high + medium
        lines.append(f"_Hiển thị đầy đủ Critical/High ({len(critical_high)}) "
                     f"và top Medium ({len(medium)}). "
                     f"Full inventory ({total}) trong artifact._")
        lines.append("")
    else:
        display = source

    for i, item in enumerate(display, 1):
        if use_table:
            fid      = item.get("finding_id", f"FIND-{i:03d}")
            title    = item.get("title", "")
            sev      = item.get("severity", "Info")
            cvss     = item.get("cvss_score", "N/A") or "N/A"
            cat      = item.get("category", "")
            descr    = item.get("description", "_Chưa được xác minh trong đợt đánh giá này._")
            ev       = item.get("evidence_source", "")
            impact   = item.get("impact", "_Chưa được xác minh trong đợt đánh giá này._")
            rec      = item.get("recommendation", "_Chưa được xác minh trong đợt đánh giá này._")
            refs     = item.get("references", "")
            asset    = item.get("affected_asset", "")
            url      = item.get("affected_url", "")
        else:
            idx = i
            fid      = f"FIND-{idx:03d}"
            sev      = str(_attr(item, "severity",
                                 _attr(item, "risk_level", "info"))).capitalize()
            cvss     = str(_attr(item, "cvss_score", "N/A") or "N/A")
            title    = str(_attr(item, "title", ""))
            cat      = str(_attr(item, "category", ""))
            descr    = str(_attr(item, "description",
                                 "_Chưa được xác minh trong đợt đánh giá này._"))
            ev_refs  = _attr(item, "evidence_refs", "")
            ev       = (", ".join(ev_refs) if isinstance(ev_refs, list) else str(ev_refs or ""))
            impact_items = _attr(item, "impact_items", []) or []
            impact   = (", ".join(impact_items) if impact_items
                        else str(_attr(item, "impact", "_Chưa được xác minh trong đợt đánh giá này._")))
            rec      = str(_attr(item, "recommendation",
                                 "_Chưa được xác minh trong đợt đánh giá này._"))
            refs_raw = _attr(item, "references", _attr(item, "cve_refs", []))
            refs     = ", ".join(refs_raw) if isinstance(refs_raw, list) else str(refs_raw or "")
            asset    = ", ".join(impact_items) if impact_items else ""
            url      = str(_attr(item, "url", _attr(item, "affected_url", "")))

        emoji = RISK_EMOJI.get(sev.lower(), "")
        asset_line = ""
        if asset:
            asset_line = f"**Affected Asset:** {asset}  \n"
        if url:
            asset_line += f"**Affected URL:** {url}  \n"

        lines += [
            f"### {fid} — {title}",
            f"**Severity:** {emoji} {sev} | **CVSS:** {cvss} | **Category:** {cat}",
            "",
            f"**Description:** {descr or '_Chưa được xác minh trong đợt đánh giá này._'}",
            "",
            f"**Evidence:** {ev or '_Không có evidence_ref._'}",
            "",
            f"**Impact:** {impact or '_Chưa được xác minh trong đợt đánh giá này._'}",
            "",
            f"**Recommendation:** {rec or '_Chưa được xác minh trong đợt đánh giá này._'}",
            "",
            f"**References:** {refs or 'N/A'}",
            "",
        ]
        if asset_line.strip():
            lines.insert(-1, asset_line.strip())
            lines.insert(-1, "")

    lines += ["---", ""]
    return lines


def _s06_risk_matrix(findings: list) -> list[str]:
    """Section 6 — Risk Matrix (likelihood × impact, deterministic)."""
    lines = [f"## 6. Risk Matrix", ""]

    if not findings:
        lines += ["_Không có findings để xây dựng risk matrix._", "", "---", ""]
        return lines

    # Build matrix: likelihood (High/Medium/Low) × Impact (Critical/High/Medium/Low)
    # Likelihood derived from confidence + public-exposure heuristics
    # Impact derived from severity

    # Bucket findings
    matrix: dict[str, dict[str, list[str]]] = {
        "High":   {"Critical": [], "High": [], "Medium": [], "Low": []},
        "Medium": {"Critical": [], "High": [], "Medium": [], "Low": []},
        "Low":    {"Critical": [], "High": [], "Medium": [], "Low": []},
    }

    for i, f in enumerate(findings, 1):
        sev = str(_attr(f, "severity", _attr(f, "risk_level", "info"))).capitalize()
        conf = float(_attr(f, "confidence", _attr(f, "confidence_score", 0.5)) or 0.5)
        ps   = float(_attr(f, "priority_score", 5) or 5)

        # Map impact level from severity
        impact_level = sev if sev in ("Critical", "High", "Medium", "Low") else "Low"

        # Likelihood heuristic: confidence + priority_score
        if conf >= 0.8 or ps >= 7:
            likelihood = "High"
        elif conf >= 0.5 or ps >= 4:
            likelihood = "Medium"
        else:
            likelihood = "Low"

        fid = f"FIND-{i:03d}"
        matrix[likelihood][impact_level].append(fid)

    # Render table
    lines += [
        "| Likelihood / Impact | Critical | High | Medium | Low |",
        "|---|---|---|---|---|",
    ]
    for likelihood in ("High", "Medium", "Low"):
        cells = []
        for impact in ("Critical", "High", "Medium", "Low"):
            ids = matrix[likelihood][impact]
            if not ids:
                cells.append("—")
            elif len(ids) <= 3:
                cells.append(", ".join(ids))
            else:
                cells.append(f"{len(ids)} findings")
        lines.append(f"| {likelihood} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "_Bảng phân loại rủi ro dựa trên mức độ nghiêm trọng (Impact) và "
        "xác suất khai thác (Likelihood) được tính từ confidence score và "
        "priority score của từng finding._",
        "",
        "---", "",
    ]
    return lines


def _s07_remediation_roadmap(findings: list, tables: dict) -> list[str]:
    """Section 7 — Remediation Roadmap (3 horizons)."""
    lines = [f"## 7. Remediation Roadmap", ""]

    find_table = tables.get("findings_table", [])

    # Categorize by urgency
    immediate:   list[str] = []   # 0-7 days: Critical/High
    short_term:  list[str] = []   # 7-30 days: Medium
    long_term:   list[str] = []   # 30-90 days: Low/Info + hardening

    # Use find_table if available (has finding_id), else raw findings
    if find_table:
        for row in find_table:
            sev = str(row.get("severity", "Info")).lower()
            fid = row.get("finding_id", "")
            title = row.get("title", "")
            rec   = row.get("recommendation", "")
            entry = f"{fid} **{title}**{': ' + rec if rec else ''}"
            if sev in ("critical", "high"):
                immediate.append(entry)
            elif sev == "medium":
                short_term.append(entry)
            else:
                long_term.append(entry)
    elif findings:
        for i, f in enumerate(findings, 1):
            sev   = str(_attr(f, "severity", _attr(f, "risk_level", "info"))).lower()
            title = str(_attr(f, "title", ""))
            rec   = str(_attr(f, "recommendation", ""))
            entry = f"FIND-{i:03d} **{title}**{': ' + rec if rec else ''}"
            if sev in ("critical", "high"):
                immediate.append(entry)
            elif sev == "medium":
                short_term.append(entry)
            else:
                long_term.append(entry)

    # Always add structural hardening
    long_term += [
        "Thiết lập Attack Surface Management (ASM) liên tục",
        "Đánh giá và thu hẹp subdomain footprint không cần thiết",
        "Kiểm tra tất cả service cũ / outdated trên internet-facing hosts",
        "Triển khai MFA trên tất cả admin/management interface",
    ]

    lines += ["### Immediate (0–7 ngày)", ""]
    if immediate:
        for item in immediate:
            lines.append(f"- {item}")
    else:
        lines.append("- Không có Critical/High findings — tiếp tục theo dõi.")
    lines += [""]

    lines += ["### Short-term (7–30 ngày)", ""]
    if short_term:
        for item in short_term:
            lines.append(f"- {item}")
    else:
        lines.append("- Không có Medium findings — xem xét hardening.")
    lines += [""]

    lines += ["### Long-term (30–90 ngày)", ""]
    for item in long_term:
        lines.append(f"- {item}")
    lines += ["", "---", ""]
    return lines


def _s08_appendix(
    spec: dict, coverage: dict, tables: dict, state: MINAState
) -> list[str]:
    """Section 8 — Appendix (tools, stats, cloud assets, subdomains, artifacts)."""
    lines = [f"## 8. Appendix", ""]

    # 8.1 Tools Used
    lines += ["### 8.1 Tools Used", ""]
    health = state.get("tool_health_snapshot", {})
    stats  = coverage.get("per_collector", {})

    collectors_run = sorted(coverage.get("collectors_run", []))
    if collectors_run:
        lines.append("**Collectors executed:**")
        for c in collectors_run:
            s = stats.get(c, {})
            lines.append(
                f"- `{c}`: {s.get('runs', 0)} run(s), "
                f"{s.get('total_events', 0)} events, "
                f"{s.get('success_rate', 0)}% success"
            )
        lines.append("")

    if health:
        lines.append("**External tool health:**")
        lines += [
            "| Tool | Installed | Ready | Version / Note |",
            "|---|---|---|---|",
        ]
        for tool, info in sorted(health.items()):
            if isinstance(info, dict):
                inst  = "✅" if info.get("installed") else "❌"
                ready = "✅" if info.get("ready")     else "❌"
                note  = info.get("version", info.get("error", ""))[:60]
                lines.append(f"| {tool} | {inst} | {ready} | {note} |")
        lines.append("")

    # 8.2 Scan Statistics
    lines += ["### 8.2 Scan Statistics", ""]
    dom_table = tables.get("domains_subdomains_table", [])
    ip_table  = tables.get("ip_asn_table", [])
    svc_table = tables.get("services_table", [])
    ep_table  = tables.get("endpoints_table", [])
    find_table = tables.get("findings_table", [])

    sev_counts: dict[str, int] = {}
    for row in find_table:
        sev = str(row.get("severity", "Info")).lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    roots  = len([r for r in dom_table if not r.get("subdomain")])
    subs   = len([r for r in dom_table if r.get("subdomain")])
    u_ips  = len({r.get("ip", "") for r in ip_table if r.get("ip")})
    u_asns = len({r.get("asn", "") for r in ip_table if r.get("asn")})

    lines += [
        "| Metric | Value |",
        "|---|---|",
        f"| Root domains | {roots} |",
        f"| Subdomains | {subs} |",
        f"| Unique IPs | {u_ips} |",
        f"| Unique ASNs | {u_asns} |",
        f"| Services | {len(svc_table)} |",
        f"| Endpoints | {len(ep_table)} |",
        f"| Total entities | {coverage.get('total_entities', 0)} |",
        f"| Total relationships | {coverage.get('total_relationships', 0)} |",
        f"| Findings — Critical | {sev_counts.get('critical', 0)} |",
        f"| Findings — High | {sev_counts.get('high', 0)} |",
        f"| Findings — Medium | {sev_counts.get('medium', 0)} |",
        f"| Findings — Low | {sev_counts.get('low', 0)} |",
        f"| Findings — Info | {sev_counts.get('info', 0)} |",
        f"| Iterations | {coverage.get('iterations', 0)} |",
        f"| Stop reason | {coverage.get('stop_reason', 'unknown')} |",
        "",
    ]

    # 8.3 Potential Cloud Assets (Unverified)
    cloud_rows = [
        r for r in tables.get("digital_assets_table", [])
        if "cloud" in str(r.get("type", "")).lower()
        or any(kw in str(r.get("value", "")).lower()
               for kw in ["amazonaws", "azure", "googleapis", "cloudfront",
                          "s3.", "blob.core", "storage.googleapis"])
    ]
    if cloud_rows:
        lines += ["### 8.3 Potential Cloud Assets (UNVERIFIED)", ""]
        lines.append("> Danh sách này dựa trên heuristic — chưa được xác minh.")
        lines.append("")
        for row in cloud_rows[:30]:
            lines.append(f"- `{row.get('value', '')}` ({row.get('type', '')})")
        if len(cloud_rows) > 30:
            lines.append(f"- _... {len(cloud_rows) - 30} more — xem digital_assets_table_")
        lines.append("")

    # 8.4 Full List of Subdomains
    all_subs = [r.get("subdomain", "") for r in dom_table if r.get("subdomain")]
    if all_subs:
        lines += ["### 8.4 Full List of Subdomains", ""]
        lines.append(f"Tổng cộng **{len(all_subs)}** subdomains:")
        lines.append("")
        preview = all_subs[:100]
        for sub in preview:
            lines.append(f"- `{sub}`")
        if len(all_subs) > 100:
            lines.append(
                f"- _... {len(all_subs) - 100} more — xem "
                f"`domains_subdomains_table.json` để có danh sách đầy đủ._"
            )
        lines.append("")

    # 8.5 Exported Table Artifacts
    lines += ["### 8.5 Exported Table Artifacts", ""]
    lines.append("Tất cả dữ liệu machine-readable lưu trong thư mục `tables/`:")
    lines.append("")
    for tname in sorted(tables.keys()):
        lines.append(f"- `tables/{tname}.json` / `tables/{tname}.csv`")
    lines += [
        "",
        "_Report file:_ `report.md` / `report.html`  ",
        "_Intelligence snapshot:_ `intel.json`",
        "",
    ]

    lines += ["---", ""]
    return lines


# ===================================================================
# HTML renderer
# ===================================================================

def _render_html(md_content: str, spec: dict, findings: list) -> str:
    """Render markdown as styled HTML report."""
    try:
        import markdown
        html_body = markdown.markdown(
            md_content, extensions=["tables", "fenced_code"]
        )
    except ImportError:
        html_body = f"<pre>{md_content}</pre>"

    risk_summary = ""
    for risk in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in findings if _attr(f, "risk_level", "") == risk)
        if count:
            color = {
                "critical": "#dc2626", "high": "#f97316", "medium": "#eab308",
                "low": "#22c55e", "info": "#94a3b8",
            }.get(risk, "#fff")
            risk_summary += (
                f'<span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:4px;margin:2px">{risk.upper()}: {count}</span> '
            )

    import html as html_mod
    target_escaped = html_mod.escape(spec.get("target", ""))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MINA Report — {target_escaped}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #1e293b; }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #3b82f6; padding-bottom: 8px; }}
  h2 {{ color: #1e40af; border-bottom: 1px solid #e2e8f0; margin-top: 2em; }}
  h3 {{ color: #334155; }}
  h4 {{ color: #475569; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left; font-size: 0.85em; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
  pre {{ background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; }}
  blockquote {{ border-left: 4px solid #f59e0b; padding: 8px 16px; background: #fffbeb; margin: 16px 0; }}
  .risk-bar {{ margin: 16px 0; }}
</style>
</head>
<body>
<div class="risk-bar">{risk_summary}</div>
{html_body}
</body>
</html>"""


# ===================================================================
# Intel JSON & file helpers
# ===================================================================

def _build_intel_json(state: MINAState, findings: list, coverage: dict) -> dict:
    """Machine-readable intelligence JSON."""
    def _safe_dict(obj):
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "dict"):
            return obj.dict()
        return {}

    return {
        "session_id": state["engagement_spec"]["session_id"],
        "target": state["engagement_spec"].get("target", ""),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage,
        "findings": [_safe_dict(f) for f in findings],
        "entities": [_safe_dict(e) for e in state.get("entities", [])],
        "relationships": [_safe_dict(r) for r in state.get("relationships", [])],
        "phase_log": state.get("phase_log", []),
    }


def _symlink_latest(session_dir: Path):
    """Copy reports to top-level output/ for easy access."""
    import shutil
    output_dir = Path("backend/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("report.md", "report.html", "intel.json"):
        src = session_dir / name
        if src.exists():
            shutil.copy2(src, output_dir / name)
