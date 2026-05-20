"""
Active Recon Agent — sends requests directly to target.
Enforces Rules of Engagement before any tool run.
Emits structured Observations with evidence_ref.
"""
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.state import MINAState
from core.schemas import Observation, Lead, normalize_lead_type
from core.evidence_store import EvidenceStore
from core.canonicalization import Canonicalizer
from core.runtime_emit import materialize_entity_from_observation, emit_runtime_relationship, emit_raw_event
from core.identity import make_entity_id
from core.scope import is_in_scope

logger = logging.getLogger(__name__)

_HIGH_RISK_PORTS = {21, 23, 25, 445, 3389, 5900, 27017, 6379, 9200, 11211}
_MEDIUM_RISK_PORTS = {80, 8080, 8443, 3306, 5432, 1433, 22, 53}


def active_recon_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Active Recon Agent."""
    if not state.get("active_tasks"):
        return state

    spec = state["engagement_spec"]

    # Get real-time log callback from LangGraph config
    _log = None
    if config is not None:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")

    # ROE global switch
    if not spec.get("active_recon_enabled", True):
        logger.warning("[ActiveRecon] Active recon DISABLED by ROE.")
        if _log:
            _log({"agent": "ActiveRecon", "level": "warning",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "message": "Active recon DISABLED by ROE — skipping all active tasks."})
        state["active_tasks"] = []
        return state

    # agents_enabled guard
    if not spec.get("agents_enabled", {}).get("active_recon", True):
        logger.warning("[ActiveRecon] Active recon DISABLED by agents_enabled.")
        if _log:
            _log({"agent": "ActiveRecon", "level": "warning",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "message": "Active recon DISABLED by agents_enabled toggle."})
        state["active_tasks"] = []
        return state

    session_dir = Path(f"backend/output/sessions/{spec['session_id']}")
    evidence_store = EvidenceStore(session_dir)

    new_observations = []
    new_leads = []

    for task in state["active_tasks"]:
        tool = str(task.get("tool", "")).strip().lower()
        target = task.get("target", state.get("target", ""))

        if not tool or not target:
            continue

        if not is_in_scope(target, spec):
            logger.warning("[ActiveRecon] %s is out of scope — skipping [%s]", target, tool)
            if _log:
                _log({"agent": "ActiveRecon", "level": "warning",
                      "timestamp": datetime.now(timezone.utc).isoformat(),
                      "message": f"[{tool.upper()}] {target} is OUT OF SCOPE — skipping"})
            continue

        if _log:
            _log({"agent": "ActiveRecon", "level": "info",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "message": f"[{tool.upper()}] scanning {target} ..."})

        try:
            time.sleep(spec.get("rate_limit_seconds", 1.5))
            result = _dispatch_tool(tool, target, wordlist_type=spec.get("wordlist_profile", "small"), spec=spec, task=task)
            if not result:
                if _log:
                    _log({"agent": "ActiveRecon", "level": "info",
                          "timestamp": datetime.now(timezone.utc).isoformat(),
                          "message": f"[{tool.upper()}] {target}: no results"})
                continue

            evidence_id = evidence_store.store_raw(
                collector=f"active/{tool}",
                query=target,
                content=json.dumps(result, indent=2, default=str),
                content_type="application/json"
            )
            result["_evidence_id"] = evidence_id

            obs, leads = _extract_observations(
                tool, target, result, state.get("current_lead"),
                spec.get("session_id", ""), evidence_id
            )
            new_observations.extend(obs)
            new_leads.extend(leads)
            _update_stats(state, f"active/{tool}", success=True,
                          events=len(obs), leads=len(leads))
            # Emit RawEvent for provenance tracking
            emit_raw_event(
                state, collector=f"active/{tool}", tool=tool, target=target,
                evidence_id=evidence_id, success=True,
                extracted_count=len(obs), new_leads_count=len(leads),
            )

            msg = f"[{tool.upper()}] {target}: {len(obs)} observations, {len(leads)} new leads"
            if _log:
                _log({"agent": "ActiveRecon", "level": "success" if obs else "info",
                      "timestamp": datetime.now(timezone.utc).isoformat(), "message": msg})
            state.setdefault("phase_log", []).append({
                "phase": "active_recon",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "success" if obs else "info",
                "message": msg,
            })

        except Exception as exc:
            logger.error("[ActiveRecon] %s on %s: %s", tool, target, exc)
            _update_stats(state, f"active/{tool}", success=False, error=str(exc))
            # Emit RawEvent for failures
            emit_raw_event(
                state, collector=f"active/{tool}", tool=tool, target=target,
                evidence_id="", success=False, error_message=str(exc),
            )
            err_msg = f"[{tool.upper()}] {target} FAILED: {exc}"
            if _log:
                _log({"agent": "ActiveRecon", "level": "error",
                      "timestamp": datetime.now(timezone.utc).isoformat(), "message": err_msg})
            state["error_log"].append({
                "tool": f"active/{tool}", "target": target,
                "error": str(exc), "timestamp": datetime.now(timezone.utc).isoformat()
            })

    state["observations"].extend(new_observations)
    state["lead_queue"].extend(new_leads)
    state["active_tasks"] = []

    # Runtime entity materialization — entities appear during scan
    current_lead = state.get("current_lead")
    parent_eid = None
    if current_lead:
        _val = getattr(current_lead, "value", "") or ""
        _type = getattr(current_lead, "type", "") or ""
        if _val and _type:
            parent_eid = make_entity_id(_type, _val)

    for obs in new_observations:
        ent = materialize_entity_from_observation(state, obs, parent_entity_id=parent_eid)
        if ent and parent_eid:
            child_eid = getattr(ent, "entity_id", "")
            if child_eid and child_eid != parent_eid:
                rel_type = _infer_relation(obs.type)
                emit_runtime_relationship(
                    state, parent_eid, child_eid, rel_type,
                    confidence=obs.confidence * 0.9,
                    evidence_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                    observation_ids=[obs.observation_id],
                    derived_by="active_recon",
                )

    return state


def _infer_relation(obs_type: str) -> str:
    """Infer relationship type from observation type."""
    mapping = {
        "subdomain_found": "belongs_to",
        "ip_found": "resolves_to",
        "port_open": "exposes",
        "service_detected": "exposes",
        "email_found": "leaks",
        "cert_found": "shares_cert",
        "org_found": "owned_by",
        "asn_found": "belongs_to",
        "technology_found": "uses_technology",
        "endpoint_found": "contains",
        "vulnerability_found": "exposes",
        "webapp_alive": "hosted_on",
        "url_found": "contains",
        "header_found": "exposes",
        "waf_detected": "uses_technology",
        "repo_found": "associated_with",
        "document_found": "leaks",
        "credential_signal_found": "leaks",
        "person_found": "employs",
        "parameter_found": "contains",
    }
    return mapping.get(obs_type, "linked_to")


def _dispatch_tool(tool: str, target: str, wordlist_type: str = "small", spec: dict = None, task: dict = None) -> dict:
    """Route tool call to appropriate module. V4: passes tool_options."""
    from tools.active_tools import run_nmap, run_subfinder, run_httpx, run_nuclei, run_vhost_discovery
    from tools.web_tools import (
        check_http_headers, ssl_tls_check, detect_waf,
        analyze_tech_stack, enumerate_directories, crawl_urls,
        parse_robots_sitemap, check_http_methods,
        find_cloud_assets, compute_favicon_hash,
        grab_banner, discover_params,
    )
    from tools.web_surface import WebSurfacePipeline

    _spec = spec or {}
    _task = task or {}
    opts = _task.get("options", {})

    dispatch = {
        "nmap":        lambda t: run_nmap(t, options=opts),
        "subfinder":   lambda t: run_subfinder(t, options=opts),
        "httpx":       lambda t: run_httpx([t], options=opts),
        "nuclei":      lambda t: run_nuclei([t], options=opts),
        "vhost":       lambda t: run_vhost_discovery(_resolve_ip(t), t),
        "headers":     lambda t: check_http_headers(_normalize_url(t), options=opts),
        "ssl":         lambda t: ssl_tls_check(_normalize_url(t), options=opts),
        "waf":         lambda t: detect_waf(_normalize_url(t), options=opts),
        "tech":        lambda t: analyze_tech_stack(_normalize_url(t), options=opts),
        "dirs":        lambda t: enumerate_directories(_normalize_url(t), wordlist_type=wordlist_type, options=opts),
        "crawl":       lambda t: crawl_urls(_normalize_url(t), max_pages=opts.get("max_pages", 50), depth=opts.get("depth", 2), options=opts),
        "robots":      lambda t: parse_robots_sitemap(_normalize_url(t), options=opts),
        "http_methods":lambda t: check_http_methods(_normalize_url(t), options=opts),
        "cloud":       lambda t: find_cloud_assets(t, options=opts),
        "favicon":     lambda t: compute_favicon_hash(_normalize_url(t), options=opts),
        "banner":      lambda t: grab_banner(t, opts.get("port", 80), options=opts),
        "params":      lambda t: discover_params(_normalize_url(t), options=opts),
        "web_surface": lambda t: WebSurfacePipeline(
            t,
            spec={"features": {
                "dir_enum": True,
                "crawler": _spec.get("enable_endpoint_crawl", False),
            }},
        ).run(),
    }

    if tool not in dispatch:
        logger.debug("[ActiveRecon] Unknown tool: %s", tool)
        return {}

    return dispatch[tool](target) or {}


def _normalize_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _resolve_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _extract_observations(tool: str, target: str, result: dict,
                           parent_lead, session_id: str,
                           evidence_id: str):
    """Extract Observations and new Leads from active tool result."""
    observations = []
    new_leads = []

    if tool == "nmap" and result.get("success"):
        ports = result.get("data", {}).get("ports", [])
        for port_info in ports:
            port = port_info.get("port") if isinstance(port_info, dict) else int(port_info)
            service = port_info.get("service", "") if isinstance(port_info, dict) else ""
            risk = _assess_port_risk(port)

            obs = Observation(
                session_id=session_id,
                raw_event_id=evidence_id,
                extractor="nmap_extractor",
                type="port_open",
                value=f"{target}:{port}",
                context=f"Nmap detected open port {port} ({service})",
                source="nmap",
                evidence_ref=evidence_id,
                confidence=0.9,
                rate=risk.capitalize(),
                attributes={"port": port, "service": service, "protocol": "tcp"}
            )
            observations.append(obs)

            if risk in ("high", "medium"):
                new_leads.append(Lead(
                    type="service",
                    value=f"{target}:{port}",
                    source="nmap",
                    confidence=0.85,
                    priority=0.8 if risk == "high" else 0.5,
                    depth=(parent_lead.depth + 1) if parent_lead else 1,
                    parent_lead_id=parent_lead.lead_id if parent_lead else None,
                    discovered_by="active_recon/nmap",
                    evidence_refs=[evidence_id]
                ))

    elif tool == "nuclei" and result.get("success"):
        findings = result.get("data", {}).get("findings", [])
        sev_conf = {"critical": 0.97, "high": 0.9, "medium": 0.75, "low": 0.5, "info": 0.3}
        for nf in findings:
            sev = nf.get("severity", "info").lower()
            obs = Observation(
                session_id=session_id,
                raw_event_id=evidence_id,
                extractor="nuclei_extractor",
                type="vulnerability_found",
                value=nf.get("matched_at", target),
                context=nf.get("description", nf.get("name", "nuclei finding")),
                source="nuclei",
                evidence_ref=evidence_id,
                confidence=sev_conf.get(sev, 0.5),
                rate=sev.capitalize(),
                attributes={
                    "template_id": nf.get("template_id", ""),
                    "severity": sev,
                    "cvss": nf.get("cvss_score", 0),
                    "references": nf.get("reference", []),
                }
            )
            observations.append(obs)

    elif tool == "subfinder" and result.get("success"):
        for subdomain in result.get("data", {}).get("subdomains", []):
            canonical = Canonicalizer.domain(subdomain)
            obs = Observation(
                session_id=session_id,
                raw_event_id=evidence_id,
                extractor="subfinder_extractor",
                type="subdomain_found",
                value=subdomain,
                normalized_value=canonical,
                context="Found by subfinder",
                source="subfinder",
                evidence_ref=evidence_id,
                confidence=0.8,
                rate="Low",
            )
            observations.append(obs)
            new_leads.append(Lead(
                type="subdomain",
                value=canonical,
                source="subfinder",
                confidence=0.8,
                priority=0.65,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="active_recon/subfinder",
                evidence_refs=[evidence_id]
            ))

    elif tool == "ssl" and result.get("success"):
        data = result.get("data", {})
        obs = Observation(
            session_id=session_id,
            raw_event_id=evidence_id,
            extractor="ssl_extractor",
            type="cert_found",
            value=target,
            context=f"TLS cert: issuer={data.get('cert_issuer','')} expires_in={data.get('cert_expiry_days','')}d grade={data.get('grade','')}",
            source="ssl",
            evidence_ref=evidence_id,
            confidence=0.95,
            rate="Low",
            attributes=data
        )
        observations.append(obs)
        # Flag issues as findings-ready observations
        for issue in data.get("issues", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="ssl_extractor", type="vulnerability_found",
                value=target,
                context=f"TLS issue: {issue.get('description', issue)}",
                source="ssl", evidence_ref=evidence_id,
                confidence=0.85, rate="Medium",
                attributes={"host": target, "issue": issue}
            ))

    elif tool == "robots" and result.get("success"):
        data = result.get("data", {})
        for path in data.get("disallowed", [])[:20]:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="robots_extractor", type="endpoint_found",
                value=f"https://{target}{path}" if path.startswith("/") else path,
                context=f"robots.txt Disallow entry for {target}",
                source="robots", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
                attributes={"domain": target, "source": "robots_txt"}
            ))
        for sitemap_url in data.get("sitemaps", [])[:10]:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="robots_extractor", type="url_found",
                value=sitemap_url,
                context=f"Sitemap URL from robots.txt for {target}",
                source="robots", evidence_ref=evidence_id,
                confidence=0.85, rate="Low",
                attributes={"domain": target, "source": "sitemap"}
            ))

    elif tool == "http_methods" and result.get("success"):
        data = result.get("data", {})
        for method in data.get("dangerous_methods", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="http_methods_extractor", type="vulnerability_found",
                value=target,
                context=f"Dangerous HTTP method {method} enabled on {target}",
                source="http_methods", evidence_ref=evidence_id,
                confidence=0.80, rate="Medium",
                attributes={"method": method, "host": target}
            ))
        # Also record all allowed methods
        for method in data.get("allowed_methods", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="http_methods_extractor", type="header_found",
                value=f"{target}:{method}",
                context=f"HTTP method {method} is allowed on {target}",
                source="http_methods", evidence_ref=evidence_id,
                confidence=0.85, rate="Low",
                attributes={"method": method, "host": target}
            ))

    elif tool == "httpx" and result.get("success"):
        data = result.get("data", {})
        for item in data.get("results", []):
            url = item.get("url", target)
            status_code = item.get("status_code", 0)
            title = item.get("title", "")
            webserver = item.get("webserver", "")
            techs = item.get("tech", [])
            # Live HTTP service observation
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="httpx_extractor", type="webapp_alive",
                value=url,
                context=f"HTTP {status_code} — {title} (server: {webserver})",
                source="httpx", evidence_ref=evidence_id,
                confidence=0.95, rate="Low",
                attributes={"url": url, "status_code": status_code,
                            "title": title, "webserver": webserver,
                            "content_length": item.get("content_length", 0)}
            ))
            # Web server detection
            if webserver:
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="httpx_extractor", type="technology_found",
                    value=webserver,
                    context=f"Web server {webserver} on {url}",
                    source="httpx", evidence_ref=evidence_id,
                    confidence=0.90, rate="Low",
                    attributes={"url": url, "server": webserver}
                ))
            # Technology detection
            for tech in techs:
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="httpx_extractor", type="technology_found",
                    value=tech,
                    context=f"Technology {tech} detected on {url}",
                    source="httpx", evidence_ref=evidence_id,
                    confidence=0.80, rate="Low",
                    attributes={"url": url, "technology": tech}
                ))
            # Create lead for live HTTP service
            if status_code and 200 <= status_code < 500:
                new_leads.append(Lead(
                    type="subdomain" if url != target else "endpoint",
                    value=url, source="httpx",
                    confidence=0.85, priority=0.7,
                    depth=(parent_lead.depth + 1) if parent_lead else 1,
                    parent_lead_id=parent_lead.lead_id if parent_lead else None,
                    discovered_by="active_recon/httpx",
                    evidence_refs=[evidence_id]
                ))

    elif tool == "headers" and result.get("success"):
        data = result.get("data", {})
        # Present security headers
        for hdr_name, hdr_val in data.get("present_headers", {}).items():
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="headers_extractor", type="header_found",
                value=f"{target}:{hdr_name}",
                context=f"Security header {hdr_name}: {str(hdr_val)[:100]}",
                source="headers", evidence_ref=evidence_id,
                confidence=0.90, rate="Low",
                attributes={"header": hdr_name, "value": str(hdr_val)[:200], "host": target}
            ))
        # Missing security headers
        for issue in data.get("missing_headers", []):
            hdr_name = issue.get("header", issue) if isinstance(issue, dict) else str(issue)
            sev = issue.get("severity", "Medium") if isinstance(issue, dict) else "Medium"
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="headers_extractor", type="header_found",
                value=f"{target}:{hdr_name}",
                context=f"Missing security header: {hdr_name} on {target}",
                source="headers", evidence_ref=evidence_id,
                confidence=0.85, rate=sev,
                attributes={"header": hdr_name, "host": target, "severity": sev}
            ))
        # Cookie issues
        for cookie_issue in data.get("cookie_issues", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="headers_extractor", type="vulnerability_found",
                value=target,
                context=f"Cookie issue: {cookie_issue.get('issue', str(cookie_issue))}",
                source="headers", evidence_ref=evidence_id,
                confidence=0.80, rate="Medium",
                attributes={"host": target, "issue": cookie_issue}
            ))
        # Server header info disclosure
        server_header = data.get("server", "")
        if server_header:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="headers_extractor", type="technology_found",
                value=server_header,
                context=f"Server header reveals: {server_header}",
                source="headers", evidence_ref=evidence_id,
                confidence=0.90, rate="Low",
                attributes={"host": target, "server": server_header}
            ))

    elif tool == "tech" and result.get("success"):
        data = result.get("data", {})
        for category, items in data.get("technologies", {}).items():
            for tech_name in (items if isinstance(items, list) else [items]):
                obs_type = "technology_found"
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="tech_extractor", type=obs_type,
                    value=tech_name if isinstance(tech_name, str) else str(tech_name),
                    context=f"{category}: {tech_name} on {target}",
                    source="tech", evidence_ref=evidence_id,
                    confidence=0.80, rate="Low",
                    attributes={"category": category, "host": target,
                                "technology": tech_name if isinstance(tech_name, str) else str(tech_name)}
                ))

    elif tool == "waf" and result.get("success"):
        data = result.get("data", {})
        waf_name = data.get("waf", data.get("detected", ""))
        if waf_name:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="waf_extractor", type="waf_detected",
                value=waf_name if isinstance(waf_name, str) else str(waf_name),
                context=f"WAF detected: {waf_name} on {target}",
                source="waf", evidence_ref=evidence_id,
                confidence=0.85, rate="Low",
                attributes={"waf": waf_name, "host": target}
            ))
        # CDN detection (sometimes included in WAF data)
        cdn = data.get("cdn", "")
        if cdn:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="waf_extractor", type="technology_found",
                value=cdn if isinstance(cdn, str) else str(cdn),
                context=f"CDN detected: {cdn} on {target}",
                source="waf", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
                attributes={"cdn": cdn, "host": target}
            ))

    elif tool == "dirs" and result.get("success"):
        data = result.get("data", {})
        for item in data.get("found", data.get("results", []))[:50]:
            path = item.get("path", item.get("url", str(item))) if isinstance(item, dict) else str(item)
            status = item.get("status_code", 200) if isinstance(item, dict) else 200
            obs_type = "endpoint_found"
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="dirs_extractor", type=obs_type,
                value=path if path.startswith("http") else f"https://{target}{path}",
                context=f"Directory enumeration: {path} (HTTP {status})",
                source="dirs", evidence_ref=evidence_id,
                confidence=0.75, rate="Medium" if status == 200 else "Low",
                attributes={"path": path, "status_code": status, "host": target}
            ))
            if status == 200:
                new_leads.append(Lead(
                    type="endpoint",
                    value=path if path.startswith("http") else f"https://{target}{path}",
                    source="dirs", confidence=0.70, priority=0.55,
                    depth=(parent_lead.depth + 1) if parent_lead else 1,
                    parent_lead_id=parent_lead.lead_id if parent_lead else None,
                    discovered_by="active_recon/dirs",
                    evidence_refs=[evidence_id]
                ))

    elif tool == "crawl" and result.get("success"):
        data = result.get("data", {})
        for url_item in data.get("urls", data.get("discovered_urls", []))[:50]:
            url = url_item.get("url", str(url_item)) if isinstance(url_item, dict) else str(url_item)
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="crawl_extractor", type="endpoint_found",
                value=url,
                context=f"Crawled URL from {target}",
                source="crawl", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
                attributes={"source_url": target, "discovered_url": url}
            ))
            new_leads.append(Lead(
                type="endpoint", value=url, source="crawl",
                confidence=0.75, priority=0.55,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="active_recon/crawl",
                evidence_refs=[evidence_id]
            ))
        for form in data.get("forms", [])[:20]:
            form_action = form.get("action", "") if isinstance(form, dict) else str(form)
            if form_action:
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="crawl_extractor", type="endpoint_found",
                    value=form_action,
                    context=f"Form action found: {form_action}",
                    source="crawl", evidence_ref=evidence_id,
                    confidence=0.75, rate="Low",
                    attributes={"form_action": form_action, "method": form.get("method", "GET") if isinstance(form, dict) else "GET"}
                ))

    elif tool == "cloud" and result.get("success"):
        data = result.get("data", {})
        for bucket in data.get("found_buckets", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="cloud_extractor", type="url_found",
                value=bucket.get("url", str(bucket)),
                context=f"Cloud storage bucket found for {target}",
                source="cloud", evidence_ref=evidence_id,
                confidence=0.85, rate="High",
                attributes={"domain": target, "provider": bucket.get("provider", ""), "public": bucket.get("public", False)}
            ))

    elif tool == "favicon" and result.get("success"):
        data = result.get("data", {})
        favicon_hash = data.get("hash", "")
        if favicon_hash:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="favicon_extractor", type="technology_found",
                value=str(favicon_hash),
                context=f"Favicon hash {favicon_hash} for {target} — useful for Shodan correlation",
                source="favicon", evidence_ref=evidence_id,
                confidence=0.70, rate="Low",
                attributes={"domain": target, "favicon_hash": favicon_hash}
            ))

    elif tool == "banner" and result.get("success"):
        data = result.get("data", {})
        banner_text = data.get("banner", "")
        if banner_text:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="banner_extractor", type="service_detected",
                value=target,
                context=f"TCP banner: {banner_text[:200]}",
                source="banner", evidence_ref=evidence_id,
                confidence=0.75, rate="Medium",
                attributes={"host": target, "port": data.get("port", 80), "banner": banner_text[:500]}
            ))

    elif tool == "params" and result.get("success"):
        data = result.get("data", {})
        for param in data.get("parameters", [])[:30]:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="params_extractor", type="parameter_found",
                value=f"{target}?{param}=",
                context=f"Hidden parameter '{param}' discovered on {target}",
                source="params", evidence_ref=evidence_id,
                confidence=0.65, rate="Low",
                attributes={"domain": target, "param": param}
            ))

    elif tool == "web_surface" and result.get("success"):
        data = result.get("data", {})
        for ep in data.get("endpoints", [])[:50]:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            score = ep.get("interesting_score", 0.0) if isinstance(ep, dict) else 0.0
            obs_type = "endpoint_found" if score >= 0.5 else "url_found"
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="web_surface_extractor", type=obs_type,
                value=url,
                context=f"Web surface endpoint (score={score:.2f}) for {target}",
                source="web_surface", evidence_ref=evidence_id,
                confidence=0.75 + score * 0.15, rate="Medium" if score >= 0.5 else "Low",
                attributes={"domain": target, "interesting_score": score,
                            "status_code": ep.get("status_code") if isinstance(ep, dict) else None}
            ))
        # Emit leads from web_surface leads list
        for lead_d in data.get("leads", [])[:20]:
            lv = lead_d.get("value", "") if isinstance(lead_d, dict) else str(lead_d)
            lt = lead_d.get("type", "endpoint") if isinstance(lead_d, dict) else "endpoint"
            if lv:
                new_leads.append(Lead(
                    type=normalize_lead_type(lt), value=lv, source="web_surface",
                    confidence=0.70, priority=0.60,
                    depth=(parent_lead.depth + 1) if parent_lead else 1,
                    parent_lead_id=parent_lead.lead_id if parent_lead else None,
                    discovered_by="active_recon/web_surface",
                    evidence_refs=[evidence_id]
                ))

    return observations, new_leads


def _assess_port_risk(port: int) -> str:
    if port in _HIGH_RISK_PORTS:
        return "high"
    if port in _MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


def _update_stats(state: MINAState, tool: str, success: bool,
                  events: int = 0, leads: int = 0, error: str = ""):
    if "collector_stats" not in state:
        state["collector_stats"] = {}
    if tool not in state["collector_stats"]:
        state["collector_stats"][tool] = {
            "runs": 0, "success": 0, "failures": 0,
            "total_events": 0, "total_leads": 0, "errors": []
        }
    stats = state["collector_stats"][tool]
    stats["runs"] += 1
    if success:
        stats["success"] += 1
        stats["total_events"] += events
        stats["total_leads"] += leads
    else:
        stats["failures"] += 1
        if error:
            stats["errors"].append(error)
