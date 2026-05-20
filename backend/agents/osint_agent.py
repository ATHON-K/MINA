"""
OSINT Agent Node — Deep passive intelligence beyond basic recon.

Runs: zone_transfer, github_dork_hints, google_dork_hints,
      extract_js_endpoints, cve_lookup_for_service, spf_dmarc_check,
      wayback_machine_query, karma_v2.

Positioned between passive_recon and active_recon in the graph.
All operations are NON-INVASIVE (no direct scanning of target).

Uses MINAState — returns observations, findings, phase_log updates.
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.state import MINAState
from core.schemas import Observation, Lead, Finding, normalize_lead_type
from core.evidence_store import EvidenceStore
from core.config import config as _cfg
from core.scope import is_garbage_lead
from core.runtime_emit import materialize_entity_from_observation, emit_runtime_relationship, emit_raw_event
from core.identity import make_entity_id
from prompts.recon_prompts import OSINT_ANALYSIS_PROMPT, OSINT_ANALYSIS_SYSTEM


def _safe_format(template: str, **kwargs) -> str:
    """str.replace-based formatting that ignores JSON literal braces."""
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template
from tools.osint_tools import (
    cve_lookup_for_service,
    extract_js_endpoints,
    github_dork_hints,
    google_dork_hints,
    google_analytics_id_lookup,
    reverse_ip_lookup,
    reverse_whois_lookup,
    spf_dmarc_check,
    wayback_machine_query,
    zone_transfer_attempt,
)
from tools.karma_tools import karma_health_check, run_karma_cve, run_karma_ip, run_karma_leaks, smap_passive_portscan

logger = logging.getLogger(__name__)


def _get_client():
    """Lazy-load OpenAI client. Raises if SDK unavailable or key missing."""
    try:
        from openai import OpenAI  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("openai SDK not installed") from exc
    return OpenAI(
        api_key=_cfg.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", ""),
        base_url=_cfg.deepseek_base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
    )


def _emit(log_cb: Optional[Callable], msg: str, level: str = "info") -> Dict:
    entry = {
        "timestamp": datetime.now().isoformat(),
        "agent": "OSINTAgent",
        "message": msg,
        "level": level,
    }
    if log_cb:
        try:
            log_cb(entry)
        except Exception:
            pass
    logger.info("[OSINT] %s", msg)
    return entry


def _extract_json(text: str) -> Optional[Dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def osint_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: OSINT Deep-Dive Agent — uses MINAState."""
    configurable = {}
    if config is not None:
        configurable = (config if isinstance(config, dict) else {}).get("configurable", {})
    log_cb = configurable.get("log_callback")

    spec = state.get("engagement_spec", {})

    # agents_enabled guard
    if not spec.get("agents_enabled", {}).get("osint", True):
        _emit(log_cb, "⛔ OSINT Agent disabled by agents_enabled — skipping.", "warning")
        return state

    # Determine target
    current_lead = state.get("current_lead")
    target = ""
    if current_lead:
        target = getattr(current_lead, "value", "") or ""
    if not target:
        target = spec.get("target", "")
    if not target:
        _emit(log_cb, "No target set — skipping OSINT", "warning")
        return state

    session_id = spec.get("session_id", "")
    session_dir = Path(f"backend/output/sessions/{session_id}")
    evidence_store = EvidenceStore(session_dir)

    _emit(log_cb, f"🕵️ OSINT Agent started for target: {target}")

    new_observations: List[Observation] = []
    new_findings: List[Finding] = []
    new_leads: List[Lead] = []
    company = spec.get("company_name") or target.split(".")[0]

    # Evidence ref registry
    ev_refs: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # 1. Zone Transfer Attempt
    # ------------------------------------------------------------------
    _emit(log_cb, "🔄 Zone transfer attempt...")
    zone_result = zone_transfer_attempt(target)
    ev_refs["zone_transfer"] = evidence_store.store_raw(
        collector="osint/zone_transfer", query=target,
        content=json.dumps(zone_result, default=str), content_type="application/json"
    )
    if zone_result.get("success") and zone_result.get("data", {}).get("hosts"):
        host_count = len(zone_result["data"]["hosts"])
        _emit(log_cb, f"  ⚠️ Zone transfer SUCCEEDED — {host_count} hosts leaked!", "alert")
        new_findings.append(Finding(
            session_id=session_id,
            title="DNS Zone Transfer Enabled",
            description=f"Zone transfer (AXFR) succeeded for {target}. Revealed {host_count} internal hosts.",
            risk_level="critical",
            category="service_misconfiguration",
            impact_category="service_misconfiguration",
            impact_items=[target],
            evidence_refs=[ev_refs["zone_transfer"]],
            confidence_score=0.95,
            recommendation="Restrict AXFR transfers to authorised secondary DNS servers only.",
        ))
        for host in zone_result["data"]["hosts"]:
            if isinstance(host, str) and not is_garbage_lead(host):
                new_observations.append(Observation(
                    session_id=session_id, raw_event_id=ev_refs["zone_transfer"],
                    extractor="zone_transfer_extractor", type="subdomain_found",
                    value=host, context=f"Zone transfer disclosed from {target}",
                    source="zone_transfer", evidence_ref=ev_refs["zone_transfer"],
                    confidence=0.95, rate="High",
                ))
    else:
        _emit(log_cb, "  ✅ Zone transfer blocked (expected)")

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 2. SPF / DMARC / DKIM Check
    # ------------------------------------------------------------------
    _emit(log_cb, "📧 Checking email security (SPF/DMARC/DKIM)...")
    email_sec_result = spf_dmarc_check(target)
    ev_refs["email_sec"] = evidence_store.store_raw(
        collector="osint/spf_dmarc", query=target,
        content=json.dumps(email_sec_result, default=str), content_type="application/json"
    )
    if email_sec_result.get("success"):
        data = email_sec_result.get("data", {})
        if not data.get("dmarc_exists"):
            _emit(log_cb, "  ⚠️ DMARC record MISSING — email spoofing possible!", "alert")
            new_findings.append(Finding(
                session_id=session_id,
                title="DMARC Not Configured",
                description=f"No DMARC policy found for {target}. Email spoofing possible.",
                risk_level="high",
                category="social_engineering_surface",
                impact_category="social_engineering_surface",
                impact_items=[target],
                evidence_refs=[ev_refs["email_sec"]],
                confidence_score=0.85,
                recommendation=f"Add DMARC TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@{target}",
            ))
        if not data.get("spf_exists"):
            _emit(log_cb, "  ⚠️ SPF record MISSING — spoofing risk!", "alert")

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 3. Wayback Machine
    # ------------------------------------------------------------------
    _emit(log_cb, "⏮️ Querying Wayback Machine for historical exposure...")
    wayback_result = wayback_machine_query(target, limit=300)
    ev_refs["wayback"] = evidence_store.store_raw(
        collector="osint/wayback", query=target,
        content=json.dumps(wayback_result, default=str), content_type="application/json"
    )
    if wayback_result.get("success"):
        interesting = wayback_result.get("data", {}).get("interesting", [])
        count = wayback_result.get("data", {}).get("total_urls", 0)
        _emit(log_cb, f"  ↳ {count} URLs found, {len(interesting)} sensitive paths", "info" if not interesting else "warning")
        for path in (interesting or [])[:15]:
            new_observations.append(Observation(
                session_id=session_id, raw_event_id=ev_refs["wayback"],
                extractor="wayback_extractor", type="url_found",
                value=path if path.startswith("http") else f"https://{target}{path}",
                context="Historical sensitive path from Wayback Machine",
                source="wayback", evidence_ref=ev_refs["wayback"],
                confidence=0.7, rate="Low",
            ))

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 4. JS Endpoint Extraction
    # ------------------------------------------------------------------
    _emit(log_cb, "🔍 Extracting API endpoints from JavaScript files...")
    js_result = extract_js_endpoints(target)
    ev_refs["js_endpoints"] = evidence_store.store_raw(
        collector="osint/js_endpoints", query=target,
        content=json.dumps(js_result, default=str), content_type="application/json"
    )
    if js_result.get("success"):
        endpoints = js_result.get("data", {}).get("endpoints", [])
        _emit(log_cb, f"  ↳ {len(endpoints)} API endpoints discovered", "success" if endpoints else "info")
        for ep in endpoints[:25]:
            new_observations.append(Observation(
                session_id=session_id, raw_event_id=ev_refs["js_endpoints"],
                extractor="js_endpoint_extractor", type="endpoint_found",
                value=ep if isinstance(ep, str) else str(ep),
                context=f"API endpoint from JS on {target}",
                source="js_endpoints", evidence_ref=ev_refs["js_endpoints"],
                confidence=0.7, rate="Low",
            ))

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 5. CVE Lookup for discovered services
    # ------------------------------------------------------------------
    entities = state.get("entities", [])
    discovered_services = []
    for ent in entities:
        ent_d = ent if isinstance(ent, dict) else (ent.model_dump() if hasattr(ent, "model_dump") else {})
        if ent_d.get("type") in ("service", "open_port"):
            svc = (ent_d.get("attributes") or {}).get("service", "")
            ver = (ent_d.get("attributes") or {}).get("version", "")
            if svc:
                discovered_services.append({"service": svc, "version": ver})

    if discovered_services:
        _emit(log_cb, f"🔥 CVE lookup for {len(discovered_services)} discovered services...")
        for svc_info in discovered_services[:5]:
            svc = svc_info["service"]
            ver = svc_info.get("version", "")
            result = cve_lookup_for_service(svc, ver)
            if result.get("success") and result.get("data", {}).get("cves"):
                cve_count = len(result["data"]["cves"])
                _emit(log_cb, f"  ⚠️ {cve_count} CVEs found for {svc}!", "warning")
                for cve in result["data"]["cves"][:3]:
                    score = float(cve.get("cvss", {}).get("score", 0) or 0)
                    if score >= 7.0:
                        new_findings.append(Finding(
                            session_id=session_id,
                            title=cve.get("id", "CVE"),
                            description=f"{svc} {ver}: {cve.get('summary', '')}",
                            risk_level="critical" if score >= 9 else "high",
                            category="infrastructure_exposure",
                            impact_category="infrastructure_exposure",
                            impact_items=[target],
                            evidence_refs=[],
                            confidence_score=0.85,
                            recommendation=f"Upgrade {svc} to latest stable version.",
                        ))
            time.sleep(1)
    else:
        _emit(log_cb, "ℹ️ No services discovered yet — skipping CVE lookup")

    # ------------------------------------------------------------------
    # 6. Dork Hints (informational)
    # ------------------------------------------------------------------
    _emit(log_cb, "🔎 Generating OSINT dork queries...")
    github_dork_result = github_dork_hints(target, company)
    google_dork_result = google_dork_hints(target)
    ev_refs["dorks"] = evidence_store.store_raw(
        collector="osint/dorks", query=target,
        content=json.dumps({"github": github_dork_result, "google": google_dork_result}, default=str),
        content_type="application/json"
    )

    # ------------------------------------------------------------------
    # 7. Karma v2 — Shodan-powered OSINT
    # ------------------------------------------------------------------
    karma_ip_result: Dict = {}
    karma_leaks_result: Dict = {}
    karma_cve_result: Dict = {}

    if spec.get("agents_enabled", {}).get("karma_v2", False) or spec.get("enable_karma_v2", False):
        health = karma_health_check()
        if health["ready"]:
            _emit(log_cb, "🔱 Karma v2 | Shodan IP enumeration...")
            karma_ip_result = run_karma_ip(target, limit=100)
            ev_refs["karma_ip"] = evidence_store.store_raw(
                collector="osint/karma_ip", query=target,
                content=json.dumps(karma_ip_result, default=str), content_type="application/json"
            )
            if karma_ip_result.get("success"):
                ip_count = karma_ip_result.get("data", {}).get("ip_count", 0)
                _emit(log_cb, f"  ↳ {ip_count} IPs discovered via Shodan", "success" if ip_count else "info")

            time.sleep(2)

            _emit(log_cb, "🔱 Karma v2 | Credential/secret leak detection...")
            karma_leaks_result = run_karma_leaks(target, limit=100)
            ev_refs["karma_leaks"] = evidence_store.store_raw(
                collector="osint/karma_leaks", query=target,
                content=json.dumps(karma_leaks_result, default=str), content_type="application/json"
            )
            if karma_leaks_result.get("success"):
                leak_count = karma_leaks_result.get("data", {}).get("leak_count", 0)
                if leak_count:
                    _emit(log_cb, f"  🚨 {leak_count} leaked secrets found!", "alert")
                else:
                    _emit(log_cb, "  ✅ No leaks detected", "info")

            time.sleep(2)

            _emit(log_cb, "🔱 Karma v2 | CVE enumeration via Shodan...")
            karma_cve_result = run_karma_cve(target, limit=100)
            ev_refs["karma_cve"] = evidence_store.store_raw(
                collector="osint/karma_cve", query=target,
                content=json.dumps(karma_cve_result, default=str), content_type="application/json"
            )
            if karma_cve_result.get("success"):
                cves = karma_cve_result.get("data", {}).get("cves_found", [])
                if cves:
                    _emit(log_cb, f"  🚨 {len(cves)} CVEs found via Shodan: {', '.join(cves[:5])}", "alert")
                    for cve_id in cves[:10]:
                        new_findings.append(Finding(
                            session_id=session_id,
                            title=cve_id,
                            description=f"CVE found via Shodan/karma_v2 for {target}.",
                            risk_level="high",
                            category="infrastructure_exposure",
                            impact_category="infrastructure_exposure",
                            impact_items=[target],
                            evidence_refs=[ev_refs.get("karma_cve", "")],
                            confidence_score=0.8,
                            recommendation=f"Verify affected asset and apply vendor patch for {cve_id}",
                        ))
    else:
        _emit(log_cb, "⏩ Karma v2 skipped — disabled by agents_enabled", "info")

    # ------------------------------------------------------------------
    # 8. Reverse IP Lookup (Virtual Hosting)
    # ------------------------------------------------------------------
    _emit(log_cb, "🌐 Reverse IP lookup — discovering virtual hosting co-tenants...")
    rev_ip_result = reverse_ip_lookup(target)
    ev_refs["reverse_ip"] = evidence_store.store_raw(
        collector="osint/reverse_ip", query=target,
        content=json.dumps(rev_ip_result, default=str), content_type="application/json"
    )
    if rev_ip_result.get("success"):
        vhost_domains = rev_ip_result.get("data", {}).get("domains_on_ip", [])
        if len(vhost_domains) > 1:
            _emit(log_cb, f"  ↳ {len(vhost_domains)} domains on same IP — virtual hosting", "warning")
        for vd in vhost_domains[:20]:
            if is_garbage_lead(vd):
                continue
            new_observations.append(Observation(
                session_id=session_id, raw_event_id=ev_refs["reverse_ip"],
                extractor="reverse_ip_extractor", type="subdomain_found",
                value=vd,
                context=f"Virtual hosting co-tenant on same IP as {target}",
                source="reverse_ip", evidence_ref=ev_refs["reverse_ip"],
                confidence=0.70, rate="Medium",
            ))

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 9. Google Analytics ID Correlation
    # ------------------------------------------------------------------
    _emit(log_cb, "📊 Google Analytics ID correlation lookup...")
    ga_result = google_analytics_id_lookup(target)
    ev_refs["ga_tracking"] = evidence_store.store_raw(
        collector="osint/ga_tracking", query=target,
        content=json.dumps(ga_result, default=str), content_type="application/json"
    )
    if ga_result.get("success"):
        shared = ga_result.get("data", {}).get("shared_domains", {})
        total_correlated = ga_result.get("data", {}).get("total_correlated", 0)
        if total_correlated:
            _emit(log_cb, f"  ↳ {total_correlated} domains share same GA ID as {target}", "info")
        for _ga_id, domains in shared.items():
            for corr_domain in domains[:10]:
                if is_garbage_lead(corr_domain) or corr_domain == target:
                    continue
                new_observations.append(Observation(
                    session_id=session_id, raw_event_id=ev_refs["ga_tracking"],
                    extractor="ga_tracking_extractor", type="org_found",
                    value=corr_domain,
                    context=f"Domain shares Google Analytics ID with {target}",
                    source="ga_tracking", evidence_ref=ev_refs["ga_tracking"],
                    confidence=0.65, rate="Low",
                ))

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 10. Reverse WHOIS — find other domains by same registrant
    # ------------------------------------------------------------------
    # Collect any email observations we may have discovered so far
    email_obs = [o for o in new_observations if o.type == "email_found"]
    emails_to_query = [o.value for o in email_obs if "@" in (o.value or "")][:3]
    # Fallback: use domain admin email pattern
    if not emails_to_query:
        emails_to_query = [f"admin@{target}", f"hostmaster@{target}"]

    for reg_email in emails_to_query[:2]:
        _emit(log_cb, f"🔍 Reverse WHOIS for registrant: {reg_email}")
        rwhois_result = reverse_whois_lookup(reg_email)
        ev_refs[f"rwhois_{reg_email}"] = evidence_store.store_raw(
            collector="osint/reverse_whois", query=reg_email,
            content=json.dumps(rwhois_result, default=str), content_type="application/json"
        )
        if rwhois_result.get("success"):
            domains_found = rwhois_result.get("data", {}).get("domains_found", [])
            if domains_found:
                _emit(log_cb, f"  ↳ {len(domains_found)} domains registered by {reg_email}", "info")
            for d in domains_found[:15]:
                if is_garbage_lead(d) or d == target:
                    continue
                new_observations.append(Observation(
                    session_id=session_id,
                    raw_event_id=ev_refs[f"rwhois_{reg_email}"],
                    extractor="reverse_whois_extractor", type="org_found",
                    value=d,
                    context=f"Domain registered by same entity as {target} (registrant: {reg_email})",
                    source="reverse_whois",
                    evidence_ref=ev_refs[f"rwhois_{reg_email}"],
                    confidence=0.65, rate="Low",
                ))
        time.sleep(0.5)

    # ------------------------------------------------------------------
    # 11. Smap Passive Port Scan (Shodan-backed)
    # ------------------------------------------------------------------
    _emit(log_cb, "🔭 Smap passive port scan (Shodan data — zero traffic to target)...")
    smap_result = smap_passive_portscan(target)
    ev_refs["smap"] = evidence_store.store_raw(
        collector="osint/smap", query=target,
        content=json.dumps(smap_result, default=str), content_type="application/json"
    )
    if smap_result.get("success"):
        ports = smap_result.get("data", {}).get("ports", [])
        _emit(log_cb, f"  ↳ {len(ports)} open ports discovered passively", "success" if ports else "info")
        high_risk_ports = {21, 23, 3389, 5900, 27017, 6379, 9200, 11211, 2375, 4444}
        for p in ports:
            port_num = p.get("port", 0)
            service = p.get("service", "unknown")
            new_observations.append(Observation(
                session_id=session_id, raw_event_id=ev_refs["smap"],
                extractor="smap_extractor", type="port_open",
                value=f"{target}:{port_num}",
                context=f"Port {port_num}/{p.get('protocol','tcp')} open ({service}) — discovered via Shodan (passive)",
                source="smap", evidence_ref=ev_refs["smap"],
                confidence=0.85, rate="High" if port_num in high_risk_ports else "Low",
                attributes={"host": target, "port": port_num, "service": service,
                             "product": p.get("product", ""), "version": p.get("version", ""),
                             "vulns": p.get("vulns", [])}
            ))

    time.sleep(0.5)

    # ------------------------------------------------------------------
    # 12. LLM Analysis
    # ------------------------------------------------------------------
    _emit(log_cb, "🧠 LLM synthesising OSINT intelligence...")
    llm_new_leads: List[Dict] = []

    try:
        api_key = _cfg.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", "")
        if not api_key:
            raise ValueError("DEEPSEEK_API_KEY not configured")

        client = _get_client()
        prompt = _safe_format(
            OSINT_ANALYSIS_PROMPT,
            target=target,
            zone_transfer_result=json.dumps(zone_result, default=str)[:1500],
            github_dork_result=json.dumps(github_dork_result, default=str)[:1000],
            google_dork_result=json.dumps(google_dork_result, default=str)[:1000],
            js_endpoints_result=json.dumps(js_result, default=str)[:2000],
            cve_lookup_result=json.dumps([], default=str)[:1500],
            karma_ip_result=json.dumps(karma_ip_result, default=str)[:1500],
            karma_leaks_result=json.dumps(karma_leaks_result, default=str)[:1500],
            karma_cve_result=json.dumps(karma_cve_result, default=str)[:1500],
        )
        response = client.chat.completions.create(
            model=_cfg.deepseek_model or "deepseek-chat",
            messages=[
                {"role": "system", "content": OSINT_ANALYSIS_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
        )
        content = response.choices[0].message.content or ""
        llm_findings = _extract_json(content) or {}
        _emit(log_cb, "  ✅ OSINT LLM analysis complete", "success")

        # Extract new leads from LLM
        llm_new_leads = llm_findings.get("new_leads", [])
    except Exception as exc:
        _emit(log_cb, f"❌ OSINT LLM error: {exc}", "alert")
        state.setdefault("error_log", []).append({
            "tool": "osint_llm", "error": str(exc),
            "timestamp": datetime.now().isoformat()
        })

    # ------------------------------------------------------------------
    # Convert LLM new_leads to proper Lead objects
    # ------------------------------------------------------------------
    processed_keys = state.get("processed_lead_ids", set())
    for lead_data in llm_new_leads:
        val = (lead_data.get("value") or "").strip()
        ltype = lead_data.get("type", "subdomain")
        if not val or is_garbage_lead(val):
            continue
        dedup_key = f"{ltype}:{val.lower()}"
        if dedup_key in processed_keys:
            continue
        # Scope check for domain-type leads
        if ltype in ("subdomain", "domain"):
            root = target.split(".", 1)[-1] if "." in target else target
            if not val.lower().endswith(root) and root not in val.lower():
                continue
        new_leads.append(Lead(
            type=normalize_lead_type(ltype), value=val.lower(), raw_value=val,
            source="osint_agent", confidence=float(lead_data.get("confidence", 0.7)),
            priority=0.6,
            depth=((current_lead.depth if hasattr(current_lead, "depth") else 0) + 1) if current_lead else 1,
            parent_lead_id=current_lead.lead_id if hasattr(current_lead, "lead_id") else None,
            discovered_by="osint_agent",
        ))

    if new_leads:
        _emit(log_cb, f"  ↳ {len(new_leads)} new leads queued from OSINT")

    # ------------------------------------------------------------------
    # Emit RawEvents for all OSINT tool executions (provenance layer)
    # ------------------------------------------------------------------
    for tool_name, eid in ev_refs.items():
        emit_raw_event(
            state, collector=f"osint/{tool_name}", tool=tool_name, target=target,
            evidence_id=eid, success=True, how="API call",
        )

    # ------------------------------------------------------------------
    # Update state
    # ------------------------------------------------------------------
    state["observations"] = state.get("observations", []) + new_observations
    state["findings"] = state.get("findings", []) + new_findings
    state["lead_queue"] = state.get("lead_queue", []) + new_leads

    # ------------------------------------------------------------------
    # Runtime entity materialization
    # ------------------------------------------------------------------
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
                    derived_by="osint_agent",
                )

    state.setdefault("phase_log", []).append({
        "phase": "osint",
        "timestamp": datetime.now().isoformat(),
        "level": "success",
        "message": f"OSINT complete — {len(new_observations)} obs, {len(new_findings)} findings, {len(new_leads)} leads",
    })

    _emit(log_cb,
          f"✅ OSINT complete — {len(new_observations)} observations, "
          f"{len(new_findings)} findings, {len(new_leads)} leads",
          "success")

    return state


def _infer_relation(obs_type: str) -> str:
    """Infer relationship type from observation type."""
    mapping = {
        "subdomain_found": "belongs_to",
        "ip_found": "resolves_to",
        "port_open": "exposes",
        "email_found": "leaks",
        "org_found": "owned_by",
        "asn_found": "belongs_to",
        "endpoint_found": "contains",
        "url_found": "contains",
        "credential_signal_found": "leaks",
    }
    return mapping.get(obs_type, "linked_to")
