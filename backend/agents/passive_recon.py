"""
Passive Recon Agent � breadth ch�nh, kh�ng g?i request tr?c ti?p d?n target.
Emit structured Observations v?i evidence_ref d?y d?.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.state import MINAState
from core.schemas import Observation, Lead
from core.evidence_store import EvidenceStore
from core.canonicalization import Canonicalizer
from core.runtime_emit import materialize_entity_from_observation, emit_runtime_relationship, emit_raw_event
from core.identity import make_entity_id

logger = logging.getLogger(__name__)


def passive_recon_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Passive Recon Agent."""
    if not state.get("passive_tasks"):
        return state

    spec = state["engagement_spec"]
    session_dir = Path(f"backend/output/sessions/{spec['session_id']}")
    evidence_store = EvidenceStore(session_dir)

    # Get real-time log callback from LangGraph config
    _log = None
    if config is not None:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")

    new_observations = []
    new_leads = []

    for task in state["passive_tasks"]:
        tool = task.get("tool", "")
        target = task.get("target", "")

        if not tool or not target:
            continue

        if _log:
            _log({"agent": "PassiveRecon", "level": "info",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "message": f"[{tool.upper()}] querying {target} ..."})

        try:
            result = _run_tool(tool, target, spec, evidence_store, task=task)
            if result:
                obs, leads = _extract_observations(
                    tool, target, result, state.get("current_lead"),
                    spec.get("session_id", ""), evidence_store
                )
                new_observations.extend(obs)
                new_leads.extend(leads)
                _update_stats(state, tool, success=True, events=len(obs), leads=len(leads))
                # Emit RawEvent for provenance tracking
                emit_raw_event(
                    state, collector=f"passive/{tool}", tool=tool, target=target,
                    evidence_id=result.get("_evidence_id", ""),
                    success=True, extracted_count=len(obs), new_leads_count=len(leads),
                )
                msg = f"[{tool.upper()}] {target}: {len(obs)} observations, {len(leads)} new leads"
                if _log:
                    _log({"agent": "PassiveRecon", "level": "success" if obs else "info",
                          "timestamp": datetime.now(timezone.utc).isoformat(), "message": msg})
                state.setdefault("phase_log", []).append({
                    "phase": "passive_recon",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "success" if obs else "info",
                    "message": msg,
                })
            else:
                # Emit RawEvent even for empty results
                emit_raw_event(
                    state, collector=f"passive/{tool}", tool=tool, target=target,
                    evidence_id="", success=True, extracted_count=0,
                )
                if _log:
                    _log({"agent": "PassiveRecon", "level": "info",
                          "timestamp": datetime.now(timezone.utc).isoformat(),
                          "message": f"[{tool.upper()}] {target}: no results"})
        except Exception as exc:
            logger.error("[PassiveRecon] %s on %s: %s", tool, target, exc)
            _update_stats(state, tool, success=False, error=str(exc))
            # Emit RawEvent for failures
            emit_raw_event(
                state, collector=f"passive/{tool}", tool=tool, target=target,
                evidence_id="", success=False, error_message=str(exc),
            )
            err_msg = f"[{tool.upper()}] {target} FAILED: {exc}"
            if _log:
                _log({"agent": "PassiveRecon", "level": "error",
                      "timestamp": datetime.now(timezone.utc).isoformat(), "message": err_msg})
            state.setdefault("error_log", []).append({
                "tool": tool, "target": target,
                "error": str(exc), "timestamp": datetime.now(timezone.utc).isoformat()
            })

    state["observations"].extend(new_observations)
    state["lead_queue"].extend(new_leads)
    state["passive_tasks"] = []

    # Runtime entity materialization � entities appear during scan
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
                    derived_by="passive_recon",
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
        "url_found": "contains",
        "parameter_found": "contains",
        "webapp_alive": "hosted_on",
        "header_found": "exposes",
        "waf_detected": "uses_technology",
        "repo_found": "associated_with",
        "document_found": "leaks",
        "vulnerability_found": "exposes",
        "credential_signal_found": "leaks",
        "person_found": "employs",
    }
    return mapping.get(obs_type, "linked_to")


def _run_tool(tool: str, target: str, spec: dict, evidence_store: EvidenceStore, task: dict = None) -> dict:
    """Dispatch tool call and store evidence. V4: forwards task-level options."""
    import time
    time.sleep(spec.get("rate_limit_seconds", 1.0))

    _task = task or {}
    opts = _task.get("options", _task.get("tool_options", {}))

    from tools import dns_tools, cert_tools
    tool_functions = {
        "whois":        dns_tools.whois_lookup,
        "dns":          lambda t: dns_tools.dns_lookup(t, ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]),
        "crt_sh":       cert_tools.crt_sh_query,
        "reverse_dns":  dns_tools.reverse_dns_lookup,
    }

    # Optional tools with keys
    try:
        from tools import shodan_tools
        from core.config import config as _cfg
        _shodan_key = _cfg.shodan_api_key or ""
        tool_functions["shodan"] = lambda t: shodan_tools.shodan_host_lookup(t, _shodan_key)
        tool_functions["shodan_search"] = lambda t: shodan_tools.shodan_query(t, _shodan_key)
    except (ImportError, AttributeError):
        pass

    # OSINT tools � spf_dmarc, wayback, zone_transfer, js_endpoints, asn, email_harvest, dns_dumpster
    try:
        from tools.osint_tools import (
            spf_dmarc_check, wayback_machine_query, zone_transfer_attempt,
            extract_js_endpoints, asn_lookup, email_harvest_cleartext,
            dns_dumpster_query,
        )
        tool_functions["spf_dmarc"]       = spf_dmarc_check
        tool_functions["wayback"]         = lambda t: wayback_machine_query(t, limit=300)
        tool_functions["zone_transfer"]   = zone_transfer_attempt
        tool_functions["js_endpoints"]    = extract_js_endpoints
        tool_functions["asn"]             = asn_lookup
        tool_functions["email_harvest"]   = lambda t: email_harvest_cleartext(f"https://{t}")
        tool_functions["dns_dumpster"]    = dns_dumpster_query
    except (ImportError, AttributeError):
        pass

    # Subdomain discovery (tiered: quick/balanced/deep)
    try:
        from tools.subdomain_tools import run_subdomain_discovery
        _profile = spec.get("profile", "balanced")
        tool_functions["subdomain_discovery"] = lambda t: run_subdomain_discovery(t, profile=_profile)
    except (ImportError, AttributeError):
        pass

    # New collector modules (company, people, repo, document, infrastructure)
    try:
        from tools.company_tools import org_profile_lookup, company_stack_hint_lookup, related_root_domain_discovery
        _company = spec.get("company_name", "")
        tool_functions["company_profile"]  = lambda t: org_profile_lookup(_company, t)
        tool_functions["company_stack"]    = lambda t: company_stack_hint_lookup(_company, t)
        tool_functions["related_domains"]  = lambda t: related_root_domain_discovery(_company, t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.people_tools import public_contact_harvest, about_team_page_harvest
        tool_functions["public_contact"]   = public_contact_harvest
        tool_functions["team_harvest"]     = about_team_page_harvest
    except (ImportError, AttributeError):
        pass

    try:
        from tools.repo_tools import repo_discovery as _repo_disc
        _company = spec.get("company_name", "")
        tool_functions["repo_discovery"]   = lambda t: _repo_disc(t, _company)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.document_tools import public_document_discovery
        tool_functions["public_doc_discovery"] = public_document_discovery
    except (ImportError, AttributeError):
        pass

    try:
        from tools.infrastructure_tools import asn_enrichment
        tool_functions["infra_asn_enrich"] = asn_enrichment
    except (ImportError, AttributeError):
        pass

    if tool not in tool_functions:
        logger.debug("[PassiveRecon] Unknown tool: %s", tool)
        return {}

    raw_result = tool_functions[tool](target)
    if not raw_result:
        return {}

    # Store evidence
    evidence_id = evidence_store.store_raw(
        collector=tool,
        query=target,
        content=json.dumps(raw_result, indent=2, default=str),
        content_type="application/json"
    )
    raw_result["_evidence_id"] = evidence_id
    return raw_result


def _extract_observations(tool: str, target: str, result: dict,
                           parent_lead, session_id: str,
                           evidence_store: EvidenceStore):
    """Extract Observations and new Leads from tool result."""
    observations = []
    new_leads = []
    evidence_id = result.get("_evidence_id", "")

    if tool == "crt_sh" and result.get("success"):
        for subdomain in result.get("data", {}).get("subdomains", []):
            canonical = Canonicalizer.domain(subdomain)
            obs = Observation(
                session_id=session_id,
                raw_event_id=evidence_id,
                extractor="crt_sh_extractor",
                type="subdomain_found",
                value=subdomain,
                normalized_value=canonical,
                context="Found in Certificate Transparency log",
                source="crt.sh",
                evidence_ref=evidence_id,
                confidence=0.75,
                rate="Medium"
            )
            observations.append(obs)
            new_leads.append(Lead(
                type="subdomain",
                value=canonical,
                raw_value=subdomain,
                source="crt_sh",
                confidence=0.75,
                priority=0.75,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/crt_sh",
                evidence_refs=[evidence_id]
            ))

    elif tool == "dns" and result.get("success"):
        records = result.get("data", {})
        for record_type, values in records.items():
            if record_type == "A":
                for ip in values:
                    if not isinstance(ip, str):
                        continue
                    canonical_ip = Canonicalizer.ip(ip)
                    obs = Observation(
                        session_id=session_id,
                        raw_event_id=evidence_id,
                        extractor="dns_extractor",
                        type="ip_found",
                        value=ip,
                        normalized_value=canonical_ip,
                        context=f"DNS A record for {target}",
                        source="dns",
                        evidence_ref=evidence_id,
                        confidence=0.95,
                        rate="Low",
                        attributes={"record_type": "A", "domain": target}
                    )
                    observations.append(obs)
                    new_leads.append(Lead(
                        type="ip",
                        value=canonical_ip,
                        raw_value=ip,
                        source="dns",
                        confidence=0.95,
                        priority=0.8,
                        depth=(parent_lead.depth + 1) if parent_lead else 1,
                        parent_lead_id=parent_lead.lead_id if parent_lead else None,
                        discovered_by="passive_recon/dns",
                        evidence_refs=[evidence_id]
                    ))

    elif tool == "shodan" and result.get("success"):
        data = result.get("data", {})
        for port_info in data.get("ports", []):
            port = port_info if isinstance(port_info, int) else port_info.get("port")
            if port:
                obs = Observation(
                    session_id=session_id,
                    raw_event_id=evidence_id,
                    extractor="shodan_extractor",
                    type="port_open",
                    value=f"{target}:{port}",
                    context=f"Port {port} open on {target} (Shodan)",
                    source="shodan",
                    evidence_ref=evidence_id,
                    confidence=0.85,
                    rate="Medium",
                    attributes={"port": port, "host": target}
                )
                observations.append(obs)

    elif tool == "spf_dmarc" and result.get("success"):
        data = result.get("data", {})
        if data.get("spf_record"):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="spf_dmarc_extractor", type="spf_record",
                value=data["spf_record"], normalized_value=data["spf_record"],
                context=f"SPF record for {target}", source="spf_dmarc",
                evidence_ref=evidence_id, confidence=0.9, rate="Low",
                attributes={"domain": target, "spf_exists": data.get("spf_exists", True)}
            ))
        if not data.get("dmarc_exists"):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="spf_dmarc_extractor", type="email_found",
                value=f"no-dmarc@{target}",
                context=f"DMARC record missing for {target} � email spoofing possible",
                source="spf_dmarc", evidence_ref=evidence_id,
                confidence=0.85, rate="High",
                attributes={"domain": target, "dmarc_exists": False}
            ))

    elif tool == "wayback" and result.get("success"):
        data = result.get("data", {})
        for path in (data.get("interesting", []) or [])[:20]:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="wayback_extractor", type="url_found",
                value=path if path.startswith("http") else f"https://{target}{path}",
                context=f"Historical path from Wayback Machine for {target}",
                source="wayback", evidence_ref=evidence_id,
                confidence=0.7, rate="Low",
                attributes={"domain": target, "source": "wayback_machine"}
            ))
            new_leads.append(Lead(
                type="endpoint",
                value=path if path.startswith("http") else f"https://{target}{path}",
                raw_value=path, source="wayback", confidence=0.65,
                priority=0.5,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/wayback",
                evidence_refs=[evidence_id]
            ))

    elif tool == "zone_transfer" and result.get("success"):
        hosts = result.get("data", {}).get("hosts", [])
        for host in hosts:
            canonical = Canonicalizer.domain(host) if isinstance(host, str) else str(host)
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="zone_transfer_extractor", type="subdomain_found",
                value=canonical, normalized_value=canonical,
                context=f"Zone transfer (AXFR) disclosed host from {target}",
                source="zone_transfer", evidence_ref=evidence_id,
                confidence=0.95, rate="High",
                attributes={"domain": target, "method": "AXFR"}
            ))
            new_leads.append(Lead(
                type="subdomain", value=canonical, raw_value=str(host),
                source="zone_transfer", confidence=0.95, priority=0.85,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/zone_transfer",
                evidence_refs=[evidence_id]
            ))

    elif tool == "js_endpoints" and result.get("success"):
        endpoints = result.get("data", {}).get("endpoints", [])
        for ep in endpoints[:30]:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="js_endpoint_extractor", type="endpoint_found",
                value=ep if isinstance(ep, str) else str(ep),
                context=f"API endpoint extracted from JavaScript on {target}",
                source="js_endpoints", evidence_ref=evidence_id,
                confidence=0.7, rate="Low",
                attributes={"domain": target, "source": "js_extraction"}
            ))

    elif tool == "subdomain_discovery" and result.get("success"):
        # Tiered subdomain discovery � discovered + resolved
        for subdomain in result.get("discovered", []):
            canonical = Canonicalizer.domain(subdomain)
            source_tag = result.get("sources", {}).get(subdomain, ["subdomain_discovery"])
            conf = 0.80 if subdomain in result.get("live", []) else 0.65
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="subdomain_discovery_extractor", type="subdomain_found",
                value=subdomain, normalized_value=canonical,
                context=f"Subdomain discovered via tiered enumeration for {target}",
                source="subdomain_discovery", evidence_ref=evidence_id,
                confidence=conf, rate="Medium",
                attributes={"domain": target, "live": subdomain in result.get("live", []),
                            "resolved_ip": result.get("resolved", {}).get(subdomain, ""),
                            "sources": source_tag}
            ))
            new_leads.append(Lead(
                type="subdomain", value=canonical, raw_value=subdomain,
                source="subdomain_discovery", confidence=conf, priority=0.80,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/subdomain_discovery",
                evidence_refs=[evidence_id]
            ))
        # Also emit IP leads from resolved map
        for subdomain, ip in result.get("resolved", {}).items():
            if ip:
                canonical_ip = Canonicalizer.ip(ip)
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="subdomain_discovery_extractor", type="ip_found",
                    value=ip, normalized_value=canonical_ip,
                    context=f"{subdomain} resolves to {ip}",
                    source="subdomain_discovery", evidence_ref=evidence_id,
                    confidence=0.90, rate="Low",
                    attributes={"domain": subdomain, "record_type": "A"}
                ))

    elif tool == "asn" and result.get("success"):
        data = result.get("data", {})
        asn_number = data.get("asn", "")
        org = data.get("org", "")
        if asn_number:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="asn_extractor", type="asn_found",
                value=str(asn_number), normalized_value=str(asn_number),
                context=f"ASN {asn_number} ({org}) for {target}",
                source="asn", evidence_ref=evidence_id,
                confidence=0.85, rate="High",
                attributes={"asn": asn_number, "org": org,
                            "ip_ranges": data.get("ip_ranges", [])}
            ))
            new_leads.append(Lead(
                type="asn", value=str(asn_number), source="asn",
                confidence=0.85, priority=0.75,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/asn",
                evidence_refs=[evidence_id]
            ))

    elif tool == "email_harvest" and result.get("success"):
        for email in result.get("data", {}).get("emails", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="email_harvest_extractor", type="email_found",
                value=email, normalized_value=email.lower().strip(),
                context=f"Email harvested from {target} homepage",
                source="email_harvest", evidence_ref=evidence_id,
                confidence=0.75, rate="Medium",
                attributes={"domain": target}
            ))

    elif tool == "dns_dumpster" and result.get("success"):
        data = result.get("data", {})
        for subdomain in data.get("subdomains", []):
            canonical = Canonicalizer.domain(subdomain)
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="dns_dumpster_extractor", type="subdomain_found",
                value=subdomain, normalized_value=canonical,
                context=f"Subdomain from DNSDumpster passive lookup for {target}",
                source="dns_dumpster", evidence_ref=evidence_id,
                confidence=0.70, rate="Medium",
                attributes={"domain": target}
            ))
            new_leads.append(Lead(
                type="subdomain", value=canonical, raw_value=subdomain,
                source="dns_dumpster", confidence=0.70, priority=0.65,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/dns_dumpster",
                evidence_refs=[evidence_id]
            ))

    # -- New collector modules --------------------------------------
    elif tool == "company_profile" and result.get("success"):
        data = result.get("data", {})
        for org_name in data.get("org_names", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="company_profile_extractor", type="org_found",
                value=org_name, normalized_value=org_name.strip(),
                context=f"Organization linked to {target}",
                source="company_profile", evidence_ref=evidence_id,
                confidence=0.70, rate="Low",
            ))
        for rd in data.get("related_domains", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="company_profile_extractor", type="subdomain_found",
                value=rd, normalized_value=Canonicalizer.domain(rd),
                context=f"Related domain discovered via org profile for {target}",
                source="company_profile", evidence_ref=evidence_id,
                confidence=0.55, rate="Low",
            ))
            new_leads.append(Lead(
                type="domain", value=Canonicalizer.domain(rd), raw_value=rd,
                source="company_profile", confidence=0.55, priority=0.50,
                depth=(parent_lead.depth + 1) if parent_lead else 1,
                parent_lead_id=parent_lead.lead_id if parent_lead else None,
                discovered_by="passive_recon/company_profile",
                evidence_refs=[evidence_id]
            ))

    elif tool == "public_contact" and result.get("success"):
        for email in result.get("data", {}).get("emails", []):
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="public_contact_extractor", type="email_found",
                value=email, normalized_value=email.lower().strip(),
                context=f"Public contact email harvested from {target}",
                source="public_contact", evidence_ref=evidence_id,
                confidence=0.75, rate="Medium",
            ))

    elif tool == "repo_discovery" and result.get("success"):
        for repo in result.get("data", {}).get("repos", []):
            repo_url = repo.get("html_url", "")
            if repo_url:
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="repo_discovery_extractor", type="repo_found",
                    value=repo_url, normalized_value=repo_url,
                    context=f"Public repo associated with {target}: {repo.get('full_name', '')}",
                    source="repo_discovery", evidence_ref=evidence_id,
                    confidence=0.60, rate="Low",
                    attributes={"language": repo.get("language", ""), "stars": repo.get("stars", 0)},
                ))

    elif tool == "public_doc_discovery" and result.get("success"):
        for doc in result.get("data", {}).get("documents", []):
            doc_url = doc.get("url", "")
            if doc_url:
                observations.append(Observation(
                    session_id=session_id, raw_event_id=evidence_id,
                    extractor="document_discovery_extractor", type="document_found",
                    value=doc_url, normalized_value=doc_url,
                    context=f"Public document on {target}: {doc.get('extension', '')}",
                    source="public_doc_discovery", evidence_ref=evidence_id,
                    confidence=0.55, rate="Low",
                    attributes={"extension": doc.get("extension", "")},
                ))

    elif tool == "infra_asn_enrich" and result.get("success"):
        data = result.get("data", {})
        asn_num = data.get("asn", "")
        if asn_num:
            observations.append(Observation(
                session_id=session_id, raw_event_id=evidence_id,
                extractor="infra_asn_extractor", type="asn_found",
                value=str(asn_num), normalized_value=str(asn_num),
                context=f"ASN enrichment for {target}: {data.get('asn_name', '')}",
                source="infra_asn_enrich", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
                attributes={"asn_name": data.get("asn_name", ""), "country": data.get("country", ""),
                            "prefix": data.get("prefix", "")},
            ))

    return observations, new_leads


def _update_stats(state: MINAState, tool: str, success: bool,
                  events: int = 0, leads: int = 0, error: str = ""):
    """Track per-collector statistics."""
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
