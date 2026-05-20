"""
Shared observation extractors — tool-specific parsing logic.

Each function: extract_{context}(tool, target, result, state, evidence_id)
  → (observations: list[Observation], leads: list[Lead])

Separates parsing from agent logic (Layer 2 ↔ Layer 3 boundary).
"""
from typing import List, Tuple

from core.canonicalization import Canonicalizer
from core.schemas import Finding, Lead, Observation
from core.scope import is_garbage_lead

# type alias
ExtractResult = Tuple[List[Observation], List[Lead]]


def _parent_depth(state: dict) -> int:
    cl = state.get("current_lead")
    if cl:
        return (getattr(cl, "depth", 0) or 0) + 1
    return 1


def _parent_id(state: dict) -> str:
    cl = state.get("current_lead")
    if cl:
        return getattr(cl, "lead_id", "") or ""
    return ""


def _sid(state: dict) -> str:
    return state.get("engagement_spec", {}).get("session_id", "")


# ── Root Domain / DNS extractors ──────────────────────────────────

def extract_whois(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    registrar = data.get("registrar", "")
    if registrar:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="whois_extractor", type="org_found",
            value=registrar, context=f"WHOIS registrar for {target}",
            source="whois", evidence_ref=evidence_id,
            confidence=0.80, rate="Low",
        ))
    for email in data.get("emails", []):
        if isinstance(email, str) and "@" in email:
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="whois_extractor", type="email_found",
                value=email, normalized_value=email.lower().strip(),
                context=f"WHOIS registrant email for {target}",
                source="whois", evidence_ref=evidence_id,
                confidence=0.75, rate="Low",
            ))
    return obs, leads


def extract_dns(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    records = result.get("data", {})
    for ip in records.get("A", []):
        if not isinstance(ip, str):
            continue
        canonical_ip = Canonicalizer.ip(ip)
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="dns_extractor", type="ip_found",
            value=ip, normalized_value=canonical_ip,
            context=f"DNS A record for {target}",
            source="dns", evidence_ref=evidence_id,
            confidence=0.95, rate="Low",
            attributes={"record_type": "A", "domain": target},
        ))
        leads.append(Lead(
            type="ip", value=canonical_ip, raw_value=ip,
            source="dns", confidence=0.95, priority=0.8,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by=f"dns", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_reverse_dns(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    # dns_tools.reverse_dns_lookup returns {"hostname": str, "aliases": list}
    # collect both into a unified hostnames list
    hostnames = []
    h = data.get("hostname", "")
    if h:
        hostnames.append(h)
    hostnames.extend(data.get("aliases", []))
    hostnames.extend(data.get("hostnames", []))  # legacy key safety
    for h in hostnames:
        if isinstance(h, str) and not is_garbage_lead(h):
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="reverse_dns_extractor", type="subdomain_found",
                value=h, normalized_value=Canonicalizer.domain(h),
                context=f"Reverse DNS for {target}",
                source="reverse_dns", evidence_ref=evidence_id,
                confidence=0.85, rate="Low",
            ))
    return obs, leads


# ── Subdomain extractors ─────────────────────────────────────────

def extract_crt_sh(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for subdomain in result.get("data", {}).get("subdomains", []):
        canonical = Canonicalizer.domain(subdomain)
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="crt_sh_extractor", type="subdomain_found",
            value=subdomain, normalized_value=canonical,
            context="Found in Certificate Transparency log",
            source="crt.sh", evidence_ref=evidence_id,
            confidence=0.75, rate="Medium",
        ))
        leads.append(Lead(
            type="subdomain", value=canonical, raw_value=subdomain,
            source="crt_sh", confidence=0.75, priority=0.75,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="crt_sh", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_subdomain_discovery(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for subdomain in result.get("discovered", []):
        canonical = Canonicalizer.domain(subdomain)
        conf = 0.80 if subdomain in result.get("live", []) else 0.65
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="subdomain_discovery_extractor", type="subdomain_found",
            value=subdomain, normalized_value=canonical,
            context=f"Subdomain discovered via tiered enumeration for {target}",
            source="subdomain_discovery", evidence_ref=evidence_id,
            confidence=conf, rate="Medium",
            attributes={"domain": target, "live": subdomain in result.get("live", []),
                        "resolved_ip": result.get("resolved", {}).get(subdomain, ""),
                        "sources": result.get("sources", {}).get(subdomain, [])},
        ))
        leads.append(Lead(
            type="subdomain", value=canonical, raw_value=subdomain,
            source="subdomain_discovery", confidence=conf, priority=0.80,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="subdomain_discovery", evidence_refs=[evidence_id],
        ))
    for subdomain, ip in result.get("resolved", {}).items():
        if ip:
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="subdomain_discovery_extractor", type="ip_found",
                value=ip, normalized_value=Canonicalizer.ip(ip),
                context=f"{subdomain} resolves to {ip}",
                source="subdomain_discovery", evidence_ref=evidence_id,
                confidence=0.90, rate="Low",
                attributes={"domain": subdomain, "record_type": "A"},
            ))
    return obs, leads


def extract_dns_dumpster(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for subdomain in result.get("data", {}).get("subdomains", []):
        canonical = Canonicalizer.domain(subdomain)
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="dns_dumpster_extractor", type="subdomain_found",
            value=subdomain, normalized_value=canonical,
            context=f"Subdomain from DNSDumpster passive lookup for {target}",
            source="dns_dumpster", evidence_ref=evidence_id,
            confidence=0.70, rate="Medium",
        ))
        leads.append(Lead(
            type="subdomain", value=canonical, raw_value=subdomain,
            source="dns_dumpster", confidence=0.70, priority=0.65,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="dns_dumpster", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_subfinder(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for subdomain in result.get("data", {}).get("subdomains", []):
        canonical = Canonicalizer.domain(subdomain)
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="subfinder_extractor", type="subdomain_found",
            value=subdomain, normalized_value=canonical,
            context="Found by subfinder",
            source="subfinder", evidence_ref=evidence_id,
            confidence=0.8, rate="Low",
        ))
        leads.append(Lead(
            type="subdomain", value=canonical, raw_value=subdomain,
            source="subfinder",
            confidence=0.8, priority=0.65,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="subfinder", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_zone_transfer(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for host in result.get("data", {}).get("hosts", []):
        if isinstance(host, str) and not is_garbage_lead(host):
            canonical = Canonicalizer.domain(host)
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="zone_transfer_extractor", type="subdomain_found",
                value=canonical, normalized_value=canonical,
                context=f"Zone transfer (AXFR) disclosed host from {target}",
                source="zone_transfer", evidence_ref=evidence_id,
                confidence=0.95, rate="High",
                attributes={"domain": target, "method": "AXFR"},
            ))
            leads.append(Lead(
                type="subdomain", value=canonical, raw_value=str(host),
                source="zone_transfer", confidence=0.95, priority=0.85,
                depth=_parent_depth(state),
                parent_lead_id=_parent_id(state),
                discovered_by="zone_transfer", evidence_refs=[evidence_id],
            ))
    return obs, leads


# ── Infrastructure / ASN extractors ───────────────────────────────

def extract_shodan(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for port_info in result.get("data", {}).get("ports", []):
        port = port_info if isinstance(port_info, int) else port_info.get("port")
        if port:
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="shodan_extractor", type="port_open",
                value=f"{target}:{port}",
                context=f"Port {port} open on {target} (Shodan)",
                source="shodan", evidence_ref=evidence_id,
                confidence=0.85, rate="Medium",
                attributes={"port": port, "host": target},
            ))
    return obs, leads


def extract_asn(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    asn_number = data.get("asn", "")
    org = data.get("org", "")
    if asn_number:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="asn_extractor", type="asn_found",
            value=str(asn_number), normalized_value=str(asn_number),
            context=f"ASN {asn_number} ({org}) for {target}",
            source="asn", evidence_ref=evidence_id,
            confidence=0.85, rate="High",
            attributes={"asn": asn_number, "org": org, "ip_ranges": data.get("ip_ranges", [])},
        ))
        leads.append(Lead(
            type="asn", value=str(asn_number), source="asn",
            confidence=0.85, priority=0.75,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="asn", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_infra_asn_enrich(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    asn_num = data.get("asn", "")
    if asn_num:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="infra_asn_extractor", type="asn_found",
            value=str(asn_num), normalized_value=str(asn_num),
            context=f"ASN enrichment for {target}: {data.get('asn_name', '')}",
            source="infra_asn_enrich", evidence_ref=evidence_id,
            confidence=0.80, rate="Low",
            attributes={"asn_name": data.get("asn_name", ""), "country": data.get("country", ""),
                        "prefix": data.get("prefix", "")},
        ))
    return obs, leads


# ── Service Surface extractors ────────────────────────────────────

def extract_nmap(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    HIGH_RISK = {21, 23, 25, 445, 3389, 5900, 27017, 6379, 9200, 11211}
    MEDIUM_RISK = {80, 8080, 8443, 3306, 5432, 1433, 22, 53}
    for port_info in result.get("data", {}).get("ports", []):
        port = port_info.get("port") if isinstance(port_info, dict) else int(port_info)
        service = port_info.get("service", "") if isinstance(port_info, dict) else ""
        risk = "high" if port in HIGH_RISK else ("medium" if port in MEDIUM_RISK else "low")
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="nmap_extractor", type="port_open",
            value=f"{target}:{port}",
            context=f"Nmap detected open port {port} ({service})",
            source="nmap", evidence_ref=evidence_id,
            confidence=0.9, rate=risk.capitalize(),
            attributes={"port": port, "service": service, "protocol": "tcp"},
        ))
        if risk in ("high", "medium"):
            leads.append(Lead(
                type="service", value=f"{target}:{port}", source="nmap",
                confidence=0.85, priority=0.8 if risk == "high" else 0.5,
                depth=_parent_depth(state),
                parent_lead_id=_parent_id(state),
                discovered_by="nmap", evidence_refs=[evidence_id],
            ))
    return obs, leads


def extract_banner(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    banner_text = data.get("banner", "")
    if banner_text:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="banner_extractor", type="service_detected",
            value=target, context=f"Banner: {banner_text[:200]}",
            source="banner", evidence_ref=evidence_id,
            confidence=0.78, rate="Low",
            attributes={"banner": banner_text[:500]},
        ))
    return obs, leads


def extract_smap(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    HIGH_RISK = {21, 23, 3389, 5900, 27017, 6379, 9200, 11211, 2375, 4444}
    for p in result.get("data", {}).get("ports", []):
        port_num = p.get("port", 0)
        service = p.get("service", "unknown")
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="smap_extractor", type="port_open",
            value=f"{target}:{port_num}",
            context=f"Port {port_num}/{p.get('protocol','tcp')} open ({service}) — passive via Shodan",
            source="smap", evidence_ref=evidence_id,
            confidence=0.85, rate="High" if port_num in HIGH_RISK else "Low",
            attributes={"host": target, "port": port_num, "service": service,
                        "product": p.get("product", ""), "version": p.get("version", ""),
                        "vulns": p.get("vulns", [])},
        ))
    return obs, leads


# ── Web Surface extractors ────────────────────────────────────────

def extract_httpx(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for item in result.get("data", {}).get("results", []):
        url = item.get("url", target)
        status_code = item.get("status_code", 0)
        webserver = item.get("webserver", "")
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="httpx_extractor", type="webapp_alive",
            value=url, context=f"HTTP {status_code} — {item.get('title','')} (server: {webserver})",
            source="httpx", evidence_ref=evidence_id,
            confidence=0.95, rate="Low",
            attributes={"url": url, "status_code": status_code,
                        "title": item.get("title", ""), "webserver": webserver},
        ))
        if webserver:
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="httpx_extractor", type="technology_found",
                value=webserver, context=f"Web server {webserver} on {url}",
                source="httpx", evidence_ref=evidence_id,
                confidence=0.90, rate="Low",
            ))
        for tech in item.get("tech", []):
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="httpx_extractor", type="technology_found",
                value=tech, context=f"Technology {tech} detected on {url}",
                source="httpx", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
            ))
        if status_code and 200 <= status_code < 500:
            leads.append(Lead(
                type="subdomain" if url != target else "endpoint",
                value=url, source="httpx", confidence=0.85, priority=0.7,
                depth=_parent_depth(state),
                parent_lead_id=_parent_id(state),
                discovered_by="httpx", evidence_refs=[evidence_id],
            ))
    return obs, leads


def extract_headers(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    data = result.get("data", {})
    for hdr, val in data.get("present_headers", {}).items():
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="headers_extractor", type="header_found",
            value=f"{hdr}: {val[:200]}", source="headers",
            evidence_ref=evidence_id, confidence=0.85, rate="Low",
        ))
    for hdr in data.get("missing_headers", []):
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="headers_extractor", type="header_found",
            value=hdr, context=f"Security header {hdr} missing on {target}",
            source="headers", evidence_ref=evidence_id,
            confidence=0.85, rate="Medium",
        ))
    return obs, leads


def extract_ssl(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    obs.append(Observation(
        session_id=_sid(state), raw_event_id=evidence_id,
        extractor="ssl_extractor", type="cert_found",
        value=target,
        context=f"TLS cert: issuer={data.get('cert_issuer','')} expires_in={data.get('cert_expiry_days','')}d",
        source="ssl", evidence_ref=evidence_id,
        confidence=0.95, rate="Low", attributes=data,
    ))
    for issue in data.get("issues", []):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="ssl_extractor", type="vulnerability_found",
            value=target, context=f"TLS issue: {issue.get('description', issue)}",
            source="ssl", evidence_ref=evidence_id,
            confidence=0.85, rate="Medium",
        ))
    return obs, leads


def extract_tech(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for tech_item in result.get("data", {}).get("technologies", []):
        name = tech_item if isinstance(tech_item, str) else tech_item.get("name", "")
        if name:
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="tech_extractor", type="technology_found",
                value=name, source="tech", evidence_ref=evidence_id,
                confidence=0.78, rate="Low",
            ))
    return obs, leads


def extract_robots(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    data = result.get("data", {})
    for path in data.get("disallowed", [])[:20]:
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="robots_extractor", type="endpoint_found",
            value=f"https://{target}{path}" if path.startswith("/") else path,
            context=f"robots.txt Disallow for {target}",
            source="robots", evidence_ref=evidence_id,
            confidence=0.80, rate="Low",
        ))
    for sitemap_url in data.get("sitemaps", [])[:10]:
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="robots_extractor", type="url_found",
            value=sitemap_url, context=f"Sitemap URL from robots.txt for {target}",
            source="robots", evidence_ref=evidence_id,
            confidence=0.85, rate="Low",
        ))
    return obs, leads


def extract_waf(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    waf_name = data.get("waf", "")
    if waf_name:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="waf_extractor", type="waf_detected",
            value=waf_name, context=f"WAF detected on {target}: {waf_name}",
            source="waf", evidence_ref=evidence_id,
            confidence=0.80, rate="Low",
        ))
    return obs, leads


def extract_dirs(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for entry in result.get("data", {}).get("found", [])[:30]:
        path = entry if isinstance(entry, str) else entry.get("path", "")
        if path:
            obs.append(Observation(
                session_id=sid, raw_event_id=evidence_id,
                extractor="dirs_extractor", type="endpoint_found",
                value=path, context=f"Directory found on {target}",
                source="dirs", evidence_ref=evidence_id,
                confidence=0.72, rate="Low",
            ))
    return obs, leads


def extract_nuclei(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    sev_conf = {"critical": 0.97, "high": 0.9, "medium": 0.75, "low": 0.5, "info": 0.3}
    for nf in result.get("data", {}).get("findings", []):
        sev = nf.get("severity", "info").lower()
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="nuclei_extractor", type="vulnerability_found",
            value=nf.get("matched_at", target),
            context=nf.get("description", nf.get("name", "nuclei finding")),
            source="nuclei", evidence_ref=evidence_id,
            confidence=sev_conf.get(sev, 0.5), rate=sev.capitalize(),
            attributes={"template_id": nf.get("template_id", ""), "severity": sev,
                        "cvss": nf.get("cvss_score", 0), "references": nf.get("reference", [])},
        ))
    return obs, leads


def extract_http_methods(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    data = result.get("data", {})
    for method in data.get("dangerous_methods", []):
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="http_methods_extractor", type="vulnerability_found",
            value=target, context=f"Dangerous HTTP method {method} enabled on {target}",
            source="http_methods", evidence_ref=evidence_id,
            confidence=0.80, rate="Medium",
            attributes={"method": method, "host": target},
        ))
    return obs, leads


# ── Company Intel extractors ──────────────────────────────────────

def extract_company_profile(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    for org_name in data.get("org_names", []):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="company_profile_extractor", type="org_found",
            value=org_name, context=f"Organization linked to {target}",
            source="company_profile", evidence_ref=evidence_id,
            confidence=0.70, rate="Low",
        ))
    for rd in data.get("related_domains", []):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="company_profile_extractor", type="subdomain_found",
            value=rd, normalized_value=Canonicalizer.domain(rd),
            context=f"Related domain via org profile for {target}",
            source="company_profile", evidence_ref=evidence_id,
            confidence=0.55, rate="Low",
        ))
        leads.append(Lead(
            type="domain", value=Canonicalizer.domain(rd), raw_value=rd,
            source="company_profile", confidence=0.55, priority=0.50,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="company_profile", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_related_domains(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for domain in result.get("data", {}).get("domains", []):
        if is_garbage_lead(domain):
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="related_domains_extractor", type="subdomain_found",
            value=domain, normalized_value=Canonicalizer.domain(domain),
            context=f"Related root domain for {target}",
            source="related_domains", evidence_ref=evidence_id,
            confidence=0.60, rate="Low",
        ))
        leads.append(Lead(
            type="domain", value=Canonicalizer.domain(domain),
            source="related_domains", confidence=0.60, priority=0.55,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="related_domains", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_reverse_whois(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for d in result.get("data", {}).get("domains_found", [])[:15]:
        if is_garbage_lead(d) or d == state.get("engagement_spec", {}).get("target", ""):
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="reverse_whois_extractor", type="org_found",
            value=d, context=f"Domain registered by same entity as {target}",
            source="reverse_whois", evidence_ref=evidence_id,
            confidence=0.65, rate="Low",
        ))
    return obs, leads


def extract_reverse_ip(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for vd in result.get("data", {}).get("domains_on_ip", [])[:20]:
        if is_garbage_lead(vd):
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="reverse_ip_extractor", type="subdomain_found",
            value=vd, context=f"Virtual hosting co-tenant on same IP as {target}",
            source="reverse_ip", evidence_ref=evidence_id,
            confidence=0.70, rate="Medium",
        ))
    return obs, leads


def extract_google_analytics_id(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    shared = result.get("data", {}).get("shared_domains", {})
    for _ga_id, domains in shared.items():
        for d in domains[:10]:
            if is_garbage_lead(d) or d == target:
                continue
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="ga_tracking_extractor", type="org_found",
                value=d, context=f"Shares Google Analytics ID with {target}",
                source="ga_tracking", evidence_ref=evidence_id,
                confidence=0.65, rate="Low",
            ))
    return obs, leads


# ── People Intel extractors ───────────────────────────────────────

def extract_email_harvest(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for email in result.get("data", {}).get("emails", []):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="email_harvest_extractor", type="email_found",
            value=email, normalized_value=email.lower().strip(),
            context=f"Email harvested from {target}",
            source="email_harvest", evidence_ref=evidence_id,
            confidence=0.75, rate="Medium",
        ))
    return obs, leads


def extract_public_contact(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for email in result.get("data", {}).get("emails", []):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="public_contact_extractor", type="email_found",
            value=email, normalized_value=email.lower().strip(),
            context=f"Public contact from {target}",
            source="public_contact", evidence_ref=evidence_id,
            confidence=0.75, rate="Medium",
        ))
    return obs, leads


# ── OSINT extractors ─────────────────────────────────────────────

def extract_wayback(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for path in (result.get("data", {}).get("interesting", []) or [])[:20]:
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="wayback_extractor", type="url_found",
            value=path if path.startswith("http") else f"https://{target}{path}",
            context=f"Historical path from Wayback Machine for {target}",
            source="wayback", evidence_ref=evidence_id,
            confidence=0.7, rate="Low",
        ))
        leads.append(Lead(
            type="endpoint",
            value=path if path.startswith("http") else f"https://{target}{path}",
            raw_value=path, source="wayback", confidence=0.65, priority=0.5,
            depth=_parent_depth(state),
            parent_lead_id=_parent_id(state),
            discovered_by="wayback", evidence_refs=[evidence_id],
        ))
    return obs, leads


def extract_js_endpoints(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    sid = _sid(state)
    for ep in result.get("data", {}).get("endpoints", [])[:30]:
        obs.append(Observation(
            session_id=sid, raw_event_id=evidence_id,
            extractor="js_endpoint_extractor", type="endpoint_found",
            value=ep if isinstance(ep, str) else str(ep),
            context=f"API endpoint from JS on {target}",
            source="js_endpoints", evidence_ref=evidence_id,
            confidence=0.7, rate="Low",
        ))
    return obs, leads


def extract_spf_dmarc(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    if data.get("spf_record"):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="spf_dmarc_extractor", type="header_found",
            value=data["spf_record"],
            context=f"SPF record for {target}",
            source="spf_dmarc", evidence_ref=evidence_id,
            confidence=0.9, rate="Low",
        ))
    if not data.get("dmarc_exists"):
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="spf_dmarc_extractor", type="email_found",
            value=f"no-dmarc@{target}",
            context=f"DMARC missing for {target} — email spoofing risk",
            source="spf_dmarc", evidence_ref=evidence_id,
            confidence=0.85, rate="High",
        ))
    return obs, leads


def extract_repo_discovery(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for repo in result.get("data", {}).get("repos", []):
        repo_url = repo.get("html_url", "")
        if repo_url:
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="repo_discovery_extractor", type="repo_found",
                value=repo_url, context=f"Public repo for {target}",
                source="repo_discovery", evidence_ref=evidence_id,
                confidence=0.60, rate="Low",
                attributes={"language": repo.get("language", ""), "stars": repo.get("stars", 0)},
            ))
    return obs, leads


def extract_cve_lookup(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for cve in result.get("data", {}).get("cves", [])[:10]:
        score = float(cve.get("cvss", {}).get("score", 0) or 0)
        if score >= 5.0:
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="cve_lookup_extractor", type="vulnerability_found",
                value=cve.get("id", "CVE"),
                context=f"{target}: {cve.get('summary', '')}",
                source="cve_lookup", evidence_ref=evidence_id,
                confidence=0.85, rate="High" if score >= 7.0 else "Medium",
                attributes={"cvss": score, "cve_id": cve.get("id", "")},
            ))
    return obs, leads


# ── Karma extractors ──────────────────────────────────────────────

def extract_karma_ip(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for ip_info in result.get("data", {}).get("ips", [])[:50]:
        ip = ip_info if isinstance(ip_info, str) else ip_info.get("ip", "")
        if ip:
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="karma_ip_extractor", type="ip_found",
                value=ip, normalized_value=Canonicalizer.ip(ip),
                context=f"IP discovered via Karma/Shodan for {target}",
                source="karma_ip", evidence_ref=evidence_id,
                confidence=0.80, rate="Low",
            ))
    return obs, leads


def extract_karma_leaks(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for leak in result.get("data", {}).get("leaks", [])[:20]:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="karma_leaks_extractor", type="credential_signal_found",
            value=f"leak:{target}",
            context=f"Credential leak detected for {target}",
            source="karma_leaks", evidence_ref=evidence_id,
            confidence=0.85, rate="High",
        ))
    return obs, leads


def extract_karma_cve(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for cve_id in result.get("data", {}).get("cves_found", [])[:10]:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="karma_cve_extractor", type="vulnerability_found",
            value=cve_id, context=f"CVE via Karma/Shodan for {target}",
            source="karma_cve", evidence_ref=evidence_id,
            confidence=0.80, rate="High",
        ))
    return obs, leads


# ── Web crawl / params / cloud / favicon / vhost / docs ──────────

def extract_crawl(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    for url in data.get("all_urls", [])[:200]:
        if not url:
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="crawl_extractor", type="url_found",
            value=url, normalized_value=Canonicalizer.url(url),
            context=f"URL discovered by crawler on {target}",
            source="crawl", evidence_ref=evidence_id,
            confidence=0.75, rate="Info",
        ))
        if not is_garbage_lead(url):
            leads.append(Lead(
                type="url", value=url, raw_value=url,
                source="crawl", confidence=0.65, priority=0.4,
                depth=_parent_depth(state), parent_lead_id=_parent_id(state),
                scope_status="in_scope",
            ))
    for ep in data.get("interesting_urls", [])[:50]:
        if not ep:
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="crawl_extractor", type="endpoint_found",
            value=ep, normalized_value=Canonicalizer.url(ep),
            context=f"Interesting endpoint found by crawler on {target}",
            source="crawl", evidence_ref=evidence_id,
            confidence=0.80, rate="Low",
        ))
    return obs, leads


def extract_params(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for p in result.get("data", {}).get("params_discovered", [])[:100]:
        param_name = p.get("param", "") if isinstance(p, dict) else str(p)
        if not param_name:
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="params_extractor", type="parameter_found",
            value=param_name,
            context=f"Hidden parameter '{param_name}' on {target}",
            source="params", evidence_ref=evidence_id,
            confidence=0.70, rate="Low",
            attributes={"url": target, "method": p.get("method", "GET") if isinstance(p, dict) else "GET"},
        ))
    return obs, leads


def extract_web_surface(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", result)  # WebSurfacePipeline returns top-level dict
    fingerprint = data.get("fingerprint", {})
    # Live webapp signal
    if fingerprint:
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="web_surface_extractor", type="webapp_alive",
            value=target,
            context=f"Web surface pipeline completed on {target}",
            source="web_surface", evidence_ref=evidence_id,
            confidence=0.85, rate="Info",
        ))
    # Technologies from fingerprint
    for tech in fingerprint.get("tech", [])[:20]:
        if tech:
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="web_surface_extractor", type="technology_found",
                value=tech,
                context=f"Technology '{tech}' detected on {target}",
                source="web_surface", evidence_ref=evidence_id,
                confidence=0.75, rate="Info",
            ))
    # Endpoints from pipeline
    for ep in data.get("endpoints", [])[:100]:
        url = ep.get("url", "") if isinstance(ep, dict) else ""
        if url and not is_garbage_lead(url):
            obs.append(Observation(
                session_id=_sid(state), raw_event_id=evidence_id,
                extractor="web_surface_extractor", type="endpoint_found",
                value=url, normalized_value=Canonicalizer.url(url),
                context=f"Endpoint found by web surface on {target}",
                source="web_surface", evidence_ref=evidence_id,
                confidence=0.75, rate="Info",
            ))
    return obs, leads


def extract_favicon(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    favicon_hash = data.get("hash")
    if favicon_hash is not None:
        tech_hint = f"favicon_hash:{favicon_hash}"
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="favicon_extractor", type="technology_found",
            value=tech_hint,
            context=f"Favicon MurmurHash3={favicon_hash} for {target}",
            source="favicon", evidence_ref=evidence_id,
            confidence=0.60, rate="Info",
            attributes={"favicon_hash": favicon_hash, "shodan_query": data.get("shodan_query", "")},
        ))
    return obs, leads


def extract_cloud(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    data = result.get("data", {})
    for bucket in data.get("found_buckets", [])[:50]:
        bucket_url = bucket.get("url", "")
        bucket_name = bucket.get("name", "")
        bucket_type = bucket.get("type", "cloud")
        is_public = bucket.get("status", "") == "PUBLIC"
        if not bucket_url:
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="cloud_extractor", type="url_found",
            value=bucket_url, normalized_value=Canonicalizer.url(bucket_url),
            context=(
                f"{'PUBLIC' if is_public else 'PRIVATE'} {bucket_type} bucket "
                f"'{bucket_name}' found for {target}"
            ),
            source="cloud", evidence_ref=evidence_id,
            confidence=0.85 if is_public else 0.70,
            rate="Critical" if is_public else "Medium",
            attributes={"bucket_type": bucket_type, "status": bucket.get("status", ""), "name": bucket_name},
        ))
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="cloud_extractor", type="technology_found",
            value=f"{bucket_type.lower()}_storage",
            context=f"{bucket_type} object storage in use by {target}",
            source="cloud", evidence_ref=evidence_id,
            confidence=0.75, rate="Info",
        ))
    return obs, leads


def extract_vhost(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for vhost in result.get("data", {}).get("vhosts", [])[:50]:
        vhost_name = vhost.get("vhost", "") if isinstance(vhost, dict) else str(vhost)
        if not vhost_name or is_garbage_lead(vhost_name):
            continue
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="vhost_extractor", type="subdomain_found",
            value=vhost_name, normalized_value=Canonicalizer.domain(vhost_name),
            context=f"Virtual host '{vhost_name}' discovered on {target}",
            source="vhost", evidence_ref=evidence_id,
            confidence=0.85, rate="Medium",
        ))
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="vhost_extractor", type="webapp_alive",
            value=vhost_name,
            context=f"VHost '{vhost_name}' responded on {target}",
            source="vhost", evidence_ref=evidence_id,
            confidence=0.80, rate="Info",
        ))
        leads.append(Lead(
            type="subdomain", value=vhost_name, raw_value=vhost_name,
            source="vhost", confidence=0.80, priority=0.55,
            depth=_parent_depth(state), parent_lead_id=_parent_id(state),
            scope_status="in_scope",
        ))
    return obs, leads


def extract_public_doc_discovery(tool, target, result, state, evidence_id) -> ExtractResult:
    obs, leads = [], []
    if not result.get("success"):
        return obs, leads
    for doc in result.get("data", {}).get("documents", [])[:100]:
        doc_url = doc.get("url", "") if isinstance(doc, dict) else str(doc)
        if not doc_url:
            continue
        ext = doc.get("extension", "") if isinstance(doc, dict) else ""
        obs.append(Observation(
            session_id=_sid(state), raw_event_id=evidence_id,
            extractor="public_doc_extractor", type="document_found",
            value=doc_url, normalized_value=Canonicalizer.url(doc_url),
            context=f"Public document ({ext.upper() or 'doc'}) found on {target}",
            source="public_doc_discovery", evidence_ref=evidence_id,
            confidence=0.75, rate="Low",
            attributes={"extension": ext, "source_page": doc.get("source_page", "")},
        ))
    return obs, leads


# ── Generic fallback ──────────────────────────────────────────────

def extract_generic(tool, target, result, state, evidence_id) -> ExtractResult:
    """Fallback — just record that the tool ran."""
    return [], []


# ── Extractor registry — maps tool name → extraction function ────

EXTRACTOR_REGISTRY = {
    "whois": extract_whois,
    "dns": extract_dns,
    "reverse_dns": extract_reverse_dns,
    "crt_sh": extract_crt_sh,
    "subdomain_discovery": extract_subdomain_discovery,
    "dns_dumpster": extract_dns_dumpster,
    "subfinder": extract_subfinder,
    "zone_transfer": extract_zone_transfer,
    "shodan": extract_shodan,
    "asn": extract_asn,
    "infra_asn_enrich": extract_infra_asn_enrich,
    "nmap": extract_nmap,
    "banner": extract_banner,
    "smap": extract_smap,
    "httpx": extract_httpx,
    "headers": extract_headers,
    "ssl": extract_ssl,
    "tech": extract_tech,
    "robots": extract_robots,
    "waf": extract_waf,
    "dirs": extract_dirs,
    "nuclei": extract_nuclei,
    "http_methods": extract_http_methods,
    "company_profile": extract_company_profile,
    "related_domains": extract_related_domains,
    "reverse_whois": extract_reverse_whois,
    "reverse_ip": extract_reverse_ip,
    "google_analytics_id": extract_google_analytics_id,
    "email_harvest": extract_email_harvest,
    "public_contact": extract_public_contact,
    "wayback": extract_wayback,
    "js_endpoints": extract_js_endpoints,
    "spf_dmarc": extract_spf_dmarc,
    "repo_discovery": extract_repo_discovery,
    "cve_lookup": extract_cve_lookup,
    "karma_ip": extract_karma_ip,
    "karma_leaks": extract_karma_leaks,
    "karma_cve": extract_karma_cve,
    # Web crawl / surface / params
    "crawl": extract_crawl,
    "params": extract_params,
    "web_surface": extract_web_surface,
    "favicon": extract_favicon,
    "cloud": extract_cloud,
    "vhost": extract_vhost,
    "public_doc_discovery": extract_public_doc_discovery,
}


def extract_for_tool(tool: str, target: str, result: dict,
                     state: dict, evidence_id: str) -> ExtractResult:
    """Route to the correct extractor by tool name."""
    fn = EXTRACTOR_REGISTRY.get(tool, extract_generic)
    return fn(tool, target, result, state, evidence_id)
