"""
Unified tool dispatcher — single entry point for all tool calls.

Layer 3 (Tool/Engine Adapter):
  - Chỉ gọi tool, trả raw result
  - Không mutate state, không extract observation, không tạo entity
  - Chuẩn hoá output thành ToolResult dict

Usage:
    result = dispatch_tool("dns", "example.com", spec=spec, options={})
"""
import logging
import socket
import time
from typing import Any, Dict, Optional, TypedDict

logger = logging.getLogger(__name__)


class ToolResult(TypedDict, total=False):
    """Standardised tool output."""
    tool: str
    target: str
    success: bool
    data: dict
    error: Optional[str]
    evidence_id: str          # filled later by evidence_store


# ── Registry helpers ──────────────────────────────────────────────

def _normalize_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _resolve_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


# ── Passive tool loaders ──────────────────────────────────────────

def _get_passive_dispatch() -> Dict[str, Any]:
    """Lazy-load passive tools."""
    funcs: Dict[str, Any] = {}
    try:
        from tools import dns_tools, cert_tools
        funcs["whois"] = lambda t, **kw: dns_tools.whois_lookup(t)
        funcs["dns"] = lambda t, **kw: dns_tools.dns_lookup(t, ["A", "AAAA", "MX", "NS", "TXT", "CNAME"])
        funcs["crt_sh"] = lambda t, **kw: cert_tools.crt_sh_query(t)
        funcs["cert_detail"] = lambda t, **kw: cert_tools.cert_detail_collect(
            t, port=kw.get("port", 443))
        funcs["reverse_dns"] = lambda t, **kw: dns_tools.reverse_dns_lookup(t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools import shodan_tools
        from core.config import config as _cfg
        _key = _cfg.shodan_api_key or ""
        funcs["shodan"] = lambda t, **kw: shodan_tools.shodan_host_lookup(t, _key)
        funcs["shodan_search"] = lambda t, **kw: shodan_tools.shodan_query(t, _key)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.osint_tools import (
            spf_dmarc_check, wayback_machine_query, zone_transfer_attempt,
            extract_js_endpoints, asn_lookup, email_harvest_cleartext,
            dns_dumpster_query, cve_lookup_for_service,
            github_dork_hints, google_dork_hints,
            google_analytics_id_lookup, reverse_ip_lookup, reverse_whois_lookup,
            credential_signal_check, service_metadata_enrich,
        )
        funcs["spf_dmarc"] = lambda t, **kw: spf_dmarc_check(t)
        funcs["wayback"] = lambda t, **kw: wayback_machine_query(t, limit=kw.get("limit", 300))
        funcs["zone_transfer"] = lambda t, **kw: zone_transfer_attempt(t)
        funcs["js_endpoints"] = lambda t, **kw: extract_js_endpoints(t)
        funcs["asn"] = lambda t, **kw: asn_lookup(t)
        funcs["email_harvest"] = lambda t, **kw: email_harvest_cleartext(f"https://{t}")
        funcs["dns_dumpster"] = lambda t, **kw: dns_dumpster_query(t)
        funcs["cve_lookup"] = lambda t, **kw: cve_lookup_for_service(
            kw.get("service", t), kw.get("version", ""))
        funcs["github_dorks"] = lambda t, **kw: github_dork_hints(t, kw.get("company", ""))
        funcs["google_dorks"] = lambda t, **kw: google_dork_hints(t)
        funcs["google_analytics_id"] = lambda t, **kw: google_analytics_id_lookup(t)
        funcs["reverse_ip"] = lambda t, **kw: reverse_ip_lookup(t)
        funcs["reverse_whois"] = lambda t, **kw: reverse_whois_lookup(t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.osint_tools import credential_signal_check, service_metadata_enrich
        funcs["credential_signal"] = lambda t, **kw: credential_signal_check(t)
        funcs["service_metadata"] = lambda t, **kw: service_metadata_enrich(
            t, port=kw.get("port", 0))
    except (ImportError, AttributeError):
        pass

    try:
        from tools.subdomain_tools import run_subdomain_discovery
        funcs["subdomain_discovery"] = lambda t, **kw: run_subdomain_discovery(
            t, profile=kw.get("profile", "balanced"))
    except (ImportError, AttributeError):
        pass

    try:
        from tools.company_tools import (
            org_profile_lookup, company_stack_hint_lookup, related_root_domain_discovery)
        funcs["company_profile"] = lambda t, **kw: org_profile_lookup(kw.get("company", ""), t)
        funcs["company_stack"] = lambda t, **kw: company_stack_hint_lookup(kw.get("company", ""), t)
        funcs["related_domains"] = lambda t, **kw: related_root_domain_discovery(kw.get("company", ""), t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.people_tools import public_contact_harvest, about_team_page_harvest
        funcs["public_contact"] = lambda t, **kw: public_contact_harvest(t)
        funcs["team_harvest"] = lambda t, **kw: about_team_page_harvest(t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.repo_tools import repo_discovery as _repo_disc
        funcs["repo_discovery"] = lambda t, **kw: _repo_disc(t, kw.get("company", ""))
    except (ImportError, AttributeError):
        pass

    try:
        from tools.document_tools import public_document_discovery
        funcs["public_doc_discovery"] = lambda t, **kw: public_document_discovery(t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.infrastructure_tools import asn_enrichment, bgp_range_summary, org_ip_range_summary
        funcs["infra_asn_enrich"] = lambda t, **kw: asn_enrichment(t)
        funcs["bgp_range"] = lambda t, **kw: bgp_range_summary(t)
        funcs["org_ip_range"] = lambda t, **kw: org_ip_range_summary(t)
    except (ImportError, AttributeError):
        pass

    return funcs


def _get_active_dispatch() -> Dict[str, Any]:
    """Lazy-load active tools."""
    funcs: Dict[str, Any] = {}
    try:
        from tools.active_tools import run_nmap, run_subfinder, run_httpx, run_nuclei, run_vhost_discovery
        funcs["nmap"] = lambda t, **kw: run_nmap(t, options=kw.get("options", {}))
        funcs["subfinder"] = lambda t, **kw: run_subfinder(t, options=kw.get("options", {}))
        funcs["httpx"] = lambda t, **kw: run_httpx([t], options=kw.get("options", {}))
        funcs["nuclei"] = lambda t, **kw: run_nuclei([t], options=kw.get("options", {}))
        funcs["vhost"] = lambda t, **kw: run_vhost_discovery(_resolve_ip(t), t)
    except (ImportError, AttributeError):
        pass

    try:
        from tools.web_tools import (
            check_http_headers, ssl_tls_check, detect_waf,
            analyze_tech_stack, enumerate_directories, crawl_urls,
            parse_robots_sitemap, check_http_methods,
            find_cloud_assets, compute_favicon_hash,
            grab_banner, discover_params,
        )
        funcs["headers"] = lambda t, **kw: check_http_headers(_normalize_url(t), options=kw.get("options", {}))
        funcs["ssl"] = lambda t, **kw: ssl_tls_check(_normalize_url(t), options=kw.get("options", {}))
        funcs["waf"] = lambda t, **kw: detect_waf(_normalize_url(t), options=kw.get("options", {}))
        funcs["tech"] = lambda t, **kw: analyze_tech_stack(_normalize_url(t), options=kw.get("options", {}))
        funcs["dirs"] = lambda t, **kw: enumerate_directories(
            _normalize_url(t), wordlist_type=kw.get("wordlist_type", "small"), options=kw.get("options", {}))
        funcs["crawl"] = lambda t, **kw: crawl_urls(
            _normalize_url(t), max_pages=kw.get("max_pages", 50), options=kw.get("options", {}))
        funcs["robots"] = lambda t, **kw: parse_robots_sitemap(_normalize_url(t), options=kw.get("options", {}))
        funcs["http_methods"] = lambda t, **kw: check_http_methods(_normalize_url(t), options=kw.get("options", {}))
        funcs["cloud"] = lambda t, **kw: find_cloud_assets(t, options=kw.get("options", {}))
        funcs["favicon"] = lambda t, **kw: compute_favicon_hash(_normalize_url(t), options=kw.get("options", {}))
        funcs["banner"] = lambda t, **kw: grab_banner(t, kw.get("port", 80), options=kw.get("options", {}))
        funcs["params"] = lambda t, **kw: discover_params(_normalize_url(t), options=kw.get("options", {}))
    except (ImportError, AttributeError):
        pass

    try:
        from tools.web_surface import WebSurfacePipeline
        funcs["web_surface"] = lambda t, **kw: WebSurfacePipeline(
            t, spec={"features": kw.get("features", {"dir_enum": True, "crawler": False})}
        ).run()
    except (ImportError, AttributeError):
        pass

    return funcs


def _get_karma_dispatch() -> Dict[str, Any]:
    """Lazy-load karma tools."""
    funcs: Dict[str, Any] = {}
    try:
        from tools.karma_tools import (
            karma_health_check, run_karma_cve, run_karma_ip,
            run_karma_leaks, smap_passive_portscan,
        )
        funcs["karma_health"] = lambda t, **kw: karma_health_check()
        funcs["karma_ip"] = lambda t, **kw: run_karma_ip(t, limit=kw.get("limit", 100))
        funcs["karma_leaks"] = lambda t, **kw: run_karma_leaks(t, limit=kw.get("limit", 100))
        funcs["karma_cve"] = lambda t, **kw: run_karma_cve(t, limit=kw.get("limit", 100))
        funcs["smap"] = lambda t, **kw: smap_passive_portscan(t)
    except (ImportError, AttributeError):
        pass
    return funcs


# ── Cached registries ─────────────────────────────────────────────

_PASSIVE_TOOLS: Optional[Dict] = None
_ACTIVE_TOOLS: Optional[Dict] = None
_KARMA_TOOLS: Optional[Dict] = None


def _all_tools() -> Dict[str, Any]:
    global _PASSIVE_TOOLS, _ACTIVE_TOOLS, _KARMA_TOOLS
    if _PASSIVE_TOOLS is None:
        _PASSIVE_TOOLS = _get_passive_dispatch()
    if _ACTIVE_TOOLS is None:
        _ACTIVE_TOOLS = _get_active_dispatch()
    if _KARMA_TOOLS is None:
        _KARMA_TOOLS = _get_karma_dispatch()
    merged = {}
    merged.update(_PASSIVE_TOOLS)
    merged.update(_ACTIVE_TOOLS)
    merged.update(_KARMA_TOOLS)
    return merged


# ── Public API ────────────────────────────────────────────────────

def dispatch_tool(
    tool: str,
    target: str,
    *,
    rate_limit: float = 1.0,
    options: Optional[Dict] = None,
    **kwargs,
) -> ToolResult:
    """
    Call any registered tool and return a standardised ToolResult.
    This is the ONLY entry point for tool execution.
    """
    registry = _all_tools()
    if tool not in registry:
        logger.debug("[Dispatcher] Unknown tool: %s", tool)
        return ToolResult(tool=tool, target=target, success=False,
                          data={}, error=f"Unknown tool: {tool}")

    time.sleep(rate_limit)

    try:
        merged_kw = dict(kwargs)
        if options:
            merged_kw["options"] = options
        raw = registry[tool](target, **merged_kw)
        if not raw:
            return ToolResult(tool=tool, target=target, success=True, data={})
        if isinstance(raw, dict):
            return ToolResult(
                tool=tool, target=target,
                success=raw.get("success", True),
                data=raw.get("data", raw),
                error=raw.get("error"),
            )
        return ToolResult(tool=tool, target=target, success=True, data={"raw": raw})
    except Exception as exc:
        logger.error("[Dispatcher] %s on %s failed: %s", tool, target, exc)
        return ToolResult(tool=tool, target=target, success=False,
                          data={}, error=str(exc))


def is_tool_available(tool: str) -> bool:
    """Check if a tool is registered."""
    return tool in _all_tools()
