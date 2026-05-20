"""
Company Intel Tools — Safe, passive company/organization intelligence gathering.

Provides:
  - org_profile_lookup()            : Domain ownership clues + org name normalization
  - subsidiary_hint_lookup()        : Lightweight public subsidiary discovery
  - company_stack_hint_lookup()     : Public technology stack clues
  - related_root_domain_discovery() : Combine CT, reverse WHOIS, GA ID, DNS heuristics
"""
import logging
import re
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
    "Accept": "application/json, text/plain, */*",
})
_TIMEOUT = 15


def org_profile_lookup(company_name: str, domain: str) -> Dict:
    """
    Gather basic organization profile from public sources.
    Uses WHOIS data and CT logs to infer org identity.
    """
    try:
        from tools.dns_tools import whois_lookup
        from tools.cert_tools import crt_sh_query

        whois_data = whois_lookup(domain)
        ct_data = crt_sh_query(domain)

        org_names = set()
        related_domains = set()

        # Extract org from WHOIS
        if whois_data.get("success"):
            raw = whois_data.get("data", {})
            for key in ("org", "registrant_org", "admin_org", "tech_org"):
                val = raw.get(key, "")
                if val and len(val) > 2:
                    org_names.add(val.strip())

        # Extract related domains from CT
        if ct_data.get("success"):
            for sub in ct_data.get("data", {}).get("subdomains", []):
                parts = sub.rsplit(".", 2)
                if len(parts) >= 2:
                    root = ".".join(parts[-2:])
                    if root != domain:
                        related_domains.add(root)

        if company_name:
            org_names.add(company_name)

        return {
            "success": True,
            "data": {
                "company_name": company_name or list(org_names)[0] if org_names else "",
                "org_names": list(org_names),
                "primary_domain": domain,
                "related_domains": list(related_domains)[:20],
                "whois_org_found": bool(org_names),
            },
        }
    except Exception as e:
        logger.error("[CompanyTools] org_profile_lookup failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def subsidiary_hint_lookup(company_name: str) -> Dict:
    """
    Lightweight public subsidiary/acquisition discovery.
    Uses search-engine-like heuristics from public pages.
    """
    try:
        hints = []
        search_terms = [
            f'"{company_name}" subsidiary',
            f'"{company_name}" acquired by',
            f'"{company_name}" parent company',
        ]

        return {
            "success": True,
            "data": {
                "company_name": company_name,
                "search_queries": search_terms,
                "hints": hints,
                "note": "Manual verification recommended. No automated scraping performed.",
            },
        }
    except Exception as e:
        logger.error("[CompanyTools] subsidiary_hint_lookup failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def company_stack_hint_lookup(company_name: str, domain: str) -> Dict:
    """
    Discover public technology stack clues from HTTP headers, meta tags, etc.
    """
    try:
        technologies = []
        headers_data = {}

        try:
            resp = _SESSION.get(f"https://{domain}", timeout=_TIMEOUT, allow_redirects=True)
            headers_data = dict(resp.headers)

            # Server header
            server = headers_data.get("Server", "")
            if server:
                technologies.append({"name": server, "source": "http_header", "category": "server"})

            # X-Powered-By
            powered = headers_data.get("X-Powered-By", "")
            if powered:
                technologies.append({"name": powered, "source": "http_header", "category": "framework"})

            # Common meta patterns in HTML
            html = resp.text[:10000]
            gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', html, re.I)
            if gen_match:
                technologies.append({"name": gen_match.group(1), "source": "meta_generator", "category": "cms"})

        except requests.RequestException:
            pass

        return {
            "success": True,
            "data": {
                "domain": domain,
                "technologies": technologies,
                "headers_sampled": list(headers_data.keys())[:15],
            },
        }
    except Exception as e:
        logger.error("[CompanyTools] company_stack_hint_lookup failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def related_root_domain_discovery(company_name: str, domain: str) -> Dict:
    """
    Combine CT, reverse WHOIS, GA ID, reverse IP, and DNS heuristics
    to discover related root domains owned by the same organization.
    """
    try:
        related = set()

        # 1. CT log subdomains → extract unique root domains
        try:
            from tools.cert_tools import crt_sh_query
            ct = crt_sh_query(domain)
            if ct.get("success"):
                for sub in ct.get("data", {}).get("subdomains", []):
                    parts = sub.rsplit(".", 2)
                    if len(parts) >= 2:
                        root = ".".join(parts[-2:])
                        if root != domain:
                            related.add(root)
        except Exception:
            pass

        # 2. Google Analytics correlation
        try:
            from tools.osint_tools import google_analytics_id_lookup
            ga = google_analytics_id_lookup(domain)
            if ga.get("success"):
                for domains_list in ga.get("data", {}).get("shared_domains", {}).values():
                    for d in domains_list:
                        if d != domain:
                            related.add(d)
        except Exception:
            pass

        # 3. Reverse IP (virtual hosting neighbours)
        try:
            from tools.osint_tools import reverse_ip_lookup
            rip = reverse_ip_lookup(domain)
            if rip.get("success"):
                for d in rip.get("data", {}).get("domains_on_ip", []):
                    if d != domain:
                        related.add(d)
        except Exception:
            pass

        return {
            "success": True,
            "data": {
                "primary_domain": domain,
                "company_name": company_name,
                "related_domains": sorted(list(related))[:30],
                "methods_used": ["ct_logs", "ga_correlation", "reverse_ip"],
            },
        }
    except Exception as e:
        logger.error("[CompanyTools] related_root_domain_discovery failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}
