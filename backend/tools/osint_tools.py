"""
OSINT Tools — Passive intelligence gathering without direct target contact.

Provides:
  - wayback_machine_query()   : Archive.org / Wayback URLs
  - asn_lookup()              : ASN & IP block enumeration
  - google_dork_hints()       : Generate Google dork queries
  - github_dork_hints()       : Generate GitHub search queries
  - email_harvest_cleartext() : Extract emails from web page source
  - dns_dumpster_query()      : Passive subdomain discovery via HackerTarget
  - spf_dmarc_check()         : Email security policy analysis
  - zone_transfer_attempt()   : DNS zone transfer AXFR attempt
  - credential_signal_check() : Check for leaked credential signals
  - service_metadata_enrich() : Enrich service banners
"""

import json
import logging
import re
import socket
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
    "Accept": "application/json, text/plain, */*",
})
_TIMEOUT = 15


# ── Wayback Machine ────────────────────────────────────────────────────────

def wayback_machine_query(domain: str, limit: int = 200) -> Dict:
    """
    Query Wayback CDX API for archived URLs of a domain.
    Returns unique endpoints/paths useful for attack surface discovery.
    """
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}&fastLatest=true"
        )
        r = _SESSION.get(url, timeout=_TIMEOUT)
        r.raise_for_status()
        rows = r.json()

        urls = []
        paths = set()
        params = set()
        interesting = []

        for row in rows[1:]:  # Skip header row
            raw_url = row[0]
            parsed = urlparse(raw_url)
            path = parsed.path
            paths.add(path)
            urls.append(raw_url)

            # Flag juicy patterns
            patterns = [
                r"\.git", r"\.env", r"admin", r"api/", r"login", r"upload",
                r"config", r"backup", r"\.sql", r"\.tar", r"\.zip",
                r"swagger", r"graphql", r"/v[0-9]+/", r"\.php", r"debug",
            ]
            for p in patterns:
                if re.search(p, raw_url, re.IGNORECASE):
                    interesting.append(raw_url)
                    break

            if parsed.query:
                for q in parsed.query.split("&"):
                    k = q.split("=")[0]
                    if k:
                        params.add(k)

        return {
            "success": True,
            "domain": domain,
            "data": {
                "total_urls": len(urls),
                "unique_paths": len(paths),
                "interesting_endpoints": list(set(interesting))[:50],
                "url_params": list(params)[:100],
                "sample_paths": sorted(list(paths))[:100],
            },
        }
    except Exception as exc:
        logger.error("wayback_machine_query(%s): %s", domain, exc)
        return {"success": False, "domain": domain, "error": str(exc), "data": {}}


# ── ASN Lookup ─────────────────────────────────────────────────────────────

def asn_lookup(domain: str) -> Dict:
    """
    Resolve domain → IP → ASN info using bgpview.io API.
    Reveals hosting provider, IP range, and organisation.
    """
    try:
        ip = socket.gethostbyname(domain)
        r = _SESSION.get(f"https://api.bgpview.io/ip/{ip}", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data", {})
        prefixes = data.get("prefixes", [])
        asns = []
        ip_ranges = []
        for pfx in prefixes:
            asn_data = pfx.get("asn", {})
            asns.append({
                "asn": asn_data.get("asn"),
                "name": asn_data.get("name"),
                "description": asn_data.get("description"),
                "country_code": asn_data.get("country_code"),
            })
            ip_ranges.append(pfx.get("prefix"))

        return {
            "success": True,
            "domain": domain,
            "data": {
                "resolved_ip": ip,
                "asns": asns,
                "ip_ranges": ip_ranges[:20],
                "rir_allocation": data.get("rir_allocation", {}),
            },
        }
    except Exception as exc:
        logger.error("asn_lookup(%s): %s", domain, exc)
        return {"success": False, "domain": domain, "error": str(exc), "data": {}}


# ── SPF / DMARC / DKIM Policy ──────────────────────────────────────────────

def spf_dmarc_check(domain: str) -> Dict:
    """
    Check email security posture: SPF, DMARC, DKIM (common selectors).
    Missing/misconfigured records = potential email spoofing vector.
    """
    import dns.resolver  # lazy import

    results = {
        "domain": domain,
        "spf": None,
        "dmarc": None,
        "dkim_selectors_found": [],
        "issues": [],
    }

    # SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if "v=spf1" in txt:
                results["spf"] = txt.strip('"')
                if "-all" not in txt and "~all" not in txt:
                    results["issues"].append("SPF không có -all / ~all → spoofing risk")
                break
        if results["spf"] is None:
            results["issues"].append("Không có SPF record → email spoofing vulnerable")
    except Exception:
        results["issues"].append("Không thể resolve SPF TXT record")

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata)
            if "v=DMARC1" in txt:
                results["dmarc"] = txt.strip('"')
                if "p=none" in txt:
                    results["issues"].append("DMARC policy=none → không enforce, chỉ monitor")
                break
        if results["dmarc"] is None:
            results["issues"].append("Không có DMARC record → email spoofing dễ hơn")
    except Exception:
        results["issues"].append("Không thể resolve DMARC record")

    # DKIM common selectors
    common_selectors = ["default", "google", "mail", "k1", "selector1", "selector2", "dkim", "smtp"]
    for sel in common_selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            results["dkim_selectors_found"].append(sel)
        except Exception:
            pass

    return {"success": True, "data": results}


# ── Zone Transfer Attempt ──────────────────────────────────────────────────

def zone_transfer_attempt(domain: str) -> Dict:
    """
    Attempt DNS zone transfer (AXFR) against all nameservers.
    If successful → full DNS zone exposed = critical finding.
    """
    import dns.query
    import dns.resolver
    import dns.zone

    findings = []
    nameservers = []

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        nameservers = [str(r.target).rstrip(".") for r in ns_answers]
    except Exception as exc:
        return {"success": False, "domain": domain, "error": str(exc), "data": {}}

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            findings.append({
                "nameserver": ns,
                "status": "VULNERABLE — Zone transfer succeeded!",
                "records_count": len(records),
                "records_sample": records[:20],
            })
        except Exception as exc:
            findings.append({
                "nameserver": ns,
                "status": f"refused ({type(exc).__name__})",
            })

    vulnerable = [f for f in findings if "VULNERABLE" in f.get("status", "")]
    return {
        "success": True,
        "domain": domain,
        "data": {
            "nameservers": nameservers,
            "results": findings,
            "vulnerable": len(vulnerable) > 0,
            "critical_finding": bool(vulnerable),
        },
    }


# ── DNS Dumpster (passive subdomain lookup) ────────────────────────────────

def dns_dumpster_query(domain: str) -> Dict:
    """
    Passive sub-domain discovery via HackerTarget hostsearch API.
    Returns list of discovered subdomains.
    """
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = _SESSION.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        subdomains = []
        for line in lines:
            if "," in line:
                host, _ip = line.split(",", 1)
                host = host.strip().lower()
                if host and host.endswith(domain) and host != domain:
                    subdomains.append(host)
        # Deduplicate
        subdomains = sorted(set(subdomains))
        return {
            "success": True,
            "data": {
                "domain": domain,
                "subdomains": subdomains,
                "subdomain_count": len(subdomains),
            },
        }
    except Exception as exc:
        logger.error("dns_dumpster_query(%s): %s", domain, exc)
        return {"success": False, "data": {"subdomains": []}, "error": str(exc)}


# ── Email Harvest (cleartext) ─────────────────────────────────────────────

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def email_harvest_cleartext(url: str) -> Dict:
    """
    Fetch a URL and extract visible email addresses from page source.
    Only processes public, unauthenticated pages.
    """
    try:
        resp = _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        emails_raw = _EMAIL_RE.findall(resp.text[:200000])
        # Deduplicate and lowercase
        emails = sorted({e.lower() for e in emails_raw})
        return {
            "success": True,
            "data": {
                "url": url,
                "emails": emails,
                "email_count": len(emails),
            },
        }
    except Exception as exc:
        logger.error("email_harvest_cleartext(%s): %s", url, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ── GitHub Dork Query Hints ────────────────────────────────────────────────

def github_dork_hints(domain: str, company: str = "") -> Dict:
    """
    Generate professional GitHub dork queries for secrets/code exposure.
    Returns ready-to-use search strings — NOT executing live searches
    (avoids GitHub API auth requirement) but consumable by the reporting agent.
    """
    keywords = [domain]
    if company:
        keywords.append(company.lower().replace(" ", "-"))
        keywords.append(company.lower().replace(" ", ""))

    dorks = []
    for kw in keywords:
        dorks.extend([
            f'"{kw}" password',
            f'"{kw}" api_key',
            f'"{kw}" secret',
            f'"{kw}" BEGIN RSA PRIVATE KEY',
            f'"{kw}" .env',
            f'"{kw}" db_password',
            f'"{kw}" aws_access_key_id',
            f'"{kw}" token',
            f'"{kw}" connection_string',
            f'"{kw}" smtp_password',
        ])

    return {
        "success": True,
        "data": {
            "dork_queries": dorks,
            "github_search_url": f"https://github.com/search?q={requests.utils.quote(dorks[0])}&type=code",
            "note": "Execute these searches manually at github.com/search — check for exposed credentials, API keys, and internal configs.",
        },
    }


# ── Google Dork Hints ──────────────────────────────────────────────────────

def google_dork_hints(domain: str) -> Dict:
    """
    Generate Google dork queries for attack surface expansion.
    """
    dorks = [
        f"site:{domain}",
        f"site:{domain} ext:php OR ext:asp OR ext:aspx",
        f"site:{domain} inurl:admin OR inurl:login OR inurl:panel",
        f"site:{domain} inurl:api",
        f"site:{domain} ext:sql OR ext:bak OR ext:env OR ext:log",
        f"site:{domain} inurl:upload OR inurl:backup",
        f'site:{domain} "index of"',
        f"inurl:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx",
        f'"@{domain}" email',
        f"site:pastebin.com OR site:github.com {domain}",
        f"site:{domain} \"Error\" OR \"Warning\" OR \"SQL syntax\"",
    ]
    return {
        "success": True,
        "data": {
            "dork_queries": dorks,
            "note": "Execute at google.com — look for exposed files, admin panels, and error messages.",
        },
    }


# ── Shodan CVE Lookup ──────────────────────────────────────────────────────

def cve_lookup_for_service(service: str, version: str) -> Dict:
    """
    Query cve.circl.lu (free, no auth) for known CVEs matching a service/version.
    """
    try:
        # Use CIRCL CVE API — rate limit friendly
        query = f"{service} {version}".strip()
        r = _SESSION.get(
            f"https://cve.circl.lu/api/search/{requests.utils.quote(service)}/{requests.utils.quote(version)}",
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            cves = r.json()
            if isinstance(cves, list):
                top = cves[:5]
                return {
                    "success": True,
                    "data": {
                        "service": service,
                        "version": version,
                        "cve_count": len(cves),
                        "top_cves": [
                            {
                                "id": c.get("id"),
                                "summary": c.get("summary", "")[:200],
                                "cvss": c.get("cvss"),
                            }
                            for c in top
                        ],
                    },
                }
        return {"success": False, "data": {}, "error": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"success": False, "data": {}, "error": str(exc)}


# ── JS Endpoint Extraction ─────────────────────────────────────────────────

def extract_js_endpoints(domain: str, max_pages: int = 3) -> Dict:
    """
    Crawl homepage and linked JS files to extract API endpoints.
    """
    endpoints = set()
    base_url = f"https://{domain}"
    visited = set()
    js_files = set()

    # Patterns for endpoint extraction from JS
    endpoint_patterns = [
        r'["\']((?:/api|/v[0-9]|/rest|/graphql)[/\w\-\.?=&%]+)["\']',
        r'url\s*[=:]\s*["\']([/\w\-\.?=&%]+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'(?:get|post|put|delete)\(["\']([/\w\-\.?=&%]+)["\']',
    ]

    def scrape_page(url: str) -> str:
        try:
            resp = _SESSION.get(url, timeout=_TIMEOUT, verify=False)
            return resp.text
        except Exception:
            return ""

    try:
        html = scrape_page(base_url)
        if html:
            # Find JS file references
            js_refs = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html)
            for js in js_refs[:10]:
                if js.startswith("http"):
                    js_files.add(js)
                elif js.startswith("/"):
                    js_files.add(f"{base_url}{js}")

            # Extract endpoints from HTML too
            for pattern in endpoint_patterns:
                for match in re.findall(pattern, html):
                    if len(match) > 3 and not match.startswith("//"):
                        endpoints.add(match)

        # Scrape JS files
        for js_url in list(js_files)[:max_pages]:
            if js_url in visited:
                continue
            visited.add(js_url)
            js_content = scrape_page(js_url)
            if js_content:
                for pattern in endpoint_patterns:
                    for match in re.findall(pattern, js_content):
                        if len(match) > 3 and not match.startswith("//"):
                            endpoints.add(match)

    except Exception as exc:
        logger.error("extract_js_endpoints(%s): %s", domain, exc)

    return {
        "success": True,
        "data": {
            "domain": domain,
            "js_files_found": list(js_files),
            "endpoints_extracted": sorted(list(endpoints))[:100],
            "endpoint_count": len(endpoints),
        },
    }


# ── Reverse WHOIS Lookup ───────────────────────────────────────────────────

def reverse_whois_lookup(registrant_email: str) -> Dict:
    """
    Find domains registered by the same email/org using viewdns.info free API.
    Useful for discovering org-owned domains not in scope yet.
    """
    try:
        url = f"https://viewdns.info/reversewhois/?q={requests.utils.quote(registrant_email)}&output=json"
        r = _SESSION.get(url, timeout=_TIMEOUT)
        # viewdns free endpoint returns HTML; parse table rows
        matches = re.findall(r'<td>([a-z0-9\-\.]+\.[a-z]{2,})</td>', r.text, re.IGNORECASE)
        domains = list({d.lower() for d in matches if "." in d})[:100]

        # Fallback: try jsonwhois (no auth needed for basic lookup)
        if not domains:
            r2 = _SESSION.get(
                f"https://api.whoapi.com/?domain={registrant_email.split('@')[-1]}&r=list",
                timeout=_TIMEOUT
            )
            if r2.status_code == 200:
                data2 = r2.json()
                domains = data2.get("list", [])[:50]

        return {
            "success": True,
            "data": {
                "query": registrant_email,
                "domains_found": domains,
                "total": len(domains),
                "note": "Domains registered by the same registrant — confirm scope before targeting",
            },
        }
    except Exception as exc:
        logger.error("reverse_whois_lookup(%s): %s", registrant_email, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ── Reverse IP Lookup ──────────────────────────────────────────────────────

def reverse_ip_lookup(ip_or_domain: str) -> Dict:
    """
    Find all domains hosted on the same IP using hackertarget.com API (free).
    Virtual hosting discovery — reveals co-tenants and forgotten subdomains.
    """
    try:
        # Resolve to IP first if domain given
        ip = ip_or_domain
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_or_domain):
            ip = socket.gethostbyname(ip_or_domain)

        r = _SESSION.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=_TIMEOUT,
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:30]:
            domains = [line.strip() for line in r.text.splitlines() if line.strip()]
            return {
                "success": True,
                "data": {
                    "ip": ip,
                    "query": ip_or_domain,
                    "domains_on_ip": domains[:200],
                    "total": len(domains),
                    "virtual_hosting": len(domains) > 1,
                },
            }
        return {"success": False, "data": {}, "error": r.text[:100]}
    except Exception as exc:
        logger.error("reverse_ip_lookup(%s): %s", ip_or_domain, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ── Google Analytics ID Lookup ─────────────────────────────────────────────

def google_analytics_id_lookup(domain: str) -> Dict:
    """
    Extract Google Analytics / Tag Manager IDs from a site's HTML,
    then search for other domains using the same tracking ID.
    Uses spyonweb.com (no auth) for reverse-GA correlation.
    """
    ga_ids: List[str] = []
    gtm_ids: List[str] = []
    shared_domains: dict = {}

    try:
        r = _SESSION.get(f"https://{domain}", timeout=_TIMEOUT, verify=False)
        html = r.text

        # Extract GA4 / UA IDs
        ga_matches = re.findall(r'G-[A-Z0-9]{8,12}|UA-\d{5,10}-\d{1,3}', html)
        ga_ids = list(set(ga_matches))

        # Extract GTM IDs
        gtm_matches = re.findall(r'GTM-[A-Z0-9]{6,8}', html)
        gtm_ids = list(set(gtm_matches))

        # Reverse lookup via spyonweb.com for each GA ID
        for ga_id in ga_ids[:3]:
            try:
                spy = _SESSION.get(
                    f"https://api.spyonweb.com/v1/analytics/{ga_id}?access_token=demo",
                    timeout=_TIMEOUT
                )
                if spy.status_code == 200:
                    result = spy.json()
                    items = result.get("result", {}).get("analytics", {}).get(ga_id, {}).get("items", {})
                    shared_domains[ga_id] = list(items.keys())[:50]
            except Exception:
                pass

        return {
            "success": True,
            "data": {
                "domain": domain,
                "ga_ids": ga_ids,
                "gtm_ids": gtm_ids,
                "shared_domains": shared_domains,
                "total_correlated": sum(len(v) for v in shared_domains.values()),
                "note": "Domains sharing the same GA ID may belong to the same organization",
            },
        }
    except Exception as exc:
        logger.error("google_analytics_id_lookup(%s): %s", domain, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ── Credential Signal Detection ────────────────────────────────────────────

def credential_signal_check(domain: str) -> Dict:
    """
    Check for credential-related signals using public sources:
      - HaveIBeenPwned API (query style — no account lookup)
      - GitHub code search for leaked credentials
      - Exposed .env / config file checks
    Passive and non-intrusive; does NOT enumerate individual accounts.
    """
    signals: List[Dict] = []

    try:
        # Check for exposed .env file (passive HEAD)
        for path in ["/.env", "/.env.local", "/.env.production", "/config.json", "/wp-config.php.bak"]:
            try:
                r = _SESSION.head(
                    f"https://{domain}{path}",
                    timeout=8, allow_redirects=False, verify=False,
                )
                if r.status_code == 200:
                    signals.append({
                        "type": "exposed_config",
                        "path": path,
                        "status_code": r.status_code,
                        "severity": "high",
                        "detail": f"Config file accessible: {path}",
                    })
            except Exception:
                pass

        # GitHub code search for domain mentions in secrets context
        try:
            for query_suffix in ["password", "secret", "api_key"]:
                gh_url = f"https://api.github.com/search/code?q={domain}+{query_suffix}&per_page=5"
                r = _SESSION.get(gh_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    count = data.get("total_count", 0)
                    if count > 0:
                        signals.append({
                            "type": "github_code_leak",
                            "query": f"{domain} {query_suffix}",
                            "result_count": count,
                            "severity": "medium",
                            "detail": f"Found {count} GitHub code results for '{domain} {query_suffix}'",
                            "items": [
                                {"repo": item.get("repository", {}).get("full_name", ""),
                                 "path": item.get("path", "")}
                                for item in data.get("items", [])[:5]
                            ],
                        })
                elif r.status_code == 403:
                    break  # rate limited
        except Exception:
            pass

        return {
            "success": True,
            "data": {
                "domain": domain,
                "signals": signals,
                "signal_count": len(signals),
                "has_critical": any(s.get("severity") == "high" for s in signals),
            },
        }
    except Exception as exc:
        logger.error("credential_signal_check(%s): %s", domain, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ── Service Metadata Enrichment ────────────────────────────────────────────

def service_metadata_enrich(service_banner: str, port: int = 0) -> Dict:
    """
    Enrich a service banner with CVE references and known vulnerability context.
    Input: raw banner string (e.g. 'Apache/2.4.49') and optional port.
    """
    try:
        product = ""
        version = ""
        # Extract product/version from common banner formats
        m = re.match(r'([A-Za-z][\w\-\.]*)\s*/?\s*([\d][\d\.]*\w*)', service_banner)
        if m:
            product = m.group(1)
            version = m.group(2)

        # Fetch CVE data from cve.circl.lu (public, no auth)
        cves: List[Dict] = []
        if product:
            try:
                search_q = f"{product} {version}".strip()
                r = _SESSION.get(
                    f"https://cve.circl.lu/api/search/{search_q}",
                    timeout=_TIMEOUT,
                )
                if r.status_code == 200:
                    data = r.json()
                    for cve in (data if isinstance(data, list) else data.get("results", []))[:10]:
                        cves.append({
                            "id": cve.get("id", ""),
                            "summary": (cve.get("summary") or "")[:200],
                            "cvss": cve.get("cvss", None),
                        })
            except Exception:
                pass

        return {
            "success": True,
            "data": {
                "banner": service_banner,
                "product": product,
                "version": version,
                "port": port,
                "known_cves": cves,
                "cve_count": len(cves),
            },
        }
    except Exception as exc:
        logger.error("service_metadata_enrich: %s", exc)
        return {"success": False, "data": {}, "error": str(exc)}
