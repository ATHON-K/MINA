"""
web_tools.py — Active web reconnaissance tools.

Covers the 12 active tools required by the assessment guide:
  ssl_tls_check          : TLS version, cipher, cert validity, grade
  check_http_headers     : Missing/misconfigured security headers
  detect_waf             : WAF identification (Cloudflare, Akamai, ModSec, ...)
  analyze_tech_stack     : CMS, framework, server, language detection
  parse_robots_sitemap   : robots.txt disallowed paths + sitemap URLs
  check_http_methods     : Dangerous HTTP methods (PUT, DELETE, TRACE, ...)
  find_cloud_assets      : S3 / Azure Blob / GCS bucket enumeration
  compute_favicon_hash   : Favicon MurmurHash3 for Shodan correlation
  enumerate_directories  : Dir/file bruteforce with built-in wordlists
  crawl_urls             : BFS URL discovery from a starting page
  grab_banner            : Raw TCP banner from a host:port
  discover_params        : Hidden GET/POST parameter discovery

All functions return: {"success": bool, "data": {...}, "error": str | None}
"""

import base64
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0; +https://github.com/)",
}
_TIMEOUT = 10

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSL / TLS Checker
# ─────────────────────────────────────────────────────────────────────────────

_WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}
_TLS_GRADES: Dict[str, str] = {
    "TLSv1.3": "A", "TLSv1.2": "B", "TLSv1.1": "C", "TLSv1.0": "D", "SSLv3": "F"
}


def ssl_tls_check(host: str, port: int = 443, timeout: int = 15, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Check SSL/TLS configuration for a host.
    Returns TLS version, cipher, cert info, days until expiry, issues, and grade.
    """
    options = options or {}
    port = options.get("port", port)
    timeout = options.get("timeout", timeout)
    issues: List[Dict[str, str]] = []
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "cert_expiry_days": None,
        "cert_issuer": None,
        "cert_subject": None,
        "san_domains": [],
        "self_signed": False,
        "wildcard_cert": False,
        "issues": issues,
        "grade": "Unknown",
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as s:
                tls_ver = s.version() or "Unknown"
                cipher = s.cipher()
                cipher_name = cipher[0] if cipher else "Unknown"
                cert_bin = s.getpeercert(binary_form=True)
                cert_der = s.getpeercert()

                result["tls_version"] = tls_ver
                result["cipher_suite"] = cipher_name

                # Check cipher strength
                if any(w in cipher_name.upper() for w in _WEAK_CIPHERS):
                    issues.append({
                        "type": "weak_cipher",
                        "severity": "High",
                        "detail": f"Weak cipher detected: {cipher_name}",
                    })

                # Check TLS version
                if tls_ver in ("TLSv1.0", "TLSv1.1"):
                    issues.append({
                        "type": "outdated_tls",
                        "severity": "High",
                        "detail": f"Outdated TLS version supported: {tls_ver}",
                    })
                elif tls_ver == "SSLv3":
                    issues.append({
                        "type": "sslv3",
                        "severity": "Critical",
                        "detail": "SSLv3 is supported — POODLE attack possible",
                    })

                # Certificate details
                if cert_der:
                    subject = dict(x[0] for x in cert_der.get("subject", []))
                    issuer = dict(x[0] for x in cert_der.get("issuer", []))
                    result["cert_subject"] = subject.get("commonName", "")
                    result["cert_issuer"] = issuer.get("commonName", "")
                    result["self_signed"] = (
                        subject.get("commonName") == issuer.get("commonName")
                    )
                    if result["self_signed"]:
                        issues.append({
                            "type": "self_signed",
                            "severity": "High",
                            "detail": "Self-signed certificate — browser will warn users",
                        })

                    # SAN
                    san_list: List[str] = []
                    for san_type, san_val in cert_der.get("subjectAltName", []):
                        if san_type == "DNS":
                            san_list.append(san_val)
                            if san_val.startswith("*."):
                                result["wildcard_cert"] = True
                    result["san_domains"] = san_list

                    # Expiry
                    not_after = cert_der.get("notAfter", "")
                    if not_after:
                        try:
                            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp_dt - datetime.now(timezone.utc)).days
                            result["cert_expiry_days"] = days_left
                            if days_left < 0:
                                issues.append({
                                    "type": "expired_cert",
                                    "severity": "Critical",
                                    "detail": f"Certificate expired {abs(days_left)} days ago",
                                })
                            elif days_left < 30:
                                issues.append({
                                    "type": "expiring_soon",
                                    "severity": "Medium",
                                    "detail": f"Certificate expires in {days_left} days",
                                })
                        except Exception:
                            pass

        # Determine grade
        grade = _TLS_GRADES.get(result["tls_version"], "C")
        if any(i["severity"] == "Critical" for i in issues):
            grade = "F"
        elif any(i["severity"] == "High" for i in issues):
            grade = min(grade, "D") if grade not in ("F",) else "F"
        result["grade"] = grade

        return {"success": True, "data": result, "error": None}

    except ssl.SSLError as exc:
        return {"success": False, "data": result, "error": f"SSL error: {exc}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"success": False, "data": result, "error": str(exc)}
    except Exception as exc:
        logger.error("ssl_tls_check(%s:%d): %s", host, port, exc)
        return {"success": False, "data": result, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 2. HTTP Security Headers Checker
# ─────────────────────────────────────────────────────────────────────────────

_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "recommendation": "Add a strict Content-Security-Policy header to prevent XSS",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Add Permissions-Policy to restrict browser feature access",
    },
}

_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "Via"]


def check_http_headers(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Analyse security headers of a URL.
    Returns present headers, missing/misconfigured issues, score and grade.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(
            url,
            headers=_HEADERS,
            timeout=_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
        headers_present = {k: v for k, v in resp.headers.items()}
        final_url = resp.url

        issues: List[Dict] = []
        # Check required security headers
        for header, meta in _SECURITY_HEADERS.items():
            val = headers_present.get(header)
            if not val:
                issues.append({
                    "header": header,
                    "present": False,
                    "severity": meta["severity"],
                    "current_value": None,
                    "recommendation": meta["recommendation"],
                })
            else:
                # CSP unsafe-inline / unsafe-eval
                if header == "Content-Security-Policy":
                    if "unsafe-inline" in val or "unsafe-eval" in val:
                        issues.append({
                            "header": header,
                            "present": True,
                            "severity": "Medium",
                            "current_value": val,
                            "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP",
                        })
                # HSTS max-age check
                if header == "Strict-Transport-Security":
                    match = re.search(r"max-age=(\d+)", val)
                    if match and int(match.group(1)) < 31536000:
                        issues.append({
                            "header": header,
                            "present": True,
                            "severity": "Low",
                            "current_value": val,
                            "recommendation": "Increase HSTS max-age to at least 31536000 (1 year)",
                        })

        # Info leaking headers
        leaking = []
        for lh in _LEAK_HEADERS:
            val = headers_present.get(lh)
            if val:
                leaking.append({"header": lh, "value": val})
                issues.append({
                    "header": lh,
                    "present": True,
                    "severity": "Low",
                    "current_value": val,
                    "recommendation": f"Remove or genericise '{lh}' header to avoid version disclosure",
                })

        # Score: start at 100, -10 per High, -5 per Medium, -2 per Low
        score = 100
        for issue in issues:
            if issue.get("severity") == "High":
                score -= 10
            elif issue.get("severity") == "Medium":
                score -= 5
            elif issue.get("severity") == "Low":
                score -= 2
        score = max(0, score)
        grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else "F"

        return {
            "success": True,
            "data": {
                "url": url,
                "final_url": final_url,
                "status_code": resp.status_code,
                "headers_found": headers_present,
                "issues": issues,
                "leaking_headers": leaking,
                "score": f"{score}/100",
                "grade": grade,
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("check_http_headers(%s): %s", url, exc)
        return {"success": False, "data": {}, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 3. WAF Detector
# ─────────────────────────────────────────────────────────────────────────────

_WAF_SIGNATURES = [
    {"product": "Cloudflare",   "headers": ["cf-ray", "cf-cache-status"],   "cookies": ["__cfduid", "__cf_bm"], "server": ["cloudflare"]},
    {"product": "AWS WAF",      "headers": ["x-amzn-requestid", "x-amz-cf-id"], "cookies": [], "server": []},
    {"product": "Akamai",       "headers": ["x-akamai-transformed", "x-check-cacheable"], "cookies": ["akacd_", "aka-"], "server": ["akamaighost"]},
    {"product": "Sucuri",       "headers": ["x-sucuri-id", "x-sucuri-cache"], "cookies": [], "server": ["sucuri"]},
    {"product": "Imperva/Incapsula", "headers": ["x-iinfo", "x-cdn"], "cookies": ["incap_ses", "visid_incap"], "server": []},
    {"product": "F5 BIG-IP ASM", "headers": ["x-wa-info"], "cookies": ["TS"], "server": ["bigip"]},
    {"product": "Barracuda",    "headers": ["barra_counter_session"], "cookies": ["barra_counter_session"], "server": []},
    {"product": "ModSecurity",  "headers": ["x-mod-security"], "cookies": [], "server": ["mod_security", "modsecurity"]},
    {"product": "Wordfence",    "headers": [], "cookies": [], "server": [], "body_keywords": ["generated by wordfence"]},
    {"product": "Fortinet FortiWeb", "headers": ["x-powered-by-fortiweb"], "cookies": ["cookiesession1"], "server": ["fortiweb"]},
]


def detect_waf(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Detect WAF by analysing headers, cookies, server strings, and body.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    detected: List[Dict] = []
    evidence: List[str] = []

    try:
        resp_normal = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, verify=False, allow_redirects=True)
        # Probe with attack payload
        resp_attack = requests.get(
            url + "?id=1+AND+1=1--",
            headers=_HEADERS,
            timeout=_TIMEOUT,
            verify=False,
            allow_redirects=False,
        )

        resp_headers_lower = {k.lower(): v.lower() for k, v in resp_normal.headers.items()}
        cookie_str = " ".join(
            c.name.lower() + "=" + c.value.lower()
            for c in resp_normal.cookies
        )
        server_val = resp_headers_lower.get("server", "")
        body_lower = (resp_normal.text or "").lower()[:3000]

        for sig in _WAF_SIGNATURES:
            matched = False
            ev: List[str] = []
            for h in sig.get("headers", []):
                if h.lower() in resp_headers_lower:
                    matched = True
                    ev.append(f"header '{h}' found")
            for c in sig.get("cookies", []):
                if c.lower() in cookie_str:
                    matched = True
                    ev.append(f"cookie pattern '{c}' found")
            for s in sig.get("server", []):
                if s.lower() in server_val:
                    matched = True
                    ev.append(f"server header contains '{s}'")
            for bk in sig.get("body_keywords", []):
                if bk.lower() in body_lower:
                    matched = True
                    ev.append(f"body contains '{bk}'")
            if matched:
                detected.append({"product": sig["product"], "evidence": ev})
                evidence.extend(ev)

        # Generic check: attack payload returns 403/406/429 while normal is 200
        if resp_attack.status_code in (403, 406, 429, 503) and resp_normal.status_code == 200:
            evidence.append(f"Attack payload returned {resp_attack.status_code} vs normal {resp_normal.status_code}")
            if not detected:
                detected.append({"product": "Generic WAF", "evidence": evidence})

        waf_detected = bool(detected)
        primary = detected[0]["product"] if detected else None
        confidence = "High" if len(evidence) >= 3 else "Medium" if len(evidence) >= 1 else "Low"

        return {
            "success": True,
            "data": {
                "url": url,
                "waf_detected": waf_detected,
                "waf_product": primary,
                "all_detected": detected,
                "confidence": confidence,
                "evidence": evidence,
                "bypass_suggestions": [
                    "Use case variation in payload",
                    "Encode payload with URL/Base64",
                    "Split payload across parameters",
                    "Use IPv6 address if available",
                ] if waf_detected else [],
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("detect_waf(%s): %s", url, exc)
        return {"success": False, "data": {"waf_detected": False}, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 4. Technology Stack Analyzer
# ─────────────────────────────────────────────────────────────────────────────

def analyze_tech_stack(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Fingerprint the technology stack of a web application from HTTP response.
    Detects: CMS, server, framework, language, CDN, JS libraries.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    tech: Dict[str, Any] = {
        "cms": None,
        "server": None,
        "framework": None,
        "language": None,
        "cdn": None,
        "js_libraries": [],
        "analytics": [],
        "meta_generator": None,
        "raw_headers": {},
    }

    _CMS_PATTERNS = [
        ("WordPress", [r"/wp-content/", r"/wp-includes/", r"wp-login"]),
        ("Drupal",    [r"sites/default/", r"/misc/drupal.js", r"Drupal.settings"]),
        ("Joomla",    [r"/components/com_", r"joomla", r"/media/jui/"]),
        ("Magento",   [r"/skin/frontend/", r"Mage.Cookies", r"/js/mage/"]),
        ("Shopify",   [r"cdn.shopify.com", r"Shopify.theme"]),
        ("Django",    [r"csrfmiddlewaretoken", r"django"]),
        ("Laravel",   [r"laravel_session", r"_token"]),
        ("Rails",     [r"_rails_session", r"/assets/application-"]),
        ("Express",   [r"X-Powered-By.*Express"]),
        ("Next.js",   [r"__NEXT_DATA__", r"/_next/static/"]),
        ("React",     [r"__react", r"react-root", r"data-reactroot"]),
        ("Vue",       [r"__vue", r"data-v-"]),
        ("Angular",   [r"ng-version", r"ng-app"]),
    ]
    _JS_LIBS = [
        ("jQuery",     r"jquery(?:\.min)?\.js"),
        ("Bootstrap",  r"bootstrap(?:\.min)?\.js"),
        ("Lodash",     r"lodash(?:\.min)?\.js"),
        ("Axios",      r"axios(?:\.min)?\.js"),
        ("Moment.js",  r"moment(?:\.min)?\.js"),
        ("D3.js",      r"d3(?:\.min)?\.js"),
    ]
    _ANALYTICS = [
        ("Google Analytics", r"google-analytics\.com|gtag\("),
        ("Google Tag Manager", r"googletagmanager\.com"),
        ("Facebook Pixel",   r"connect\.facebook\.net"),
        ("Hotjar",           r"hotjar\.com"),
        ("Mixpanel",         r"mixpanel\.com"),
    ]

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, verify=False, allow_redirects=True)
        body = resp.text[:50000]
        tech["raw_headers"] = dict(resp.headers)
        tech["server"] = resp.headers.get("Server", "")
        tech["framework"] = resp.headers.get("X-Powered-By", "") or resp.headers.get("X-Framework", "")

        # Language hints from headers
        x_powered = resp.headers.get("X-Powered-By", "").lower()
        if "php" in x_powered:
            tech["language"] = "PHP"
        elif "asp.net" in x_powered:
            tech["language"] = "ASP.NET"
        elif "ruby" in x_powered:
            tech["language"] = "Ruby"
        elif "python" in x_powered or "django" in x_powered or "flask" in x_powered:
            tech["language"] = "Python"

        # CDN detection
        via = resp.headers.get("Via", "").lower()
        cdn_hints = {
            "cloudflare": resp.headers.get("cf-ray"),
            "aws_cloudfront": resp.headers.get("x-amz-cf-id"),
            "akamai": resp.headers.get("x-akamai-transformed"),
            "fastly": resp.headers.get("x-fastly-request-id"),
        }
        for cdn_name, cdn_val in cdn_hints.items():
            if cdn_val:
                tech["cdn"] = cdn_name
                break

        # CMS / framework detection
        for cms_name, patterns in _CMS_PATTERNS:
            if any(re.search(p, body, re.IGNORECASE) for p in patterns):
                tech["cms"] = cms_name
                break

        # JS library detection
        for lib_name, pattern in _JS_LIBS:
            if re.search(pattern, body, re.IGNORECASE):
                tech["js_libraries"].append(lib_name)

        # Analytics
        for an_name, pattern in _ANALYTICS:
            if re.search(pattern, body, re.IGNORECASE):
                tech["analytics"].append(an_name)

        # Meta generator
        meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if not meta_match:
            meta_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.IGNORECASE)
        if meta_match:
            tech["meta_generator"] = meta_match.group(1)

        return {"success": True, "data": tech, "error": None}

    except Exception as exc:
        logger.error("analyze_tech_stack(%s): %s", url, exc)
        return {"success": False, "data": tech, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Robots.txt & Sitemap Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_robots_sitemap(base_url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Fetch and parse robots.txt, then follow sitemap URLs.
    Returns disallowed paths (potential hidden endpoints) and sitemap URLs.
    """
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    result: Dict[str, Any] = {
        "disallowed": [],
        "allowed": [],
        "sitemaps": [],
        "sitemap_urls": [],
        "interesting_paths": [],
        "robots_found": False,
        "sitemap_found": False,
    }

    _INTERESTING_KEYWORDS = [
        "admin", "login", "wp-admin", "dashboard", "api", "internal",
        "staging", "dev", "test", "backup", "secret", "config", "private",
        "phpinfo", ".git", ".env", "swagger", "graphql",
    ]

    # Fetch robots.txt
    try:
        r = requests.get(f"{origin}/robots.txt", headers=_HEADERS, timeout=_TIMEOUT, verify=False)
        if r.status_code == 200 and "text" in r.headers.get("Content-Type", ""):
            result["robots_found"] = True
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        result["disallowed"].append(path)
                        if any(kw in path.lower() for kw in _INTERESTING_KEYWORDS):
                            result["interesting_paths"].append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["allowed"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    if sm_url:
                        result["sitemaps"].append(sm_url)
    except Exception as exc:
        logger.debug("robots.txt fetch failed for %s: %s", origin, exc)

    # If no sitemap from robots.txt, try /sitemap.xml
    if not result["sitemaps"]:
        result["sitemaps"].append(f"{origin}/sitemap.xml")

    # Parse sitemaps (first 3 only)
    import xml.etree.ElementTree as ET
    for sm_url in result["sitemaps"][:3]:
        try:
            r = requests.get(sm_url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)
            if r.status_code == 200:
                result["sitemap_found"] = True
                try:
                    root = ET.fromstring(r.content)
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    for loc in root.findall(".//sm:loc", ns):
                        url_val = (loc.text or "").strip()
                        if url_val:
                            result["sitemap_urls"].append(url_val)
                            if any(kw in url_val.lower() for kw in _INTERESTING_KEYWORDS):
                                result["interesting_paths"].append(url_val)
                except ET.ParseError:
                    # Try plain-text extraction
                    for line in r.text.splitlines():
                        if line.strip().startswith("http"):
                            result["sitemap_urls"].append(line.strip())
        except Exception as exc:
            logger.debug("sitemap fetch failed: %s", exc)

    result["sitemap_urls"] = result["sitemap_urls"][:500]
    result["interesting_paths"] = list(set(result["interesting_paths"]))[:100]
    return {"success": True, "data": result, "error": None}


# ─────────────────────────────────────────────────────────────────────────────
# 6. HTTP Method Checker
# ─────────────────────────────────────────────────────────────────────────────

_DANGEROUS_METHODS = {
    "PUT":     ("High",   "Can upload arbitrary files to server"),
    "DELETE":  ("High",   "Can delete files/resources on server"),
    "TRACE":   ("Medium", "Cross-Site Tracing (XST) attack vector"),
    "CONNECT": ("Medium", "Can be abused as HTTP proxy tunnel"),
    "DEBUG":   ("High",   "Microsoft IIS debug mode / information disclosure"),
    "PATCH":   ("Low",    "Partial resource modification"),
}
_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT", "DEBUG"]


def check_http_methods(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Test which HTTP methods are accepted by the server.
    Flags dangerous methods: PUT, DELETE, TRACE, CONNECT, DEBUG.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    methods_allowed: List[str] = []
    dangerous_found: List[Dict] = []
    methods_tested: List[Dict] = []

    # Try OPTIONS first to get Allow header
    options_allow: Optional[str] = None
    try:
        r = requests.options(url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)
        options_allow = r.headers.get("Allow", "")
    except Exception:
        pass

    for method in _ALL_METHODS:
        try:
            r = requests.request(
                method, url,
                headers=_HEADERS,
                timeout=_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            enabled = r.status_code not in (405, 501, 400, 403)
            entry = {"method": method, "status_code": r.status_code, "enabled": enabled}
            if enabled:
                methods_allowed.append(method)
            if enabled and method in _DANGEROUS_METHODS:
                sev, reason = _DANGEROUS_METHODS[method]
                entry["risk"] = reason
                entry["severity"] = sev
                dangerous_found.append(entry)
            methods_tested.append(entry)
        except Exception as exc:
            methods_tested.append({"method": method, "status_code": None, "enabled": False, "error": str(exc)})

    return {
        "success": True,
        "data": {
            "url": url,
            "options_header": options_allow,
            "methods_tested": methods_tested,
            "methods_allowed": methods_allowed,
            "dangerous_methods_found": dangerous_found,
            "risk_summary": (
                f"Found {len(dangerous_found)} dangerous method(s): "
                f"{[d['method'] for d in dangerous_found]}"
                if dangerous_found
                else "No dangerous methods detected"
            ),
        },
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 7. Cloud Asset Finder
# ─────────────────────────────────────────────────────────────────────────────

def find_cloud_assets(domain: str, timeout: int = 6, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Enumerate common S3 buckets, Azure blobs, and GCS buckets for a domain/org.
    Uses HEAD requests — does NOT read bucket contents.
    """
    company = domain.split(".")[0]
    patterns = list({
        company, f"{company}-backup", f"{company}-dev", f"{company}-staging",
        f"{company}-prod", f"{company}-data", f"{company}-assets",
        f"{company}-media", f"{company}-uploads", f"{company}-files",
        f"{company}-static", f"{company}-public", f"{company}-private",
        f"backup-{company}", f"dev-{company}", f"www-{company}",
        domain.replace(".", "-"), domain.replace(".", ""),
    })

    s3_found: List[Dict] = []
    azure_found: List[Dict] = []
    gcs_found: List[Dict] = []

    def _probe(url: str, bucket_type: str, name: str) -> Optional[Dict]:
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=False, verify=False)
            if r.status_code in (200, 301, 302, 307, 403):
                status = (
                    "PUBLIC"            if r.status_code == 200
                    else "REDIRECT"     if r.status_code in (301, 302, 307)
                    else "EXISTS_PRIVATE"
                )
                return {
                    "name": name,
                    "url": url,
                    "status": status,
                    "http_code": r.status_code,
                    "type": bucket_type,
                    "risk": "Critical" if status == "PUBLIC" else "Medium",
                }
        except Exception:
            pass
        return None

    jobs: List[tuple] = []
    for p in patterns:
        jobs.append((f"https://{p}.s3.amazonaws.com",             "S3",    p))
        jobs.append((f"https://s3.amazonaws.com/{p}",             "S3",    p))
        jobs.append((f"https://{p}.blob.core.windows.net",         "Azure", p))
        jobs.append((f"https://storage.googleapis.com/{p}",        "GCS",   p))
        # DigitalOcean Spaces
        jobs.append((f"https://{p}.nyc3.digitaloceanspaces.com",   "DO",    p))
        jobs.append((f"https://{p}.ams3.digitaloceanspaces.com",   "DO",    p))
        jobs.append((f"https://{p}.sgp1.digitaloceanspaces.com",   "DO",    p))
        # Alibaba Cloud OSS
        jobs.append((f"https://{p}.oss-cn-hangzhou.aliyuncs.com",  "Alibaba", p))
        jobs.append((f"https://{p}.oss-us-east-1.aliyuncs.com",    "Alibaba", p))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe, url, btype, name): (url, btype, name) for url, btype, name in jobs}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                if res["type"] == "S3":
                    s3_found.append(res)
                elif res["type"] == "Azure":
                    azure_found.append(res)
                elif res["type"] in ("DO", "Alibaba"):
                    gcs_found.append(res)  # reuse gcs_found bucket for other providers
                else:
                    gcs_found.append(res)

    public_count = sum(
        1 for b in s3_found + azure_found + gcs_found if b.get("status") == "PUBLIC"
    )

    return {
        "success": True,
        "data": {
            "domain": domain,
            "s3_buckets": s3_found,
            "azure_blobs": azure_found,
            "gcs_buckets": [b for b in gcs_found if b["type"] == "GCS"],
            "do_spaces": [b for b in gcs_found if b["type"] == "DO"],
            "alibaba_oss": [b for b in gcs_found if b["type"] == "Alibaba"],
            "found_buckets": s3_found + azure_found + gcs_found,
            "total_found": len(s3_found) + len(azure_found) + len(gcs_found),
            "public_buckets": public_count,
            "critical_finding": public_count > 0,
        },
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 8. Favicon Hash (MurmurHash3)
# ─────────────────────────────────────────────────────────────────────────────

def compute_favicon_hash(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Compute MurmurHash3 of a site's favicon for Shodan correlation.
    Shodan query: http.favicon.hash:<hash>
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    base_url = url.rstrip("/")

    # Try mmh3 library; graceful degradation if missing
    try:
        import mmh3  # type: ignore
        _has_mmh3 = True
    except ImportError:
        _has_mmh3 = False
        logger.warning("mmh3 not installed — install with: pip install mmh3")

    favicon_url = f"{base_url}/favicon.ico"

    # If /favicon.ico fails, hunt in HTML <link>
    try:
        r = requests.get(favicon_url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)
        if r.status_code != 200:
            html_r = requests.get(base_url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)
            match = re.search(
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                html_r.text, re.IGNORECASE,
            )
            if match:
                href = match.group(1)
                favicon_url = href if href.startswith("http") else urljoin(base_url + "/", href.lstrip("/"))
                r = requests.get(favicon_url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)

        if r.status_code == 200 and r.content:
            favicon_b64 = base64.encodebytes(r.content).decode("utf-8")
            favicon_hash = mmh3.hash(favicon_b64) if _has_mmh3 else None
            return {
                "success": True,
                "data": {
                    "url": url,
                    "favicon_url": favicon_url,
                    "hash": favicon_hash,
                    "size_bytes": len(r.content),
                    "shodan_query": f"http.favicon.hash:{favicon_hash}" if favicon_hash else None,
                    "shodan_search_url": (
                        f"https://www.shodan.io/search?query=http.favicon.hash:{favicon_hash}"
                        if favicon_hash else None
                    ),
                    "mmh3_available": _has_mmh3,
                },
                "error": None,
            }
        return {
            "success": False,
            "data": {"url": url, "hash": None},
            "error": f"Favicon not found (HTTP {r.status_code})",
        }
    except Exception as exc:
        logger.error("compute_favicon_hash(%s): %s", url, exc)
        return {"success": False, "data": {"url": url, "hash": None}, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# 9. Directory / File Enumerator
# ─────────────────────────────────────────────────────────────────────────────

_WORDLISTS = {
    "small": [
        "admin", "login", "dashboard", "config", "backup", "api", "swagger",
        "graphql", "phpinfo", ".env", ".git", ".git/HEAD", ".htaccess",
        "robots.txt", "sitemap.xml", "wp-admin", "wp-config.php", "wp-login.php",
        "administrator", "panel", "console", "manager", "management",
        "status", "health", "metrics", "debug", "test", "staging",
        "uploads", "files", "images", "static", "assets", "media",
        "include", "includes", "lib", "libs", "vendor",
        "phpmyadmin", "adminer", "db", "database",
        "server-status", "server-info",
        "crossdomain.xml", "security.txt", ".well-known/security.txt",
        "CHANGELOG", "README", "LICENSE", "package.json", "composer.json",
        "Dockerfile", "docker-compose.yml", ".dockerignore",
        "application.yml", "application.properties", "web.config",
        "backup.zip", "backup.tar.gz", "dump.sql",
    ],
    "medium": [],  # populated below
    "large":  [],
}

# Extend medium with 150 additional paths
_MEDIUM_EXTRA = [
    "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "api/users", "api/admin", "api/auth", "api/token",
    "auth", "auth/login", "authenticate", "oauth", "oauth2", "signin",
    "register", "signup", "logout", "password", "forgot-password", "reset-password",
    "user", "users", "profile", "account", "settings", "preferences",
    "admin/login", "admin/dashboard", "admin/config", "admin/users",
    "admin/settings", "admin/backup", "admin/update", "admin/install",
    "wp-json", "xmlrpc.php", "wp-includes/wlwmanifest.xml",
    "install", "install.php", "setup", "setup.php", "installer",
    "cgi-bin", "cgi-bin/printenv", "cgi-bin/test-cgi",
    "old", "tmp", "temp", "cache", "logs", "log",
    "etc/passwd", "proc/self/environ",
    ".svn", ".hg", ".bzr", ".DS_Store",
    "favicon.ico", "apple-touch-icon.png", "browserconfig.xml",
    "css", "js", "fonts", "img",
    "search", "download", "upload", "export", "import",
    "contact", "about", "help", "support", "terms", "privacy",
    "shop", "store", "cart", "checkout", "order", "product",
    "news", "blog", "post", "article", "feed", "rss",
    "forum", "community", "wiki", "docs", "documentation",
    "app", "application", "apps",
    "v1", "v2", "v3",
    "rest", "graphql-playground", "graphql-explorer",
    "health-check", "ping", "uptime", "version",
    "monitor", "monitoring", "analytics", "stats", "statistics",
    "report", "reports", "dashboard/reports",
    "jenkins", "jira", "confluence", "gitlab", "github",
    "kibana", "grafana", "prometheus", "elastic", "elasticsearch",
    "redis", "mongo", "mysql", "postgres",
    "smtp", "mail", "webmail", "autodiscover", "owa",
    "calendar", "contacts", "tasks",
    "crm", "erp", "payroll", "finance",
    "cdn", "s3", "bucket",
    "checkout/onepage", "checkout/cart", "onepagecheckout",
]
_WORDLISTS["medium"] = _WORDLISTS["small"] + _MEDIUM_EXTRA
_WORDLISTS["large"] = _WORDLISTS["medium"] + [
    f"page{i}" for i in range(1, 11)
] + [f"user/{i}" for i in range(1, 6)] + [
    "archive", "archives", "old", "bak", "bkp",
    "src", "source", "sources", "code",
    "conf", "conf.d", "sites-enabled", "sites-available",
    "vhost", "vhosts", "virtual",
]

_WORDLIST_FILE_MAP = {
    "small": "directories_small.txt",
    "medium": "directories_medium.txt",
    "large": "directories_medium.txt",
}


def _load_directory_wordlist_from_file(wordlist_type: str) -> List[str]:
    """Load directory wordlist from backend/wordlists, fallback handled by caller."""
    filename = _WORDLIST_FILE_MAP.get(wordlist_type, _WORDLIST_FILE_MAP["small"])
    wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")
    path = os.path.join(wordlist_dir, filename)

    if not os.path.exists(path):
        return []

    loaded: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                loaded.append(line.lstrip("/"))
    except Exception as exc:
        logger.warning("Failed reading directory wordlist file %s: %s", path, exc)
        return []

    if wordlist_type == "large":
        # Extend "large" above medium file content using the built-in large extras.
        medium_built_in = set(_WORDLISTS["medium"])
        large_extra = [item for item in _WORDLISTS["large"] if item not in medium_built_in]
        loaded = loaded + large_extra

    # Deduplicate preserving order
    deduped: List[str] = []
    seen: set = set()
    for p in loaded:
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)
    return deduped


def enumerate_directories(
    base_url: str,
    wordlist_type: str = "small",
    max_workers: int = 10,
    rate_limit: float = 0.1,
    options: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Directory/file bruteforce using file-based wordlists with built-in fallback.
    Returns found paths with status codes.
    Uses build_dirs_config() for rich options support.
    """
    from tools.command_builders import build_dirs_config

    cfg = build_dirs_config(options or {})
    # Legacy params can override if not present in options
    wordlist_type = (options or {}).get("wordlist_profile",
                     (options or {}).get("wordlist_type", wordlist_type))
    max_workers = cfg["threads"]
    rate_limit = cfg["rate_limit"]
    extensions = cfg["extensions"]
    filter_codes = cfg["filter_codes"]
    match_codes = cfg["match_codes"]
    req_timeout = cfg["timeout"]

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    file_wordlist = _load_directory_wordlist_from_file(wordlist_type)
    if file_wordlist:
        wordlist = file_wordlist
        wordlist_source = f"file:{_WORDLIST_FILE_MAP.get(wordlist_type, 'directories_small.txt')}"
    else:
        wordlist = _WORDLISTS.get(wordlist_type, _WORDLISTS["small"])
        wordlist_source = f"builtin:{wordlist_type}"

    # Expand extensions: for each path, also try path.ext
    expanded = list(wordlist)
    if extensions:
        for path in wordlist:
            for ext in extensions:
                expanded.append(f"{path}.{ext}")
        wordlist = expanded

    found: List[Dict] = []
    redirects: List[Dict] = []
    checked = 0

    def probe(path: str) -> Optional[Dict]:
        url = f"{base_url}/{path}"
        try:
            r = requests.get(
                url, headers=_HEADERS, timeout=req_timeout,
                allow_redirects=False, verify=False,
            )
            time.sleep(rate_limit)
            sc = r.status_code
            # Apply match/filter codes
            if match_codes and sc not in match_codes:
                return None
            if sc in filter_codes:
                return None
            if sc in (200, 201, 401, 403):
                return {
                    "path": f"/{path}",
                    "url": url,
                    "status": sc,
                    "size": int(r.headers.get("Content-Length", len(r.content))),
                    "note": (
                        "Found & accessible"      if sc == 200
                        else "Found (Forbidden)"  if sc == 403
                        else "Found (Auth required)"
                    ),
                }
            if sc in (301, 302, 307, 308):
                return {
                    "path": f"/{path}",
                    "url": url,
                    "status": sc,
                    "redirect_to": r.headers.get("Location", ""),
                    "is_redirect": True,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(probe, p): p for p in wordlist}
        for fut in concurrent.futures.as_completed(future_map):
            checked += 1
            res = fut.result()
            if res:
                if res.get("is_redirect"):
                    redirects.append(res)
                else:
                    found.append(res)

    return {
        "success": True,
        "data": {
            "base_url": base_url,
            "wordlist_used": wordlist_type,
            "wordlist_source": wordlist_source,
            "total_checked": checked,
            "found": found,
            "redirects": redirects,
            "interesting": [f for f in found if f.get("status") in (200, 401)],
        },
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 10. URL Crawler
# ─────────────────────────────────────────────────────────────────────────────

def crawl_urls(start_url: str, max_pages: int = 50, depth: int = 2, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    BFS URL crawler — discovers internal links starting from start_url.
    Stays within the same domain. Returns all discovered URLs.
    Uses build_crawl_config() for rich options support.
    """
    from tools.command_builders import build_crawl_config

    try:
        from bs4 import BeautifulSoup  # type: ignore
    except ImportError:
        return {"success": False, "data": {"urls": []}, "error": "beautifulsoup4 not installed"}

    cfg = build_crawl_config(options or {})
    max_pages = cfg["max_pages"]
    depth = cfg["depth"]
    same_host_only = cfg["same_host_only"]
    extract_forms = cfg["extract_forms"]
    extract_params = cfg["extract_params"]
    include_js = cfg["include_js_links"]
    req_timeout = cfg["timeout"]

    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    parsed_start = urlparse(start_url)
    base_domain = parsed_start.netloc

    visited: set = set()
    queue: List[tuple] = [(start_url, 0)]
    all_urls: List[str] = []
    external_links: List[str] = []
    forms_found: List[Dict] = []
    params_found: List[Dict] = []

    sess = requests.Session()
    sess.headers.update(_HEADERS)

    while queue and len(visited) < max_pages:
        current_url, current_depth = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            r = sess.get(current_url, timeout=req_timeout, verify=False, allow_redirects=True)
            all_urls.append(current_url)

            if "text/html" not in r.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            # Collect forms
            if extract_forms:
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = [inp.get("name", "") for inp in form.find_all("input") if inp.get("name")]
                    forms_found.append({
                        "page": current_url,
                        "action": urljoin(current_url, action) if action else current_url,
                        "method": method,
                        "inputs": inputs,
                    })

            # Extract query params from discovered URLs
            if extract_params:
                from urllib.parse import parse_qs
                parsed = urlparse(current_url)
                if parsed.query:
                    params_found.append({
                        "url": current_url,
                        "params": list(parse_qs(parsed.query).keys()),
                    })

            if current_depth >= depth:
                continue

            # Standard link extraction
            for tag in soup.find_all(["a", "link", "script", "img", "form"]):
                href = tag.get("href") or tag.get("src") or tag.get("action") or ""
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                abs_url = urljoin(current_url, href).split("#")[0].split("?")[0]
                parsed_abs = urlparse(abs_url)
                if not same_host_only or parsed_abs.netloc == base_domain:
                    if abs_url not in visited:
                        queue.append((abs_url, current_depth + 1))
                elif parsed_abs.netloc != base_domain:
                    if abs_url not in external_links:
                        external_links.append(abs_url)

            # JS-embedded link extraction
            if include_js and current_depth < depth:
                import re as _re
                for script in soup.find_all("script"):
                    text = script.string or ""
                    for match in _re.findall(r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']', text):
                        js_url = urljoin(current_url, match)
                        parsed_js = urlparse(js_url)
                        if (not same_host_only or parsed_js.netloc == base_domain) and js_url not in visited:
                            queue.append((js_url, current_depth + 1))

        except Exception as exc:
            logger.debug("crawl_urls: failed to fetch %s: %s", current_url, exc)

    return {
        "success": True,
        "data": {
            "start_url": start_url,
            "total_crawled": len(visited),
            "all_urls": all_urls[:500],
            "forms": forms_found[:50],
            "params": params_found[:100],
            "external_links": external_links[:100],
            "interesting_urls": [
                u for u in all_urls
                if any(kw in u.lower() for kw in ["admin", "login", "api", "upload", "config", "backup", ".php"])
            ][:50],
        },
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 11. Banner Grabber
# ─────────────────────────────────────────────────────────────────────────────

def grab_banner(host: str, port: int, timeout: int = 5, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Grab raw TCP service banner from host:port using socket.
    Sends a lightweight probe and reads up to 1 KB.
    """
    probe = b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            try:
                s.sendall(probe)
            except Exception:
                pass
            s.settimeout(timeout)
            data = b""
            try:
                while len(data) < 1024:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass

        banner = data.decode("utf-8", errors="replace").strip()
        service_guess = _guess_service_from_banner(banner, port)

        return {
            "success": True,
            "data": {
                "host": host,
                "port": port,
                "banner": banner[:500],
                "service_guess": service_guess,
                "banner_length": len(banner),
            },
            "error": None,
        }
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        return {"success": False, "data": {"host": host, "port": port, "banner": ""}, "error": str(exc)}
    except Exception as exc:
        logger.error("grab_banner(%s:%d): %s", host, port, exc)
        return {"success": False, "data": {"host": host, "port": port, "banner": ""}, "error": str(exc)}


def _guess_service_from_banner(banner: str, port: int) -> str:
    banner_lower = banner.lower()
    if "ssh" in banner_lower:                      return "SSH"
    if "http" in banner_lower[:5]:                 return "HTTP"
    if "smtp" in banner_lower or "220 " in banner: return "SMTP"
    if "ftp" in banner_lower or "220 " in banner and "ftp" in banner_lower: return "FTP"
    if "imap" in banner_lower:                     return "IMAP"
    if "pop3" in banner_lower:                     return "POP3"
    if "mysql" in banner_lower:                    return "MySQL"
    PORT_MAP = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
                110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
                5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
    return PORT_MAP.get(port, "Unknown")


# ─────────────────────────────────────────────────────────────────────────────
# 12. Parameter Discoverer
# ─────────────────────────────────────────────────────────────────────────────

_PARAM_WORDLIST = [
    "id", "user", "username", "email", "token", "key", "api_key", "apikey",
    "password", "pass", "passwd", "secret", "auth", "authorization",
    "action", "type", "mode", "view", "page", "p", "q", "query", "search",
    "file", "filename", "path", "dir", "url", "redirect", "return",
    "lang", "locale", "timezone", "format", "output", "callback",
    "sort", "order", "limit", "offset", "count", "start", "end",
    "date", "from", "to", "filter", "category", "tag",
    "ref", "source", "medium", "campaign",
    "debug", "test", "verbose", "dev",
    "msg", "message", "error", "info", "status",
    "uid", "sid", "session", "csrf", "nonce",
    "access_token", "refresh_token", "jwt",
    "board", "post", "article", "comment", "product", "item", "order",
]


def discover_params(url: str, method: str = "GET", max_workers: int = 5, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Probe URL for hidden GET/POST parameters by testing common names.
    A param is 'discovered' if adding it changes the response size or status.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Baseline request
        baseline = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, verify=False)
        baseline_len = len(baseline.content)
        baseline_status = baseline.status_code
    except Exception as exc:
        return {"success": False, "data": {"params": []}, "error": str(exc)}

    discovered: List[Dict] = []

    def probe_param(param: str) -> Optional[Dict]:
        try:
            if method.upper() == "GET":
                r = requests.get(
                    url, params={param: "test"},
                    headers=_HEADERS, timeout=5, verify=False, allow_redirects=False,
                )
            else:
                r = requests.post(
                    url, data={param: "test"},
                    headers=_HEADERS, timeout=5, verify=False, allow_redirects=False,
                )
            size_diff = abs(len(r.content) - baseline_len)
            status_changed = r.status_code != baseline_status
            if size_diff > 50 or status_changed:
                return {
                    "param": param,
                    "method": method.upper(),
                    "status": r.status_code,
                    "size_diff": size_diff,
                    "status_changed": status_changed,
                    "note": "Response differs from baseline",
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe_param, p): p for p in _PARAM_WORDLIST}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                discovered.append(res)

    return {
        "success": True,
        "data": {
            "url": url,
            "method": method.upper(),
            "params_tested": len(_PARAM_WORDLIST),
            "params_discovered": discovered,
            "count": len(discovered),
        },
        "error": None,
    }
