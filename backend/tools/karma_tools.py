"""
karma_tools.py — Shodan-powered OSINT using Python API.

Inspired by karma_v2 (https://github.com/Dheerajmadhukar/karma_v2).
Uses Shodan Python SDK natively on Windows (no WSL/bash required).

Requires:
  - SHODAN_API_KEY in .env (Shodan Pro/Premium for best results)
  - pip install shodan

Capabilities:
  - IP enumeration for a domain's organisation
  - ASN discovery
  - CVE lookup for live hosts
  - Credential/data leak hints (via Shodan text search)
  - Favicon hash-based asset discovery
  - Subdomain enumeration via Shodan
"""

import logging
import os
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SHODAN_ENV = "SHODAN_API_KEY"

# Lazy-load Shodan client so import never fails if library is missing
_shodan_client = None


def _get_client():
    """Return a cached Shodan API client, or None if unavailable."""
    global _shodan_client
    if _shodan_client is not None:
        return _shodan_client
    try:
        import shodan  # noqa: PLC0415
        api_key = os.environ.get(_SHODAN_ENV, "").strip()
        if not api_key:
            # Try loading from core.config as fallback
            try:
                from core.config import SHODAN_API_KEY  # noqa: PLC0415
                api_key = SHODAN_API_KEY
            except ImportError:
                pass
        if not api_key:
            logger.warning("[karma_tools] SHODAN_API_KEY not set")
            return None
        _shodan_client = shodan.Shodan(api_key)
        return _shodan_client
    except ImportError:
        logger.error("[karma_tools] shodan library not installed. Run: pip install shodan")
        return None


def _not_ready(reason: str) -> Dict[str, Any]:
    return {"success": False, "data": {}, "error": reason}


# ---------------------------------------------------------------------------
# karma_health_check
# ---------------------------------------------------------------------------

def karma_health_check() -> Dict[str, Any]:
    """
    Check if Shodan integration is ready.
    Returns dict with 'ready' bool and status details.
    """
    try:
        import shodan  # noqa: F401  # type: ignore
        lib_ok = True
    except ImportError:
        lib_ok = False

    api_key = os.environ.get(_SHODAN_ENV, "").strip()
    if not api_key:
        try:
            from core.config import SHODAN_API_KEY  # noqa: PLC0415
            api_key = SHODAN_API_KEY
        except ImportError:
            pass

    key_set = bool(api_key)
    ready = lib_ok and key_set

    return {
        "wsl_available": True,        # kept for API compatibility
        "karma_installed": lib_ok,     # True when shodan lib installed
        "shodan_key_configured": key_set,
        "ready": ready,
        "message": (
            "Shodan API ready (karma_v2 mode via Python SDK)"
            if ready
            else f"Not ready — lib_ok={lib_ok}, key_set={key_set}. "
                 "Install: pip install shodan; Set: SHODAN_API_KEY in .env"
        ),
    }


# ---------------------------------------------------------------------------
# IP Enumeration  (karma_v2 -ip equivalent)
# ---------------------------------------------------------------------------

def run_karma_ip(domain: str, limit: int = 100) -> Dict[str, Any]:
    """
    Enumerate IPs associated with a domain via Shodan.
    Resolves the domain, queries Shodan for organisation/net range.
    """
    api = _get_client()
    if not api:
        return _not_ready("Shodan client unavailable")

    try:
        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain  # might already be an IP

        # Get host info + look at organisation
        host_info = api.host(ip)
        org = host_info.get("org", "")
        asn = host_info.get("asn", "")
        country = host_info.get("country_name", "")
        hostnames = host_info.get("hostnames", [])
        ports = host_info.get("ports", [])
        vulns = list(host_info.get("vulns", {}).keys())

        # Search for more IPs in the same org
        ips: List[str] = [ip]
        subdomains: List[str] = list(hostnames)
        all_vulns: List[str] = list(vulns)

        if org:
            try:
                query = f'org:"{org}"'
                results = api.search(query, limit=min(limit, 100))
                for r in results.get("matches", []):
                    rip = r.get("ip_str", "")
                    if rip and rip not in ips:
                        ips.append(rip)
                    for h in r.get("hostnames", []):
                        if h not in subdomains:
                            subdomains.append(h)
                    for v in r.get("vulns", {}).keys():
                        if v not in all_vulns:
                            all_vulns.append(v)
            except Exception as search_exc:
                logger.warning("[karma_tools] Org search failed: %s", search_exc)

        return {
            "success": True,
            "data": {
                "mode": "ip",
                "domain": domain,
                "resolved_ip": ip,
                "org": org,
                "asn": asn,
                "country": country,
                "ips": ips[:limit],
                "ip_count": len(ips),
                "subdomains": subdomains[:50],
                "ports": ports,
                "cves_found": all_vulns,
            },
            "error": None,
        }

    except Exception as exc:
        logger.error("[karma_tools] run_karma_ip error: %s", exc)
        return _not_ready(str(exc))


# ---------------------------------------------------------------------------
# ASN Discovery  (karma_v2 -asn equivalent)
# ---------------------------------------------------------------------------

def run_karma_asn(domain: str, limit: int = 50) -> Dict[str, Any]:
    """
    Discover ASN and associated IP ranges for a domain.
    """
    api = _get_client()
    if not api:
        return _not_ready("Shodan client unavailable")

    try:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain

        host_info = api.host(ip)
        asn = host_info.get("asn", "")
        org = host_info.get("org", "")
        ip_ranges: List[str] = []
        ips: List[str] = []

        if asn:
            try:
                results = api.search(f"asn:{asn}", limit=min(limit, 100))
                for r in results.get("matches", []):
                    rip = r.get("ip_str", "")
                    if rip and rip not in ips:
                        ips.append(rip)
                    for item in r.get("ip", []):
                        if str(item) not in ip_ranges:
                            ip_ranges.append(str(item))
            except Exception as exc:
                logger.warning("[karma_tools] ASN search error: %s", exc)

        return {
            "success": True,
            "data": {
                "mode": "asn",
                "domain": domain,
                "asn": asn,
                "org": org,
                "ips": ips[:limit],
                "asn_count": 1 if asn else 0,
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("[karma_tools] run_karma_asn error: %s", exc)
        return _not_ready(str(exc))


# ---------------------------------------------------------------------------
# CVE Enumeration  (karma_v2 -cve equivalent)
# ---------------------------------------------------------------------------

def run_karma_cve(domain: str, limit: int = 100) -> Dict[str, Any]:
    """
    Find CVEs affecting hosts related to a domain via Shodan.
    """
    api = _get_client()
    if not api:
        return _not_ready("Shodan client unavailable")

    try:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain

        # Direct host CVEs
        host_info = api.host(ip)
        cves: List[str] = list(host_info.get("vulns", {}).keys())
        cve_details: List[Dict] = []

        for cve_id, cve_data in list(host_info.get("vulns", {}).items())[:20]:
            cve_details.append({
                "cve_id": cve_id,
                "cvss": cve_data.get("cvss", 0),
                "summary": cve_data.get("summary", "")[:200],
            })

        # Search org-wide for more CVEs
        org = host_info.get("org", "")
        if org:
            try:
                results = api.search(f'org:"{org}" vuln:*', limit=min(limit, 50))
                for r in results.get("matches", []):
                    for v in r.get("vulns", {}).keys():
                        if v not in cves:
                            cves.append(v)
            except Exception as exc:
                logger.warning("[karma_tools] CVE org search error: %s", exc)

        return {
            "success": True,
            "data": {
                "mode": "cve",
                "domain": domain,
                "cves_found": cves[:limit],
                "cve_count": len(cves),
                "cve_details": cve_details,
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("[karma_tools] run_karma_cve error: %s", exc)
        return _not_ready(str(exc))


# ---------------------------------------------------------------------------
# Leak Detection  (karma_v2 -leaks equivalent)
# ---------------------------------------------------------------------------

def run_karma_leaks(domain: str, limit: int = 100) -> Dict[str, Any]:
    """
    Search Shodan for exposed sensitive services and potential data leaks.
    Looks for: exposed databases, credential panels, config files, dev endpoints.
    """
    api = _get_client()
    if not api:
        return _not_ready("Shodan client unavailable")

    leaked: List[Dict] = []
    leak_types: Dict[str, int] = {}

    # Shodan queries similar to karma_v2 leak detection
    leak_queries = [
        (f'hostname:"{domain}" product:"MongoDB"',           "MongoDB exposed"),
        (f'hostname:"{domain}" product:"Redis"',             "Redis exposed"),
        (f'hostname:"{domain}" product:"Elasticsearch"',     "Elasticsearch exposed"),
        (f'hostname:"{domain}" http.title:"phpMyAdmin"',     "phpMyAdmin panel"),
        (f'hostname:"{domain}" http.title:"Kibana"',         "Kibana dashboard"),
        (f'hostname:"{domain}" http.title:"Grafana"',        "Grafana exposed"),
        (f'hostname:"{domain}" "private key"',               "Private key exposure"),
        (f'hostname:"{domain}" "password" port:8080,8443',   "Credential pages"),
        (f'hostname:"{domain}" "DB_PASSWORD" OR "API_KEY"',  "Env var leaks"),
        (f'hostname:"{domain}" port:21',                     "FTP open"),
        (f'hostname:"{domain}" port:23',                     "Telnet open"),
        (f'hostname:"{domain}" port:3306',                   "MySQL exposed"),
        (f'hostname:"{domain}" port:5432',                   "PostgreSQL exposed"),
        (f'hostname:"{domain}" port:27017',                  "MongoDB port open"),
    ]

    try:
        for query, label in leak_queries[:8]:  # limit API calls
            try:
                results = api.search(query, limit=10)
                count = results.get("total", 0)
                if count > 0:
                    matches = results.get("matches", [])
                    leaked.append({
                        "type": label,
                        "count": count,
                        "sample_ips": [m.get("ip_str") for m in matches[:3]],
                        "query": query,
                    })
                    leak_types[label] = count
            except Exception as qe:
                logger.debug("[karma_tools] Leak query failed (%s): %s", label, qe)
                continue

        return {
            "success": True,
            "data": {
                "mode": "leaks",
                "domain": domain,
                "leaks": leaked,
                "leak_count": len(leaked),
                "leak_types": leak_types,
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("[karma_tools] run_karma_leaks error: %s", exc)
        return _not_ready(str(exc))


# ---------------------------------------------------------------------------
# Favicon Hash Discovery  (karma_v2 -favicon equivalent)
# ---------------------------------------------------------------------------

def run_karma_favicon(domain: str, limit: int = 100) -> Dict[str, Any]:
    """
    Discover related assets by favicon hash fingerprinting via Shodan.
    """
    api = _get_client()
    if not api:
        return _not_ready("Shodan client unavailable")

    try:
        import hashlib
        import base64
        import urllib.request

        # Fetch favicon and compute MurmurHash (Shodan favicon hash)
        favicon_url = f"https://{domain}/favicon.ico"
        try:
            req = urllib.request.Request(
                favicon_url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                favicon_data = resp.read()
            favicon_b64 = base64.encodebytes(favicon_data)
            # Shodan uses MurmurHash of base64-encoded favicon
            favicon_hash = _mmh3_hash(favicon_b64)
        except Exception as fav_exc:
            logger.warning("[karma_tools] Favicon fetch failed: %s", fav_exc)
            return _not_ready(f"Could not fetch favicon from {favicon_url}: {fav_exc}")

        # Search Shodan by favicon hash
        results = api.search(f"http.favicon.hash:{favicon_hash}", limit=min(limit, 100))
        assets: List[Dict] = []
        for r in results.get("matches", []):
            assets.append({
                "ip": r.get("ip_str", ""),
                "port": r.get("port", 0),
                "hostnames": r.get("hostnames", []),
                "country": r.get("location", {}).get("country_name", ""),
                "org": r.get("org", ""),
            })

        return {
            "success": True,
            "data": {
                "mode": "favicon",
                "domain": domain,
                "favicon_hash": favicon_hash,
                "related_assets": assets[:limit],
                "favicon_count": len(assets),
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("[karma_tools] run_karma_favicon error: %s", exc)
        return _not_ready(str(exc))


def _mmh3_hash(data: bytes) -> int:
    """Pure-Python MurmurHash3 (32-bit) — used by Shodan for favicon hashing."""
    import struct
    length = len(data)
    seed = 0
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h1 = seed
    chunks = length // 4
    for i in range(chunks):
        k1 = struct.unpack_from('<I', data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[chunks * 4:]
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Return as signed 32-bit int (matches Shodan convention)
    return struct.unpack('i', struct.pack('I', h1))[0]


# ── Smap Passive Port Scan (Shodan-backed) ────────────────────────────────

def smap_passive_portscan(target: str) -> Dict[str, Any]:
    """
    Passive port scan using Shodan data — zero packets sent to target.
    Inspired by smap tool (https://github.com/s0md3v/Smap).
    Returns open ports with service/banner info from Shodan's database.
    """
    api = _get_client()
    if api is None:
        # Fallback: use hackertarget.com free TCP scan (limited)
        return _smap_fallback_hackertarget(target)

    try:
        ip = target
        if not target.replace(".", "").isdigit():
            ip = socket.gethostbyname(target)

        host = api.host(ip)
        ports = []
        for service in host.get("data", []):
            port_info = {
                "port": service.get("port"),
                "protocol": service.get("transport", "tcp"),
                "service": service.get("_shodan", {}).get("module", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "cpe": service.get("cpe", []),
                "banner": str(service.get("data", ""))[:200],
                "vulns": list((service.get("vulns") or {}).keys()),
                "last_seen": service.get("timestamp", ""),
            }
            ports.append(port_info)

        return {
            "success": True,
            "data": {
                "ip": ip,
                "target": target,
                "hostnames": host.get("hostnames", []),
                "asn": host.get("asn", ""),
                "org": host.get("org", ""),
                "os": host.get("os", ""),
                "ports": ports,
                "open_port_numbers": [p["port"] for p in ports],
                "total_ports": len(ports),
                "source": "shodan_passive",
            },
        }
    except Exception as exc:
        logger.error("smap_passive_portscan(%s): %s", target, exc)
        return {"success": False, "data": {}, "error": str(exc)}


def _smap_fallback_hackertarget(target: str) -> Dict[str, Any]:
    """Fallback: use hackertarget.com/nmap/ for passive-style scan (limited to 100 reqs/day)."""
    import requests as _req
    try:
        r = _req.get(
            f"https://api.hackertarget.com/nmap/?q={target}",
            timeout=15, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:20]:
            ports = []
            for line in r.text.splitlines():
                m = __import__("re").match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if m:
                    ports.append({
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "service": m.group(3),
                        "product": "", "version": "", "banner": "",
                        "vulns": [], "source": "hackertarget_fallback",
                    })
            return {
                "success": True,
                "data": {
                    "target": target,
                    "ports": ports,
                    "open_port_numbers": [p["port"] for p in ports],
                    "total_ports": len(ports),
                    "source": "hackertarget_fallback",
                },
            }
    except Exception as exc:
        logger.error("_smap_fallback_hackertarget(%s): %s", target, exc)
    return {"success": False, "data": {}, "error": "Shodan unavailable and hackertarget fallback failed"}

