"""
DNS & WHOIS tools for passive reconnaissance.
"""

import logging
import re
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── WHOIS TLD → server map for fallback raw-socket queries ────────────────
_WHOIS_SERVERS: Dict[str, str] = {
    "vn":       "whois.vnnic.vn",
    "edu.vn":   "whois.vnnic.vn",
    "com.vn":   "whois.vnnic.vn",
    "net.vn":   "whois.vnnic.vn",
    "org.vn":   "whois.vnnic.vn",
    "gov.vn":   "whois.vnnic.vn",
    "uk":       "whois.nic.uk",
    "co.uk":    "whois.nic.uk",
    "de":       "whois.denic.de",
    "jp":       "whois.jprs.jp",
    "au":       "whois.auda.org.au",
    "com.au":   "whois.auda.org.au",
    "fr":       "whois.nic.fr",
    "nl":       "whois.domain-registry.nl",
    "br":       "whois.registro.br",
    "cn":       "whois.cnnic.cn",
    "ru":       "whois.tcinet.ru",
    "in":       "whois.registry.in",
    "io":       "whois.nic.io",
    "sg":       "whois.sgnic.sg",
    "id":       "whois.pandi.or.id",
}

_IANA_WHOIS = "whois.iana.org"


def _raw_whois_query(domain: str, server: str, port: int = 43, timeout: int = 10) -> str:
    """Perform a raw WHOIS query over TCP and return the response text."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("Raw WHOIS query to %s failed: %s", server, exc)
        return ""


def _parse_raw_whois(raw: str) -> Dict[str, Any]:
    """Extract common fields from raw WHOIS text."""
    def _first(pattern: str) -> str:
        m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else ""

    def _all(pattern: str) -> List[str]:
        return [m.strip() for m in re.findall(pattern, raw, re.IGNORECASE | re.MULTILINE)]

    return {
        "registrar":       _first(r"Registrar(?:\s+Name)?:\s*(.+)"),
        "creation_date":   _first(r"(?:Created(?:\s+Date)?|Creation Date|Registered(?:\s+Date)?):\s*(.+)"),
        "expiration_date": _first(r"(?:Registry Expiry Date|Expiration Date|Expiry Date):\s*(.+)"),
        "name_servers":    _all(r"Name Server:\s*(.+)"),
        "emails":          list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", raw))),
        "org":             _first(r"(?:Registrant Organization|Organization|org-name):\s*(.+)"),
        "country":         _first(r"(?:Registrant Country|country):\s*(.+)"),
        "status":          _first(r"(?:Domain Status|Status):\s*(.+)"),
        "raw":             raw[:2000],
    }


def _whois_server_for(domain: str) -> Optional[str]:
    """Determine the WHOIS server for a domain based on TLD."""
    parts = domain.lower().rstrip(".").split(".")
    # Try longest suffix first (e.g. "edu.vn" before "vn")
    for length in range(len(parts) - 1, 0, -1):
        suffix = ".".join(parts[-length:])
        if suffix in _WHOIS_SERVERS:
            return _WHOIS_SERVERS[suffix]
    return None


# Lazy import to avoid crash if library is missing
try:
    import whois as _whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed; WHOIS lookups will fall back to raw socket.")

try:
    import dns.exception
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False
    logger.warning("dnspython not installed; DNS lookups will be skipped.")


def _whois_via_dns(domain: str) -> Dict[str, Any]:
    """
    DNS-based WHOIS enrichment fallback.
    When port-43 WHOIS is inaccessible, derive registrar hints from NS/SOA records.
    Returns partial data (name_servers, registrar hint from SOA, MX).
    """
    if not _DNS_AVAILABLE:
        return {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 6
    resolver.lifetime = 6
    ns_list, mx_list, org_hint, admin_email = [], [], "", ""

    try:
        ns_list = [str(r.target).rstrip(".") for r in resolver.resolve(domain, "NS")]
    except Exception:
        pass
    try:
        mx_list = [str(r.exchange).rstrip(".") for r in resolver.resolve(domain, "MX")]
    except Exception:
        pass
    try:
        soa = list(resolver.resolve(domain, "SOA"))[0]
        admin_email = str(soa.rname).rstrip(".").replace(".", "@", 1)
        mname = str(soa.mname).rstrip(".")
        # Infer registrar from NS/SOA mname (e.g. vdc2.vn → VDC)
        if ns_list:
            ns0 = ns_list[0].lower()
            # simple label → org map
            for kw, label in [
                ("vdc2.vn", "VDC Vietnam"), ("inet.vn", "VNPT"), ("mpt.vn", "VNPT"),
                ("vnpt", "VNPT"), ("fpt", "FPT Telecom"), ("matbao", "Mat Bao"),
                ("pavietnam", "PA Vietnam"), ("googledomains", "Google Domains"),
                ("namecheap", "Namecheap"), ("godaddy", "GoDaddy"),
                ("cloudflare", "Cloudflare"), ("awsdns", "Amazon Route 53"),
                ("azure-dns", "Azure DNS"), ("domaincontrol", "GoDaddy"),
            ]:
                if kw in ns0:
                    org_hint = label
                    break
    except Exception:
        pass

    if not ns_list and not mx_list:
        return {}
    return {
        "name_servers": ns_list,
        "mx_records": mx_list,
        "registrar": org_hint or "(inferred from NS records)",
        "admin_email": admin_email,
        "source": "dns-enrichment-fallback",
    }


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup on a domain.

    Priority: python-whois → raw TCP socket → DNS enrichment fallback.
    Returns a dict with keys: success, data, error.
    """
    data: Dict[str, Any] = {}

    # ── Attempt 1: python-whois library ──────────────────────────
    if _WHOIS_AVAILABLE:
        try:
            w = _whois.whois(domain)

            def _str(val: Any) -> Optional[str]:
                return str(val) if val else None

            # Check if we got meaningful data (empty whois = failed silently)
            ns = list(w.name_servers) if w.name_servers else []
            registrar = _str(w.registrar) or ""
            org = _str(w.org) or ""
            if registrar or org or ns:
                return {
                    "success": True,
                    "data": {
                        "registrar":       registrar,
                        "creation_date":   _str(w.creation_date),
                        "expiration_date": _str(w.expiration_date),
                        "name_servers":    ns,
                        "emails":          list(w.emails) if w.emails else [],
                        "org":             org,
                        "country":         _str(w.country),
                        "status":          _str(w.status),
                        "source":          "python-whois",
                    },
                    "error": None,
                }
            # Empty result — fall through to raw socket
            logger.debug("python-whois returned empty data for %s, trying raw socket", domain)
        except Exception as exc:
            logger.debug("python-whois failed for %s (%s), trying raw socket", domain, exc)

    # ── Attempt 2: raw socket fallback ───────────────────────────
    server = _whois_server_for(domain)
    if not server:
        iana_resp = _raw_whois_query(domain, _IANA_WHOIS, timeout=8)
        m = re.search(r"^whois:\s*([\w.\-]+)", iana_resp, re.IGNORECASE | re.MULTILINE)
        server = m.group(1).strip() if m else None

    if server:
        raw = _raw_whois_query(domain, server, timeout=12)
        if raw and len(raw) > 50:
            parsed = _parse_raw_whois(raw)
            if parsed.get("registrar") or parsed.get("org") or parsed.get("name_servers"):
                return {
                    "success": True,
                    "data": {**parsed, "source": f"raw-socket:{server}"},
                    "error": None,
                }

    # ── Attempt 3: DNS enrichment fallback (no port-43 needed) ───
    dns_data = _whois_via_dns(domain)
    if dns_data:
        return {
            "success": True,
            "data": {**dns_data, "note": "WHOIS server unreachable; data derived from DNS records"},
            "error": None,
        }

    return {
        "success": False,
        "data": {},
        "error": f"WHOIS lookup returned no data for {domain} (all methods failed)",
    }


def dns_lookup(
    domain: str,
    record_types: Optional[List[str]] = None,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Resolve several DNS record types for *domain*.

    Returns a dict with keys: success, data (dict keyed by record type), error.
    """
    if not _DNS_AVAILABLE:
        return {"success": False, "data": {}, "error": "dnspython not installed"}

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results: Dict[str, List[str]] = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results[rtype] = []
        except dns.exception.Timeout:
            results[rtype] = []
            logger.warning("DNS timeout for %s %s", domain, rtype)
        except Exception as exc:
            results[rtype] = []
            logger.error("DNS lookup error %s %s: %s", domain, rtype, exc)

    # Reverse DNS for first 3 A-records
    if results.get("A"):
        ptr: List[str] = []
        for ip in results["A"][:3]:
            try:
                ptr.append(socket.gethostbyaddr(ip)[0])
            except Exception:
                pass
        if ptr:
            results["PTR"] = ptr

    return {"success": True, "data": results, "error": None}


def reverse_dns_lookup(ip: str) -> Dict[str, Any]:
    """Perform reverse DNS lookup on an IP address.

    Returns a dict with keys: success, data, error.
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {
            "success": True,
            "data": {
                "ip": ip,
                "hostname": hostname,
                "aliases": aliases,
            },
            "error": None,
        }
    except socket.herror:
        return {"success": False, "data": {"ip": ip}, "error": "No PTR record found"}
    except Exception as exc:
        logger.error("Reverse DNS lookup failed for %s: %s", ip, exc)
        return {"success": False, "data": {"ip": ip}, "error": str(exc)}
