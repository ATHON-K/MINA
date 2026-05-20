"""
Certificate Transparency tools — queries crt.sh and collects cert metadata.
"""

import logging
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests

logger = logging.getLogger(__name__)
_CRTSH_URL = "https://crt.sh"
_HACKERTARGET_HOSTSEARCH = "https://api.hackertarget.com/hostsearch/?q={domain}"
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "MINA-Recon/1.0"})


def _crtsh_fetch(domain: str, timeout: int) -> Optional[list]:
    """Return raw JSON list from crt.sh, or None on failure."""
    url = f"{_CRTSH_URL}/?q=%.{domain}&output=json"
    try:
        resp = _SESSION.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.debug("crt.sh fetch failed: %s", exc)
        return None


def _hackertarget_hostsearch(domain: str) -> list:
    """Fallback: subdomain list via HackerTarget hostsearch API."""
    try:
        url = _HACKERTARGET_HOSTSEARCH.format(domain=domain)
        resp = _SESSION.get(url, timeout=15)
        resp.raise_for_status()
        subdomains = []
        for line in resp.text.strip().splitlines():
            if "," in line:
                host = line.split(",", 1)[0].strip().lower()
                if host and domain in host:
                    subdomains.append(host)
        return sorted(set(subdomains))
    except Exception as exc:
        logger.debug("HackerTarget hostsearch fallback failed: %s", exc)
        return []


def crt_sh_query(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """Query crt.sh for subdomains via Certificate Transparency logs.
    
    Retries once with a shorter window, then falls back to HackerTarget.
    Returns a dict with keys: success, data (subdomains list + count), error.
    """
    subdomains: Set[str] = set()
    source = "crt.sh"
    last_error: str = ""

    # Try crt.sh up to 2 times (first: given timeout, second: 10s)
    for attempt_timeout in (timeout, 10):
        data = _crtsh_fetch(domain, attempt_timeout)
        if data is not None:
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name and domain in name:
                        subdomains.add(name)
            break
        last_error = f"crt.sh timed out after {attempt_timeout}s"

    # If crt.sh gave nothing, try HackerTarget as fallback
    if not subdomains:
        logger.info("crt.sh returned no results for %s, trying HackerTarget fallback", domain)
        ht_subs = _hackertarget_hostsearch(domain)
        if ht_subs:
            subdomains.update(ht_subs)
            source = "hackertarget-hostsearch"

    if subdomains or not last_error:
        return {
            "success": True,
            "data": {"subdomains": sorted(subdomains), "count": len(subdomains), "source": source},
            "error": None,
        }

    return {
        "success": False,
        "data": {"subdomains": [], "count": 0},
        "error": last_error,
    }


def cert_detail_collect(host: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Collect detailed certificate metadata from a TLS endpoint.
    Returns issuer, subject, SAN list, validity period, chain info.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                cert_bin = s.getpeercert(binary_form=True)
                tls_ver = s.version() or "Unknown"

        if not cert:
            return {"success": False, "data": {}, "error": "No certificate returned"}

        # Parse subject
        subject = {}
        for rdn in cert.get("subject", ()):
            for attr_name, attr_val in rdn:
                subject[attr_name] = attr_val

        # Parse issuer
        issuer = {}
        for rdn in cert.get("issuer", ()):
            for attr_name, attr_val in rdn:
                issuer[attr_name] = attr_val

        # SAN domains
        san_list: List[str] = []
        for typ, val in cert.get("subjectAltName", ()):
            if typ == "DNS":
                san_list.append(val)

        # Validity
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        expiry_days = None
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_days = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass

        self_signed = subject.get("organizationName") == issuer.get("organizationName") and \
                      subject.get("commonName") == issuer.get("commonName")
        wildcard = any(d.startswith("*.") for d in san_list)

        return {
            "success": True,
            "data": {
                "host": host,
                "port": port,
                "tls_version": tls_ver,
                "subject": subject,
                "issuer": issuer,
                "san_domains": san_list,
                "not_before": not_before,
                "not_after": not_after,
                "expiry_days": expiry_days,
                "self_signed": self_signed,
                "wildcard_cert": wildcard,
                "serial_number": cert.get("serialNumber", ""),
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("cert_detail_collect(%s:%d): %s", host, port, exc)
        return {"success": False, "data": {}, "error": str(exc)}
