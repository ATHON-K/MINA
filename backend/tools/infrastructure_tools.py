"""
Infrastructure Intel Tools — ASN, BGP, IP range intelligence.

Provides:
  - asn_enrichment()              : Enrich ASN details for a domain/IP
  - bgp_range_summary()           : Get BGP prefix/range info for an ASN
  - org_ip_range_summary()        : Map organization to IP ranges
  - ip_range_to_candidate_hosts() : Extract candidate hosts from IP range (passive)

All operations are passive. No active scanning of IP ranges.
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


def asn_enrichment(domain_or_ip: str) -> Dict:
    """
    Enrich ASN details for a domain or IP address.
    Uses public BGP/ASN lookup services.
    """
    try:
        # First try to resolve domain to IP if needed
        target_ip = domain_or_ip
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_or_ip):
            import socket
            try:
                target_ip = socket.gethostbyname(domain_or_ip)
            except socket.gaierror:
                return {"success": False, "data": {}, "error": f"Cannot resolve {domain_or_ip}"}

        # Query BGPView API
        asn_data = {}
        try:
            resp = _SESSION.get(f"https://api.bgpview.io/ip/{target_ip}", timeout=_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                prefixes = data.get("rir_allocation", {})
                ptr_record = data.get("ptr_record")
                asns = data.get("prefixes", [])

                if asns:
                    first = asns[0]
                    asn_info = first.get("asn", {})
                    asn_data = {
                        "ip": target_ip,
                        "asn": asn_info.get("asn"),
                        "asn_name": asn_info.get("name", ""),
                        "asn_description": asn_info.get("description", ""),
                        "prefix": first.get("prefix", ""),
                        "cidr": first.get("prefix", ""),
                        "country": asn_info.get("country_code", ""),
                        "ptr_record": ptr_record,
                    }
        except requests.RequestException as e:
            logger.debug("[InfraTools] BGPView query failed: %s", e)

        # Fallback: try ipinfo.io
        if not asn_data:
            try:
                resp = _SESSION.get(f"https://ipinfo.io/{target_ip}/json", timeout=_TIMEOUT)
                if resp.status_code == 200:
                    info = resp.json()
                    org = info.get("org", "")
                    asn_match = re.match(r'(AS\d+)\s+(.*)', org)
                    asn_data = {
                        "ip": target_ip,
                        "asn": asn_match.group(1) if asn_match else "",
                        "asn_name": asn_match.group(2) if asn_match else org,
                        "city": info.get("city", ""),
                        "region": info.get("region", ""),
                        "country": info.get("country", ""),
                    }
            except requests.RequestException:
                pass

        if not asn_data:
            return {"success": False, "data": {}, "error": "No ASN data found"}

        return {
            "success": True,
            "data": {
                "query": domain_or_ip,
                **asn_data,
            },
        }
    except Exception as e:
        logger.error("[InfraTools] asn_enrichment failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def bgp_range_summary(asn: str) -> Dict:
    """
    Get BGP prefix/range information for an ASN.
    Uses BGPView public API.
    """
    try:
        # Normalize ASN format
        asn_num = asn.upper().replace("AS", "").strip()
        if not asn_num.isdigit():
            return {"success": False, "data": {}, "error": f"Invalid ASN: {asn}"}

        prefixes = []
        try:
            resp = _SESSION.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                for prefix in data.get("ipv4_prefixes", []):
                    prefixes.append({
                        "prefix": prefix.get("prefix", ""),
                        "name": prefix.get("name", ""),
                        "description": prefix.get("description", ""),
                        "country": prefix.get("country_code", ""),
                    })
                for prefix in data.get("ipv6_prefixes", []):
                    prefixes.append({
                        "prefix": prefix.get("prefix", ""),
                        "name": prefix.get("name", ""),
                        "description": prefix.get("description", ""),
                        "country": prefix.get("country_code", ""),
                        "ipv6": True,
                    })
        except requests.RequestException as e:
            logger.debug("[InfraTools] BGPView ASN query failed: %s", e)
            return {"success": False, "data": {}, "error": str(e)}

        return {
            "success": True,
            "data": {
                "asn": f"AS{asn_num}",
                "prefixes": prefixes[:50],
                "prefix_count": len(prefixes),
                "ipv4_count": sum(1 for p in prefixes if not p.get("ipv6")),
                "ipv6_count": sum(1 for p in prefixes if p.get("ipv6")),
            },
        }
    except Exception as e:
        logger.error("[InfraTools] bgp_range_summary failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def org_ip_range_summary(company_name: str) -> Dict:
    """
    Map an organization name to IP ranges using public WHOIS/RIR data.
    Passive lookup only.
    """
    try:
        ranges = []

        # Search ARIN for org
        try:
            resp = _SESSION.get(
                f"https://whois.arin.net/rest/orgs;name={company_name}",
                headers={"Accept": "application/json"},
                timeout=_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                orgs = data.get("orgs", {}).get("orgRef", [])
                if isinstance(orgs, dict):
                    orgs = [orgs]
                for org in orgs[:5]:
                    org_handle = org.get("@handle", "")
                    org_name = org.get("@name", "")
                    if org_handle:
                        ranges.append({
                            "org_handle": org_handle,
                            "org_name": org_name,
                            "source": "ARIN",
                        })
        except (requests.RequestException, ValueError):
            pass

        return {
            "success": True,
            "data": {
                "company_name": company_name,
                "organizations_found": ranges[:10],
                "org_count": len(ranges),
                "note": "Use ASN lookup for detailed prefix information.",
            },
        }
    except Exception as e:
        logger.error("[InfraTools] org_ip_range_summary failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}


def ip_range_to_candidate_hosts(ip_range: str) -> Dict:
    """
    Extract candidate hosts from a CIDR range.
    Returns first/last IPs and sample candidates — NO active scanning.
    """
    try:
        import ipaddress
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return {"success": False, "data": {}, "error": f"Invalid CIDR: {ip_range}"}

        total = network.num_addresses
        # Only enumerate small ranges (max /24 = 256 hosts)
        if total > 256:
            hosts = [str(network.network_address), str(network.broadcast_address)]
            sample = [str(h) for h in list(network.hosts())[:10]]
            return {
                "success": True,
                "data": {
                    "range": ip_range,
                    "total_hosts": total,
                    "sample_hosts": sample,
                    "note": f"Range too large ({total} hosts) — showing sample only. No active scanning.",
                },
            }

        hosts = [str(h) for h in network.hosts()]
        return {
            "success": True,
            "data": {
                "range": ip_range,
                "total_hosts": len(hosts),
                "candidate_hosts": hosts,
                "note": "Passive enumeration only — no active scanning performed.",
            },
        }
    except Exception as e:
        logger.error("[InfraTools] ip_range_to_candidate_hosts failed: %s", e)
        return {"success": False, "data": {}, "error": str(e)}
