"""
Shodan tools for passive reconnaissance.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def shodan_query(query: str, api_key: str) -> Dict[str, Any]:
    """Search Shodan for hosts matching *query*.

    Returns a dict: success, data (hosts list + total), error.
    """
    if not api_key or api_key in ("your_shodan_key", ""):
        return {
            "success": False,
            "data": {"hosts": [], "total": 0},
            "error": "Shodan API key not configured",
        }

    try:
        import shodan  # type: ignore

        api = shodan.Shodan(api_key)
        results = api.search(query, limit=20)

        hosts = []
        for match in results.get("matches", []):
            hosts.append(
                {
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "hostnames": match.get("hostnames", []),
                    "org": match.get("org", ""),
                    "os": match.get("os", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "banner": str(match.get("data", ""))[:500],
                    "vulns": list(match.get("vulns", {}).keys()),
                }
            )

        return {
            "success": True,
            "data": {"hosts": hosts, "total": results.get("total", 0)},
            "error": None,
        }
    except Exception as exc:
        logger.error("Shodan query failed for '%s': %s", query, exc)
        return {"success": False, "data": {"hosts": [], "total": 0}, "error": str(exc)}


def shodan_host_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    """Look up a single IP address on Shodan."""
    if not api_key or api_key in ("your_shodan_key", ""):
        return {"success": False, "data": {}, "error": "Shodan API key not configured"}

    try:
        import shodan  # type: ignore

        api = shodan.Shodan(api_key)
        host = api.host(ip)

        return {
            "success": True,
            "data": {
                "ip": host.get("ip_str", ip),
                "org": host.get("org", ""),
                "hostnames": host.get("hostnames", []),
                "ports": host.get("ports", []),
                "vulns": list(host.get("vulns", {}).keys()),
                "os": host.get("os", ""),
                "country": host.get("country_name", ""),
                "services": [
                    {
                        "port": item.get("port"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                        "banner": str(item.get("data", ""))[:300],
                    }
                    for item in host.get("data", [])
                ],
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("Shodan host lookup failed for %s: %s", ip, exc)
        return {"success": False, "data": {}, "error": str(exc)}
