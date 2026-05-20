"""
Active reconnaissance tools — subfinder, nmap, httpx, nuclei, vhost discovery.
Each function returns a dict: {success, data, error}.
Tools that are not installed are skipped gracefully.
"""

import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Use shared binary resolution + command builders
from tools.command_builders import (
    _find_bin, _SUBFINDER_BIN, _HTTPX_BIN, _NUCLEI_BIN, _NMAP_BIN,
    build_subfinder_cmd, build_httpx_cmd, build_nuclei_cmd, build_nmap_cmd,
)


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def run_subfinder(domain: str, timeout: int = 60, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """Enumerate subdomains using subfinder."""
    options = options or {}
    timeout = options.get("timeout", timeout)
    try:
        cmd = build_subfinder_cmd(domain, options)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            subdomains = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() and domain in line.strip()
            ]
            return {"success": True, "data": {"subdomains": subdomains}, "error": None}
        return {
            "success": False,
            "data": {"subdomains": []},
            "error": result.stderr[:500] or "subfinder returned non-zero exit",
        }
    except FileNotFoundError:
        logger.warning("subfinder not found in PATH — skipping")
        return {"success": False, "data": {"subdomains": []}, "error": "subfinder not installed"}
    except subprocess.TimeoutExpired:
        return {"success": False, "data": {"subdomains": []}, "error": f"subfinder timed out ({timeout}s)"}
    except Exception as exc:
        logger.error("subfinder error for %s: %s", domain, exc)
        return {"success": False, "data": {"subdomains": []}, "error": str(exc)}


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def run_nmap(target: str, options: Any = None, timeout: int = 180) -> Dict[str, Any]:
    """Port-scan *target* with nmap and return open ports + service versions."""
    if isinstance(options, dict):
        timeout = options.get("timeout", timeout)
    elif isinstance(options, str):
        # Legacy: raw flag string — fall through to nmap_flags path
        options = {"extra_flags": options, "service_detection": False, "safe_scripts": False}
    else:
        options = {}
    try:
        cmd = build_nmap_cmd(target, options)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        ports: List[Dict[str, Any]] = []
        host_status = "unknown"

        if result.stdout:
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    status_el = host.find("status")
                    if status_el is not None:
                        host_status = status_el.get("state", "unknown")
                    ports_el = host.find("ports")
                    if ports_el is not None:
                        for port_el in ports_el.findall("port"):
                            state_el = port_el.find("state")
                            svc_el = port_el.find("service")
                            if state_el is not None and state_el.get("state") == "open":
                                ports.append(
                                    {
                                        "port": int(port_el.get("portid", 0)),
                                        "protocol": port_el.get("protocol", "tcp"),
                                        "state": "open",
                                        "service": svc_el.get("name", "") if svc_el is not None else "",
                                        "version": (
                                            f"{svc_el.get('product','')} {svc_el.get('version','')}".strip()
                                            if svc_el is not None
                                            else ""
                                        ),
                                    }
                                )
            except ET.ParseError as exc:
                logger.error("Failed to parse nmap XML for %s: %s", target, exc)

        return {
            "success": True,
            "data": {"ports": ports, "host_status": host_status},
            "error": None,
        }
    except FileNotFoundError:
        logger.warning("nmap not found in PATH — skipping")
        return {
            "success": False,
            "data": {"ports": [], "host_status": "unknown"},
            "error": "nmap not installed",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "data": {"ports": [], "host_status": "unknown"},
            "error": f"nmap timed out ({timeout}s)",
        }
    except Exception as exc:
        logger.error("nmap error for %s: %s", target, exc)
        return {"success": False, "data": {"ports": [], "host_status": "unknown"}, "error": str(exc)}


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

def run_httpx(targets: List[str], timeout: int = 45, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """Probe a list of URLs/hosts with httpx and return HTTP metadata."""
    options = options or {}
    timeout = options.get("timeout", timeout)
    if not targets:
        return {"success": True, "data": {"results": []}, "error": None}

    try:
        cmd = build_httpx_cmd(options)
        result = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        results = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                entry = {
                    "url": item.get("url", ""),
                    "status_code": item.get("status_code", 0),
                    "title": item.get("title", ""),
                    "tech": item.get("tech", []),
                    "content_length": item.get("content_length", 0),
                    "webserver": item.get("webserver", ""),
                }
                # Extended fields (when enabled in options)
                if item.get("tls"):
                    entry["tls"] = item["tls"]
                if item.get("favicon_hash"):
                    entry["favicon_hash"] = item["favicon_hash"]
                if item.get("response_time"):
                    entry["response_time"] = item["response_time"]
                results.append(entry)
            except json.JSONDecodeError:
                continue

        return {"success": True, "data": {"results": results}, "error": None}
    except FileNotFoundError:
        logger.warning("httpx not found in PATH — skipping")
        return {"success": False, "data": {"results": []}, "error": "httpx not installed"}
    except subprocess.TimeoutExpired:
        return {"success": False, "data": {"results": []}, "error": f"httpx timed out ({timeout}s)"}
    except Exception as exc:
        logger.error("httpx error: %s", exc)
        return {"success": False, "data": {"results": []}, "error": str(exc)}


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

def run_nuclei(targets: List[str], severity: str = "medium,high,critical", timeout: int = 300, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run nuclei vulnerability scanner against a list of targets.
    Uses community templates for fast, broad coverage.
    """
    options = options or {}
    severity = options.get("severity", severity)
    timeout = options.get("timeout", timeout)
    if not targets:
        return {"success": True, "data": {"findings": []}, "error": None}

    try:
        cmd = build_nuclei_cmd(options)
        result = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                findings.append({
                    "template_id":  item.get("template-id", ""),
                    "name":         info.get("name", ""),
                    "severity":     info.get("severity", "info"),
                    "matched_at":   item.get("matched-at", ""),
                    "host":         item.get("host", ""),
                    "description":  info.get("description", ""),
                    "reference":    info.get("reference", []),
                    "cvss_score":   info.get("classification", {}).get("cvss-score", None),
                })
            except json.JSONDecodeError:
                continue

        return {"success": True, "data": {"findings": findings}, "error": None}
    except FileNotFoundError:
        logger.warning("nuclei not found in PATH — skipping")
        return {"success": False, "data": {"findings": []}, "error": "nuclei not installed"}
    except subprocess.TimeoutExpired:
        return {"success": False, "data": {"findings": []}, "error": f"nuclei timed out ({timeout}s)"}
    except Exception as exc:
        logger.error("nuclei error: %s", exc)
        return {"success": False, "data": {"findings": []}, "error": str(exc)}


# ---------------------------------------------------------------------------
# Virtual host discovery
# ---------------------------------------------------------------------------

def run_vhost_discovery(ip: str, domain: str, wordlist: List[str] = None, timeout: int = 30) -> Dict[str, Any]:
    """
    Virtual host discovery by brute-forcing Host headers.
    Uses httpx with custom Host headers to detect hidden vhosts.
    """
    if wordlist is None:
        # Common vhost brute list
        wordlist = [
            "dev", "staging", "test", "api", "admin", "portal", "internal",
            "vpn", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
            "mail", "smtp", "ftp", "mx", "ns1", "ns2", "monitor", "status",
            "docs", "wiki", "app", "beta", "prod", "preprod", "uat", "demo",
        ]

    hosts_to_probe = [f"http://{ip}" for _ in wordlist]
    host_headers = [f"{sub}.{domain}" for sub in wordlist]

    found_vhosts = []
    try:
        for vhost in host_headers:
            try:
                cmd = [
                    _HTTPX_BIN, "-silent", "-json", "-no-color",
                    "-H", f"Host: {vhost}",
                    "-timeout", "5",
                ]
                r = subprocess.run(
                    cmd,
                    input=f"http://{ip}",
                    capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines():
                    if line.strip():
                        try:
                            item = json.loads(line)
                            sc = item.get("status_code", 0)
                            if sc and sc not in (400, 404, 403):
                                found_vhosts.append({
                                    "vhost": vhost,
                                    "ip": ip,
                                    "status_code": sc,
                                    "title": item.get("title", ""),
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        return {"success": True, "data": {"vhosts": found_vhosts}, "error": None}
    except FileNotFoundError:
        return {"success": False, "data": {"vhosts": []}, "error": "httpx not installed"}
    except Exception as exc:
        return {"success": False, "data": {"vhosts": []}, "error": str(exc)}
