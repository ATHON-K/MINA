"""
Command builders for external CLI tools.

Each builder accepts (target, options) and returns List[str] ready for subprocess.run().
Options use sensible defaults if omitted.
"""

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# ── Binary resolution (shared with active_tools.py) ──────────────

def _find_bin(names: List[str]) -> str:
    candidates = list(names)
    for extra in [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]:
        if "nmap" in " ".join(names).lower():
            candidates.append(extra)
    for c in candidates:
        found = shutil.which(c)
        if found:
            return found
        if os.path.isfile(c):
            return c
    return names[0]


_SUBFINDER_BIN = _find_bin(["subfinder"])
_HTTPX_BIN     = _find_bin(["httpx"])
_NUCLEI_BIN    = _find_bin(["nuclei"])
_NMAP_BIN      = _find_bin(["nmap"])

_WORDLIST_DIR = Path(__file__).parent.parent / "wordlists"


# ── subfinder ─────────────────────────────────────────────────────

def build_subfinder_cmd(domain: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Supported options:
      recursive       : bool   – enable recursive subdomain enum (-recursive)
      all_sources     : bool   – use all sources (-all)
      sources_include : list   – only these sources (-sources x,y)
      sources_exclude : list   – exclude these sources (-es x,y)
      timeout         : int    – per-source timeout seconds (-timeout N)
      max_time        : int    – global max enumeration time (-max-time N)
      rate_limit      : int    – max requests/sec per source (-rate-limit N)
      use_resolvers   : bool   – use built-in resolvers (-nW)
      json            : bool   – JSON-line output (-json)
      providers       : list   – (legacy) same as sources_include
    """
    opts = options or {}
    cmd = [_SUBFINDER_BIN, "-d", domain, "-silent"]

    # Source control
    if opts.get("all_sources", True):
        cmd.append("-all")
    if opts.get("sources_include") or opts.get("providers"):
        sources = opts.get("sources_include") or opts.get("providers")
        cmd.extend(["-sources", ",".join(sources)])
    if opts.get("sources_exclude"):
        cmd.extend(["-es", ",".join(opts["sources_exclude"])])

    # Recursion
    if opts.get("recursive", False):
        cmd.append("-recursive")

    # Timing
    if opts.get("timeout"):
        cmd.extend(["-timeout", str(opts["timeout"])])
    if opts.get("max_time"):
        cmd.extend(["-max-time", str(opts["max_time"])])
    if opts.get("rate_limit"):
        cmd.extend(["-rate-limit", str(opts["rate_limit"])])

    # Resolvers
    if opts.get("use_resolvers", False):
        cmd.append("-nW")

    # Output format
    if opts.get("json", False):
        cmd.append("-json")

    return cmd


# ── httpx ─────────────────────────────────────────────────────────

def build_httpx_cmd(options: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Targets are fed via stdin.

    Supported options:
      follow_redirects : bool – follow HTTP redirects (-follow-redirects)
      title            : bool – capture page title (-title)
      tech_detect      : bool – detect technologies (-tech-detect)
      status_code      : bool – display status code (-status-code)
      tls_info         : bool – extract TLS cert info (-tls-probe -tls-grab)
      favicon_hash     : bool – compute favicon hash (-favicon)
      response_time    : bool – show response time (-response-time)
      content_length   : bool – show content length (-content-length)
      web_server       : bool – detect web server (-web-server)
      timeout          : int  – per-request timeout sec (-timeout N)
      retries          : int  – retry count (-retries N)
      rate_limit       : int  – max requests/sec (-rate-limit N)
      concurrency      : int  – concurrent probes (-threads N)
      extra_flags      : list – raw CLI flags appended
    """
    opts = options or {}
    cmd = [_HTTPX_BIN, "-json", "-silent", "-no-color"]

    # Default probes (can be toggled off)
    if opts.get("follow_redirects", True):
        cmd.append("-follow-redirects")
    if opts.get("title", True):
        cmd.append("-title")
    if opts.get("tech_detect", True):
        cmd.append("-tech-detect")
    if opts.get("status_code", True):
        cmd.append("-status-code")
    if opts.get("content_length", True):
        cmd.append("-content-length")
    if opts.get("web_server", True):
        cmd.append("-web-server")

    # Extended probes
    if opts.get("tls_info", False):
        cmd.extend(["-tls-probe", "-tls-grab"])
    if opts.get("favicon_hash", False):
        cmd.append("-favicon")
    if opts.get("response_time", False):
        cmd.append("-response-time")

    # Timing
    cmd.extend(["-timeout", str(opts.get("timeout", 10))])
    if opts.get("retries"):
        cmd.extend(["-retries", str(opts["retries"])])
    if opts.get("rate_limit"):
        cmd.extend(["-rate-limit", str(opts["rate_limit"])])
    if opts.get("concurrency"):
        cmd.extend(["-threads", str(opts["concurrency"])])

    # Pass-through
    if opts.get("extra_flags"):
        cmd.extend(opts["extra_flags"])

    return cmd


# ── nuclei ────────────────────────────────────────────────────────

def build_nuclei_cmd(options: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Targets are fed via stdin.

    Supported options:
      severity          : str|list – comma-sep or list ('medium,high,critical')
      tags              : str|list – template tags (-tags x,y)
      templates         : str|list – specific template paths (-t a.yaml,b.yaml)
      exclude_templates : str|list – exclude template IDs (-exclude-templates x,y)
      rate_limit        : int      – max requests/sec (-rate-limit N)
      concurrency       : int      – concurrent templates (-c N)
      timeout           : int      – per-request timeout sec (-timeout N)
      retries           : int      – retry count (-retries N)
      safe_mode         : bool     – only safe (non-intrusive) templates (-safe)
    """
    opts = options or {}
    cmd = [_NUCLEI_BIN, "-json", "-silent", "-no-color"]

    # Severity
    severity = opts.get("severity", "medium,high,critical")
    if isinstance(severity, list):
        severity = ",".join(severity)
    cmd.extend(["-severity", severity])

    # Template selection
    if opts.get("tags"):
        tags = opts["tags"]
        if isinstance(tags, list):
            tags = ",".join(tags)
        cmd.extend(["-tags", tags])
    if opts.get("templates"):
        tpl = opts["templates"]
        if isinstance(tpl, list):
            tpl = ",".join(tpl)
        cmd.extend(["-t", tpl])
    if opts.get("exclude_templates"):
        exc = opts["exclude_templates"]
        if isinstance(exc, list):
            exc = ",".join(exc)
        cmd.extend(["-exclude-templates", exc])

    # Timing
    cmd.extend(["-timeout", str(opts.get("timeout", 10))])
    cmd.extend(["-rate-limit", str(opts.get("rate_limit", 50))])
    cmd.extend(["-c", str(opts.get("concurrency", 10))])

    if opts.get("retries"):
        cmd.extend(["-retries", str(opts["retries"])])
    if opts.get("safe_mode", False):
        cmd.append("-safe")

    return cmd


# ── nmap ──────────────────────────────────────────────────────────

def build_nmap_cmd(target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Supported options:
      ports_mode         : str  – 'top100' | 'top1000' | 'full' (--top-ports or -p-)
      service_detection  : bool – enable service detection (-sV)
      version_detect     : bool – version probing (implied by -sV)
      timing_profile     : str  – 'T0'..'T5' (-T<n>)
      safe_scripts       : bool – default safe scripts (-sC)
      host_timeout       : str  – per-host timeout (-host-timeout 5m)
      max_retries        : int  – max retries (--max-retries N)
      udp                : bool – UDP scan (-sU)
      output_format      : str  – 'xml' (always appended as -oX -)
      extra_flags        : str  – raw flags as space-separated string
    """
    opts = options or {}
    cmd = [_NMAP_BIN]

    # Scan type
    if opts.get("service_detection", True) or opts.get("version_detect", True):
        cmd.append("-sV")
    if opts.get("safe_scripts", True):
        cmd.append("-sC")
    if opts.get("udp", False):
        cmd.append("-sU")

    # Port range
    ports_mode = opts.get("ports_mode", "top100")
    if ports_mode == "full":
        cmd.append("-p-")
    elif ports_mode == "top1000":
        cmd.extend(["--top-ports", "1000"])
    else:
        cmd.extend(["--top-ports", "100"])

    # Timing
    timing = opts.get("timing_profile", "T4")
    cmd.append(f"-{timing}")

    # Host timeout
    if opts.get("host_timeout"):
        cmd.extend(["--host-timeout", str(opts["host_timeout"])])
    if opts.get("max_retries"):
        cmd.extend(["--max-retries", str(opts["max_retries"])])

    # Extra raw flags
    if opts.get("extra_flags"):
        cmd.extend(str(opts["extra_flags"]).split())

    # Target and output
    cmd.extend([target, "-oX", "-", "--open"])

    return cmd


# ── crawl (Python-based, returns config dict) ─────────────────────

def build_crawl_config(options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Return a config dict for the Python BFS crawler in web_tools.py.

    Supported options:
      max_pages       : int  – max pages to crawl (default 50)
      depth           : int  – max link depth (default 2)
      same_host_only  : bool – restrict to same hostname (default True)
      respect_robots  : bool – honour robots.txt Disallow (default True)
      include_js_links: bool – extract links from inline JS (default False)
      extract_forms   : bool – capture <form> action URLs (default True)
      extract_params  : bool – capture query parameters (default True)
      timeout         : int  – per-request timeout sec (default 8)
    """
    opts = options or {}
    return {
        "max_pages":        opts.get("max_pages", 50),
        "depth":            opts.get("depth", 2),
        "same_host_only":   opts.get("same_host_only", True),
        "respect_robots":   opts.get("respect_robots", True),
        "include_js_links": opts.get("include_js_links", False),
        "extract_forms":    opts.get("extract_forms", True),
        "extract_params":   opts.get("extract_params", True),
        "timeout":          opts.get("timeout", 8),
    }


# ── dirs (Python-based, returns config dict) ──────────────────────

def build_dirs_config(options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Return a config dict for the directory brute-forcer in web_tools.py.

    Supported options:
      wordlist_profile : str  – 'small' | 'medium' (chooses wordlist file)
      wordlist_type    : str  – alias for wordlist_profile
      extensions       : str  – comma-sep extensions to append (e.g. 'php,asp,bak')
      recursion_depth  : int  – max recursive depth (default 0 = flat)
      match_codes      : list – only keep these HTTP status codes
      filter_codes     : list – exclude these HTTP status codes
      threads          : int  – concurrent workers (default 10)
      rate_limit       : float – seconds between requests per thread (default 0.1)
      timeout          : int  – per-request timeout sec (default 5)
    """
    opts = options or {}
    profile = opts.get("wordlist_profile") or opts.get("wordlist_type", "small")

    wordlist_map = {
        "small":  _WORDLIST_DIR / "directories_small.txt",
        "medium": _WORDLIST_DIR / "directories_medium.txt",
    }
    wordlist_path = wordlist_map.get(profile, wordlist_map["small"])

    extensions_raw = opts.get("extensions", "")
    extensions = [e.strip().lstrip(".") for e in extensions_raw.split(",") if e.strip()] if extensions_raw else []

    # Default filter: skip 404/400
    default_filter = [404, 400]

    return {
        "wordlist_path":   str(wordlist_path),
        "extensions":      extensions,
        "recursion_depth": opts.get("recursion_depth", 0),
        "match_codes":     opts.get("match_codes", []),
        "filter_codes":    opts.get("filter_codes", default_filter),
        "threads":         opts.get("threads", opts.get("max_workers", 10)),
        "rate_limit":      opts.get("rate_limit", 0.1),
        "timeout":         opts.get("timeout", 5),
    }
