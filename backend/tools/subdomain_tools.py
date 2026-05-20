"""
Subdomain discovery tools with 3 tiered profiles.
"""
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SUBDOMAIN_PROFILES = {
    "quick": {
        "wordlist": "wordlists/subdomains_top100.txt",
        "threads": 10,
        "timeout": 3.0,
        "resolvers": 1,
        "use_crt_sh": True,
        "use_bruteforce": False,
        "use_permutations": False,
    },
    "balanced": {
        "wordlist": "wordlists/subdomains_extended.txt",
        "threads": 20,
        "timeout": 5.0,
        "resolvers": 2,
        "use_crt_sh": True,
        "use_bruteforce": True,
        "use_permutations": False,
    },
    "deep": {
        "wordlist": "wordlists/subdomains_extended.txt",
        "threads": 40,
        "timeout": 8.0,
        "resolvers": 4,
        "use_crt_sh": True,
        "use_bruteforce": True,
        "use_permutations": True,
    },
}


@dataclass
class SubdomainResult:
    discovered: set = field(default_factory=set)
    resolved: dict = field(default_factory=dict)     # subdomain -> ip
    live: set = field(default_factory=set)            # with http/https open
    wildcard: set = field(default_factory=set)
    unresolved: set = field(default_factory=set)
    sources: dict = field(default_factory=dict)       # subdomain -> [sources]


def run_subdomain_discovery(domain: str, profile: str = "balanced") -> dict:
    """
    Main entry point. Returns a normalized dict with discovered/resolved/live/wildcard/unresolved.
    """
    cfg = SUBDOMAIN_PROFILES.get(profile, SUBDOMAIN_PROFILES["balanced"])
    result = SubdomainResult()

    # Step 1: crt.sh passive
    if cfg["use_crt_sh"]:
        _collect_from_crtsh(domain, result)

    # Step 2: Bruteforce via wordlist
    if cfg["use_bruteforce"]:
        wordlist = _load_wordlist(cfg["wordlist"])
        _bruteforce_subdomains(domain, wordlist, result, cfg)

    # Step 3: Permutations on already-found subdomains
    if cfg["use_permutations"] and result.discovered:
        _permutation_scan(domain, result, cfg)

    # Step 4: Resolve all discovered
    _resolve_all(domain, result, cfg)

    return {
        "success": True,
        "domain": domain,
        "profile": profile,
        "discovered": sorted(result.discovered),
        "resolved": result.resolved,
        "live": sorted(result.live),
        "wildcard": sorted(result.wildcard),
        "unresolved": sorted(result.unresolved),
        "total": len(result.discovered),
        "sources": result.sources,
    }


def _collect_from_crtsh(domain: str, result: SubdomainResult):
    """Get subdomains from Certificate Transparency via crt.sh."""
    try:
        from tools.cert_tools import crt_sh_query
        res = crt_sh_query(domain)
        if res.get("success"):
            for sub in res.get("data", {}).get("subdomains", []):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(domain) and sub not in result.discovered:
                    result.discovered.add(sub)
                    result.sources.setdefault(sub, []).append("crt_sh")
    except Exception as exc:
        logger.debug("[SubdomainTools] crt_sh error: %s", exc)


def _load_wordlist(path: str) -> list:
    """Load wordlist relative to backend/."""
    base = Path(__file__).parent.parent / path
    if not base.exists():
        alt = Path("backend") / path
        if alt.exists():
            base = alt
        else:
            logger.warning("[SubdomainTools] wordlist not found: %s", path)
            return []
    with open(base, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _bruteforce_subdomains(domain: str, wordlist: list, result: SubdomainResult, cfg: dict):
    """DNS bruteforce with threading."""
    if not wordlist:
        return

    def probe(word):
        fqdn = f"{word}.{domain}"
        try:
            socket.setdefaulttimeout(cfg["timeout"])
            addr = socket.gethostbyname(fqdn)
            return fqdn, addr
        except socket.gaierror:
            return fqdn, None

    with ThreadPoolExecutor(max_workers=cfg["threads"]) as pool:
        futures = {pool.submit(probe, w): w for w in wordlist}
        for future in as_completed(futures):
            fqdn, addr = future.result()
            result.discovered.add(fqdn)
            if addr:
                result.resolved[fqdn] = addr
                result.sources.setdefault(fqdn, []).append("bruteforce")
            else:
                result.unresolved.add(fqdn)


def _permutation_scan(domain: str, result: SubdomainResult, cfg: dict):
    """Generate permutations from already-discovered subdomains."""
    SUFFIXES = ["-dev", "-staging", "-api", "-admin", "-test", "-prod",
                "-beta", "-old", "2", "-new", "-int", "-internal"]
    PREFIXES = ["dev.", "staging.", "api.", "admin.", "test.", "prod.",
                "beta.", "old.", "new.", "int.", "internal."]

    candidates = set()
    for sub in list(result.discovered):
        label = sub.replace(f".{domain}", "").split(".")[0]
        for suffix in SUFFIXES:
            candidates.add(f"{label}{suffix}.{domain}")
        for prefix in PREFIXES:
            candidates.add(f"{prefix}{label}.{domain}")

    def probe(fqdn):
        try:
            socket.setdefaulttimeout(cfg["timeout"])
            addr = socket.gethostbyname(fqdn)
            return fqdn, addr
        except socket.gaierror:
            return fqdn, None

    with ThreadPoolExecutor(max_workers=cfg["threads"]) as pool:
        futures = {pool.submit(probe, f): f for f in candidates}
        for future in as_completed(futures):
            fqdn, addr = future.result()
            if addr:
                result.discovered.add(fqdn)
                result.resolved[fqdn] = addr
                result.sources.setdefault(fqdn, []).append("permutation")


def _resolve_all(domain: str, result: SubdomainResult, cfg: dict):
    """Resolve any discovered-but-not-yet-resolved subdomains, check wildcards."""
    for sub in list(result.discovered):
        if sub in result.resolved or sub in result.unresolved:
            continue
        try:
            socket.setdefaulttimeout(cfg["timeout"])
            addr = socket.gethostbyname(sub)
            result.resolved[sub] = addr
        except socket.gaierror:
            result.unresolved.add(sub)

    # Basic wildcard detection: if random-subdomain.domain resolves, everything "resolves"
    try:
        wc = socket.gethostbyname(f"randomxyz12345.{domain}")
        logger.debug("[SubdomainTools] wildcard detected for %s -> %s", domain, wc)
        result.wildcard.add(f"*.{domain}")
    except Exception:
        pass
