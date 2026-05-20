"""
core/planner.py — Hybrid planning: deterministic baseline + LLM augmentation.

The baseline ensures every lead type gets consistent tool coverage.
Profile (quick/balanced/deep) controls which extras are added.
LLM only AUGMENTS — never replaces — the baseline.

V4: Added tool_options forwarding, expected_observations, tool health
    filtering, collector family grouping, and reason/skip tracking.
"""
import logging
from typing import Any, Dict, List, Optional

from core.scope import filter_allowed_tasks, is_garbage_lead
from core.collector_registry import COLLECTOR_FAMILIES, get_collector_family  # noqa: F401 – re-exported for backward compat

logger = logging.getLogger(__name__)


def _field(obj, key, default=""):
    """Get field from Pydantic model or dict safely."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

# ── Baseline task matrices per lead type ──────────────────────────
# "min_profile": minimum scan profile that includes this task (quick < balanced < deep)

_PROFILE_LEVEL = {"quick": 0, "balanced": 1, "deep": 2}

BASELINE_DOMAIN: List[Dict] = [
    # === Always (quick+) ===
    {"tool": "dns",                  "priority": 0.95, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "whois",                "priority": 0.90, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "crt_sh",               "priority": 0.90, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "subdomain_discovery",  "priority": 0.85, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "asn",                  "priority": 0.75, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "spf_dmarc",            "priority": 0.80, "agent_category": "osint",    "min_profile": "quick"},
    {"tool": "reverse_dns",          "priority": 0.70, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "wayback",              "priority": 0.65, "agent_category": "osint",    "min_profile": "quick"},
    {"tool": "email_harvest",        "priority": 0.60, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "dns_dumpster",         "priority": 0.65, "agent_category": "passive",  "min_profile": "quick"},
    # === balanced+ ===
    {"tool": "subfinder",            "priority": 0.75, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "zone_transfer",        "priority": 0.60, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "js_endpoints",         "priority": 0.50, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "reverse_ip",           "priority": 0.55, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "google_analytics_id",  "priority": 0.50, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "reverse_whois",        "priority": 0.48, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "company_profile",      "priority": 0.45, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "public_contact",       "priority": 0.42, "agent_category": "osint",    "min_profile": "balanced"},
    # === deep ===
    {"tool": "repo_discovery",       "priority": 0.40, "agent_category": "osint",    "min_profile": "deep"},
    {"tool": "public_doc_discovery", "priority": 0.38, "agent_category": "osint",    "min_profile": "deep"},
    {"tool": "infra_asn_enrich",     "priority": 0.36, "agent_category": "osint",    "min_profile": "deep"},
    {"tool": "credential_signal",    "priority": 0.35, "agent_category": "osint",    "min_profile": "deep"},
    {"tool": "bgp_range",            "priority": 0.33, "agent_category": "osint",    "min_profile": "deep"},
    # === karma (requires karma toggle) ===
    {"tool": "karma_ip",             "priority": 0.55, "agent_category": "karma",    "min_profile": "balanced"},
    {"tool": "karma_leaks",          "priority": 0.50, "agent_category": "karma",    "min_profile": "balanced"},
    {"tool": "karma_cve",            "priority": 0.48, "agent_category": "karma",    "min_profile": "balanced"},
    {"tool": "smap",                 "priority": 0.45, "agent_category": "karma",    "min_profile": "balanced"},
]

BASELINE_SUBDOMAIN: List[Dict] = [
    # === Always (quick+) ===
    {"tool": "dns",          "priority": 0.95, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "httpx",        "priority": 0.85, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "headers",      "priority": 0.80, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "tech",         "priority": 0.75, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "ssl",          "priority": 0.70, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "robots",       "priority": 0.65, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "http_methods", "priority": 0.62, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "favicon",      "priority": 0.60, "agent_category": "active",   "min_profile": "quick"},
    # === balanced+ ===
    {"tool": "web_surface",  "priority": 0.68, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "wayback",      "priority": 0.58, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "js_endpoints", "priority": 0.55, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "params",       "priority": 0.52, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "dirs",         "priority": 0.50, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "crawl",        "priority": 0.45, "agent_category": "active",   "min_profile": "balanced"},
    # === deep ===
    {"tool": "nuclei",       "priority": 0.58, "agent_category": "active",   "min_profile": "deep"},
    {"tool": "waf",          "priority": 0.48, "agent_category": "active",   "min_profile": "deep"},
    {"tool": "vhost",        "priority": 0.45, "agent_category": "active",   "min_profile": "deep"},
    {"tool": "banner",       "priority": 0.42, "agent_category": "active",   "min_profile": "deep"},
    {"tool": "cloud",        "priority": 0.40, "agent_category": "active",   "min_profile": "deep"},
]

BASELINE_IP: List[Dict] = [
    {"tool": "reverse_dns",  "priority": 0.90, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "shodan",       "priority": 0.85, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "asn",          "priority": 0.75, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "nmap",         "priority": 0.80, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "ssl",          "priority": 0.60, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "banner",       "priority": 0.55, "agent_category": "active",   "min_profile": "deep"},
]

BASELINE_SERVICE: List[Dict] = [
    {"tool": "nmap",               "priority": 0.90, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "banner",             "priority": 0.82, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "cve_lookup",         "priority": 0.80, "agent_category": "osint",    "min_profile": "quick"},
    {"tool": "shodan",             "priority": 0.85, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "headers",            "priority": 0.75, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "ssl",                "priority": 0.70, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "service_metadata",   "priority": 0.65, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "nuclei",             "priority": 0.60, "agent_category": "active",   "min_profile": "deep"},
]

BASELINE_ENDPOINT: List[Dict] = [
    {"tool": "headers",      "priority": 0.85, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "web_surface",  "priority": 0.80, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "robots",       "priority": 0.78, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "http_methods", "priority": 0.75, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "crawl",        "priority": 0.72, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "dirs",         "priority": 0.68, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "tech",         "priority": 0.65, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "favicon",      "priority": 0.62, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "params",       "priority": 0.60, "agent_category": "active",   "min_profile": "balanced"},
    {"tool": "js_endpoints", "priority": 0.58, "agent_category": "osint",    "min_profile": "balanced"},
]

BASELINE_EMAIL: List[Dict] = [
    {"tool": "spf_dmarc",   "priority": 0.80, "agent_category": "osint",    "min_profile": "quick"},
]

BASELINE_ORG: List[Dict] = [
    {"tool": "crt_sh",              "priority": 0.85, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "whois",               "priority": 0.80, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "subdomain_discovery", "priority": 0.75, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "asn",                 "priority": 0.70, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "wayback",             "priority": 0.60, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "company_profile",     "priority": 0.65, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "reverse_whois",       "priority": 0.58, "agent_category": "osint",    "min_profile": "balanced"},
    {"tool": "repo_discovery",      "priority": 0.50, "agent_category": "osint",    "min_profile": "deep"},
]

BASELINE_ASN: List[Dict] = [
    {"tool": "asn",              "priority": 0.90, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "infra_asn_enrich", "priority": 0.80, "agent_category": "osint",    "min_profile": "balanced"},
]

BASELINE_CERTIFICATE: List[Dict] = [
    {"tool": "ssl",          "priority": 0.85, "agent_category": "active",   "min_profile": "quick"},
    {"tool": "crt_sh",       "priority": 0.80, "agent_category": "passive",  "min_profile": "quick"},
    {"tool": "cert_detail",  "priority": 0.75, "agent_category": "active",   "min_profile": "balanced"},
]

# Backward-compat alias (used in tests)
BASELINE_URL = BASELINE_ENDPOINT

_BASELINE_MAP: Dict[str, List[Dict]] = {
    "domain":       BASELINE_DOMAIN,
    "subdomain":    BASELINE_SUBDOMAIN,
    "ip":           BASELINE_IP,
    "ip_address":   BASELINE_IP,
    "service":      BASELINE_SERVICE,
    "port":         BASELINE_SERVICE,
    "endpoint":     BASELINE_ENDPOINT,
    "url":          BASELINE_ENDPOINT,
    "webapp":       BASELINE_SUBDOMAIN,
    "email":        BASELINE_EMAIL,
    "email_address": BASELINE_EMAIL,
    "org":          BASELINE_ORG,
    "organization": BASELINE_ORG,
    "asn":          BASELINE_ASN,
    "certificate":  BASELINE_CERTIFICATE,
}

# ── V4: Expected observations per tool (for coverage tracking) ────
TOOL_EXPECTED_OBSERVATIONS: Dict[str, List[str]] = {
    "dns":                  ["domain_found", "ip_found", "subdomain_found"],
    "whois":                ["org_found", "email_found"],
    "crt_sh":               ["cert_found", "subdomain_found"],
    "subdomain_discovery":  ["subdomain_found"],
    "subfinder":            ["subdomain_found"],
    "httpx":                ["webapp_alive", "technology_found"],
    "headers":              ["header_found"],
    "tech":                 ["technology_found"],
    "ssl":                  ["cert_found", "vulnerability_found"],
    "robots":               ["endpoint_found", "url_found"],
    "http_methods":         ["vulnerability_found", "header_found"],
    "waf":                  ["waf_detected"],
    "web_surface":          ["webapp_alive", "technology_found"],
    "dirs":                 ["endpoint_found"],
    "crawl":                ["endpoint_found", "url_found"],
    "favicon":              ["technology_found"],
    "params":               ["parameter_found"],
    "nmap":                 ["port_open", "service_detected"],
    "nuclei":               ["vulnerability_found"],
    "banner":               ["service_detected"],
    "cloud":                ["url_found", "technology_found"],
    "shodan":               ["port_open", "service_detected", "vulnerability_found"],
    "spf_dmarc":            ["header_found"],
    "asn":                  ["asn_found"],
    "reverse_dns":          ["subdomain_found"],
    "wayback":              ["url_found"],
    "email_harvest":        ["email_found"],
    "js_endpoints":         ["endpoint_found"],
    "company_profile":      ["org_found"],
    "repo_discovery":       ["repo_found"],
    "public_doc_discovery": ["document_found"],
    "public_contact":       ["person_found", "email_found"],
    "infra_asn_enrich":     ["asn_found", "ip_found"],
    "zone_transfer":        ["subdomain_found", "ip_found"],
    "reverse_ip":           ["domain_found", "subdomain_found"],
    "reverse_whois":        ["domain_found", "org_found"],
    "google_analytics_id":  ["domain_found"],
    "cve_lookup":           ["vulnerability_found"],
    "karma_ip":             ["ip_found", "port_open", "service_detected"],
    "karma_leaks":          ["credential_signal_found"],
    "karma_cve":            ["vulnerability_found"],
    "smap":                 ["port_open", "service_detected"],
    "vhost":                ["subdomain_found", "webapp_alive"],
    "cert_detail":          ["cert_found"],
    "bgp_range":            ["ip_found", "asn_found"],
    "org_ip_range":         ["ip_found", "org_found"],
    "credential_signal":    ["credential_signal_found"],
    "service_metadata":     ["service_detected", "vulnerability_found"],
}

# ── V4: Expected NEW LEAD types a tool can derive ────────────────
TOOL_EXPECTED_NEW_LEADS: Dict[str, List[str]] = {
    "dns":                  ["ip", "subdomain"],
    "whois":                ["org", "email"],
    "crt_sh":               ["subdomain", "certificate"],
    "subdomain_discovery":  ["subdomain"],
    "subfinder":            ["subdomain"],
    "httpx":                ["url", "endpoint"],
    "headers":              [],
    "tech":                 [],
    "ssl":                  ["certificate"],
    "robots":               ["endpoint", "url"],
    "http_methods":         [],
    "waf":                  [],
    "web_surface":          ["endpoint", "url"],
    "dirs":                 ["endpoint"],
    "crawl":                ["endpoint", "url", "subdomain"],
    "favicon":              [],
    "params":               [],
    "nmap":                 ["service"],
    "nuclei":               [],
    "banner":               [],
    "cloud":                ["url", "subdomain"],
    "shodan":               ["service", "ip"],
    "spf_dmarc":            [],
    "asn":                  ["ip"],
    "reverse_dns":          ["subdomain"],
    "wayback":              ["url", "endpoint"],
    "email_harvest":        ["email"],
    "js_endpoints":         ["endpoint", "url"],
    "company_profile":      ["domain", "org"],
    "repo_discovery":       ["url"],
    "public_doc_discovery": ["url", "document"],
    "public_contact":       ["email", "person"],
    "infra_asn_enrich":     ["ip", "asn"],
    "zone_transfer":        ["subdomain", "ip"],
    "reverse_ip":           ["domain", "subdomain"],
    "reverse_whois":        ["domain"],
    "google_analytics_id":  ["domain"],
    "cve_lookup":           [],
    "karma_ip":             ["ip", "service"],
    "karma_leaks":          [],
    "karma_cve":            [],
    "smap":                 ["service"],
    "vhost":                ["subdomain"],
    "cert_detail":          ["certificate", "subdomain"],
    "bgp_range":            ["ip"],
    "org_ip_range":         ["ip", "asn"],
    "credential_signal":    [],
    "service_metadata":     [],
}

# ── V4: Active level per tool ────────────────────────────────────
# "none" = pure passive, "low" = light probing (HTTP GET), "medium" = moderate scanning,
# "high" = heavy scanning (nuclei, nmap full, dir brute)
TOOL_ACTIVE_LEVEL: Dict[str, str] = {
    # Passive (none)
    "dns": "none", "whois": "none", "crt_sh": "none", "subdomain_discovery": "none",
    "asn": "none", "reverse_dns": "none", "wayback": "none", "email_harvest": "none",
    "dns_dumpster": "none", "shodan": "none", "spf_dmarc": "none",
    "zone_transfer": "none", "reverse_ip": "none", "reverse_whois": "none",
    "google_analytics_id": "none", "company_profile": "none", "public_contact": "none",
    "repo_discovery": "none", "public_doc_discovery": "none",
    "infra_asn_enrich": "none", "cve_lookup": "none",
    "karma_ip": "none", "karma_leaks": "none", "karma_cve": "none", "smap": "none",
    "cert_detail": "low", "bgp_range": "none", "org_ip_range": "none",
    "credential_signal": "none", "service_metadata": "none",
    # Low (light HTTP probing)
    "httpx": "low", "headers": "low", "tech": "low", "ssl": "low",
    "robots": "low", "http_methods": "low", "favicon": "low",
    "web_surface": "low", "banner": "low", "waf": "low",
    # Medium (active enumeration)
    "subfinder": "medium", "js_endpoints": "medium", "crawl": "medium",
    "params": "medium", "cloud": "medium", "vhost": "medium",
    # High (heavy scanning / brute force)
    "nmap": "high", "nuclei": "high", "dirs": "high",
}

# ── V4: Collector family grouping (authoritative source: core/collector_registry.py) ─────
# COLLECTOR_FAMILIES imported from core.collector_registry above.


# ── Public API ────────────────────────────────────────────────────

def build_baseline_plan_for_lead(lead: Any, state: dict) -> list:
    """
    Build deterministic baseline task plan for a lead based on type + profile.
    Each task follows the structured What/Where/How schema:
    - collector_family, tool, lead_type, target, priority, active_level,
      expected_observations, expected_new_leads, tool_options, reason, agent_category
    """
    lead_type = _field(lead, "type", "")
    lead_value = _field(lead, "value", "")

    if is_garbage_lead(lead_value):
        logger.warning("[Planner] Rejected garbage lead: %s", lead_value[:80])
        return []

    spec = state.get("engagement_spec", {})
    profile = spec.get("profile", "balanced")
    profile_level = _PROFILE_LEVEL.get(profile, 1)
    karma_enabled = spec.get("enable_karma_v2", False) or spec.get("agents_enabled", {}).get("karma_v2", False)
    features = spec.get("features", {})
    global_tool_options = spec.get("tool_options", {})
    tool_health = state.get("tool_health_snapshot", {})

    baseline = _BASELINE_MAP.get(lead_type, [])
    tasks = []
    skipped = []

    for template in baseline:
        tool = template["tool"]
        cat = template["agent_category"]
        min_prof = template.get("min_profile", "quick")
        min_level = _PROFILE_LEVEL.get(min_prof, 0)

        # Profile gate
        if profile_level < min_level:
            skipped.append(f"{tool}(need={min_prof})")
            continue

        # Karma gate
        if cat == "karma" and not karma_enabled:
            skipped.append(f"{tool}(karma_off)")
            continue

        # V4: Feature flag gate — if a feature is explicitly disabled, skip
        if tool in features and not features[tool]:
            skipped.append(f"{tool}(feature_off)")
            continue

        # V4: Tool health gate — skip tools known to be unavailable
        if tool_health and tool in tool_health:
            health_info = tool_health[tool]
            if isinstance(health_info, dict) and not health_info.get("ready", True):
                skipped.append(f"{tool}(unhealthy)")
                continue

        # V4: Merge per-tool options from engagement spec
        task_options = global_tool_options.get(tool, {})
        active_level = TOOL_ACTIVE_LEVEL.get(tool, "none")

        # Build reason — meaningful context about WHY this tool for THIS lead
        _reason_map = {
            "none": f"Passive intelligence gathering on {lead_type} — safe, no target contact",
            "low": f"Light HTTP probing to fingerprint {lead_type} surface",
            "medium": f"Active enumeration to expand attack surface from {lead_type}",
            "high": f"Deep scanning for vulnerabilities/services on {lead_type}",
        }
        reason = _reason_map.get(active_level, f"Baseline {min_prof} task for {lead_type}")

        tasks.append({
            "tool": tool,
            "target": lead_value,
            "lead_type": lead_type,
            "priority": template["priority"],
            "agent_category": cat,
            "active_level": active_level,
            "collector_family": COLLECTOR_FAMILIES.get(tool, "other"),
            "expected_observations": TOOL_EXPECTED_OBSERVATIONS.get(tool, []),
            "expected_new_leads": TOOL_EXPECTED_NEW_LEADS.get(tool, []),
            "tool_options": task_options if task_options else {},
            "reason": reason,
            "requires_scope_check": True,
            # Legacy compat — collectors still read "options"
            "options": task_options if task_options else {},
        })

    if tasks:
        logger.info("[Planner] %s:%s → %d tasks planned (profile=%s)",
                     lead_type, lead_value[:40], len(tasks), profile)
    if skipped:
        logger.debug("[Planner] Skipped for %s: %s", lead_value[:40], ", ".join(skipped[:10]))

    # ── Graceful degradation: record skipped tools for report limitations ──
    if skipped:
        degradation = state.get("_degradation_warnings", [])
        for skip_entry in skipped:
            degradation.append({
                "lead_type": lead_type,
                "lead_value": lead_value[:60],
                "tool_skipped": skip_entry,
            })
        state["_degradation_warnings"] = degradation

    return tasks


def augment_plan_with_llm(lead: Any, baseline_plan: list, llm_tasks: list) -> list:
    """
    Merge LLM-suggested tasks into the baseline plan.
    LLM tasks are added only if not already in baseline (by tool+target key).
    Enriches LLM tasks with structured fields from mapping dicts.
    """
    lead_type = _field(lead, "type", "")
    existing_keys = {(t["tool"], t["target"]) for t in baseline_plan}
    augmented = list(baseline_plan)

    for task in llm_tasks:
        tool = task.get("tool", "")
        target = task.get("target", "")
        if not tool or not target:
            continue
        key = (tool, target)
        if key in existing_keys:
            continue

        active_level = task.get("active_level") or TOOL_ACTIVE_LEVEL.get(tool, "none")
        reason = task.get("reason") or task.get("note") or f"LLM-suggested {tool} for {lead_type}"
        tool_options = task.get("tool_options") or task.get("options") or {}

        augmented.append({
            "tool": tool,
            "target": target,
            "lead_type": task.get("lead_type", lead_type),
            "priority": float(task.get("priority", 0.5)),
            "agent_category": task.get("agent_category", "passive"),
            "active_level": active_level,
            "collector_family": task.get("collector_family") or COLLECTOR_FAMILIES.get(tool, "other"),
            "expected_observations": task.get("expected_observations") or TOOL_EXPECTED_OBSERVATIONS.get(tool, []),
            "expected_new_leads": task.get("expected_new_leads") or TOOL_EXPECTED_NEW_LEADS.get(tool, []),
            "tool_options": tool_options,
            "reason": reason,
            "requires_scope_check": True,
            "source": "llm_augmentation",
            # Legacy compat
            "options": tool_options,
        })
        existing_keys.add(key)

    return augmented


def dedupe_plan(tasks: list) -> list:
    """Deduplicate tasks by (tool, target) key, keeping highest priority."""
    best: Dict[tuple, dict] = {}
    for t in tasks:
        key = (t["tool"], t["target"])
        if key not in best or t.get("priority", 0) > best[key].get("priority", 0):
            best[key] = t
    return list(best.values())


def apply_agent_toggles(tasks: list, engagement_spec: dict) -> list:
    """Filter tasks based on agent toggles and scope."""
    return filter_allowed_tasks(tasks, engagement_spec)


def split_tasks_by_category(tasks: list) -> dict:
    """Split tasks into passive_tasks and active_tasks for the pipeline."""
    passive = []
    osint = []
    active = []
    karma = []

    for t in tasks:
        cat = t.get("agent_category", "passive")
        if cat == "active":
            active.append(t)
        elif cat == "osint":
            osint.append(t)
        elif cat == "karma":
            karma.append(t)
        else:
            passive.append(t)

    # Sort each by priority descending
    for lst in (passive, osint, active, karma):
        lst.sort(key=lambda x: -x.get("priority", 0))

    # passive + osint + karma go through passive pipeline; active separate
    return {
        "passive_tasks": passive + osint + karma,
        "active_tasks": active,
    }
