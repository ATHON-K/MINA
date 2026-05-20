"""
core/scope.py — ROE/Safety layer.

Centralised scope enforcement: passive, osint, and active recon
must ALL pass through these checks before acting on any target.
"""
import re
import logging
from typing import Any

logger = logging.getLogger(__name__)


def is_in_scope(value: str, engagement_spec: dict) -> bool:
    """Check if a value (domain/IP/URL) is within allowed scope."""
    if not value:
        return False
    v = value.strip().lower()
    allowed = engagement_spec.get("allowed_scope", [])
    blocked = engagement_spec.get("blocked_scope", [])

    # First check if explicitly blocked
    if _matches_any(v, blocked):
        return False

    # If no allowed list, everything not blocked is in scope
    if not allowed:
        return True

    return _matches_any(v, allowed)


def is_out_of_scope(value: str, engagement_spec: dict) -> bool:
    """Inverse of is_in_scope. True if value should NOT be processed."""
    return not is_in_scope(value, engagement_spec)


def allow_active_for_lead(lead: Any, engagement_spec: dict) -> bool:
    """Check if active recon is allowed for this specific lead."""
    if not engagement_spec.get("active_recon_enabled", False):
        return False

    agents = engagement_spec.get("agents_enabled", {})
    if not agents.get("active_recon", True):
        return False

    value = lead.value if hasattr(lead, "value") else str(lead)
    return is_in_scope(value, engagement_spec)


def filter_in_scope_leads(leads: list, engagement_spec: dict) -> list:
    """Filter a list of leads to only those in scope."""
    result = []
    for lead in leads:
        value = lead.value if hasattr(lead, "value") else str(lead)
        if is_in_scope(value, engagement_spec):
            result.append(lead)
        else:
            logger.debug("[Scope] Filtered out lead: %s", value)
    return result


def filter_allowed_tasks(tasks: list, engagement_spec: dict) -> list:
    """Filter tasks to only those allowed by scope and agent toggles.

    Tool filtering uses the following keys (in priority order):
    - allowed_tools / blocked_tools  — preferred (new schema)
    - allowed_sources / blocked_sources — legacy backward compat
    An empty whitelist means *allow all* (no restriction).
    """
    agents = engagement_spec.get("agents_enabled", {})

    # Build tool whitelist/blacklist — merge new + legacy keys
    allowed_tools = set(engagement_spec.get("allowed_tools", []))
    blocked_tools = set(engagement_spec.get("blocked_tools", []))
    # Legacy compat: blocked_sources / allowed_sources also gate tool dispatch
    blocked_tools |= set(engagement_spec.get("blocked_sources", []))
    allowed_tools |= set(engagement_spec.get("allowed_sources", []))

    result = []

    for task in tasks:
        tool = task.get("tool", "")
        target = task.get("target", "")

        # Block if in blocked list
        if tool in blocked_tools:
            continue

        # Whitelist check — only enforced when whitelist is non-empty
        if allowed_tools and tool not in allowed_tools:
            continue

        # Check target in scope
        if target and is_out_of_scope(target, engagement_spec):
            continue

        # Check agent category toggle
        category = task.get("agent_category", "passive")
        if category == "active" and not agents.get("active_recon", True):
            continue
        if category == "active" and not engagement_spec.get("active_recon_enabled", False):
            continue
        if category == "karma" and not agents.get("karma_v2", False):
            continue
        if category == "osint" and not agents.get("osint", True):
            continue

        result.append(task)

    return result


def is_garbage_lead(value: str) -> bool:
    """
    Reject lead values that are LLM-generated garbage, not real targets.

    Catches:
    - Natural language sentences
    - Placeholders like [IP của ...]
    - Descriptive text like "Investigate actual IP..."
    """
    if not value or not isinstance(value, str):
        return True

    v = value.strip()

    # Too long for a real target (domain/IP/URL)
    if len(v) > 200:
        return True

    # Contains brackets typical of LLM placeholders
    if re.search(r"\[.*(?:IP|của|of|from|the).*\]", v, re.IGNORECASE):
        return True

    # Starts with action verbs (natural language)
    action_prefixes = [
        "investigate", "check", "look up", "analyze", "scan",
        "try", "explore", "query", "find", "search", "review",
        "note:", "todo:", "next step",
    ]
    vl = v.lower()
    for prefix in action_prefixes:
        if vl.startswith(prefix):
            return True

    # Contains too many spaces (natural language sentence)
    if v.count(" ") >= 5:
        return True

    # Contains Vietnamese sentence markers
    if any(w in vl for w in ["của", "từ", "cho", "nếu", "hoặc", "cần"]):
        return True

    return False


# ── Internal helpers ─────────────────────────────────────────────

def _matches_any(value: str, patterns: list) -> bool:
    """Check if value matches any pattern in list (suffix/exact/URL-hostname).

    Avoids false-positive substring matches (e.g. 'evil-example.com' should
    NOT match when pattern is 'example.com').
    """
    # Normalise: if value is a URL, extract hostname for domain checks
    host = _extract_host(value)

    for pattern in patterns:
        p = str(pattern).strip().lower()
        if not p:
            continue
        # Exact match on raw value or extracted host
        if value == p or host == p:
            return True
        # Domain suffix match: sub.example.com matches example.com (dot-anchored)
        if host.endswith(f".{p}") or value.endswith(f".{p}"):
            return True
        # IP / CIDR pass-through (simple equality already handled above)
    return False


def _extract_host(value: str) -> str:
    """Extract hostname from a URL, or return value as-is if not a URL."""
    if value.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            return urlparse(value).hostname or value
        except Exception:
            pass
    return value
