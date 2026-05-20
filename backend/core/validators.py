"""
core/validators.py — Data sanitation helpers.

Prevents placeholder text, LLM reasoning artifacts, and
garbage values from becoming entities or leads.
"""
import re
import socket


# ── Format validators ───────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
)

_EMAIL_RE = re.compile(
    r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
)

_URL_RE = re.compile(
    r"^https?://[a-z0-9]([a-z0-9._:-]*[a-z0-9])?(/[^\s]*)?$"
)


def is_valid_domain(value: str) -> bool:
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253:
        return False
    return bool(_DOMAIN_RE.match(v))


def is_valid_subdomain(value: str) -> bool:
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253:
        return False
    if not _DOMAIN_RE.match(v):
        return False
    return v.count(".") >= 2


def is_valid_ip(value: str) -> bool:
    v = value.strip()
    try:
        socket.inet_aton(v)
        parts = v.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (socket.error, ValueError):
        return False


def is_valid_email(value: str) -> bool:
    v = value.strip().lower()
    if not v or len(v) > 254:
        return False
    return bool(_EMAIL_RE.match(v))


def is_valid_url(value: str) -> bool:
    v = value.strip().lower()
    if not v or len(v) > 2048:
        return False
    return bool(_URL_RE.match(v))


# ── Garbage / placeholder detectors ────────────────────────────────────────

_PLACEHOLDER_PATTERNS = [
    r"\[.*(?:IP|của|of|from|the|domain|address|target|host).*\]",
    r"IP_OF_",
    r"IP_từ_",
    r"<[A-Z_]+>",
    r"\{[A-Z_]+\}",
    r"xxx+",
    r"example\.com",
    r"test\.local",
    r"placeholder",
    r"your[_-]?domain",
    r"your[_-]?ip",
    r"N/A",
    r"^unknown$",
    r"^none$",
    r"^null$",
    r"^n/a$",
    r"^tbd$",
]

_PLACEHOLDER_RE = re.compile(
    "|".join(f"(?:{p})" for p in _PLACEHOLDER_PATTERNS),
    re.IGNORECASE,
)


def is_placeholder_value(value: str) -> bool:
    if not value or not isinstance(value, str):
        return True
    v = value.strip()
    if not v:
        return True
    return bool(_PLACEHOLDER_RE.search(v))


_SEARCH_QUERY_PREFIXES = [
    "site:", "inurl:", "intext:", "intitle:", "filetype:",
    "ext:", "cache:", "link:", "related:", "info:",
    "allinurl:", "allintitle:", "allintext:",
]


def is_search_query_like(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    v = value.strip().lower()
    for prefix in _SEARCH_QUERY_PREFIXES:
        if prefix in v:
            return True
    if v.startswith('"') and v.endswith('"') and " " in v:
        return True
    return False


_ACTION_VERBS = [
    "investigate", "check", "look up", "analyze", "scan",
    "try", "explore", "query", "find", "search", "review",
    "note:", "todo:", "next step", "suggest", "recommend",
    "consider", "verify", "determine", "identify",
]


def is_reasoning_text_like(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) > 120:
        return True
    if v.count(" ") >= 6:
        vl = v.lower()
        for verb in _ACTION_VERBS:
            if vl.startswith(verb):
                return True
        if any(w in vl for w in ["của", "từ", "cho", "nếu", "hoặc", "cần", "should", "would", "could"]):
            return True
    return False


def is_garbage_value(value: str) -> bool:
    """Combined check: True if value should NOT become an entity."""
    if not value or not isinstance(value, str):
        return True
    v = value.strip()
    if not v or len(v) < 2:
        return True
    if is_placeholder_value(v):
        return True
    if is_search_query_like(v):
        return True
    if is_reasoning_text_like(v):
        return True
    return False
