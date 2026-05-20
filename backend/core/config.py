"""
Typed MINAConfig using Pydantic BaseSettings with full validation.
Backward compatible: legacy constants still exported.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

try:
    from pydantic import BaseSettings
except ImportError:
    from pydantic_settings import BaseSettings  # pydantic v2

# Load .env from backend directory
_BACKEND_DIR = Path(__file__).parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"


class MINAConfig(BaseSettings):
    # === LLM ===
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"

    # === APIs ===
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None

    # === Feature Flags ===
    enable_active_recon: bool = False
    enable_secret_scanning: bool = False
    enable_repo_intel: bool = False
    enable_doc_intel: bool = False
    enable_endpoint_crawl: bool = False
    enable_karma_v2: bool = False

    # === Runtime Limits ===
    max_iterations: int = 10
    max_leads: int = 50
    max_depth: int = 3
    tool_timeout: int = 30
    rate_limit_seconds: float = 1.0

    # === Scan Profile ===
    scan_profile: str = "balanced"  # quick | balanced | deep

    # === Server ===
    backend_port: int = 8000
    frontend_port: int = 3000

    class Config:
        env_file = str(_ENV_FILE)
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"

    @validator("scan_profile")
    def _valid_profile(cls, v):
        if v not in ("quick", "balanced", "deep"):
            return "balanced"
        return v

    @property
    def output_dir(self) -> Path:
        return _BACKEND_DIR / "output"

    @property
    def sessions_dir(self) -> Path:
        return self.output_dir / "sessions"

    @property
    def evidence_dir(self) -> Path:
        return self.output_dir / "evidence"


# Singleton
try:
    config = MINAConfig()
except Exception:
    config = MINAConfig.construct()

# ---------------------------------------------------------------------------
# Legacy module-level constants (backward compat)
# ---------------------------------------------------------------------------
DEEPSEEK_API_KEY: str = config.deepseek_api_key
DEEPSEEK_BASE_URL: str = config.deepseek_base_url
DEEPSEEK_MODEL: str = config.deepseek_model
SHODAN_API_KEY: str = config.shodan_api_key or ""
MAX_ITERATIONS: int = config.max_iterations
MAX_LEADS_PER_ITERATION: int = 5  # kept for any remaining legacy references
TOOL_TIMEOUT: int = config.tool_timeout
RATE_LIMIT_DELAY: float = config.rate_limit_seconds

OUTPUT_DIR: str = str(config.output_dir)
EVIDENCE_DIR: str = str(config.evidence_dir)
REPORT_PATH: str = str(config.output_dir / "report.md")
INTEL_PATH: str = str(config.output_dir / "intel.json")

os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(str(config.sessions_dir), exist_ok=True)


# ---------------------------------------------------------------------------
# EngagementSpec — per-scan configuration used by main.py and graph
# ---------------------------------------------------------------------------

class EngagementSpec(BaseModel):
    """Per-scan specification passed from the API to the graph."""

    target_domain: str
    company_name: str = ""
    allowed_scope: List[str] = []
    out_of_scope: List[str] = []
    active_recon_enabled: bool = True
    rate_limit: float = 2.0
    max_depth: int = 2
    max_iterations: int = 10
    scan_profile: str = "balanced"  # quick | balanced | deep
    wordlist_profile: str = "small"  # small | medium | extended
    agents_enabled: Dict[str, bool] = {}
    # V4: unified feature toggles and per-tool options
    features: Dict[str, bool] = {}
    tool_options: Dict[str, Dict[str, Any]] = {}
    report_detail: str = "detailed"  # summary | detailed | full_inventory
    # V5: explicit tool allow/block lists (separate from data source lists)
    allowed_tools: List[str] = []  # empty = allow all planned tools
    blocked_tools: List[str] = []  # specific tools to disable

    def to_graph_dict(self) -> Dict[str, Any]:
        """Convert to the dict format build_initial_state() expects."""
        # Determine allowed sources based on profile
        sources = PROFILE_SOURCES.get(self.scan_profile, PROFILE_SOURCES["balanced"])

        # V4: Build unified features from agents_enabled + explicit features
        features = {
            "subfinder": True,
            "httpx": True,
            "nuclei": self.scan_profile == "deep" or self.features.get("nuclei", False),
            "nmap": self.scan_profile == "deep" or self.features.get("nmap", False),
            "crawler": self.features.get("crawler", self.scan_profile in ("balanced", "deep")),
            "dir_enum": self.features.get("dir_enum", self.scan_profile in ("balanced", "deep")),
            "shodan": self.features.get("shodan", False),
            "karma": self.agents_enabled.get("karma_v2", False),
            "waf": self.features.get("waf", self.scan_profile == "deep"),
        }
        features.update({k: v for k, v in self.features.items() if k not in features})

        # ── V4 fix: inject tool-dispatch aliases so planner feature gate works ──
        # UI sends "crawler" but planner checks "crawl"; same for dir_enum→dirs, karma→karma_*
        _FEATURE_ALIASES = {
            "crawler":  ["crawl"],
            "dir_enum": ["dirs"],
            "karma":    ["karma_ip", "karma_leaks", "karma_cve", "smap"],
        }
        for alias_key, tool_keys in _FEATURE_ALIASES.items():
            if alias_key in features:
                for tk in tool_keys:
                    features.setdefault(tk, features[alias_key])

        # ── V4 fix: normalise tool_options keys (UI may send "crawl"/"dirs"
        #    or "crawler"/"dir_enum" — ensure both variants exist)
        tool_options = dict(self.tool_options)
        _OPT_ALIASES = {"crawler": "crawl", "dir_enum": "dirs",
                         "crawl": "crawler", "dirs": "dir_enum"}
        for src, dst in _OPT_ALIASES.items():
            if src in tool_options and dst not in tool_options:
                tool_options[dst] = tool_options[src]

        return {
            "session_id": "",
            "target": self.target_domain,
            "company_name": self.company_name,
            "allowed_scope": self.allowed_scope or [self.target_domain],
            "blocked_scope": self.out_of_scope,
            "active_recon_enabled": self.active_recon_enabled,
            "passive_only": not self.active_recon_enabled,
            # allowed_tools / blocked_tools for tool dispatch filtering
            "allowed_tools": self.allowed_tools,   # empty = allow all
            "blocked_tools": self.blocked_tools,
            # allowed_sources / blocked_sources kept for legacy compat + data-source context
            "allowed_sources": [],
            "blocked_sources": [],
            "max_depth": self.max_depth,
            "max_leads": 100,
            "max_active_budget": 20,
            "max_iterations": self.max_iterations,
            "rate_limit_seconds": self.rate_limit,
            "time_budget_seconds": 600,
            "profile": self.scan_profile,
            "wordlist_profile": self.wordlist_profile,
            "mode": "breadth_first",
            "agents_enabled": self.agents_enabled,
            "features": features,
            "tool_options": tool_options,
            "report_detail": self.report_detail,
            "enable_secret_scanning": False,
            "enable_repo_intel": False,
            "enable_doc_intel": False,
            "enable_endpoint_crawl": features.get("crawler", False),
            "enable_karma_v2": self.agents_enabled.get("karma_v2", False),
        }


# Scan profile → allowed tool sources
PROFILE_SOURCES: Dict[str, List[str]] = {
    "quick": [
        "dns", "whois", "crt_sh", "reverse_dns",
    ],
    "balanced": [
        "dns", "whois", "crt_sh", "reverse_dns", "shodan",
        "spf_dmarc", "wayback", "zone_transfer", "js_endpoints",
        "subfinder", "httpx", "headers", "tech", "ssl",
    ],
    "deep": [
        "dns", "whois", "crt_sh", "reverse_dns", "shodan",
        "spf_dmarc", "wayback", "zone_transfer", "js_endpoints",
        "subfinder", "httpx", "headers", "tech", "ssl",
        "nmap", "nuclei", "dirs", "crawl", "waf",
        "dns_bruteforce",
    ],
}

# Wordlist profile → file paths
WORDLIST_PROFILES: Dict[str, Dict[str, str]] = {
    "small": {
        "subdomains": "wordlists/subdomains_top100.txt",
        "directories": "wordlists/directories_small.txt",
    },
    "medium": {
        "subdomains": "wordlists/subdomains_top100.txt",
        "directories": "wordlists/directories_medium.txt",
    },
    "extended": {
        "subdomains": "wordlists/subdomains_extended.txt",
        "directories": "wordlists/directories_medium.txt",
    },
}
