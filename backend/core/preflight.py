"""
core/preflight.py — Pre-scan validation: binaries, API keys, config options.

Runs BEFORE the scan pipeline starts.  Returns a structured report so
setup_node can decide whether to abort or degrade gracefully.
"""
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Check result ──────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    ok: bool
    severity: str = "warning"   # "critical" | "warning" | "info"
    message: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        d = {"name": self.name, "ok": self.ok, "severity": self.severity,
             "message": self.message}
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class PreflightReport:
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(not c.ok and c.severity == "critical" for c in self.checks)

    @property
    def warnings(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.ok and c.severity == "warning"]

    @property
    def all_ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "all_ok": self.all_ok,
            "has_critical": self.has_critical,
            "checks": [c.to_dict() for c in self.checks],
        }

    def summary_lines(self) -> List[str]:
        lines = []
        for c in self.checks:
            icon = "✓" if c.ok else ("✗" if c.severity == "critical" else "⚠")
            lines.append(f"  {icon} {c.name}: {c.message}")
        return lines


# ── Individual checks ─────────────────────────────────────────────

def _check_binary_exists(name: str, version_flag: str = "--version") -> CheckResult:
    """Check if CLI binary exists in PATH."""
    path = shutil.which(name)
    if not path:
        return CheckResult(name=f"binary:{name}", ok=False, severity="warning",
                           message=f"{name} not found in PATH",
                           detail="Install the tool or add its directory to PATH")
    return CheckResult(name=f"binary:{name}", ok=True,
                       message=f"found at {path}")


def _check_binary_runnable(name: str, test_flag: str = "--version") -> CheckResult:
    """Try actually running the binary to confirm it's functional."""
    path = shutil.which(name)
    if not path:
        return CheckResult(name=f"runnable:{name}", ok=False, severity="warning",
                           message=f"{name} not in PATH — skip runnable check")
    try:
        proc = subprocess.run(
            [path, test_flag],
            capture_output=True, text=True, timeout=15,
        )
        version = (proc.stdout.strip() or proc.stderr.strip())[:120]
        return CheckResult(name=f"runnable:{name}", ok=True,
                           message=f"OK — {version[:60]}")
    except subprocess.TimeoutExpired:
        return CheckResult(name=f"runnable:{name}", ok=False, severity="warning",
                           message=f"{name} timed out on {test_flag}")
    except Exception as exc:
        return CheckResult(name=f"runnable:{name}", ok=False, severity="warning",
                           message=f"{name} error: {exc}")


_API_KEY_PATTERNS = {
    "SHODAN_API_KEY": (r"^[a-zA-Z0-9]{20,}$", "Shodan API key"),
    "VIRUSTOTAL_API_KEY": (r"^[a-fA-F0-9]{64}$", "VirusTotal API key"),
}


def _check_api_key(env_var: str) -> CheckResult:
    """Check if API key env var is set and has valid format."""
    val = os.environ.get(env_var, "")
    if not val:
        return CheckResult(name=f"apikey:{env_var}", ok=False, severity="warning",
                           message=f"{env_var} not set — tools that require it will be skipped")
    pattern_info = _API_KEY_PATTERNS.get(env_var)
    if pattern_info:
        pat, desc = pattern_info
        if not re.match(pat, val):
            return CheckResult(name=f"apikey:{env_var}", ok=False, severity="warning",
                               message=f"{desc} format looks invalid (length={len(val)})")
    return CheckResult(name=f"apikey:{env_var}", ok=True,
                       message=f"{env_var} set (length={len(val)})")


def _check_config_option(key: str, value: Any, spec: dict) -> CheckResult:
    """Validate a single EngagementSpec config value."""
    constraints = {
        "max_depth":       (1, 10,  "integer"),
        "max_iterations":  (1, 50,  "integer"),
        "rate_limit":      (0.1, 30, "float"),
        "max_active_budget": (0, 100, "integer"),
        "time_budget_seconds": (60, 7200, "integer"),
    }
    if key in constraints:
        lo, hi, typ = constraints[key]
        try:
            v = float(value)
        except (TypeError, ValueError):
            return CheckResult(name=f"config:{key}", ok=False, severity="warning",
                               message=f"{key}={value!r} — expected {typ}")
        if v < lo or v > hi:
            return CheckResult(name=f"config:{key}", ok=False, severity="warning",
                               message=f"{key}={v} outside [{lo}..{hi}]")
    profile = spec.get("scan_profile") or spec.get("profile", "balanced")
    if key == "scan_profile" or key == "profile":
        if profile not in ("quick", "balanced", "deep"):
            return CheckResult(name=f"config:{key}", ok=False, severity="warning",
                               message=f"Unknown profile '{profile}'")
    wordlist = spec.get("wordlist_profile", "small")
    if key == "wordlist_profile":
        if wordlist not in ("small", "medium", "extended"):
            return CheckResult(name=f"config:{key}", ok=False, severity="warning",
                               message=f"Unknown wordlist profile '{wordlist}'")
    return CheckResult(name=f"config:{key}", ok=True, message="OK")


# ── Main preflight runner ─────────────────────────────────────────

_REQUIRED_BINARIES = [
    ("subfinder", "-version"),
    ("httpx",     "-version"),
    ("nuclei",    "-version"),
    ("nmap",      "--version"),
]

_OPTIONAL_BINARIES: list = []
# Note: karma/karma_v2 CLI binaries are NOT checked here.
# MINA uses the Shodan Python SDK (karma_tools.py), not the CLI.
# SDK readiness is reported by check_all_tools() via karma_health_check().

_API_KEYS = ["SHODAN_API_KEY", "VIRUSTOTAL_API_KEY"]

_CONFIG_KEYS = [
    "max_depth", "max_iterations", "rate_limit", "scan_profile",
    "wordlist_profile",
]


def run_preflight(engagement_spec: dict) -> PreflightReport:
    """
    Execute all preflight checks for the given engagement spec.
    Returns a PreflightReport with per-check results.
    """
    report = PreflightReport()

    # 1) Required binaries — exist + runnable
    for name, flag in _REQUIRED_BINARIES:
        report.checks.append(_check_binary_exists(name, flag))
        report.checks.append(_check_binary_runnable(name, flag))

    # 2) Optional binaries (karma)
    for name, flag in _OPTIONAL_BINARIES:
        report.checks.append(_check_binary_exists(name, flag))

    # 3) API keys
    for env_var in _API_KEYS:
        report.checks.append(_check_api_key(env_var))

    # 4) Config options validation
    for key in _CONFIG_KEYS:
        val = engagement_spec.get(key)
        if val is not None:
            report.checks.append(_check_config_option(key, val, engagement_spec))

    # 5) DeepSeek API key — critical (needed for LLM)
    ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not ds_key:
        # Also check config
        from core.config import config as mina_config
        ds_key = mina_config.deepseek_api_key
    if ds_key:
        report.checks.append(CheckResult(
            name="apikey:DEEPSEEK_API_KEY", ok=True,
            message=f"Set (length={len(ds_key)})"))
    else:
        report.checks.append(CheckResult(
            name="apikey:DEEPSEEK_API_KEY", ok=False, severity="critical",
            message="DEEPSEEK_API_KEY not set — LLM calls will fail"))

    # Log summary
    passed = sum(1 for c in report.checks if c.ok)
    total = len(report.checks)
    logger.info("[Preflight] %d/%d checks passed | critical=%s",
                passed, total, report.has_critical)
    for line in report.summary_lines():
        logger.info("[Preflight] %s", line)

    return report
