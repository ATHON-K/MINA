"""
core/tool_health.py — Tool availability & health checks.

Reports which external tools are installed, accessible, and configured.
Used by the frontend to show tool status and by the planner to skip
unavailable tools gracefully.
"""
import logging
import os
import shutil
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolHealth:
    """Health status for a single tool."""

    def __init__(self, name: str, installed: bool, version: str = "",
                 error: str = "", env_key: Optional[str] = None):
        self.name = name
        self.installed = installed
        self.version = version
        self.error = error
        self.env_key = env_key
        self.env_configured = True
        if env_key:
            self.env_configured = bool(os.environ.get(env_key))

    @property
    def ready(self) -> bool:
        return self.installed and self.env_configured

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "installed": self.installed,
            "ready": self.ready,
            "version": self.version,
        }
        if self.error:
            d["error"] = self.error
        if self.env_key and not self.env_configured:
            d["error"] = f"Missing env: {self.env_key}"
        return d


def _check_binary(name: str, version_flag: str = "--version",
                  env_key: Optional[str] = None) -> ToolHealth:
    """Check if a CLI binary is installed and get its version."""
    path = shutil.which(name)
    if not path:
        return ToolHealth(name, installed=False,
                          error=f"{name}: not found in PATH", env_key=env_key)
    try:
        proc = subprocess.run(
            [path, version_flag],
            capture_output=True, text=True, timeout=10,
        )
        version = (proc.stdout.strip() or proc.stderr.strip())[:120]
        return ToolHealth(name, installed=True, version=version, env_key=env_key)
    except subprocess.TimeoutExpired:
        return ToolHealth(name, installed=True, version="timeout",
                          error=f"{name}: version check timed out", env_key=env_key)
    except Exception as exc:
        return ToolHealth(name, installed=True, version="",
                          error=f"{name}: {exc}", env_key=env_key)


def _check_python_module(name: str, import_name: Optional[str] = None,
                         env_key: Optional[str] = None) -> ToolHealth:
    """Check if a Python module is importable."""
    mod = import_name or name
    try:
        __import__(mod)
        return ToolHealth(name, installed=True, env_key=env_key)
    except ImportError:
        return ToolHealth(name, installed=False,
                          error=f"Python module '{mod}' not installed", env_key=env_key)


def check_all_tools() -> Dict[str, dict]:
    """
    Run health checks for all known tools.
    Returns dict of {tool_name: ToolHealth.to_dict()}.
    """
    results: Dict[str, dict] = {}

    # CLI binaries
    binaries = [
        ("subfinder", "-version", None),
        ("httpx", "-version", None),
        ("nuclei", "-version", None),
        ("nmap", "--version", None),
    ]
    for name, flag, env in binaries:
        h = _check_binary(name, flag, env)
        results[name] = h.to_dict()

    # Shodan / karma_v2 — MINA uses the Python SDK, NOT the karma CLI binary
    # Use karma_health_check() which checks: shodan lib + SHODAN_API_KEY
    try:
        from tools.karma_tools import karma_health_check  # noqa: PLC0415
        kr = karma_health_check()
        results["karma_v2"] = {
            "name": "karma_v2",
            "installed": kr.get("karma_installed", False),  # True = shodan SDK available
            "ready": kr.get("ready", False),                # True = SDK + API key both set
            "version": "Shodan Python SDK" if kr.get("karma_installed") else "",
            "error": "" if kr.get("ready") else kr.get("message", ""),
        }
    except Exception as _kex:
        results["karma_v2"] = {
            "name": "karma_v2",
            "installed": False,
            "ready": False,
            "error": f"karma_tools import error: {_kex}",
        }

    return results


def get_unavailable_tools() -> List[str]:
    """Return list of tool names that are NOT ready."""
    all_health = check_all_tools()
    return [name for name, info in all_health.items() if not info.get("ready")]


def get_available_tools() -> List[str]:
    """Return list of tool names that ARE ready."""
    all_health = check_all_tools()
    return [name for name, info in all_health.items() if info.get("ready")]
