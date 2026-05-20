"""
core/resilience.py — Timeout, retry, exponential backoff for tool execution.

Every external tool call should go through `run_with_resilience()`.
Provides:
  - Per-tool configurable timeout
  - Retry with exponential backoff + jitter
  - Partial result handling (return whatever we collected before timeout)
  - Fallback chain support
"""
import asyncio
import logging
import random
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Per-tool defaults ─────────────────────────────────────────────

DEFAULT_TOOL_TIMEOUTS: Dict[str, int] = {
    # Passive / API tools — fast
    "dns": 30, "whois": 30, "crt_sh": 45, "reverse_dns": 30,
    "spf_dmarc": 20, "wayback": 45, "email_harvest": 30,
    "asn": 20, "shodan": 45, "zone_transfer": 30,
    "company_profile": 30, "public_contact": 30,
    "reverse_ip": 30, "reverse_whois": 30, "google_analytics_id": 20,
    "repo_discovery": 30, "public_doc_discovery": 30,
    "infra_asn_enrich": 30, "cve_lookup": 30,
    "credential_signal": 30, "service_metadata": 30,
    "bgp_range": 30, "org_ip_range": 30,
    "dns_dumpster": 30,
    # Active — moderate
    "subfinder": 120, "httpx": 60, "headers": 30, "tech": 30,
    "ssl": 30, "robots": 20, "http_methods": 20, "favicon": 20,
    "web_surface": 60, "banner": 30, "waf": 30,
    "js_endpoints": 60, "params": 60, "cert_detail": 30,
    "vhost": 60, "cloud": 45,
    # Heavy — long
    "nmap": 300, "nuclei": 600, "dirs": 300, "crawl": 180,
    # Karma
    "karma_ip": 90, "karma_leaks": 90, "karma_cve": 90, "smap": 120,
    # OSINT
    "subdomain_discovery": 90,
}

DEFAULT_RETRY_CONFIG: Dict[str, int] = {
    # tool → max retries (0 = no retry)
    "dns": 2, "whois": 1, "crt_sh": 2, "shodan": 1,
    "subfinder": 1, "httpx": 1, "nmap": 0, "nuclei": 0,
    "dirs": 0, "crawl": 0,
}

BACKOFF_BASE_SECONDS = 2.0
BACKOFF_MAX_SECONDS = 30.0
BACKOFF_JITTER = 0.5


# ── Result wrapper ────────────────────────────────────────────────

@dataclass
class ResilientResult:
    """Wraps a tool execution result with resilience metadata."""
    success: bool
    data: Any = None
    partial: bool = False        # True if we got some data before timeout
    attempts: int = 1
    elapsed_seconds: float = 0.0
    error: str = ""
    tool: str = ""
    timed_out: bool = False

    def to_dict(self) -> dict:
        d = {
            "success": self.success,
            "partial": self.partial,
            "attempts": self.attempts,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "tool": self.tool,
        }
        if self.error:
            d["error"] = self.error
        if self.timed_out:
            d["timed_out"] = True
        return d


# ── Backoff calculator ────────────────────────────────────────────

def _calc_backoff(attempt: int) -> float:
    """Exponential backoff with jitter."""
    delay = min(BACKOFF_BASE_SECONDS * (2 ** attempt), BACKOFF_MAX_SECONDS)
    jitter = random.uniform(-BACKOFF_JITTER, BACKOFF_JITTER) * delay
    return max(0.1, delay + jitter)


# ── Sync tool runner with resilience ──────────────────────────────

def run_with_resilience(
    tool_name: str,
    func: Callable[..., Any],
    *args,
    timeout_override: Optional[int] = None,
    max_retries_override: Optional[int] = None,
    tool_options: Optional[dict] = None,
    **kwargs,
) -> ResilientResult:
    """
    Execute a tool function with timeout + retry + backoff.

    Args:
        tool_name: Tool identifier for config lookup.
        func: The callable to execute.
        timeout_override: Override default timeout for this tool.
        max_retries_override: Override default retry count.
        tool_options: Per-tool options (may contain 'timeout').
    Returns:
        ResilientResult with success/data/error info.
    """
    # Resolve timeout
    opt_timeout = (tool_options or {}).get("timeout")
    timeout = (timeout_override
               or (int(opt_timeout) if opt_timeout else None)
               or DEFAULT_TOOL_TIMEOUTS.get(tool_name, 60))

    max_retries = (max_retries_override
                   if max_retries_override is not None
                   else DEFAULT_RETRY_CONFIG.get(tool_name, 1))

    attempts = 0
    last_error = ""
    start_total = time.monotonic()

    while attempts <= max_retries:
        attempts += 1
        try:
            start = time.monotonic()
            # Use a thread timeout via concurrent.futures if needed
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(func, *args, **kwargs)
                try:
                    result = future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    elapsed = time.monotonic() - start_total
                    logger.warning("[Resilience] %s timed out after %ds (attempt %d/%d)",
                                   tool_name, timeout, attempts, max_retries + 1)
                    last_error = f"Timeout after {timeout}s"
                    if attempts > max_retries:
                        return ResilientResult(
                            success=False, tool=tool_name,
                            attempts=attempts, elapsed_seconds=elapsed,
                            error=last_error, timed_out=True)
                    time.sleep(_calc_backoff(attempts - 1))
                    continue

            elapsed = time.monotonic() - start_total
            return ResilientResult(
                success=True, data=result, tool=tool_name,
                attempts=attempts, elapsed_seconds=elapsed)

        except Exception as exc:
            elapsed = time.monotonic() - start_total
            last_error = str(exc)
            logger.warning("[Resilience] %s failed (attempt %d/%d): %s",
                           tool_name, attempts, max_retries + 1, last_error)
            if attempts > max_retries:
                return ResilientResult(
                    success=False, tool=tool_name,
                    attempts=attempts, elapsed_seconds=elapsed,
                    error=last_error)
            time.sleep(_calc_backoff(attempts - 1))

    elapsed = time.monotonic() - start_total
    return ResilientResult(
        success=False, tool=tool_name,
        attempts=attempts, elapsed_seconds=elapsed,
        error=last_error)


# ── Subprocess runner with timeout ────────────────────────────────

def run_command_resilient(
    tool_name: str,
    cmd: List[str],
    timeout_override: Optional[int] = None,
    max_retries_override: Optional[int] = None,
    input_data: Optional[str] = None,
    partial_ok: bool = False,
) -> ResilientResult:
    """
    Execute a CLI command with timeout + retry + backoff.
    If partial_ok=True and the command times out, returns partial stdout.
    """
    timeout = timeout_override or DEFAULT_TOOL_TIMEOUTS.get(tool_name, 60)
    max_retries = (max_retries_override
                   if max_retries_override is not None
                   else DEFAULT_RETRY_CONFIG.get(tool_name, 1))

    attempts = 0
    last_error = ""
    start_total = time.monotonic()

    while attempts <= max_retries:
        attempts += 1
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data,
            )
            elapsed = time.monotonic() - start_total
            if proc.returncode != 0 and not proc.stdout.strip():
                last_error = proc.stderr.strip()[:200] or f"exit code {proc.returncode}"
                logger.warning("[Resilience] %s returned code %d (attempt %d/%d)",
                               tool_name, proc.returncode, attempts, max_retries + 1)
                if attempts > max_retries:
                    return ResilientResult(
                        success=False, data=proc.stdout, tool=tool_name,
                        attempts=attempts, elapsed_seconds=elapsed,
                        error=last_error, partial=bool(proc.stdout.strip()))
                time.sleep(_calc_backoff(attempts - 1))
                continue

            return ResilientResult(
                success=True, data=proc.stdout, tool=tool_name,
                attempts=attempts, elapsed_seconds=elapsed)

        except subprocess.TimeoutExpired as te:
            elapsed = time.monotonic() - start_total
            partial_out = ""
            if partial_ok and te.stdout:
                partial_out = te.stdout if isinstance(te.stdout, str) else te.stdout.decode("utf-8", errors="replace")
            last_error = f"Timeout after {timeout}s"
            logger.warning("[Resilience] %s timed out (attempt %d/%d), partial=%d bytes",
                           tool_name, attempts, max_retries + 1, len(partial_out))
            if attempts > max_retries:
                return ResilientResult(
                    success=bool(partial_out), data=partial_out, tool=tool_name,
                    attempts=attempts, elapsed_seconds=elapsed,
                    error=last_error, timed_out=True,
                    partial=bool(partial_out))
            time.sleep(_calc_backoff(attempts - 1))

        except FileNotFoundError:
            return ResilientResult(
                success=False, tool=tool_name,
                attempts=attempts,
                elapsed_seconds=time.monotonic() - start_total,
                error=f"Command not found: {cmd[0]}")

        except Exception as exc:
            elapsed = time.monotonic() - start_total
            last_error = str(exc)
            logger.warning("[Resilience] %s error (attempt %d/%d): %s",
                           tool_name, attempts, max_retries + 1, last_error)
            if attempts > max_retries:
                return ResilientResult(
                    success=False, tool=tool_name,
                    attempts=attempts, elapsed_seconds=elapsed,
                    error=last_error)
            time.sleep(_calc_backoff(attempts - 1))

    return ResilientResult(
        success=False, tool=tool_name,
        attempts=attempts,
        elapsed_seconds=time.monotonic() - start_total,
        error=last_error)


def get_tool_timeout(tool_name: str, tool_options: Optional[dict] = None) -> int:
    """Get effective timeout for a tool considering options override."""
    if tool_options and "timeout" in tool_options:
        return int(tool_options["timeout"])
    return DEFAULT_TOOL_TIMEOUTS.get(tool_name, 60)
