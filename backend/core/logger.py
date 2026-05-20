"""
Structured logger for MINA — JSON-formatted log entries with context.
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        # Carry through any extra fields
        _EXTRA_KEYS = (
            "session_id", "agent", "tool", "target",
            "input_lead", "tool_command", "raw_result_summary",
            "observation_count", "derived_leads_count",
            "elapsed_seconds", "error_detail", "partial_results",
            "skip_reason",
        )
        for key in _EXTRA_KEYS:
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry, ensure_ascii=False)


class StructuredLogger:
    """
    Named structured logger with optional file sink.
    Usage:
        log = StructuredLogger("director", session_id="abc123")
        log.info("Task dispatched", tool="crt_sh", target="example.com")
    """

    def __init__(self, name: str, session_id: Optional[str] = None,
                 log_dir: Optional[Path] = None):
        self.session_id = session_id
        self._logger = logging.getLogger(f"mina.{name}")
        self._extra = {"session_id": session_id} if session_id else {}

        if not self._logger.handlers:
            self._logger.setLevel(logging.DEBUG)
            # Console handler
            console = logging.StreamHandler(sys.stdout)
            console.setFormatter(JSONFormatter())
            self._logger.addHandler(console)

        # Optional file handler
        if log_dir and session_id:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_dir / f"{session_id}.log", encoding="utf-8")
            fh.setFormatter(JSONFormatter())
            self._logger.addHandler(fh)

    def _merge(self, extra: dict) -> dict:
        return {**self._extra, **extra}

    def debug(self, msg: str, **extra):
        self._logger.debug(msg, extra=self._merge(extra))

    def info(self, msg: str, **extra):
        self._logger.info(msg, extra=self._merge(extra))

    def warning(self, msg: str, **extra):
        self._logger.warning(msg, extra=self._merge(extra))

    def error(self, msg: str, **extra):
        self._logger.error(msg, extra=self._merge(extra))

    def critical(self, msg: str, **extra):
        self._logger.critical(msg, extra=self._merge(extra))


class CollectorLogger(StructuredLogger):
    """
    Per-collector structured logger — emits standardised fields for every
    tool invocation so we get consistent, machine-parseable audit trails.

    Usage:
        clog = CollectorLogger("passive_recon", session_id="abc")
        clog.tool_start("dns", lead=lead_dict, command="dig +short example.com")
        # ... run tool ...
        clog.tool_done("dns", observations=5, leads=2, elapsed=1.3)
        clog.tool_error("dns", error="timeout after 30s")
    """

    def tool_start(self, tool: str, *, lead: Optional[dict] = None,
                   command: str = "", target: str = ""):
        self.info(
            f"[{tool}] START",
            tool=tool,
            input_lead=_summarise_lead(lead) if lead else "",
            tool_command=command[:300],
            target=target,
        )

    def tool_done(self, tool: str, *,
                  observations: int = 0, leads: int = 0,
                  elapsed: float = 0.0, raw_summary: str = ""):
        self.info(
            f"[{tool}] DONE — {observations} obs, {leads} leads, {elapsed:.1f}s",
            tool=tool,
            observation_count=observations,
            derived_leads_count=leads,
            elapsed_seconds=round(elapsed, 2),
            raw_result_summary=raw_summary[:200],
        )

    def tool_error(self, tool: str, *, error: str = "",
                   partial_results: int = 0):
        self.warning(
            f"[{tool}] ERROR — {error}",
            tool=tool,
            error_detail=error[:300],
            partial_results=partial_results,
        )

    def tool_skip(self, tool: str, *, reason: str = ""):
        self.info(
            f"[{tool}] SKIP — {reason}",
            tool=tool,
            skip_reason=reason,
        )


def _summarise_lead(lead: Optional[dict]) -> str:
    """Compact one-liner summary of a lead for logging."""
    if not lead:
        return ""
    if hasattr(lead, "type"):
        return f"{lead.type}:{lead.value}"
    return f"{lead.get('type', '?')}:{lead.get('value', '?')}"


def setup_root_logging(level: str = "INFO", log_dir: Optional[Path] = None):
    """Configure root logging for the MINA backend."""
    root = logging.getLogger("mina")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        root.addHandler(handler)

    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "mina.log", encoding="utf-8")
        fh.setFormatter(JSONFormatter())
        root.addHandler(fh)
