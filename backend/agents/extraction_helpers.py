"""
Shared extraction helpers — used by all collector agents.

Centralises:
  - Observation creation from tool results
  - Lead creation from discoveries
  - Relationship type inference
  - Evidence storage and raw event emission
  - Runtime entity materialization + relationship

This ensures agents only *decide* what to run;
the actual parsing/materializing is standardised here.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.canonicalization import Canonicalizer
from core.evidence_store import EvidenceStore
from core.identity import make_entity_id
from core.runtime_emit import (
    emit_raw_event,
    emit_runtime_relationship,
    materialize_entity_from_observation,
)
from core.schemas import Lead, Observation
from core.state import MINAState

logger = logging.getLogger(__name__)

# ── Observation → Relationship inference ──────────────────────────

OBS_TYPE_REL_MAP: Dict[str, str] = {
    # Network / Infra
    "domain_found":             "contains",
    "subdomain_found":          "belongs_to",
    "ip_found":                 "resolves_to",
    "asn_found":                "belongs_to",
    "service_detected":         "exposes",
    "port_open":                "exposes",

    # Web surface
    "webapp_alive":             "hosted_on",
    "url_found":                "contains",
    "endpoint_found":           "contains",
    "parameter_found":          "contains",
    "technology_found":         "uses_technology",
    "waf_detected":             "uses_technology",
    "header_found":             "exposes",

    # Assets
    "repo_found":               "associated_with",
    "document_found":           "leaks",

    # Security
    "vulnerability_found":      "exposes",
    "credential_signal_found":  "leaks",

    # People / Org
    "person_found":             "employs",
    "email_found":              "leaks",
    "org_found":                "owned_by",
    "cert_found":               "shares_cert",
}


def infer_relation(obs_type: str) -> str:
    return OBS_TYPE_REL_MAP.get(obs_type, "linked_to")


# ── Evidence helpers ──────────────────────────────────────────────

def get_evidence_store(state: MINAState) -> EvidenceStore:
    spec = state["engagement_spec"]
    session_dir = Path(f"backend/output/sessions/{spec['session_id']}")
    return EvidenceStore(session_dir)


def store_evidence(evidence_store: EvidenceStore, collector: str,
                   target: str, result: dict) -> str:
    """Store raw tool result, return evidence_id."""
    return evidence_store.store_raw(
        collector=collector,
        query=target,
        content=json.dumps(result, indent=2, default=str),
        content_type="application/json",
    )


# ── Log callback helper ──────────────────────────────────────────

def get_log_callback(config) -> Optional[Callable]:
    if config is None:
        return None
    configurable = (config if isinstance(config, dict) else {}).get("configurable", {})
    return configurable.get("log_callback")


def emit_log(log_cb: Optional[Callable], agent: str, msg: str,
             level: str = "info") -> None:
    if log_cb:
        try:
            log_cb({
                "agent": agent,
                "level": level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": msg,
            })
        except Exception:
            pass


# ── Runtime materialization ───────────────────────────────────────

def materialize_observations(
    state: MINAState,
    observations: List[Observation],
    collector_name: str,
) -> None:
    """
    Materialize entities and relationships from new observations.
    Called AFTER observations are appended to state.
    """
    current_lead = state.get("current_lead")
    parent_eid = None
    if current_lead:
        _val = getattr(current_lead, "value", "") or ""
        _type = getattr(current_lead, "type", "") or ""
        if _val and _type:
            parent_eid = make_entity_id(_type, _val)

    for obs in observations:
        ent = materialize_entity_from_observation(state, obs, parent_entity_id=parent_eid)
        if ent and parent_eid:
            child_eid = getattr(ent, "entity_id", "")
            if child_eid and child_eid != parent_eid:
                rel_type = infer_relation(obs.type)
                emit_runtime_relationship(
                    state, parent_eid, child_eid, rel_type,
                    confidence=obs.confidence * 0.9,
                    evidence_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                    observation_ids=[obs.observation_id],
                    derived_by=collector_name,
                )


# ── Collector runner — the shared execute loop ────────────────────

def run_collector_tasks(
    state: MINAState,
    tasks: List[dict],
    collector_prefix: str,
    agent_name: str,
    config=None,
    extract_fn=None,
) -> Tuple[List[Observation], List[Lead]]:
    """
    Execute a list of tasks via the unified dispatcher.
    Returns (new_observations, new_leads).

    Args:
        state: MINAState
        tasks: list of {"tool": str, "target": str, ...}
        collector_prefix: e.g. "passive", "active", "osint"
        agent_name: for logging
        config: LangGraph config (for log_callback)
        extract_fn: optional custom extraction function(tool, target, result, state) → (obs, leads)
    """
    from tools.adapters.dispatcher import dispatch_tool

    log_cb = get_log_callback(config)
    spec = state["engagement_spec"]
    evidence_store = get_evidence_store(state)
    rate_limit = spec.get("rate_limit_seconds", 1.0)

    new_observations: List[Observation] = []
    new_leads: List[Lead] = []

    for task in tasks:
        tool = task.get("tool", "")
        target = task.get("target", "")
        if not tool or not target:
            continue

        emit_log(log_cb, agent_name, f"[{tool.upper()}] querying {target} ...")

        # Call tool via unified dispatcher
        result = dispatch_tool(
            tool, target,
            rate_limit=rate_limit,
            options=task.get("options", {}),
            company=spec.get("company_name", ""),
            profile=spec.get("profile", "balanced"),
            features=spec.get("features", {}),
        )

        if result.get("success"):
            evidence_id = store_evidence(
                evidence_store, f"{collector_prefix}/{tool}", target, result)

            if extract_fn:
                obs, leads = extract_fn(tool, target, result, state, evidence_id)
            else:
                obs, leads = [], []

            new_observations.extend(obs)
            new_leads.extend(leads)
            _update_stats(state, f"{collector_prefix}/{tool}", success=True,
                          events=len(obs), leads=len(leads))
            emit_raw_event(
                state, collector=f"{collector_prefix}/{tool}", tool=tool,
                target=target, evidence_id=evidence_id,
                success=True, extracted_count=len(obs), new_leads_count=len(leads),
            )

            msg = f"[{tool.upper()}] {target}: {len(obs)} observations, {len(leads)} new leads"
            emit_log(log_cb, agent_name, msg, "success" if obs else "info")
            state.setdefault("phase_log", []).append({
                "phase": collector_prefix,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "success" if obs else "info",
                "message": msg,
            })
        else:
            error_msg = result.get("error", "unknown error")
            _update_stats(state, f"{collector_prefix}/{tool}", success=False, error=error_msg)
            emit_raw_event(
                state, collector=f"{collector_prefix}/{tool}", tool=tool,
                target=target, evidence_id="", success=False, error_message=error_msg,
            )
            emit_log(log_cb, agent_name, f"[{tool.upper()}] {target} FAILED: {error_msg}", "error")
            state.setdefault("error_log", []).append({
                "tool": f"{collector_prefix}/{tool}", "target": target,
                "error": error_msg, "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    return new_observations, new_leads


def _update_stats(state: MINAState, tool_key: str, *, success: bool,
                  events: int = 0, leads: int = 0, error: str = "") -> None:
    stats = state.setdefault("collector_stats", {})
    entry = stats.setdefault(tool_key, {"runs": 0, "success": 0, "fail": 0,
                                        "total_events": 0, "total_leads": 0})
    entry["runs"] += 1
    if success:
        entry["success"] += 1
        entry["total_events"] += events
        entry["total_leads"] += leads
    else:
        entry["fail"] += 1
        if error:
            entry["last_error"] = error
