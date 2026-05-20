"""
Karma v2 Passive Recon — shared node that runs all karma tools.

karma_ip, karma_leaks, karma_cve, smap — all Shodan-backed passive intelligence.
Runs for the current lead's target, guarded by enable_karma_v2 toggle.
"""
import logging
from core.state import MINAState
from core.schemas import Finding
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log, get_evidence_store, store_evidence,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

KARMA_TOOLS = {"karma_ip", "karma_leaks", "karma_cve", "smap"}


def karma_passive_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Karma v2 shared passive recon."""
    spec = state["engagement_spec"]
    log_cb = get_log_callback(config)

    # Guard: karma must be explicitly enabled
    karma_enabled = (
        spec.get("agents_enabled", {}).get("karma_v2", False)
        or spec.get("enable_karma_v2", False)
    )
    if not karma_enabled:
        emit_log(log_cb, "KarmaPassive", "Karma v2 disabled — skipping", "info")
        return state

    # Check karma health first
    from tools.adapters.dispatcher import dispatch_tool
    health_result = dispatch_tool("karma_health", "", rate_limit=0)
    if not health_result.get("data", {}).get("ready", False):
        emit_log(log_cb, "KarmaPassive", "Karma v2 not ready — skipping", "warning")
        return state

    # Determine target
    current_lead = state.get("current_lead")
    target = ""
    if current_lead:
        target = getattr(current_lead, "value", "") or ""
    if not target:
        target = spec.get("target", "")
    if not target:
        return state

    emit_log(log_cb, "KarmaPassive", f"Running Karma v2 passive recon for {target}")

    # Build karma tasks
    tasks = [
        {"tool": "karma_ip", "target": target},
        {"tool": "karma_leaks", "target": target},
        {"tool": "karma_cve", "target": target},
        {"tool": "smap", "target": target},
    ]

    obs, leads = run_collector_tasks(
        state, tasks, "karma", "KarmaPassive", config,
        extract_fn=extract_for_tool,
    )

    # Generate findings for critical karma discoveries
    evidence_store = get_evidence_store(state)
    session_id = spec.get("session_id", "")
    new_findings = []

    for o in obs:
        if o.type == "credential_signal_found":
            new_findings.append(Finding(
                session_id=session_id,
                title="Credential Leak Detected",
                description=f"Credential leak found via Karma v2 for {target}",
                risk_level="high",
                category="credential_exposure",
                impact_category="credential_exposure",
                impact_items=[target],
                evidence_refs=[o.evidence_ref] if o.evidence_ref else [],
                confidence_score=0.85,
                recommendation="Rotate affected credentials immediately.",
            ))
        elif o.type == "vulnerability_found" and "CVE" in (o.value or ""):
            new_findings.append(Finding(
                session_id=session_id,
                title=o.value,
                description=f"CVE found via Karma/Shodan for {target}",
                risk_level="high",
                category="infrastructure_exposure",
                impact_category="infrastructure_exposure",
                impact_items=[target],
                evidence_refs=[o.evidence_ref] if o.evidence_ref else [],
                confidence_score=0.80,
                recommendation=f"Verify and patch {o.value}",
            ))

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state.setdefault("findings", []).extend(new_findings)

    materialize_observations(state, obs, "karma_passive")

    emit_log(log_cb, "KarmaPassive",
             f"Karma v2 complete: {len(obs)} observations, {len(new_findings)} findings",
             "success" if obs else "info")
    return state
