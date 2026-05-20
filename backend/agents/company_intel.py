"""
Company Intel Agent — company_profile, company_stack, related_domains.

Gathers organizational intelligence: corporate structure, tech stack hints,
and related domains through organizational links.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

COMPANY_TOOLS = {"company_profile", "company_stack", "related_domains"}


def company_intel_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Company Intelligence."""
    tasks = [t for t in state.get("passive_tasks", [])
             if t.get("tool") in COMPANY_TOOLS]
    if not tasks:
        return state

    log_cb = get_log_callback(config)
    emit_log(log_cb, "CompanyIntel", f"Running {len(tasks)} company intel tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "company", "CompanyIntel", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in COMPANY_TOOLS]

    materialize_observations(state, obs, "company_intel")
    return state
