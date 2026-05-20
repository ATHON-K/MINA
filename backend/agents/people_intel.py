"""
User / People Intel Agent — email_harvest, public_contact, team_harvest.

Discovers people-related intelligence: emails, public contacts, team members.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

PEOPLE_TOOLS = {"email_harvest", "public_contact", "team_harvest"}


def people_intel_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: User / People Intelligence."""
    tasks = [t for t in state.get("passive_tasks", [])
             if t.get("tool") in PEOPLE_TOOLS]
    if not tasks:
        return state

    log_cb = get_log_callback(config)
    emit_log(log_cb, "PeopleIntel", f"Running {len(tasks)} people intel tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "people", "PeopleIntel", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in PEOPLE_TOOLS]

    materialize_observations(state, obs, "people_intel")
    return state
