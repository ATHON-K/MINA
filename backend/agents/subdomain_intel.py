"""
Subdomain Intel Agent — crt_sh, subdomain_discovery, subfinder, dns_dumpster, zone_transfer.

Focused exclusively on discovering and enumerating subdomains of the target.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

SUBDOMAIN_TOOLS = {"crt_sh", "subdomain_discovery", "subfinder", "dns_dumpster", "zone_transfer"}


def subdomain_intel_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Subdomain Intelligence."""
    # Collect tasks from both passive and active pools
    passive_tasks = [t for t in state.get("passive_tasks", [])
                     if t.get("tool") in SUBDOMAIN_TOOLS]
    active_tasks = [t for t in state.get("active_tasks", [])
                    if t.get("tool") in SUBDOMAIN_TOOLS]
    tasks = passive_tasks + active_tasks
    if not tasks:
        return state

    log_cb = get_log_callback(config)
    emit_log(log_cb, "SubdomainIntel", f"Running {len(tasks)} subdomain tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "subdomain", "SubdomainIntel", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in SUBDOMAIN_TOOLS]
    state["active_tasks"] = [t for t in state.get("active_tasks", [])
                             if t.get("tool") not in SUBDOMAIN_TOOLS]

    materialize_observations(state, obs, "subdomain_intel")
    return state
