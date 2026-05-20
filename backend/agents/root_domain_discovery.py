"""
Root Domain Discovery Agent — whois, reverse_whois, related_domains.

Discovers root-level domains related to the target through WHOIS records,
registrant correlation, and organizational links.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

# Tools this agent is responsible for
ROOT_DOMAIN_TOOLS = {"whois", "reverse_whois", "related_domains"}


def root_domain_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Root Domain Discovery."""
    tasks = [t for t in state.get("passive_tasks", [])
             if t.get("tool") in ROOT_DOMAIN_TOOLS]
    if not tasks:
        return state

    log_cb = get_log_callback(config)
    emit_log(log_cb, "RootDomainDiscovery", f"Running {len(tasks)} root domain tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "passive", "RootDomainDiscovery", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    # Remove consumed tasks
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in ROOT_DOMAIN_TOOLS]

    materialize_observations(state, obs, "root_domain_discovery")
    return state
