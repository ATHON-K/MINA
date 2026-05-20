"""
Infrastructure / Network ASN Intel Agent — shodan, asn, reverse_dns, infra_asn_enrich, reverse_ip.

Maps the network infrastructure: IPs, ASNs, hosting, virtual hosts.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

INFRA_TOOLS = {"shodan", "shodan_search", "asn", "reverse_dns", "infra_asn_enrich",
               "reverse_ip", "google_analytics_id"}


def infra_network_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Infrastructure / Network ASN Intel."""
    passive_tasks = [t for t in state.get("passive_tasks", [])
                     if t.get("tool") in INFRA_TOOLS]
    if not passive_tasks:
        return state

    log_cb = get_log_callback(config)
    emit_log(log_cb, "InfraNetworkIntel", f"Running {len(passive_tasks)} infra tasks")

    obs, leads = run_collector_tasks(
        state, passive_tasks, "infra", "InfraNetworkIntel", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in INFRA_TOOLS]

    materialize_observations(state, obs, "infra_network_intel")
    return state
