"""
Service Surface Agent — nmap, banner, smap (port scanning & service detection).

Discovers open ports, running services, and service banners.
Active tools require ROE checks.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

SERVICE_TOOLS = {"nmap", "banner", "smap", "vhost"}


def service_surface_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Service Surface scanning."""
    spec = state["engagement_spec"]
    log_cb = get_log_callback(config)

    active_tasks = [t for t in state.get("active_tasks", [])
                    if t.get("tool") in SERVICE_TOOLS]
    # smap is passive (Shodan-backed), but categorised under service
    passive_tasks = [t for t in state.get("passive_tasks", [])
                     if t.get("tool") in SERVICE_TOOLS]
    tasks = passive_tasks + active_tasks

    if not tasks:
        return state

    # ROE guard for active tools
    roe_active = spec.get("active_recon_enabled", True)
    agent_enabled = spec.get("agents_enabled", {}).get("active_recon", True)
    if not roe_active or not agent_enabled:
        # Keep only passive tools (smap)
        tasks = [t for t in tasks if t.get("tool") in {"smap"}]
        if not tasks:
            emit_log(log_cb, "ServiceSurface", "Active recon disabled — no service tasks to run", "warning")
            return state

    emit_log(log_cb, "ServiceSurface", f"Running {len(tasks)} service tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "service", "ServiceSurface", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["active_tasks"] = [t for t in state.get("active_tasks", [])
                             if t.get("tool") not in SERVICE_TOOLS]
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in SERVICE_TOOLS]

    materialize_observations(state, obs, "service_surface")
    return state
