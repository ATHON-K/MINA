"""
Web Surface Agent — httpx, headers, tech, robots, dirs, crawl, ssl, waf,
                   http_methods, favicon, cloud, params, web_surface, nuclei.

Analyses the web layer: live HTTP services, technologies, security headers,
TLS configuration, directory enumeration, vulnerability scanning.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

WEB_TOOLS = {
    "httpx", "headers", "tech", "robots", "dirs", "crawl", "ssl",
    "waf", "http_methods", "favicon", "cloud", "params", "web_surface",
    "nuclei",
}


def web_surface_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Web Surface analysis."""
    spec = state["engagement_spec"]
    log_cb = get_log_callback(config)

    active_tasks = [t for t in state.get("active_tasks", [])
                    if t.get("tool") in WEB_TOOLS]
    if not active_tasks:
        return state

    # ROE guard
    roe_active = spec.get("active_recon_enabled", True)
    agent_enabled = spec.get("agents_enabled", {}).get("active_recon", True)
    if not roe_active or not agent_enabled:
        emit_log(log_cb, "WebSurface", "Active recon disabled — skipping web surface", "warning")
        state["active_tasks"] = [t for t in state.get("active_tasks", [])
                                 if t.get("tool") not in WEB_TOOLS]
        return state

    emit_log(log_cb, "WebSurface", f"Running {len(active_tasks)} web surface tasks")

    obs, leads = run_collector_tasks(
        state, active_tasks, "web", "WebSurface", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["active_tasks"] = [t for t in state.get("active_tasks", [])
                             if t.get("tool") not in WEB_TOOLS]

    materialize_observations(state, obs, "web_surface")
    return state
