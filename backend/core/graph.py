"""
LangGraph Graph — Phase 0 → 5
Evidence-first intelligence pipeline with specialised collector agents.

V5 Architecture:
  Phase 0: setup
  Phase 1: collection loop (director → specialised agents → provenance → quality gate)
  Phase 2: normalize
  Phase 3: correlate → conflict_resolution
  Phase 4: impact → table_compose
  Phase 5: report
"""
import logging
from langgraph.graph import StateGraph, START, END

from core.state import MINAState

# ── Old monolith agents (kept for backward compat, used as fallback) ──
from agents.director import director_node
from agents.normalizer import normalizer_node
from agents.correlator import correlator_node
from agents.impact_analyst import impact_node
from agents.reporter import reporter_node as report_node

# ── New specialised collector agents ──
from agents.root_domain_discovery import root_domain_node
from agents.subdomain_intel import subdomain_intel_node
from agents.infra_network_intel import infra_network_node
from agents.service_surface import service_surface_node
from agents.web_surface_agent import web_surface_node
from agents.company_intel import company_intel_node
from agents.people_intel import people_intel_node
from agents.credentials_access import credentials_access_node
from agents.karma_passive import karma_passive_node
from agents.osint_deep_dive import osint_deep_dive_node
from agents.attach_provenance import attach_provenance_node
from agents.table_composer import table_composer_node

# ── Gates ──
from nodes.gates import (
    setup_node,
    policy_gate_node,
    lead_quality_gate_node,
    conflict_resolution_node,
    stop_condition_node,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------

def route_after_director(state: MINAState) -> str:
    """After director: always start with passive collection chain."""
    if state.get("passive_tasks") or state.get("active_tasks"):
        return "root_domain"
    return "lead_quality_gate"


def route_after_passive_chain(state: MINAState) -> str:
    """After OSINT deep-dive: go to active chain or provenance."""
    spec = state.get("engagement_spec", {})
    if state.get("active_tasks") and spec.get("active_recon_enabled"):
        return "service_surface"
    return "attach_provenance"


def route_after_active_chain(state: MINAState) -> str:
    """After web_surface: always attach provenance."""
    return "attach_provenance"


def route_after_quality_gate(state: MINAState) -> str:
    """Decide: continue loop or proceed to normalize."""
    spec = state.get("engagement_spec", {})

    if not state.get("lead_queue"):
        return "stop_condition"
    if state.get("iteration_count", 0) >= spec.get("max_iterations", 15):
        return "stop_condition"
    if state.get("active_budget_used", 0) >= spec.get("max_active_budget", 20):
        return "stop_condition"
    if len(state.get("raw_events", [])) >= spec.get("max_leads", 100) * 10:
        return "stop_condition"

    no_yield_threshold = 3
    if state.get("iteration_count", 0) - state.get("last_yield_iteration", 0) >= no_yield_threshold:
        return "stop_condition"

    return "director"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_graph(db_path: str = "backend/output/checkpoint.db"):
    """Compile and return the MINA LangGraph with specialised agents."""
    graph = StateGraph(MINAState)

    # === PHASE 0: Setup ===
    graph.add_node("setup", setup_node)

    # === PHASE 1: Collection Loop ===
    graph.add_node("policy_gate", policy_gate_node)
    graph.add_node("director", director_node)

    # Passive collection chain (sequential — each enriches state for next)
    graph.add_node("root_domain", root_domain_node)
    graph.add_node("subdomain_intel", subdomain_intel_node)
    graph.add_node("infra_network", infra_network_node)
    graph.add_node("company_intel", company_intel_node)
    graph.add_node("people_intel", people_intel_node)
    graph.add_node("credentials_access", credentials_access_node)
    graph.add_node("karma_passive", karma_passive_node)
    graph.add_node("osint_deep_dive", osint_deep_dive_node)

    # Active collection chain
    graph.add_node("service_surface", service_surface_node)
    graph.add_node("web_surface", web_surface_node)

    # Evidence & quality
    graph.add_node("attach_provenance", attach_provenance_node)
    graph.add_node("lead_quality_gate", lead_quality_gate_node)
    graph.add_node("stop_condition", stop_condition_node)

    # === PHASE 2: Normalize ===
    graph.add_node("normalize", normalizer_node)

    # === PHASE 3: Correlate + Conflict Resolution ===
    graph.add_node("correlate", correlator_node)
    graph.add_node("conflict_resolution", conflict_resolution_node)

    # === PHASE 4: Impact + Table Compose ===
    graph.add_node("impact_analysis", impact_node)
    graph.add_node("table_compose", table_composer_node)

    # === PHASE 5: Report ===
    graph.add_node("report", report_node)

    # ================================================================
    # EDGES
    # ================================================================

    # Phase 0 → Phase 1
    graph.add_edge(START, "setup")
    graph.add_edge("setup", "policy_gate")
    graph.add_edge("policy_gate", "director")

    # Director → collector chain (conditional)
    graph.add_conditional_edges("director", route_after_director, {
        "root_domain": "root_domain",
        "lead_quality_gate": "lead_quality_gate",
    })

    # Passive collection chain (sequential)
    graph.add_edge("root_domain", "subdomain_intel")
    graph.add_edge("subdomain_intel", "infra_network")
    graph.add_edge("infra_network", "company_intel")
    graph.add_edge("company_intel", "people_intel")
    graph.add_edge("people_intel", "credentials_access")
    graph.add_edge("credentials_access", "karma_passive")
    graph.add_edge("karma_passive", "osint_deep_dive")

    # After passive → active or provenance
    graph.add_conditional_edges("osint_deep_dive", route_after_passive_chain, {
        "service_surface": "service_surface",
        "attach_provenance": "attach_provenance",
    })

    # Active collection chain
    graph.add_edge("service_surface", "web_surface")
    graph.add_edge("web_surface", "attach_provenance")

    # Provenance → quality gate → loop or stop
    graph.add_edge("attach_provenance", "lead_quality_gate")
    graph.add_conditional_edges("lead_quality_gate", route_after_quality_gate, {
        "director": "director",
        "stop_condition": "stop_condition",
    })

    # Phase 1 → Phase 2
    graph.add_edge("stop_condition", "normalize")

    # Phase 2 → Phase 3 → Phase 4 → Phase 5
    graph.add_edge("normalize", "correlate")
    graph.add_edge("correlate", "conflict_resolution")
    graph.add_edge("conflict_resolution", "impact_analysis")
    graph.add_edge("impact_analysis", "table_compose")
    graph.add_edge("table_compose", "report")
    graph.add_edge("report", END)

    # Compile with SqliteSaver for session persistence
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        import pathlib
        pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        saver = SqliteSaver.from_conn_string(db_path)
        return graph.compile(checkpointer=saver)
    except Exception:
        from langgraph.checkpoint.memory import MemorySaver
        logger.warning("SqliteSaver unavailable, falling back to MemorySaver")
        return graph.compile(checkpointer=MemorySaver())


# ---------------------------------------------------------------------------
# Backward-compatible helper for main.py
# ---------------------------------------------------------------------------

def build_initial_state(target: str, engagement_spec: dict, max_iterations: int = 15) -> MINAState:
    """Build initial MINAState for a new scan session."""
    from datetime import datetime, timezone
    spec = {
        "session_id": engagement_spec.get("session_id", ""),
        "target": target,
        "company_name": engagement_spec.get("company_name", ""),
        "allowed_scope": engagement_spec.get("allowed_scope", [target]),
        "blocked_scope": engagement_spec.get("blocked_scope", []),
        "active_recon_enabled": engagement_spec.get("active_recon_enabled", False),
        "passive_only": engagement_spec.get("passive_only", True),
        "allowed_sources": engagement_spec.get("allowed_sources", ["crt_sh", "whois", "dns"]),
        "blocked_sources": engagement_spec.get("blocked_sources", []),
        "agents_enabled": engagement_spec.get("agents_enabled", {}),
        "max_depth": engagement_spec.get("max_depth", 3),
        "max_leads": engagement_spec.get("max_leads", 100),
        "max_active_budget": engagement_spec.get("max_active_budget", 20),
        "max_iterations": max_iterations,
        "rate_limit_seconds": engagement_spec.get("rate_limit_seconds", 2.0),
        "time_budget_seconds": engagement_spec.get("time_budget_seconds", 600),
        "profile": engagement_spec.get("profile", "balanced"),
        "wordlist_profile": engagement_spec.get("wordlist_profile", "small"),
        "mode": engagement_spec.get("mode", "breadth_first"),
        "agents_enabled": engagement_spec.get("agents_enabled", {}),
        "enable_secret_scanning": engagement_spec.get("enable_secret_scanning", False),
        "enable_repo_intel": engagement_spec.get("enable_repo_intel", False),
        "enable_doc_intel": engagement_spec.get("enable_doc_intel", False),
        "features": engagement_spec.get("features", {}),
        "tool_options": engagement_spec.get("tool_options", {}),
        "report_detail": engagement_spec.get("report_detail", "detailed"),
        "enable_endpoint_crawl": engagement_spec.get("enable_endpoint_crawl", False),
        "enable_karma_v2": engagement_spec.get("enable_karma_v2", False),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return MINAState(
        engagement_spec=spec,
        lead_queue=[],
        processed_lead_ids=set(),
        active_budget_used=0,
        iteration_count=0,
        last_yield_iteration=0,
        current_lead=None,
        passive_tasks=[],
        active_tasks=[],
        raw_events=[],
        observations=[],
        entities=[],
        entity_index={},
        relationships=[],
        conflict_queue=[],
        findings=[],
        impact_insights=[],
        report="",
        export_paths={},
        collector_stats={},
        phase_log=[],
        tool_health_snapshot={},
        stop_reason=None,
        error_log=[],
    )

