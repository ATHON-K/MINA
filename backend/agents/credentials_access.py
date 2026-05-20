"""
Credentials & Access Surface Agent — credential/secret scanning, repo intel.

Discovers leaked credentials, exposed secrets, and access surface information.
"""
import logging
from core.state import MINAState
from agents.extraction_helpers import (
    run_collector_tasks, materialize_observations,
    get_log_callback, emit_log,
)
from agents.extractors import extract_for_tool

logger = logging.getLogger(__name__)

CREDENTIAL_TOOLS = {"repo_discovery", "public_doc_discovery", "github_dorks", "google_dorks"}


def credentials_access_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Credentials & Access Surface."""
    spec = state["engagement_spec"]
    log_cb = get_log_callback(config)

    tasks = [t for t in state.get("passive_tasks", [])
             if t.get("tool") in CREDENTIAL_TOOLS]
    if not tasks:
        return state

    # Feature flags guard
    if not spec.get("enable_repo_intel", False) and not spec.get("enable_secret_scanning", False):
        emit_log(log_cb, "CredentialsAccess",
                 "Repo intel and secret scanning disabled — skipping", "info")
        state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                                  if t.get("tool") not in CREDENTIAL_TOOLS]
        return state

    emit_log(log_cb, "CredentialsAccess", f"Running {len(tasks)} credential/access tasks")

    obs, leads = run_collector_tasks(
        state, tasks, "credentials", "CredentialsAccess", config,
        extract_fn=extract_for_tool,
    )

    state["observations"].extend(obs)
    state["lead_queue"].extend(leads)
    state["passive_tasks"] = [t for t in state.get("passive_tasks", [])
                              if t.get("tool") not in CREDENTIAL_TOOLS]

    materialize_observations(state, obs, "credentials_access")
    return state
