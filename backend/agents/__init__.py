"""
MINA Agents — V5 specialised agent architecture.

Layer 2 (Plan/Decide): Each agent decides which tasks to run, then delegates
execution to Layer 3 (tools/adapters/dispatcher).

Old monolith agents (passive_recon, osint_agent, active_recon) are kept for
backward compatibility but are no longer wired in the default graph.

Imports are lazy: just importing this package will NOT eagerly load every agent
(and will NOT fail if optional SDKs like `openai` are not installed).
Use explicit imports where needed, e.g.:
    from agents.director import director_node
"""

# Public surface — string-only so that importing backend.agents never fails
# even when optional dependencies (openai, etc.) are missing.
__all__ = [
    # Orchestration
    "director_node",
    # Specialised collectors (Phase 1)
    "root_domain_node",
    "subdomain_intel_node",
    "infra_network_node",
    "service_surface_node",
    "web_surface_node",
    "company_intel_node",
    "people_intel_node",
    "credentials_access_node",
    "karma_passive_node",
    "osint_deep_dive_node",
    # Evidence & provenance
    "attach_provenance_node",
    # Post-collection pipeline
    "normalizer_node",
    "correlator_node",
    "conflict_resolution_node",
    "impact_node",
    "table_composer_node",
    "reporter_node",
]

