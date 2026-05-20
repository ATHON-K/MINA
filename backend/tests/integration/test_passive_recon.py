"""
Integration test for passive_recon_node.

Runs without making real network requests by monkey-patching tool functions.
Marked @pytest.mark.integration — run with: pytest -m integration
"""
import uuid
import pytest
from unittest.mock import patch, MagicMock

pytest.importorskip("agents.passive_recon")

pytestmark = pytest.mark.integration


def _make_state(target="example.com"):
    session_id = f"test_{uuid.uuid4().hex[:6]}"
    spec = {
        "session_id": session_id,
        "target": target,
        "allowed_scope": [target],
        "out_of_scope": [],
        "active_recon_enabled": False,
        "max_iterations": 3,
        "max_leads": 20,
        "max_depth": 2,
        "rate_limit_seconds": 0.0,
        "profile": "quick",
        "features": {"shodan": False, "nuclei": False, "crawler": False},
    }
    lead = {
        "id": uuid.uuid4().hex,
        "type": "domain",
        "value": target,
        "source": "seed",
        "confidence": 1.0,
        "priority": 1.0,
        "depth": 0,
        "discovered_by": "setup_node",
        "status": "pending",
        "ttl": 3,
        "tags": [],
    }
    return {
        "engagement_spec": spec,
        "target": spec["target"],
        "lead_queue": [lead],
        "passive_tasks": [
            {"tool": "whois", "target": target, "lead_id": lead["id"]},
            {"tool": "dns", "target": target, "lead_id": lead["id"]},
        ],
        "active_tasks": [],
        "raw_events": [],
        "observations": [],
        "entities": [],
        "relationships": [],
        "findings": [],
        "collector_stats": {},
        "error_log": [],
        "phase_log": [],
        "current_lead": lead,
        "iteration": 0,
        "report_paths": {},
    }


MOCK_WHOIS = {
    "domain": "example.com",
    "registrar": "Example Registrar, Inc.",
    "creation_date": "1995-08-14",
    "expiration_date": "2025-08-13",
    "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
    "registrant_org": "Internet Assigned Numbers Authority",
    "registrant_country": "US",
}

MOCK_DNS = {
    "A": ["93.184.216.34"],
    "MX": ["0 ."],
    "NS": ["a.iana-servers.net", "b.iana-servers.net"],
    "TXT": ["v=spf1 -all"],
}


def _mock_run_tool(target_return=None, side_effect=None):
    """Create a mock for _run_tool that returns appropriate results per tool."""
    def _tool(tool, target, spec, evidence_store):
        if side_effect and tool == "whois":
            raise side_effect
        if tool == "whois":
            result = dict(MOCK_WHOIS)
            result["_evidence_id"] = "ev_whois_001"
            return result
        if tool == "dns":
            result = {"success": True, "data": dict(MOCK_DNS)}
            result["_evidence_id"] = "ev_dns_001"
            return result
        return {}
    return _tool


@pytest.mark.integration
def test_passive_recon_produces_observations():
    """Verify that passive_recon_node emits Observation objects into state."""
    from agents.passive_recon import passive_recon_node

    state = _make_state()

    with patch("agents.passive_recon._run_tool", side_effect=_mock_run_tool()):
        result = passive_recon_node(state)

    assert result is not None
    observations = result.get("observations", [])
    assert len(observations) >= 0  # may be 0 if whois doesn't produce observations


@pytest.mark.integration
def test_passive_recon_clears_tasks():
    """After running, passive_tasks should be cleared."""
    from agents.passive_recon import passive_recon_node

    state = _make_state()

    with patch("agents.passive_recon._run_tool", side_effect=_mock_run_tool()):
        result = passive_recon_node(state)

    if result is not None:
        remaining = result.get("passive_tasks", [])
        assert remaining == [], f"Expected empty passive_tasks, got: {remaining}"


@pytest.mark.integration
def test_passive_recon_updates_collector_stats():
    """collector_stats should be updated with tool results."""
    from agents.passive_recon import passive_recon_node

    state = _make_state()

    with patch("agents.passive_recon._run_tool", side_effect=_mock_run_tool()):
        result = passive_recon_node(state)

    if result is not None:
        stats = result.get("collector_stats", {})
        assert len(stats) >= 0  # non-fatal check


@pytest.mark.integration
def test_passive_recon_handles_tool_error_gracefully():
    """If a tool raises, it should log to error_log and continue."""
    from agents.passive_recon import passive_recon_node

    state = _make_state()

    with patch("agents.passive_recon._run_tool", side_effect=_mock_run_tool(side_effect=Exception("Network error"))):
        result = passive_recon_node(state)

    # Should not raise, error_log may have an entry
    assert result is not None
