"""
Unit tests for backend/nodes/gates.py
"""
import uuid
import pytest

pytest.importorskip("nodes.gates")

from nodes.gates import lead_quality_gate_node, policy_gate_node
from core.schemas import Lead


def _make_state_with_lead(lead, allowed_scope=None, out_of_scope=None):
    session_id = f"test_{uuid.uuid4().hex[:6]}"
    spec = {
        "session_id": session_id,
        "target": "example.com",
        "allowed_scope": allowed_scope or ["example.com"],
        "out_of_scope": out_of_scope or [],
        "active_recon_enabled": False,
        "max_iterations": 3,
        "max_leads": 20,
        "max_depth": 2,
        "rate_limit_seconds": 0.0,
        "profile": "quick",
        "features": {},
    }
    return {
        "engagement_spec": spec,
        "target": spec["target"],
        "lead_queue": [lead],
        "passive_tasks": [],
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
        "iteration_count": 0,
        "processed_lead_ids": set(),
        "report_paths": {},
    }


def _make_lead(ltype="domain", value="example.com", confidence=0.9, ttl=3, status="pending"):
    return Lead(
        type=ltype,
        value=value,
        raw_value=value,
        source="test",
        confidence=confidence,
        priority=0.7,
        depth=1,
        discovered_by="test",
        status=status,
        ttl=ttl,
        tags=[],
    )


class TestLeadQualityGate:
    def test_low_confidence_filtered(self):
        lead = _make_lead(confidence=0.15)
        state = _make_state_with_lead(lead)
        result = lead_quality_gate_node(state)
        # Lead below threshold (0.2) should be filtered out
        if result and "lead_queue" in result:
            filtered_queue = result["lead_queue"]
            assert all(l.confidence >= 0.2 for l in filtered_queue)

    def test_expired_ttl_filtered(self):
        lead = _make_lead(ttl=0, confidence=0.9)
        state = _make_state_with_lead(lead)
        result = lead_quality_gate_node(state)
        # Expired TTL lead should be filtered out
        if result and "lead_queue" in result:
            filtered_queue = result["lead_queue"]
            assert all(l.ttl > 0 for l in filtered_queue)

    def test_valid_lead_passes(self):
        lead = _make_lead(confidence=0.9, ttl=3)
        state = _make_state_with_lead(lead)
        result = lead_quality_gate_node(state)
        assert result is not None
        assert len(result.get("lead_queue", [])) >= 1


class TestPolicyGate:
    def test_in_scope_lead_allowed(self):
        lead = _make_lead(value="sub.example.com")
        state = _make_state_with_lead(lead, allowed_scope=["example.com"])
        result = policy_gate_node(state)
        # In-scope lead should remain in queue
        assert len(result.get("lead_queue", [])) >= 1
        for l in result["lead_queue"]:
            assert l.scope_status != "out_of_scope"

    def test_explicitly_out_of_scope_blocked(self):
        lead = _make_lead(value="evil.com")
        state = _make_state_with_lead(lead, allowed_scope=["example.com"], out_of_scope=["evil.com"])
        result = policy_gate_node(state)
        # Out-of-scope lead should be removed from queue
        for l in result.get("lead_queue", []):
            assert l.value != "evil.com"
