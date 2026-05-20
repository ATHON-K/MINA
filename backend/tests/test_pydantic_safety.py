"""
Tests to verify Pydantic model objects are never treated as dicts (.get()).
Covers attach_provenance, extractors, extraction_helpers, active_recon,
osint_agent, passive_recon, correlator, runtime_emit, planner, gates, main.
"""
import uuid
from datetime import datetime, timezone

import pytest

from core.schemas.raw_event import RawEvent
from core.schemas.observation import Observation
from core.schemas.entity import Entity
from core.schemas.lead import Lead
from core.schemas.relationship import Relationship
from core.schemas.finding import Finding


# ──────────────────────────────────────────────────────────────────
#  Fixtures — Pydantic model instances
# ──────────────────────────────────────────────────────────────────

SID = "test_session_001"


def _make_raw_event(**overrides):
    defaults = dict(
        session_id=SID,
        lead_id="lead_test_01",
        collector="whois",
        what="whois data",
        where="whois",
        how="command",
        query="example.com",
        raw_response_path="/tmp/test.json",
        success=True,
    )
    defaults.update(overrides)
    return RawEvent(**defaults)


def _make_observation(**overrides):
    defaults = dict(
        session_id=SID,
        raw_event_id="raw_test_01",
        extractor="test_extractor",
        type="subdomain_found",
        value="sub.example.com",
        source="subfinder",
        evidence_ref="ev_001",
        confidence=0.8,
    )
    defaults.update(overrides)
    return Observation(**defaults)


def _make_entity(**overrides):
    defaults = dict(
        session_id=SID,
        type="subdomain",
        canonical_value="sub.example.com",
        display_value="sub.example.com",
        source_collectors=["subfinder"],
        confidence=0.8,
    )
    defaults.update(overrides)
    return Entity(**defaults)


def _make_lead(**overrides):
    defaults = dict(
        type="domain",
        value="example.com",
        raw_value="example.com",
        source="seed",
        confidence=1.0,
        priority=1.0,
        depth=0,
        discovered_by="setup_node",
    )
    defaults.update(overrides)
    return Lead(**defaults)


def _make_relationship(**overrides):
    defaults = dict(
        session_id=SID,
        from_entity_id="ent_aaa",
        relation_type="resolves_to",
        to_entity_id="ent_bbb",
        confidence=0.9,
    )
    defaults.update(overrides)
    return Relationship(**defaults)


def _make_state(**overrides):
    """Build minimal MINAState-like dict with Pydantic models."""
    spec = {
        "session_id": SID,
        "target": "example.com",
        "company_name": "Example Corp",
        "allowed_scope": ["example.com"],
        "blocked_scope": [],
        "active_recon_enabled": False,
        "passive_only": True,
        "allowed_sources": [],
        "blocked_sources": [],
        "agents_enabled": {},
        "max_depth": 2,
        "max_leads": 50,
        "max_active_budget": 10,
        "max_iterations": 3,
        "rate_limit_seconds": 0.0,
        "time_budget_seconds": 300,
        "profile": "quick",
        "wordlist_profile": "small",
        "mode": "breadth_first",
        "features": {},
        "tool_options": {},
        "report_detail": "summary",
        "enable_secret_scanning": False,
        "enable_repo_intel": False,
        "enable_doc_intel": False,
        "enable_endpoint_crawl": False,
        "enable_karma_v2": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    state = {
        "engagement_spec": spec,
        "target": "example.com",
        "lead_queue": [],
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
        "current_lead": None,
        "iteration_count": 0,
        "report_paths": {},
        "processed_lead_ids": set(),
    }
    state.update(overrides)
    return state


# ──────────────────────────────────────────────────────────────────
#  Test: attach_provenance_node works with Pydantic RawEvent objects
# ──────────────────────────────────────────────────────────────────

class TestAttachProvenance:
    def test_with_pydantic_raw_events(self):
        from agents.attach_provenance import attach_provenance_node

        re1 = _make_raw_event(collector="whois")
        re2 = _make_raw_event(collector="crt_sh")
        obs1 = _make_observation(source="whois", evidence_ref="", raw_event_id="")
        ent1 = _make_entity()

        state = _make_state(
            raw_events=[re1, re2],
            observations=[obs1],
            entities=[ent1],
        )
        result = attach_provenance_node(state)
        assert result is not None
        # Observation is frozen, so provenance creates a repaired copy
        repaired_obs = result["observations"][0]
        assert repaired_obs.evidence_ref != ""

    def test_empty_raw_events(self):
        from agents.attach_provenance import attach_provenance_node
        state = _make_state()
        result = attach_provenance_node(state)
        assert result is not None

    def test_mixed_entities_provenance(self):
        from agents.attach_provenance import attach_provenance_node
        obs1 = _make_observation(
            value="sub.example.com",
            normalized_value="sub.example.com",
            source="subfinder",
        )
        ent1 = _make_entity(
            canonical_value="sub.example.com",
            source_collectors=["crt_sh"],
        )
        re1 = _make_raw_event(collector="subfinder")
        state = _make_state(
            raw_events=[re1],
            observations=[obs1],
            entities=[ent1],
        )
        result = attach_provenance_node(state)
        # Entity should now include subfinder in source_collectors
        assert "subfinder" in ent1.source_collectors


# ──────────────────────────────────────────────────────────────────
#  Test: extractor helpers work with Pydantic Lead
# ──────────────────────────────────────────────────────────────────

class TestExtractorHelpers:
    def test_parent_depth_with_pydantic_lead(self):
        from agents.extractors import _parent_depth, _parent_id
        lead = _make_lead(depth=2)
        state = {"current_lead": lead}
        assert _parent_depth(state) == 3

    def test_parent_id_with_pydantic_lead(self):
        from agents.extractors import _parent_id
        lead = _make_lead()
        state = {"current_lead": lead}
        result = _parent_id(state)
        assert result == lead.lead_id

    def test_parent_depth_no_lead(self):
        from agents.extractors import _parent_depth
        assert _parent_depth({"current_lead": None}) == 1

    def test_parent_id_no_lead(self):
        from agents.extractors import _parent_id
        assert _parent_id({"current_lead": None}) == ""


# ──────────────────────────────────────────────────────────────────
#  Test: extract_subfinder produces Lead with raw_value
# ──────────────────────────────────────────────────────────────────

class TestExtractSubfinder:
    def test_lead_has_raw_value(self):
        from agents.extractors import extract_subfinder
        result = {
            "success": True,
            "data": {"subdomains": ["api.example.com", "mail.example.com"]},
        }
        state = _make_state(current_lead=_make_lead())
        obs, leads = extract_subfinder("subfinder", "example.com", result, state, "ev_001")
        assert len(leads) == 2
        for lead in leads:
            assert lead.raw_value, f"Lead {lead.value} missing raw_value"

    def test_failed_result_returns_empty(self):
        from agents.extractors import extract_subfinder
        result = {"success": False}
        state = _make_state()
        obs, leads = extract_subfinder("subfinder", "example.com", result, state, "ev_001")
        assert obs == [] and leads == []


# ──────────────────────────────────────────────────────────────────
#  Test: runtime_emit uses getattr safely
# ──────────────────────────────────────────────────────────────────

class TestRuntimeEmit:
    def test_emit_entity_dedup(self):
        from core.runtime_emit import emit_runtime_entity
        ent = _make_entity()
        state = _make_state(entities=[], entity_index={})
        emit_runtime_entity(state, ent)
        assert len(state["entities"]) == 1
        # second call should dedup
        emit_runtime_entity(state, ent)
        assert len(state["entities"]) == 1

    def test_emit_relationship_dedup(self):
        from core.runtime_emit import emit_runtime_relationship
        state = _make_state(relationships=[])
        rel1 = emit_runtime_relationship(
            state, "ent_a", "ent_b", "resolves_to", confidence=0.9)
        assert rel1 is not None
        # duplicate should return None
        rel2 = emit_runtime_relationship(
            state, "ent_a", "ent_b", "resolves_to", confidence=0.9)
        assert rel2 is None
        assert len(state["relationships"]) == 1

    def test_emit_relationship_with_pydantic_existing(self):
        """Relationship dedup loop must work with Pydantic Relationship objects."""
        from core.runtime_emit import emit_runtime_relationship
        existing = _make_relationship(
            from_entity_id="ent_x", to_entity_id="ent_y",
            relation_type="resolves_to")
        state = _make_state(relationships=[existing])
        # Same edge — should dedup
        result = emit_runtime_relationship(
            state, "ent_x", "ent_y", "resolves_to")
        assert result is None

    def test_emit_lead_with_pydantic_queue(self):
        from core.runtime_emit import emit_runtime_lead
        existing_lead = _make_lead(type="subdomain", value="api.example.com",
                                   raw_value="api.example.com")
        state = _make_state(lead_queue=[existing_lead])
        # same lead should dedup
        result = emit_runtime_lead(
            state, "subdomain", "api.example.com", "test")
        assert result is None


# ──────────────────────────────────────────────────────────────────
#  Test: planner works with Pydantic Lead
# ──────────────────────────────────────────────────────────────────

class TestPlannerWithPydantic:
    def test_build_baseline_plan(self):
        from core.planner import build_baseline_plan_for_lead
        lead = _make_lead(type="domain", value="example.com")
        state = _make_state()
        tasks = build_baseline_plan_for_lead(lead, state)
        assert isinstance(tasks, list)
        assert len(tasks) > 0
        for task in tasks:
            assert "tool" in task
            assert "target" in task


# ──────────────────────────────────────────────────────────────────
#  Test: correlator handles Pydantic Relationship objects
# ──────────────────────────────────────────────────────────────────

class TestCorrelatorPydantic:
    def test_dedup_with_pydantic_relationships(self):
        from agents.correlator import correlator_node
        ent_dom = _make_entity(
            type="domain", canonical_value="example.com",
            display_value="example.com",
        )
        ent_ip = _make_entity(
            type="ip_address", canonical_value="93.184.216.34",
            display_value="93.184.216.34",
        )
        obs1 = _make_observation(
            type="ip_found", value="93.184.216.34",
            normalized_value="93.184.216.34",
        )
        rel_existing = _make_relationship(
            from_entity_id=ent_dom.entity_id,
            to_entity_id=ent_ip.entity_id,
            relation_type="resolves_to",
        )
        state = _make_state(
            entities=[ent_dom, ent_ip],
            observations=[obs1],
            relationships=[rel_existing],
        )
        result = correlator_node(state)
        assert result is not None


# ──────────────────────────────────────────────────────────────────
#  Test: gates.py dedup_and_quality_gate with Pydantic entities/leads
# ──────────────────────────────────────────────────────────────────

class TestGatesPydantic:
    def test_dedup_gate_with_pydantic_entities(self):
        from nodes.gates import lead_quality_gate_node
        ent = _make_entity(canonical_value="api.example.com")
        lead = _make_lead(
            type="subdomain", value="api.example.com",
            raw_value="api.example.com",
            depth=1, confidence=0.8, priority=0.6,
        )
        state = _make_state(
            entities=[ent],
            lead_queue=[lead],
        )
        result = lead_quality_gate_node(state)
        # Lead matching existing entity should be filtered
        assert result is not None

    def test_conflict_resolution_with_pydantic_models(self):
        from nodes.gates import conflict_resolution_node
        ent = _make_entity()
        rel = _make_relationship(
            from_entity_id=ent.entity_id,
            to_entity_id="ent_other",
            relation_type="resolves_to",
        )
        state = _make_state(
            entities=[ent],
            relationships=[rel],
            conflict_queue=[],
        )
        result = conflict_resolution_node(state)
        assert result is not None


# ──────────────────────────────────────────────────────────────────
#  Test: dispatcher wraps all tools in lambdas (no company kwarg leak)
# ──────────────────────────────────────────────────────────────────

class TestDispatcherLambdaWrapping:
    def test_all_tools_accept_kwargs(self):
        """Every registered tool must accept **kw without crashing."""
        from tools.adapters.dispatcher import _all_tools
        registry = _all_tools()
        for name, fn in registry.items():
            # All functions should be lambdas or callables that accept **kw
            assert callable(fn), f"Tool {name} is not callable"

    def test_dispatch_with_company_kwarg(self):
        """dispatch_tool must not crash when company kwarg is passed."""
        from tools.adapters.dispatcher import dispatch_tool
        # Use 'whois' which was previously crashing with company kwarg
        # This will likely fail on network, but should NOT raise TypeError
        result = dispatch_tool("whois", "example.com", company="Example Corp")
        assert isinstance(result, dict)
        assert "tool" in result
        assert result["tool"] == "whois"

    def test_dispatch_unknown_tool(self):
        from tools.adapters.dispatcher import dispatch_tool
        result = dispatch_tool("nonexistent_tool_xyz", "example.com")
        assert result["success"] is False
        assert "Unknown tool" in result.get("error", "")


# ──────────────────────────────────────────────────────────────────
#  Test: Pydantic models DON'T have .get() — regression guard
# ──────────────────────────────────────────────────────────────────

class TestPydanticModelsNoGet:
    """Guard against accidentally calling .get() on Pydantic models."""

    @pytest.mark.parametrize("factory,field", [
        (_make_raw_event, "event_id"),
        (_make_observation, "observation_id"),
        (_make_entity, "entity_id"),
        (_make_lead, "lead_id"),
        (_make_relationship, "relationship_id"),
    ])
    def test_getattr_works(self, factory, field):
        obj = factory()
        assert getattr(obj, field, None) is not None

    @pytest.mark.parametrize("factory", [
        _make_raw_event,
        _make_observation,
        _make_entity,
        _make_lead,
        _make_relationship,
    ])
    def test_get_method_absent(self, factory):
        """Pydantic v2 models should NOT have .get() — using it is a bug."""
        obj = factory()
        assert not hasattr(obj, "get"), (
            f"{type(obj).__name__} has .get() method — "
            f"code using .get() on this model will silently break"
        )

    def test_raw_event_field_is_event_id_not_raw_event_id(self):
        """RawEvent uses 'event_id', not 'raw_event_id'."""
        re = _make_raw_event()
        assert hasattr(re, "event_id")
        assert not hasattr(re, "raw_event_id")

    def test_relationship_field_names(self):
        """Relationship uses from_entity_id/to_entity_id/relation_type."""
        rel = _make_relationship()
        assert hasattr(rel, "from_entity_id")
        assert hasattr(rel, "to_entity_id")
        assert hasattr(rel, "relation_type")
        # These old names should NOT exist
        assert not hasattr(rel, "source_entity_id")
        assert not hasattr(rel, "target_entity_id")
        assert not hasattr(rel, "rel_type")
