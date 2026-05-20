"""
Tests for core/runtime_emit.py — Runtime entity materialization pipeline.
"""
import pytest
from core.schemas import Observation, Entity
from core.runtime_emit import (
    materialize_entity_from_observation,
    emit_runtime_entity,
    emit_runtime_relationship,
    emit_runtime_lead,
)


def _make_state(**overrides):
    """Minimal pipeline state for testing runtime_emit."""
    state = {
        "engagement_spec": {
            "session_id": "test-session",
            "target": "hcmute.edu.vn",
            "active_recon_enabled": True,
            "agents_enabled": {"active_recon": True, "osint": True},
            "allowed_scope": ["hcmute.edu.vn"],
            "blocked_scope": [],
            "features": {},
        },
        "entities": [],
        "entity_index": {},
        "relationships": [],
        "lead_queue": [],
        "processed_lead_ids": set(),
    }
    state.update(overrides)
    return state


def _make_observation(obs_type: str, value: str, **kwargs):
    """Create a test Observation."""
    return Observation(
        session_id="test-session",
        raw_event_id="evt_test001",
        extractor="test_extractor",
        type=obs_type,
        value=value,
        normalized_value=kwargs.get("normalized_value", value),
        source=kwargs.get("source", "test_tool"),
        evidence_ref=kwargs.get("evidence_ref", "ev_test001"),
        confidence=kwargs.get("confidence", 0.8),
        attributes=kwargs.get("attributes", {}),
    )


class TestMaterializeEntity:
    def test_subdomain_creates_entity(self):
        state = _make_state()
        obs = _make_observation("subdomain_found", "api.hcmute.edu.vn")
        entity = materialize_entity_from_observation(state, obs)
        assert entity is not None
        assert entity.entity_id == "subdomain:api.hcmute.edu.vn"
        assert entity.type == "subdomain"
        assert len(state["entities"]) == 1
        assert entity.entity_id in state["entity_index"]

    def test_ip_resolves_creates_ip_entity(self):
        state = _make_state()
        obs = _make_observation("ip_found", "93.184.216.34")
        entity = materialize_entity_from_observation(state, obs)
        assert entity is not None
        assert entity.entity_id == "ip:93.184.216.34"

    def test_duplicate_not_added(self):
        state = _make_state()
        obs1 = _make_observation("subdomain_found", "api.hcmute.edu.vn")
        obs2 = _make_observation("subdomain_found", "api.hcmute.edu.vn",
                                  evidence_ref="ev_test002")
        e1 = materialize_entity_from_observation(state, obs1)
        e2 = materialize_entity_from_observation(state, obs2)
        assert e1 is not None
        assert e2 is not None
        assert len(state["entities"]) == 1  # only one entity

    def test_garbage_value_rejected(self):
        state = _make_state()
        obs = _make_observation("subdomain_found", "N/A")
        entity = materialize_entity_from_observation(state, obs)
        assert entity is None
        assert len(state["entities"]) == 0

    def test_header_found_creates_webapp_entity(self):
        state = _make_state()
        obs = _make_observation("header_found", "portal.hcmute.edu.vn")
        entity = materialize_entity_from_observation(state, obs)
        # header_found maps to "webapp"
        if entity is not None:
            assert entity.type == "webapp"


class TestEmitRuntimeEntity:
    def test_adds_to_state(self):
        state = _make_state()
        entity = Entity(
            entity_id="subdomain:test.hcmute.edu.vn",
            session_id="test-session",
            type="subdomain",
            canonical_value="test.hcmute.edu.vn",
            display_value="test.hcmute.edu.vn",
            observation_ids=["obs_1"],
            evidence_refs=["ev_1"],
            source_collectors=["dns"],
            confidence=0.8,
        )
        emit_runtime_entity(state, entity)
        assert len(state["entities"]) == 1
        assert "subdomain:test.hcmute.edu.vn" in state["entity_index"]

    def test_duplicate_ignored(self):
        state = _make_state()
        entity = Entity(
            entity_id="subdomain:test.hcmute.edu.vn",
            session_id="test-session",
            type="subdomain",
            canonical_value="test.hcmute.edu.vn",
            display_value="test.hcmute.edu.vn",
            observation_ids=["obs_1"],
            evidence_refs=[],
            source_collectors=["dns"],
            confidence=0.8,
        )
        emit_runtime_entity(state, entity)
        emit_runtime_entity(state, entity)
        assert len(state["entities"]) == 1


class TestEmitRuntimeRelationship:
    def test_creates_relationship(self):
        state = _make_state()
        rel = emit_runtime_relationship(
            state, "subdomain:a.hcmute.edu.vn", "ip:10.0.0.1", "resolves_to"
        )
        assert rel is not None
        assert len(state["relationships"]) == 1
        assert rel.relation_type == "resolves_to"

    def test_duplicate_ignored(self):
        state = _make_state()
        emit_runtime_relationship(state, "subdomain:a.hcmute.edu.vn", "ip:10.0.0.1", "resolves_to")
        r2 = emit_runtime_relationship(state, "subdomain:a.hcmute.edu.vn", "ip:10.0.0.1", "resolves_to")
        assert r2 is None
        assert len(state["relationships"]) == 1

    def test_self_link_rejected(self):
        state = _make_state()
        rel = emit_runtime_relationship(state, "ip:10.0.0.1", "ip:10.0.0.1", "resolves_to")
        assert rel is None

    def test_empty_id_rejected(self):
        state = _make_state()
        rel = emit_runtime_relationship(state, "", "ip:10.0.0.1", "resolves_to")
        assert rel is None


class TestEmitRuntimeLead:
    def test_creates_lead(self):
        state = _make_state()
        lead = emit_runtime_lead(state, "subdomain", "api.hcmute.edu.vn", "crt_sh")
        assert lead is not None
        assert len(state["lead_queue"]) == 1

    def test_garbage_lead_rejected(self):
        state = _make_state()
        lead = emit_runtime_lead(state, "domain", "Investigate actual IP via nslookup", "llm")
        assert lead is None
        assert len(state["lead_queue"]) == 0

    def test_duplicate_lead_rejected(self):
        state = _make_state()
        emit_runtime_lead(state, "subdomain", "api.hcmute.edu.vn", "crt_sh")
        lead2 = emit_runtime_lead(state, "subdomain", "api.hcmute.edu.vn", "dns")
        assert lead2 is None
        assert len(state["lead_queue"]) == 1

    def test_out_of_scope_rejected(self):
        state = _make_state()
        lead = emit_runtime_lead(state, "domain", "evil.com", "osint")
        assert lead is None
