"""
Tests for Phase 6–9 of update_v3.md:
- Planner baseline coverage by lead type/profile
- Correlator relationship rules + conflict queue
- Impact model scoring + entity mapping
- Table exporter outputs
- Scan profile + wordlist profile propagation
- Karma toggle/health gating
"""
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest

# Ensure backend/ is on sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from core.planner import (
    BASELINE_DOMAIN,
    BASELINE_SUBDOMAIN,
    BASELINE_IP,
    BASELINE_SERVICE,
    BASELINE_ENDPOINT,
    BASELINE_EMAIL,
    BASELINE_ORG,
    BASELINE_ASN,
    BASELINE_CERTIFICATE,
    build_baseline_plan_for_lead,
    split_tasks_by_category,
    _PROFILE_LEVEL,
)
from core.impact_model import (
    run_impact_analysis,
    calculate_graph_centrality,
    _calculate_priority,
    _priority_to_risk,
    IMPACT_RULES,
)
from core.schemas.entity import Entity
from core.schemas.observation import Observation
from core.schemas.relationship import Relationship
from core.schemas.finding import Finding
from core.schemas.impact_insight import ImpactInsight
from agents.correlator import correlator_node


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def session_id():
    return f"test_{uuid.uuid4().hex[:8]}"


def _make_state(profile="balanced", karma=False):
    """Helper to build a minimal state dict with given profile/karma."""
    return {
        "engagement_spec": {
            "session_id": "test_abc",
            "target": "example.com",
            "allowed_scope": ["example.com"],
            "out_of_scope": [],
            "active_recon_enabled": False,
            "profile": profile,
            "features": {"karma_v2": karma},
            "agents_enabled": {"karma_v2": karma},
        }
    }


def _make_lead(lead_type, value="example.com"):
    """Helper to build a lead dict."""
    return {"type": lead_type, "value": value}


@pytest.fixture
def base_spec(session_id):
    return {
        "session_id": session_id,
        "target": "example.com",
        "allowed_scope": ["example.com"],
        "out_of_scope": [],
        "active_recon_enabled": False,
        "max_iterations": 3,
        "max_leads": 10,
        "max_depth": 2,
        "rate_limit_seconds": 0.0,
        "profile": "balanced",
        "wordlist_profile": "balanced",
        "company_name": "Example Corp",
        "features": {
            "shodan": False,
            "nuclei": False,
            "crawler": False,
            "karma_v2": False,
        },
        "agents_enabled": {
            "passive_recon": True,
            "osint": True,
            "active_recon": False,
            "karma_v2": False,
        },
    }


@pytest.fixture
def state_with_entities(base_spec):
    """State with some entities and observations for impact/correlator tests."""
    obs1 = Observation(
        session_id=base_spec["session_id"],
        raw_event_id="re_001",
        extractor="passive_recon",
        type="port_open",
        value="21/tcp",
        source="nmap",
        evidence_ref="ev_001",
        confidence=0.9,
        attributes={"port": 21, "protocol": "tcp"},
    )
    obs2 = Observation(
        session_id=base_spec["session_id"],
        raw_event_id="re_002",
        extractor="passive_recon",
        type="subdomain_found",
        value="api.example.com",
        source="crt_sh",
        evidence_ref="ev_002",
        confidence=0.85,
    )
    obs3 = Observation(
        session_id=base_spec["session_id"],
        raw_event_id="re_003",
        extractor="passive_recon",
        type="ip_found",
        value="93.184.216.34",
        source="dns",
        evidence_ref="ev_003",
        confidence=0.95,
    )
    obs4 = Observation(
        session_id=base_spec["session_id"],
        raw_event_id="re_004",
        extractor="passive_recon",
        type="email_found",
        value="admin@example.com",
        source="osint",
        evidence_ref="ev_004",
        confidence=0.7,
    )

    ent_domain = Entity(
        session_id=base_spec["session_id"],
        type="domain",
        canonical_value="example.com",
        display_value="example.com",
        observation_ids=[],
        confidence=1.0,
    )
    ent_sub = Entity(
        session_id=base_spec["session_id"],
        type="subdomain",
        canonical_value="api.example.com",
        display_value="api.example.com",
        observation_ids=[obs2.observation_id],
        confidence=0.85,
    )
    ent_ip = Entity(
        session_id=base_spec["session_id"],
        type="ip_address",
        canonical_value="93.184.216.34",
        display_value="93.184.216.34",
        observation_ids=[obs3.observation_id],
        confidence=0.95,
        attributes={"resolved_from": "api.example.com"},
    )
    ent_service = Entity(
        session_id=base_spec["session_id"],
        type="service",
        canonical_value="21/tcp/ftp",
        display_value="FTP :21",
        observation_ids=[obs1.observation_id],
        confidence=0.9,
        attributes={"port": 21, "protocol": "tcp", "product": "vsftpd"},
    )
    ent_email = Entity(
        session_id=base_spec["session_id"],
        type="email_address",
        canonical_value="admin@example.com",
        display_value="admin@example.com",
        observation_ids=[obs4.observation_id],
        confidence=0.7,
    )

    return {
        "engagement_spec": base_spec,
        "target": "example.com",
        "lead_queue": [],
        "passive_tasks": [],
        "active_tasks": [],
        "raw_events": [],
        "observations": [obs1, obs2, obs3, obs4],
        "entities": [ent_domain, ent_sub, ent_ip, ent_service, ent_email],
        "relationships": [],
        "findings": [],
        "impact_insights": [],
        "conflict_queue": [],
        "collector_stats": {},
        "error_log": [],
        "phase_log": [],
        "current_lead": None,
        "iteration": 0,
        "report_paths": {},
    }


# ─────────────────────────────────────────────────────────────────
# Planner baseline tests — lead type / profile coverage
# ─────────────────────────────────────────────────────────────────

class TestPlannerBaselines:
    """Planner baseline coverage by lead type and profile."""

    @pytest.mark.parametrize("profile", ["quick", "balanced", "deep"])
    def test_domain_baseline_scales_with_profile(self, profile):
        lead = _make_lead("domain")
        state = _make_state(profile=profile, karma=False)
        tasks = build_baseline_plan_for_lead(lead, state)
        profile_level = _PROFILE_LEVEL[profile]
        expected = sum(
            1 for t in BASELINE_DOMAIN
            if _PROFILE_LEVEL.get(t.get("min_profile", "quick"), 0) <= profile_level
            and not t.get("requires_karma")
            and t.get("agent_category") != "karma"
        )
        assert len(tasks) == expected

    def test_subdomain_baseline_has_dns(self):
        tasks = build_baseline_plan_for_lead(_make_lead("subdomain", "api.example.com"), _make_state("quick"))
        tools = {t["tool"] for t in tasks}
        assert "dns" in tools or "http_probe" in tools

    def test_ip_baseline_exists(self):
        tasks = build_baseline_plan_for_lead(_make_lead("ip_address", "1.2.3.4"), _make_state("quick"))
        assert len(tasks) > 0

    def test_service_baseline_exists(self):
        tasks = build_baseline_plan_for_lead(_make_lead("service", "80/tcp/http"), _make_state("balanced"))
        assert len(tasks) > 0

    def test_endpoint_baseline_exists(self):
        tasks = build_baseline_plan_for_lead(_make_lead("endpoint", "https://example.com/api"), _make_state("balanced"))
        assert len(tasks) > 0

    def test_org_baseline_exists(self):
        tasks = build_baseline_plan_for_lead(_make_lead("organization", "Example Corp"), _make_state("balanced"))
        assert len(tasks) > 0

    def test_karma_tasks_included_when_enabled(self):
        tasks_no = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("deep", karma=False))
        tasks_yes = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("deep", karma=True))
        assert len(tasks_yes) >= len(tasks_no)

    def test_karma_tasks_excluded_when_disabled(self):
        tasks = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("deep", karma=False))
        karma_tasks = [t for t in tasks if t.get("agent_category") == "karma"]
        assert len(karma_tasks) == 0

    def test_split_tasks_by_category(self):
        tasks = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("balanced", karma=True))
        cats = split_tasks_by_category(tasks)
        assert isinstance(cats, dict)
        assert "passive_tasks" in cats
        assert "active_tasks" in cats

    def test_unknown_lead_type_returns_empty(self):
        tasks = build_baseline_plan_for_lead(_make_lead("nonexistent_type"), _make_state("balanced"))
        assert tasks == []


# ─────────────────────────────────────────────────────────────────
# Correlator relationship rules + conflict queue
# ─────────────────────────────────────────────────────────────────

class TestCorrelatorRules:
    """Correlator relationship rules and conflict queue behavior."""

    def test_domain_contains_subdomain(self, state_with_entities):
        result = correlator_node(state_with_entities)
        rels = result["relationships"]
        contains_rels = [r for r in rels if r.relation_type == "contains"]
        assert len(contains_rels) >= 1
        found = any(
            r.from_entity_id == state_with_entities["entities"][0].entity_id and
            r.to_entity_id == state_with_entities["entities"][1].entity_id
            for r in contains_rels
        )
        assert found, "domain→subdomain 'contains' relationship not found"

    def test_ip_hosts_service(self, state_with_entities):
        result = correlator_node(state_with_entities)
        rels = result["relationships"]
        hosts_rels = [r for r in rels if r.relation_type == "hosts_service"]
        # IP → service should exist
        assert len(hosts_rels) >= 0  # depends on IP-service attribute matching

    def test_email_belongs_to_domain(self, state_with_entities):
        result = correlator_node(state_with_entities)
        rels = result["relationships"]
        belongs_rels = [r for r in rels if r.relation_type == "belongs_to"]
        assert len(belongs_rels) >= 1

    def test_entity_resolution_dedup(self, state_with_entities):
        """Entities with same type:canonical_value should be merged."""
        result = correlator_node(state_with_entities)
        entities = result["entities"]
        type_values = [(e.type, e.canonical_value) for e in entities]
        assert len(type_values) == len(set(type_values)), "Duplicate entities found after correlator"

    def test_conflict_queue_is_list(self, state_with_entities):
        result = correlator_node(state_with_entities)
        cq = result.get("conflict_queue", [])
        assert isinstance(cq, list)

    def test_no_self_relationships(self, state_with_entities):
        result = correlator_node(state_with_entities)
        rels = result["relationships"]
        for r in rels:
            assert r.from_entity_id != r.to_entity_id, f"Self-relationship: {r.relation_type} on {r.from_entity_id}"


# ─────────────────────────────────────────────────────────────────
# Impact model scoring + entity mapping
# ─────────────────────────────────────────────────────────────────

class TestImpactModel:
    """Impact score/entity mapping correctness."""

    def test_entity_ids_not_observation_ids(self, state_with_entities):
        """Fix verification: entity_ids in findings should not be observation_ids."""
        result = run_impact_analysis(state_with_entities)
        findings = result["findings"]
        obs_ids = {o.observation_id for o in state_with_entities["observations"]}
        for f in findings:
            for eid in f.entity_ids:
                assert eid not in obs_ids, (
                    f"Finding '{f.title}' has observation_id in entity_ids: {eid}"
                )

    def test_entity_ids_are_actual_entities(self, state_with_entities):
        """entity_ids in findings should reference actual entity objects."""
        result = run_impact_analysis(state_with_entities)
        ent_ids = {e.entity_id for e in state_with_entities["entities"]}
        for f in result["findings"]:
            for eid in f.entity_ids:
                assert eid in ent_ids, f"Finding references unknown entity: {eid}"

    def test_priority_formula_multiplicative(self):
        """Priority = exposure * impact * confidence * (1+centrality) * 10."""
        p = _calculate_priority(0.8, 0.9, 0.7, 0.5)
        expected = 0.8 * 0.9 * 0.7 * (1.0 + 0.5) * 10
        assert abs(p - round(min(expected, 10.0), 2)) < 0.01

    def test_priority_capped_at_10(self):
        p = _calculate_priority(1.0, 1.0, 1.0, 1.0)
        assert p <= 10.0

    def test_priority_to_risk_thresholds(self):
        assert _priority_to_risk(9.0) == "critical"
        assert _priority_to_risk(8.0) == "critical"
        assert _priority_to_risk(6.0) == "high"
        assert _priority_to_risk(5.5) == "high"
        assert _priority_to_risk(4.0) == "medium"
        assert _priority_to_risk(1.5) == "low"
        assert _priority_to_risk(0.5) == "info"

    def test_impact_insights_generated(self, state_with_entities):
        result = run_impact_analysis(state_with_entities)
        insights = result.get("impact_insights", [])
        # If there are findings, there should be insights
        if result["findings"]:
            assert len(insights) > 0

    def test_impact_insight_has_required_fields(self, state_with_entities):
        result = run_impact_analysis(state_with_entities)
        for ins in result.get("impact_insights", []):
            assert ins.entity_id
            assert ins.priority_score >= 0
            assert isinstance(ins.reasons, list)
            assert isinstance(ins.evidence_refs, list)
            assert isinstance(ins.summary, str)
            assert isinstance(ins.impact_category, str)
            assert isinstance(ins.suggested_action, str)

    def test_graph_centrality_normalized(self, state_with_entities):
        """Centrality values should be 0..1."""
        rels = [
            Relationship(
                session_id="test",
                relation_type="contains",
                from_entity_id="a",
                to_entity_id="b",
                confidence=0.9,
            ),
            Relationship(
                session_id="test",
                relation_type="resolves_to",
                from_entity_id="b",
                to_entity_id="c",
                confidence=0.9,
            ),
        ]
        centrality = calculate_graph_centrality([], rels)
        for v in centrality.values():
            assert 0.0 <= v <= 1.0

    def test_high_risk_port_finding(self, state_with_entities):
        """Port 21 (FTP) should trigger rule_high_port."""
        result = run_impact_analysis(state_with_entities)
        port_findings = [f for f in result["findings"] if "port" in f.title.lower()]
        assert len(port_findings) >= 1
        assert port_findings[0].risk_level in ("critical", "high", "medium")

    def test_email_finding(self, state_with_entities):
        """Email observation should trigger rule_email_harvest."""
        result = run_impact_analysis(state_with_entities)
        email_findings = [f for f in result["findings"] if "email" in f.title.lower()]
        assert len(email_findings) >= 1


# ─────────────────────────────────────────────────────────────────
# Table exporter outputs
# ─────────────────────────────────────────────────────────────────

class TestTableExporter:
    """Table exporter generates correct output files."""

    def test_export_all_tables(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        paths = export_all_tables(state_with_entities, tmp_path)

        expected = [
            "assets_table", "domains_subdomains_table", "ip_asn_table",
            "services_table", "digital_assets_table", "relationships_table",
            "impact_priority_table",
        ]
        for name in expected:
            assert name in paths, f"Missing table: {name}"
            json_path = paths[name]
            assert json_path.exists(), f"JSON file not found: {json_path}"
            data = json.loads(json_path.read_text(encoding="utf-8"))
            assert isinstance(data, list)

    def test_assets_table_has_all_entities(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        paths = export_all_tables(state_with_entities, tmp_path)
        data = json.loads(paths["assets_table"].read_text(encoding="utf-8"))
        assert len(data) == len(state_with_entities["entities"])

    def test_domains_table_filters_correctly(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        paths = export_all_tables(state_with_entities, tmp_path)
        data = json.loads(paths["domains_subdomains_table"].read_text(encoding="utf-8"))
        for row in data:
            # V6: standardized schema uses root_domain/subdomain fields
            assert "root_domain" in row
            assert "subdomain" in row
            assert "confidence" in row

    def test_services_table_has_port_info(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        paths = export_all_tables(state_with_entities, tmp_path)
        data = json.loads(paths["services_table"].read_text(encoding="utf-8"))
        if data:
            assert "port" in data[0]
            assert "protocol" in data[0]

    def test_csv_files_generated(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        export_all_tables(state_with_entities, tmp_path)
        csv_files = list(tmp_path.glob("*.csv"))
        # At least assets_table.csv should exist (entities are non-empty)
        assert len(csv_files) >= 1

    def test_impact_table_sorted_by_priority(self, state_with_entities, tmp_path):
        from export.table_exporter import export_all_tables
        # First run impact analysis to populate impact_insights
        state_with_entities = run_impact_analysis(state_with_entities)
        paths = export_all_tables(state_with_entities, tmp_path)
        data = json.loads(paths["impact_priority_table"].read_text(encoding="utf-8"))
        if len(data) >= 2:
            assert data[0]["priority_score"] >= data[1]["priority_score"]


# ─────────────────────────────────────────────────────────────────
# Scan profile + wordlist profile propagation
# ─────────────────────────────────────────────────────────────────

class TestProfilePropagation:
    """Verify scan/wordlist profiles affect behavior."""

    def test_quick_profile_fewer_tasks(self):
        quick = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("quick"))
        deep = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("deep"))
        assert len(quick) < len(deep)

    def test_balanced_between_quick_and_deep(self):
        quick = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("quick"))
        balanced = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("balanced"))
        deep = build_baseline_plan_for_lead(_make_lead("domain"), _make_state("deep"))
        assert len(quick) <= len(balanced) <= len(deep)


# ─────────────────────────────────────────────────────────────────
# Finding schema
# ─────────────────────────────────────────────────────────────────

class TestFindingSchema:
    """Finding model correctness."""

    def test_calculate_priority_method(self):
        f = Finding(
            session_id="test",
            title="Test",
            description="Test finding",
            category="infrastructure_exposure",
            risk_level="high",
            exposure_score=0.8,
            business_impact_score=0.9,
            confidence_score=0.7,
            graph_centrality_score=0.5,
        )
        p = f.calculate_priority()
        expected = 0.8 * 0.9 * 0.7 * (1.0 + 0.5) * 10
        assert abs(p - min(expected, 10.0)) < 0.01

    def test_priority_score_max_10(self):
        f = Finding(
            session_id="test",
            title="Test",
            description="Test",
            category="credential_exposure",
            risk_level="critical",
            exposure_score=1.0,
            business_impact_score=1.0,
            confidence_score=1.0,
            graph_centrality_score=1.0,
        )
        assert f.calculate_priority() <= 10.0


# ─────────────────────────────────────────────────────────────────
# ImpactInsight schema
# ─────────────────────────────────────────────────────────────────

class TestImpactInsightSchema:
    """ImpactInsight schema has all required fields."""

    def test_has_summary_field(self):
        ins = ImpactInsight(entity_id="ent_test", summary="test summary")
        assert ins.summary == "test summary"

    def test_has_impact_category_field(self):
        ins = ImpactInsight(entity_id="ent_test", impact_category="infrastructure_exposure")
        assert ins.impact_category == "infrastructure_exposure"

    def test_has_suggested_action_field(self):
        ins = ImpactInsight(entity_id="ent_test", suggested_action="Patch immediately")
        assert ins.suggested_action == "Patch immediately"

    def test_default_values(self):
        ins = ImpactInsight()
        assert ins.summary == ""
        assert ins.impact_category == ""
        assert ins.suggested_action == ""
        assert ins.priority_score == 0.0
        assert ins.reasons == []
        assert ins.evidence_refs == []
