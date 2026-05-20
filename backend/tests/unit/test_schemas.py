"""
Unit tests for core/schemas — Lead, Finding, Observation.
"""
import uuid
import pytest
from datetime import datetime, timedelta

pytest.importorskip("core")

from core.schemas.lead import Lead, LeadType, LeadStatus
from core.schemas.finding import Finding, FindingCategory, RiskLevel
from core.schemas.observation import Observation, ObservationType


# ---------------------------------------------------------------------------
# Lead tests
# ---------------------------------------------------------------------------
class TestLeadDedupKey:
    def _make_lead(self, ltype, value):
        return Lead(
            type=ltype,
            value=value,
            raw_value=value,
            source="test",
            confidence=0.9,
            priority=0.5,
            depth=1,
            discovered_by="test_agent",
            status="pending",
            ttl=3,
            tags=[],
        )

    def test_dedup_key_format(self):
        lead = self._make_lead("domain", "example.com")
        assert lead.dedup_key == "domain:example.com"

    def test_dedup_key_ip(self):
        lead = self._make_lead("ip", "1.2.3.4")
        assert lead.dedup_key == "ip:1.2.3.4"

    def test_unique_type_same_value(self):
        lead_a = self._make_lead("domain", "example.com")
        lead_b = self._make_lead("ip", "example.com")
        assert lead_a.dedup_key != lead_b.dedup_key


class TestLeadExpiry:
    def _make_lead(self, ttl=3):
        return Lead(
            type="domain",
            value="example.com",
            raw_value="example.com",
            source="test",
            confidence=0.9,
            priority=0.5,
            depth=1,
            discovered_by="test_agent",
            status="pending",
            ttl=ttl,
            tags=[],
        )

    def test_not_expired_when_ttl_positive(self):
        lead = self._make_lead(ttl=3)
        assert not lead.is_expired()

    def test_expired_when_ttl_zero(self):
        lead = self._make_lead(ttl=0)
        assert lead.is_expired()

    def test_expired_when_ttl_negative(self):
        # TTL < 0 is rejected by Pydantic (ge=0), so invalid input raises
        with pytest.raises(Exception):
            self._make_lead(ttl=-1)

    def test_decrement_ttl_returns_updated(self):
        lead = self._make_lead(ttl=3)
        updated = lead.decrement_ttl()
        assert updated.ttl == 2

    def test_decrement_ttl_original_unchanged(self):
        lead = self._make_lead(ttl=3)
        updated = lead.decrement_ttl()
        assert lead.ttl == 3  # original unchanged (immutable)
        assert updated.ttl == 2


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------
class TestFindingPriority:
    def _make_finding(self, exposure=0.8, impact=0.7, confidence=0.9, centrality=0.5):
        return Finding(
            session_id="test_session",
            title="Test vulnerability",
            category="infrastructure_exposure",
            risk_level="high",
            description="Test description",
            entity_ids=[],
            observation_ids=[],
            evidence_refs=[],
            exposure_score=exposure,
            business_impact_score=impact,
            confidence_score=confidence,
            graph_centrality_score=centrality,
        )

    def test_priority_is_float(self):
        f = self._make_finding()
        p = f.calculate_priority()
        assert isinstance(p, float)

    def test_priority_range(self):
        f = self._make_finding()
        p = f.calculate_priority()
        # Priority: formula x 10, max should be ~10
        assert 0.0 <= p <= 10.0

    def test_high_scores_give_high_priority(self):
        f_high = self._make_finding(exposure=1.0, impact=1.0, confidence=1.0, centrality=1.0)
        f_low = self._make_finding(exposure=0.1, impact=0.1, confidence=0.1, centrality=0.1)
        assert f_high.calculate_priority() > f_low.calculate_priority()
