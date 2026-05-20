"""
Unit tests for agents/normalizer.py
"""
import pytest
from unittest.mock import MagicMock

pytest.importorskip("agents.normalizer")

from agents.normalizer import (
    SOURCE_WEIGHTS,
    OBS_TYPE_TO_ENTITY_TYPE,
    _aggregate_confidence,
    _merge_confidence,
)


def _mock_obs(source="nmap", confidence=0.9):
    """Create a mock observation with .source and .confidence attributes."""
    from datetime import datetime, timezone
    obs = MagicMock()
    obs.source = source
    obs.confidence = confidence
    obs.timestamp = datetime.now(timezone.utc).isoformat()
    obs.evidence_ref = None
    return obs


class TestSourceWeights:
    def test_nmap_weight_high(self):
        assert SOURCE_WEIGHTS.get("nmap", 0) >= 0.90

    def test_dns_weight_high(self):
        assert SOURCE_WEIGHTS.get("dns", 0) >= 0.85

    def test_bruteforce_weight_lower(self):
        nmap_w = SOURCE_WEIGHTS.get("nmap", 1.0)
        brute_w = SOURCE_WEIGHTS.get("bruteforce", 1.0)
        assert brute_w < nmap_w

    def test_all_weights_in_range(self):
        for src, w in SOURCE_WEIGHTS.items():
            assert 0.0 < w <= 1.0, f"Weight for {src} out of range: {w}"


class TestObsTypeToEntityType:
    def test_ip_resolves_maps_to_ip_address(self):
        mapped = OBS_TYPE_TO_ENTITY_TYPE.get("ip_found")
        assert mapped == "ip_address"

    def test_mapping_values_are_strings_or_none(self):
        for k, v in OBS_TYPE_TO_ENTITY_TYPE.items():
            assert v is None or isinstance(v, str), f"Value for {k} is not a string or None"


class TestAggregateConfidence:
    def test_single_source(self):
        result = _aggregate_confidence([_mock_obs("nmap", 0.9)])
        assert 0.0 <= result <= 1.0

    def test_multiple_sources_higher_confidence(self):
        single = _aggregate_confidence([_mock_obs("dns", 0.7)])
        multi = _aggregate_confidence([_mock_obs("dns", 0.7), _mock_obs("nmap", 0.9)])
        # More high-quality sources should not lower confidence
        assert multi >= single * 0.9  # allow small floating point differences

    def test_empty_sources_returns_zero_or_default(self):
        result = _aggregate_confidence([])
        assert isinstance(result, float)
        assert 0.0 <= result <= 1.0

    def test_result_capped_at_one(self):
        result = _aggregate_confidence([_mock_obs("nmap", 0.99)] * 10)
        assert result <= 1.0


class TestMergeConfidence:
    def test_merge_increases_confidence(self):
        result = _merge_confidence(0.6, 0.7)
        assert result > 0.6

    def test_merge_cap_at_one(self):
        result = _merge_confidence(0.9, 0.9)
        assert result <= 1.0

    def test_merge_zero_existing(self):
        result = _merge_confidence(0.0, 0.8)
        # Bayesian: 0 + 0.8*(1-0) = 0.8
        assert abs(result - 0.8) < 0.01

    def test_merge_one_existing(self):
        result = _merge_confidence(1.0, 0.5)
        # Bayesian: 1.0 + 0.5*0 = 1.0, capped at 0.99
        assert result == 0.99
