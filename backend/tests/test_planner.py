"""
Tests for core/planner.py — Deterministic baseline + LLM augmentation planner.
"""
from unittest.mock import MagicMock
from core.planner import (
    build_baseline_plan_for_lead,
    augment_plan_with_llm,
    dedupe_plan,
    apply_agent_toggles,
    split_tasks_by_category,
    BASELINE_DOMAIN,
    BASELINE_IP,
    BASELINE_URL,
    _BASELINE_MAP,
)


def _make_lead(lead_type: str, value: str):
    """Create a simple lead-like object for testing."""
    lead = MagicMock()
    lead.type = lead_type
    lead.value = value
    return lead


def _make_spec(**overrides):
    """Create a minimal engagement_spec dict."""
    spec = {
        "target": "example.com",
        "active_recon_enabled": True,
        "agents_enabled": {
            "active_recon": True,
            "karma_v2": False,
            "osint": True,
        },
        "features": {},
        "allowed_scope": ["example.com"],
        "blocked_scope": [],
        "allowed_sources": [],
        "blocked_sources": [],
        "profile": "balanced",
    }
    spec.update(overrides)
    return spec


class TestBaselinePlanForLead:
    def test_domain_baseline_has_dns(self):
        lead = _make_lead("domain", "example.com")
        spec = _make_spec()
        tasks = build_baseline_plan_for_lead(lead, spec)
        tools = [t["tool"] for t in tasks]
        assert "dns" in tools

    def test_domain_baseline_count(self):
        """balanced profile + karma off → quick + balanced tasks only."""
        lead = _make_lead("domain", "example.com")
        spec = _make_spec()
        tasks = build_baseline_plan_for_lead(lead, spec)
        # Profile=balanced, karma=off: excludes deep (3) + karma (4) from 25 total
        expected = [t for t in BASELINE_DOMAIN
                    if t.get("min_profile", "quick") in ("quick", "balanced")
                    and t.get("agent_category") != "karma"]
        assert len(tasks) == len(expected)

    def test_ip_baseline_has_reverse_dns(self):
        lead = _make_lead("ip", "10.0.0.1")
        spec = _make_spec(allowed_scope=["10.0.0.1"])
        tasks = build_baseline_plan_for_lead(lead, spec)
        tools = [t["tool"] for t in tasks]
        assert "reverse_dns" in tools

    def test_url_baseline_has_crawl(self):
        lead = _make_lead("url", "https://example.com/app")
        spec = _make_spec()
        tasks = build_baseline_plan_for_lead(lead, spec)
        tools = [t["tool"] for t in tasks]
        assert "crawl" in tools

    def test_garbage_lead_returns_empty(self):
        lead = _make_lead("domain", "Investigate actual IP via nslookup")
        spec = _make_spec()
        tasks = build_baseline_plan_for_lead(lead, spec)
        assert tasks == []

    def test_unknown_type_returns_empty(self):
        lead = _make_lead("unknown_type_xyz", "whatever")
        spec = _make_spec(allowed_scope=[])
        tasks = build_baseline_plan_for_lead(lead, spec)
        assert tasks == []

    def test_task_has_target(self):
        lead = _make_lead("domain", "example.com")
        spec = _make_spec()
        tasks = build_baseline_plan_for_lead(lead, spec)
        for t in tasks:
            assert t["target"] == "example.com"


class TestAugmentPlanWithLLM:
    def test_new_tool_added(self):
        baseline = [{"tool": "dns", "target": "example.com", "priority": 0.9, "agent_category": "passive"}]
        llm_tasks = [{"tool": "whois", "target": "example.com", "priority": 0.8, "agent_category": "passive"}]
        result = augment_plan_with_llm(MagicMock(), baseline, llm_tasks)
        tools = [t["tool"] for t in result]
        assert "whois" in tools
        assert len(result) == 2

    def test_duplicate_not_added(self):
        baseline = [{"tool": "dns", "target": "example.com", "priority": 0.9, "agent_category": "passive"}]
        llm_tasks = [{"tool": "dns", "target": "example.com", "priority": 0.5}]
        result = augment_plan_with_llm(MagicMock(), baseline, llm_tasks)
        assert len(result) == 1

    def test_empty_tool_skipped(self):
        baseline = []
        llm_tasks = [{"tool": "", "target": "example.com"}]
        result = augment_plan_with_llm(MagicMock(), baseline, llm_tasks)
        assert result == []


class TestDedupePlan:
    def test_keeps_highest_priority(self):
        tasks = [
            {"tool": "dns", "target": "example.com", "priority": 0.5},
            {"tool": "dns", "target": "example.com", "priority": 0.9},
        ]
        result = dedupe_plan(tasks)
        assert len(result) == 1
        assert result[0]["priority"] == 0.9

    def test_different_targets_kept(self):
        tasks = [
            {"tool": "dns", "target": "a.com", "priority": 0.5},
            {"tool": "dns", "target": "b.com", "priority": 0.5},
        ]
        result = dedupe_plan(tasks)
        assert len(result) == 2


class TestApplyAgentToggles:
    def test_active_disabled_filters_active(self):
        spec = _make_spec(active_recon_enabled=False, agents_enabled={"active_recon": False, "osint": True})
        tasks = [
            {"tool": "dns", "target": "example.com", "agent_category": "passive"},
            {"tool": "nmap", "target": "example.com", "agent_category": "active"},
        ]
        result = apply_agent_toggles(tasks, spec)
        tools = [t["tool"] for t in result]
        assert "dns" in tools
        assert "nmap" not in tools

    def test_karma_disabled_filters_karma(self):
        spec = _make_spec(agents_enabled={"active_recon": True, "karma_v2": False, "osint": True})
        tasks = [
            {"tool": "karma_check", "target": "example.com", "agent_category": "karma"},
        ]
        result = apply_agent_toggles(tasks, spec)
        assert len(result) == 0


class TestSplitByCategory:
    def test_splits_passive_and_active(self):
        tasks = [
            {"tool": "dns", "target": "a.com", "priority": 0.9, "agent_category": "passive"},
            {"tool": "nmap", "target": "a.com", "priority": 0.8, "agent_category": "active"},
            {"tool": "wayback", "target": "a.com", "priority": 0.6, "agent_category": "osint"},
        ]
        result = split_tasks_by_category(tasks)
        assert len(result["passive_tasks"]) == 2  # passive + osint
        assert len(result["active_tasks"]) == 1

    def test_sorted_by_priority_desc(self):
        tasks = [
            {"tool": "a", "target": "x", "priority": 0.3, "agent_category": "passive"},
            {"tool": "b", "target": "x", "priority": 0.8, "agent_category": "passive"},
        ]
        result = split_tasks_by_category(tasks)
        assert result["passive_tasks"][0]["tool"] == "b"


class TestBaselineMapCoverage:
    def test_webapp_maps_to_subdomain_baseline(self):
        from core.planner import BASELINE_SUBDOMAIN
        assert _BASELINE_MAP["webapp"] is BASELINE_SUBDOMAIN

    def test_ip_address_maps_to_ip_baseline(self):
        assert _BASELINE_MAP["ip_address"] is _BASELINE_MAP["ip"]
