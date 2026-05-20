"""
Tests for toggle wiring — verifying that agent/feature toggles correctly
filter tasks, block active recon, and respect rate_limit / scope settings.
"""
from unittest.mock import MagicMock

from core.scope import (
    filter_allowed_tasks,
    is_in_scope,
    is_out_of_scope,
    allow_active_for_lead,
    is_garbage_lead,
)
from core.planner import (
    build_baseline_plan_for_lead,
    apply_agent_toggles,
    split_tasks_by_category,
)


def _make_spec(**overrides):
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
        "rate_limit": 1000,
    }
    spec.update(overrides)
    return spec


def _make_lead(lead_type, value):
    lead = MagicMock()
    lead.type = lead_type
    lead.value = value
    return lead


class TestActiveReconToggleOff:
    """When active_recon_enabled=False, no active tasks should pass."""

    def test_filter_strips_active_tasks(self):
        spec = _make_spec(
            active_recon_enabled=False,
            agents_enabled={"active_recon": False, "osint": True},
        )
        tasks = [
            {"tool": "dns", "target": "example.com", "agent_category": "passive"},
            {"tool": "nmap", "target": "example.com", "agent_category": "active"},
            {"tool": "httpx", "target": "example.com", "agent_category": "active"},
            {"tool": "wayback", "target": "example.com", "agent_category": "osint"},
        ]
        result = filter_allowed_tasks(tasks, spec)
        cats = {t["agent_category"] for t in result}
        assert "active" not in cats
        assert "passive" in cats
        assert "osint" in cats

    def test_allow_active_for_lead_returns_false(self):
        spec = _make_spec(active_recon_enabled=False)
        lead = _make_lead("subdomain", "api.example.com")
        assert allow_active_for_lead(lead, spec) is False

    def test_planner_baseline_then_toggle_filters(self):
        """Full pipeline: build baseline → apply toggles → no active tasks."""
        spec = _make_spec(
            active_recon_enabled=False,
            agents_enabled={"active_recon": False, "osint": True},
        )
        lead = _make_lead("domain", "example.com")
        tasks = build_baseline_plan_for_lead(lead, spec)
        filtered = apply_agent_toggles(tasks, spec)
        for t in filtered:
            assert t["agent_category"] != "active"


class TestKarmaToggleOff:
    """When karma_v2 is disabled, karma tasks should be filtered."""

    def test_karma_tasks_removed(self):
        spec = _make_spec(agents_enabled={"active_recon": True, "karma_v2": False, "osint": True})
        tasks = [
            {"tool": "karma_check", "target": "user@example.com", "agent_category": "karma"},
            {"tool": "dns", "target": "example.com", "agent_category": "passive"},
        ]
        result = filter_allowed_tasks(tasks, spec)
        tools = [t["tool"] for t in result]
        assert "karma_check" not in tools
        assert "dns" in tools


class TestScopeEnforcement:
    def test_in_scope_subdomain(self):
        spec = _make_spec(allowed_scope=["example.com"])
        assert is_in_scope("api.example.com", spec) is True

    def test_out_of_scope(self):
        spec = _make_spec(allowed_scope=["example.com"])
        assert is_in_scope("evil.com", spec) is False

    def test_blocked_scope_overrides_allowed(self):
        spec = _make_spec(
            allowed_scope=["example.com"],
            blocked_scope=["internal.example.com"],
        )
        assert is_in_scope("internal.example.com", spec) is False

    def test_empty_allowed_scope_accepts_all(self):
        spec = _make_spec(allowed_scope=[], blocked_scope=[])
        assert is_in_scope("anything.random.org", spec) is True

    def test_task_out_of_scope_filtered(self):
        spec = _make_spec(allowed_scope=["example.com"])
        tasks = [
            {"tool": "dns", "target": "example.com", "agent_category": "passive"},
            {"tool": "dns", "target": "evil.com", "agent_category": "passive"},
        ]
        result = filter_allowed_tasks(tasks, spec)
        targets = [t["target"] for t in result]
        assert "example.com" in targets
        assert "evil.com" not in targets


class TestBlockedSources:
    def test_blocked_tool_removed(self):
        spec = _make_spec(blocked_sources=["nmap"])
        tasks = [
            {"tool": "nmap", "target": "example.com", "agent_category": "active"},
            {"tool": "dns", "target": "example.com", "agent_category": "passive"},
        ]
        result = filter_allowed_tasks(tasks, spec)
        tools = [t["tool"] for t in result]
        assert "nmap" not in tools
        assert "dns" in tools


class TestGarbageLeadRejection:
    def test_natural_language_rejected(self):
        assert is_garbage_lead("Investigate actual IP via nslookup") is True

    def test_bracket_placeholder_rejected(self):
        assert is_garbage_lead("[IP của dev.hcmute.edu.vn]") is True

    def test_vietnamese_sentence_rejected(self):
        assert is_garbage_lead("Cần kiểm tra IP từ DNS") is True

    def test_valid_domain_accepted(self):
        assert is_garbage_lead("api.example.com") is False

    def test_valid_ip_accepted(self):
        assert is_garbage_lead("10.0.0.1") is False

    def test_empty_rejected(self):
        assert is_garbage_lead("") is True

    def test_too_long_rejected(self):
        assert is_garbage_lead("a" * 201) is True


class TestSplitTasksByCategory:
    def test_passive_and_active_split(self):
        spec = _make_spec()
        lead = _make_lead("domain", "example.com")
        tasks = build_baseline_plan_for_lead(lead, spec)
        result = split_tasks_by_category(tasks)
        assert len(result["passive_tasks"]) > 0
        assert len(result["active_tasks"]) > 0

    def test_osint_goes_to_passive(self):
        tasks = [{"tool": "wayback", "target": "x", "priority": 0.5, "agent_category": "osint"}]
        result = split_tasks_by_category(tasks)
        assert len(result["passive_tasks"]) == 1
        assert len(result["active_tasks"]) == 0
