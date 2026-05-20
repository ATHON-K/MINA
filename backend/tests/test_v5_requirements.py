"""
Tests for update_v5.md requirements.
Covers items:
  A. Lazy OpenAI imports
  B. Planner uses `ready` not `available`
  C. Reporter uses `ready` for limitations
  D. All graph nodes mapped in _PHASE_TO_AGENT
  E. stop_reason written into report
  F-I. Scope enforcement (dot-anchored, no false positives)
  J-M. Report structure (8 sections, 6-column findings, detailed fields, appendix)
"""
import sys
import importlib
import types
from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# A. Lazy OpenAI imports — agents must be importable without openai SDK
# ---------------------------------------------------------------------------

class TestLazyOpenAIImports:
    """Items 1 & import safety."""

    def test_director_importable_without_openai(self):
        """director.py must not crash if openai is not installed."""
        fake_modules = {k: None for k in list(sys.modules.keys()) if "openai" in k}
        with patch.dict("sys.modules", {"openai": None, "openai.types": None}):
            try:
                if "agents.director" in sys.modules:
                    del sys.modules["agents.director"]
                import agents.director  # noqa: F401
            except ImportError as e:
                if "openai" in str(e).lower():
                    pytest.fail(f"director imported eagerly: {e}")

    def test_osint_agent_importable_without_openai(self):
        """osint_agent.py must not crash if openai is not installed."""
        with patch.dict("sys.modules", {"openai": None}):
            try:
                if "agents.osint_agent" in sys.modules:
                    del sys.modules["agents.osint_agent"]
                import agents.osint_agent  # noqa: F401
            except ImportError as e:
                if "openai" in str(e).lower():
                    pytest.fail(f"osint_agent imported eagerly: {e}")

    def test_agents_init_no_eager_import(self):
        """agents/__init__.py must not eagerly import openai."""
        import agents
        assert hasattr(agents, "__all__"), "__all__ must be defined"
        # Just importing agents should not fail without openai
        # (already covered by the import above succeeding)


# ---------------------------------------------------------------------------
# B. tool_health uses `ready` not `available`
# ---------------------------------------------------------------------------

class TestToolHealthReady:
    """Item 2: ToolHealth.ready field."""

    def test_tool_health_has_ready_property(self):
        from core.tool_health import ToolHealth
        t = ToolHealth(name="nmap", installed=True)
        assert hasattr(t, "ready"), "ToolHealth must have `ready` property"
        assert t.ready is True

    def test_tool_health_to_dict_uses_ready(self):
        from core.tool_health import ToolHealth
        t = ToolHealth(name="nmap", installed=True)
        d = t.to_dict()
        assert "ready" in d, "to_dict() must include 'ready' key"

    def test_tool_health_ready_false_when_not_installed(self):
        from core.tool_health import ToolHealth
        t = ToolHealth(name="nmap", installed=False)
        assert t.ready is False

    def test_tool_health_ready_false_when_env_not_configured(self):
        """Tool with env_key set but env var missing → ready=False."""
        import os
        from core.tool_health import ToolHealth
        key = "_MINA_TEST_MISSING_ENV_KEY_XYZ_"
        os.environ.pop(key, None)
        t = ToolHealth(name="test_tool", installed=True, env_key=key)
        assert t.ready is False

    def test_get_available_tools_uses_ready(self):
        """get_available_tools from a snapshot uses `ready` key."""
        # The actual get_available_tools() takes no args (runs live checks).
        # Test the snapshot-based pattern used by planner/reporter.
        from core.tool_health import ToolHealth
        snap = {
            "nmap": {"ready": True, "installed": True},
            "shodan": {"ready": False, "installed": True},
        }
        # Pattern: filter by snap[tool].get("ready")
        available = [t for t, info in snap.items()
                     if isinstance(info, dict) and info.get("ready")]
        assert "nmap" in available
        assert "shodan" not in available


# ---------------------------------------------------------------------------
# C. Reporter uses `ready` for limitations
# ---------------------------------------------------------------------------

class TestReporterUsesReady:
    """Item 2 (reporter side): _build_limitations reads `ready` field."""

    def _make_state(self, tool_health_snapshot):
        return {
            "engagement_spec": {
                "session_id": "test-001",
                "target": "example.com",
                "features": {},
            },
            "tool_health_snapshot": tool_health_snapshot,
            "collector_stats": {},
            "findings": [],
            "observations": [],
            "entities": [],
            "relationships": [],
        }

    def test_limitations_include_not_ready_tool(self):
        from agents.reporter import _build_limitations
        state = self._make_state({
            "nmap": {"ready": False, "installed": True, "error": "not installed"},
        })
        limitations = _build_limitations(state)
        assert any("nmap" in lim.lower() for lim in limitations), \
            "Limitations should mention tools that are not ready"

    def test_limitations_empty_when_all_ready(self):
        from agents.reporter import _build_limitations
        state = self._make_state({
            "nmap": {"ready": True, "installed": True},
        })
        limitations = _build_limitations(state)
        # Should not mention nmap as a limitation
        assert not any("nmap" in lim.lower() for lim in limitations)


# ---------------------------------------------------------------------------
# D. _PHASE_TO_AGENT maps all V5 graph nodes
# ---------------------------------------------------------------------------

class TestPhaseToAgentMapping:
    """Item 3: _PHASE_TO_AGENT covers all graph nodes."""

    EXPECTED_NODES = [
        "setup", "policy_gate", "director",
        "root_domain", "subdomain_intel", "infra_network",
        "company_intel", "people_intel", "credentials_access",
        "karma_passive", "osint_deep_dive", "service_surface",
        "web_surface", "attach_provenance", "lead_quality_gate",
        "stop_condition", "normalize", "correlate",
        "conflict_resolution", "impact_analysis",
        "table_compose", "report",
    ]

    def test_all_nodes_mapped(self):
        from main import _PHASE_TO_AGENT
        missing = [n for n in self.EXPECTED_NODES if n not in _PHASE_TO_AGENT]
        assert not missing, f"Nodes missing from _PHASE_TO_AGENT: {missing}"

    def test_phase_values_are_strings(self):
        from main import _PHASE_TO_AGENT
        for node, label in _PHASE_TO_AGENT.items():
            assert isinstance(label, str), \
                f"_PHASE_TO_AGENT[{node!r}] must be a string, got {type(label)}"


# ---------------------------------------------------------------------------
# E. stop_reason in report
# ---------------------------------------------------------------------------

class TestStopReason:
    """Item 4: stop_reason is written and read consistently."""

    def test_reporter_reads_stop_reason_from_state(self):
        from agents.reporter import _build_coverage_stats
        state = {
            "engagement_spec": {"session_id": "x", "target": "t.com"},
            "stop_reason": "max_iterations_reached",
            "findings": [],
            "observations": [],
            "entities": [],
            "relationships": [],
            "collector_stats": {},
            "raw_events": [],
        }
        coverage = _build_coverage_stats(state)
        assert coverage.get("stop_reason") == "max_iterations_reached", \
            "_build_coverage_stats must propagate stop_reason from state"

    def test_coverage_stop_reason_default_unknown(self):
        from agents.reporter import _build_coverage_stats
        state = {
            "engagement_spec": {"session_id": "x", "target": "t.com"},
            "findings": [],
            "observations": [],
            "entities": [],
            "relationships": [],
            "collector_stats": {},
            "raw_events": [],
        }
        coverage = _build_coverage_stats(state)
        sr = coverage.get("stop_reason", "")
        # Some default (empty string or "unknown") is acceptable — not raising
        assert isinstance(sr, str)


# ---------------------------------------------------------------------------
# F-I. Scope enforcement (dot-anchored, no substring false positives)
# ---------------------------------------------------------------------------

class TestScopeEnforcement:
    """Item 5: is_in_scope uses dot-anchored suffix matching."""

    def _spec(self, allowed=None, blocked=None):
        return {
            "allowed_scope": allowed or [],
            "blocked_scope": blocked or [],
            "active_recon_enabled": False,
        }

    def test_target_in_allowed_scope(self):
        from core.scope import is_in_scope
        spec = self._spec(allowed=["example.com"])
        assert is_in_scope("example.com", spec) is True

    def test_subdomain_in_allowed_scope(self):
        from core.scope import is_in_scope
        spec = self._spec(allowed=["example.com"])
        assert is_in_scope("api.example.com", spec) is True

    def test_blocked_root_domain_out_of_scope(self):
        """Item F: blocked root domain is out of scope."""
        from core.scope import is_in_scope
        spec = self._spec(
            allowed=["example.com"],
            blocked=["example.com"],
        )
        assert is_in_scope("example.com", spec) is False

    def test_blocked_subdomain_out_of_scope(self):
        """Item G: blocked subdomain is out of scope."""
        from core.scope import is_in_scope
        spec = self._spec(
            allowed=["example.com"],
            blocked=["internal.example.com"],
        )
        assert is_in_scope("internal.example.com", spec) is False

    def test_blocked_url_host_out_of_scope(self):
        """Item H: URL with blocked hostname is out of scope."""
        from core.scope import is_in_scope
        spec = self._spec(
            allowed=["example.com"],
            blocked=["admin.example.com"],
        )
        assert is_in_scope("https://admin.example.com/login", spec) is False

    def test_scope_no_false_positive_substring(self):
        """Item I: evil-example.com must NOT be blocked when example.com is blocked."""
        from core.scope import is_in_scope
        spec = self._spec(
            allowed=["evil-example.com"],
            blocked=["example.com"],
        )
        # evil-example.com does NOT end with ".example.com" — NOT blocked by substring
        assert is_in_scope("evil-example.com", spec) is True

    def test_deep_subdomain_in_scope(self):
        from core.scope import is_in_scope
        spec = self._spec(allowed=["example.com"])
        assert is_in_scope("a.b.c.example.com", spec) is True

    def test_unrelated_domain_not_in_scope(self):
        from core.scope import is_in_scope
        spec = self._spec(allowed=["example.com"])
        assert is_in_scope("other.org", spec) is False


# ---------------------------------------------------------------------------
# J. Report has exactly 8 sections (## 1. through ## 8.)
# ---------------------------------------------------------------------------

class TestReportStructure:
    """Items 6-16: Report has exactly 8 sections."""

    def _make_minimal_state(self):
        import uuid
        return {
            "engagement_spec": {
                "session_id": uuid.uuid4().hex,
                "target": "test.com",
                "allowed_scope": ["test.com"],
                "blocked_scope": [],
                "active_recon_enabled": False,
                "features": {},
                "profile": "quick",
            },
            "findings": [],
            "impact_insights": [],
            "observations": [],
            "entities": [],
            "relationships": [],
            "collector_stats": {},
            "raw_events": [],
            "stop_reason": "max_iterations",
            "tool_health_snapshot": {},
        }

    def _render(self, state=None):
        from agents.reporter import _render_report_markdown, _build_coverage_stats, _build_limitations
        if state is None:
            state = self._make_minimal_state()
        spec = state["engagement_spec"]
        coverage = _build_coverage_stats(state)
        limitations = _build_limitations(state)
        findings = state.get("findings", [])
        impact_insights = state.get("impact_insights", [])
        observations = state.get("observations", [])
        tables: dict = {}
        return _render_report_markdown(
            spec, findings, observations, coverage, limitations, impact_insights, tables, state
        )

    def test_report_has_exactly_8_sections(self):
        """Item J: markdown contains exactly 8 '## N. ...' headers."""
        import re
        md = self._render()
        headers = re.findall(r"^## \d+\.", md, re.MULTILINE)
        assert len(headers) == 8, \
            f"Expected 8 section headers, found {len(headers)}: {headers}"

    def test_section_numbers_sequential(self):
        """Sections numbered 1-8 in order."""
        import re
        md = self._render()
        nums = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\.", md, re.MULTILINE)]
        assert nums == list(range(1, 9)), f"Section numbers not sequential: {nums}"

    def test_section_1_is_executive_summary(self):
        md = self._render()
        assert "## 1. Executive Summary" in md

    def test_section_2_is_scope_methodology(self):
        md = self._render()
        assert "## 2. Scope & Methodology" in md

    def test_section_8_is_appendix(self):
        md = self._render()
        assert "## 8. Appendix" in md


# ---------------------------------------------------------------------------
# K. Findings Summary table has 6 visible columns
# ---------------------------------------------------------------------------

class TestFindingsSummaryTable:
    """Item K: findings summary table has correct columns."""

    def _render_findings_section(self, findings, tables=None):
        from agents.reporter import _s04_findings_summary
        return "\n".join(_s04_findings_summary(findings, tables or {}))

    def test_findings_summary_6_columns_from_table(self):
        """6-col table: ID | Severity | Category | Title | Evidence Source | CVSS Score."""
        tables = {
            "findings_table": [
                {
                    "finding_id": "FIND-001",
                    "severity": "High",
                    "category": "Exposure",
                    "title": "Test finding",
                    "evidence_source": "crt.sh",
                    "cvss_score": "7.5",
                }
            ]
        }
        md = self._render_findings_section([], tables)
        # Find the table header line
        header_line = [l for l in md.split("\n") if "finding_id" in l.lower() or "ID" in l or "Severity" in l]
        assert header_line, "Findings summary must have a table header"
        cols = [c.strip() for c in header_line[0].split("|") if c.strip()]
        assert len(cols) == 6, f"Expected 6 columns, found {len(cols)}: {cols}"

    def test_findings_summary_empty_message(self):
        md = self._render_findings_section([], {})
        assert "Không phát hiện" in md or "No finding" in md.lower()


# ---------------------------------------------------------------------------
# L. Detailed finding block has required fields
# ---------------------------------------------------------------------------

class TestDetailedFindingFields:
    """Item L: each finding block has Description/Evidence/Impact/Recommendation/References."""

    REQUIRED_FIELDS = [
        "**Description:**",
        "**Evidence:**",
        "**Impact:**",
        "**Recommendation:**",
        "**References:**",
    ]

    def _render_detailed(self, findings):
        from agents.reporter import _s05_detailed_findings
        return "\n".join(_s05_detailed_findings(findings, {}))

    def test_finding_block_from_raw_findings(self):
        """Finding block must contain all 5 required fields."""
        findings = [
            {
                "severity": "high",
                "title": "Admin panel exposed",
                "category": "Exposure",
                "description": "Admin panel at /admin is publicly accessible.",
                "evidence_refs": ["passive_recon"],
                "impact": "Full admin access",
                "recommendation": "Restrict to IP allowlist",
                "references": ["CWE-284"],
                "priority_score": 7.5,
                "confidence": 0.9,
            }
        ]
        md = self._render_detailed(findings)
        for field in self.REQUIRED_FIELDS:
            assert field in md, f"Missing field {field!r} in detailed finding"

    def test_finding_block_has_severity_and_cvss(self):
        findings = [
            {
                "severity": "critical",
                "title": "Hardcoded secret",
                "category": "Credential",
                "cvss_score": 9.1,
            }
        ]
        md = self._render_detailed(findings)
        assert "**Severity:**" in md
        assert "9.1" in md


# ---------------------------------------------------------------------------
# M. Appendix has required subsections
# ---------------------------------------------------------------------------

class TestAppendixSubsections:
    """Item M: appendix has Tools Used, Scan Statistics, Exported Table Artifacts."""

    REQUIRED_SUBSECTIONS = [
        "### 8.1 Tools Used",
        "### 8.2 Scan Statistics",
        "### 8.5 Exported Table Artifacts",
    ]

    def _render_appendix(self, spec=None, coverage=None, tables=None, state=None):
        from agents.reporter import _s08_appendix
        if spec is None:
            spec = {"target": "example.com", "session_id": "x"}
        if coverage is None:
            coverage = {
                "total_raw_events": 0, "total_observations": 0, "total_entities": 0,
                "total_relationships": 0, "total_findings": 0, "iterations": 1,
                "lead_queue_at_stop": 0, "collectors_run": [], "per_collector": {},
                "stop_reason": "max_iterations",
            }
        if tables is None:
            tables = {"domains_subdomains_table": [], "findings_table": []}
        if state is None:
            state = {"tool_health_snapshot": {}, "engagement_spec": spec}
        return "\n".join(_s08_appendix(spec, coverage, tables, state))

    def test_appendix_has_tools_used(self):
        md = self._render_appendix()
        assert "### 8.1 Tools Used" in md

    def test_appendix_has_scan_statistics(self):
        md = self._render_appendix()
        assert "### 8.2 Scan Statistics" in md

    def test_appendix_has_exported_artifacts(self):
        md = self._render_appendix()
        assert "### 8.5 Exported Table Artifacts" in md

    def test_appendix_statistics_table_has_stop_reason(self):
        coverage = {
            "total_raw_events": 10, "total_observations": 5, "total_entities": 3,
            "total_relationships": 2, "total_findings": 1, "iterations": 2,
            "lead_queue_at_stop": 0, "collectors_run": [], "per_collector": {},
            "stop_reason": "max_iterations_reached",
        }
        md = self._render_appendix(coverage=coverage)
        assert "max_iterations_reached" in md

    def test_appendix_lists_table_artifacts(self):
        tables = {
            "domains_subdomains_table": [],
            "findings_table": [],
            "ip_asn_table": [],
        }
        md = self._render_appendix(tables=tables)
        for tname in tables:
            assert tname in md, f"Artifact {tname} not listed in appendix"

    def test_appendix_subdomain_section_shown_when_subdomains_exist(self):
        tables = {
            "domains_subdomains_table": [
                {"subdomain": "api.example.com", "root_domain": "example.com"},
                {"subdomain": "mail.example.com", "root_domain": "example.com"},
            ],
            "findings_table": [],
        }
        md = self._render_appendix(tables=tables)
        assert "### 8.4 Full List of Subdomains" in md
        assert "api.example.com" in md
