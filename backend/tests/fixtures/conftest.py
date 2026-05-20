"""
Shared pytest fixtures for MINA tests.
"""
import uuid
from datetime import datetime
import pytest


@pytest.fixture
def sample_session_id():
    return f"session_test_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def sample_engagement_spec(sample_session_id):
    return {
        "session_id": sample_session_id,
        "target": "example.com",
        "allowed_scope": ["example.com"],
        "out_of_scope": [],
        "active_recon_enabled": False,
        "max_iterations": 3,
        "max_leads": 10,
        "max_depth": 2,
        "rate_limit_seconds": 0.0,
        "profile": "quick",
        "features": {
            "shodan": False,
            "nuclei": False,
            "crawler": False,
        },
    }


@pytest.fixture
def empty_mina_state(sample_engagement_spec):
    return {
        "engagement_spec": sample_engagement_spec,
        "target": sample_engagement_spec["target"],
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
        "iteration": 0,
        "report_paths": {},
    }
