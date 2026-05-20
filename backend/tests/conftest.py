"""
Root conftest for MINA backend tests.
"""
import sys
import os
import uuid
from datetime import datetime

import pytest

# Ensure backend/ is on sys.path so imports work
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


@pytest.fixture
def sample_session_id():
    return f"test_{uuid.uuid4().hex[:8]}"


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
def seed_lead_dict(sample_engagement_spec):
    """A seed Lead as a plain dict (before schema instantiation)."""
    return {
        "id": uuid.uuid4().hex,
        "type": "domain",
        "value": "example.com",
        "source": "seed",
        "confidence": 1.0,
        "priority": 1.0,
        "depth": 0,
        "discovered_by": "setup_node",
        "status": "pending",
        "ttl": 3,
        "tags": [],
    }


@pytest.fixture
def empty_mina_state(sample_engagement_spec, seed_lead_dict):
    return {
        "engagement_spec": sample_engagement_spec,
        "target": sample_engagement_spec["target"],
        "lead_queue": [seed_lead_dict],
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
        "current_lead": seed_lead_dict,
        "iteration": 0,
        "report_paths": {},
    }
