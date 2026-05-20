import os
import time

import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("RUN_LIVE_SCAN_INTEGRATION", "0") != "1",
    reason="Set RUN_LIVE_SCAN_INTEGRATION=1 to run live scan integration test",
)
def test_scanme_end_to_end_flow():
    import main as mina_main

    client = TestClient(mina_main.app)

    payload = {
        "target": "scanme.nmap.org",
        "company_name": "Nmap Scanme",
        "active_recon_enabled": True,
        "max_iterations": 1,
        "agents_enabled": {
            "passive_recon": True,
            "active_recon": True,
            "normalizer": True,
            "reporter": True,
        },
    }

    res = client.post("/api/scan/start", json=payload)
    assert res.status_code == 200
    scan_id = res.json().get("scan_id")
    assert scan_id

    deadline = time.time() + 300
    status = "pending"
    while time.time() < deadline:
        sres = client.get(f"/api/scan/{scan_id}/status")
        assert sres.status_code == 200
        status = sres.json().get("status")
        if status in ("complete", "error"):
            break
        time.sleep(2)

    assert status == "complete", f"scan ended with status={status}"

    rres = client.get(f"/api/scan/{scan_id}/results")
    assert rres.status_code == 200
    data = rres.json()
    assert "entities" in data
    assert "vulnerabilities" in data

    for fmt in ("md", "html", "pdf"):
        eres = client.get(f"/api/scan/{scan_id}/export/{fmt}")
        assert eres.status_code == 200
