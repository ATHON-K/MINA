"""Quick E2E scan test script."""
import requests, time, json, sys

scan_id = sys.argv[1] if len(sys.argv) > 1 else None

if not scan_id:
    r = requests.post("http://localhost:8000/api/scan/start", json={
        "target": "hcmute.edu.vn",
        "company_name": "HCMUTE",
        "max_iterations": 2,
    })
    print(f"Start: {r.status_code} {r.text}")
    scan_id = r.json()["scan_id"]

for i in range(120):
    r = requests.get(f"http://localhost:8000/api/scan/{scan_id}/status")
    d = r.json()
    st = d["status"]
    print(f"[{i*5:>4}s] status={st}")
    if st in ("complete", "error"):
        break
    time.sleep(5)

print("\n=== STATUS ===")
print(json.dumps(d, indent=2))

r2 = requests.get(f"http://localhost:8000/api/scan/{scan_id}/results")
res = r2.json()
print(f"\n=== RESULTS === (HTTP {r2.status_code})")
print(f"  entities:        {res.get('entity_count', 0)}")
print(f"  relationships:   {len(res.get('relationships', []))}")
print(f"  vulnerabilities: {len(res.get('vulnerabilities', []))}")
print(f"  intel_events:    {res.get('intel_event_count', 0)}")

if res.get("entities"):
    print("\nFirst 5 entities:")
    for e in res["entities"][:5]:
        print(f"  - [{e.get('type')}] {e.get('canonical_value')} (conf={e.get('confidence')})")

# Try report
r3 = requests.get(f"http://localhost:8000/api/scan/{scan_id}/report")
print(f"\n=== REPORT === (HTTP {r3.status_code}, len={len(r3.text)})")
if r3.status_code == 200:
    print(r3.text[:500])
