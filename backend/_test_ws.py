"""Test WebSocket events during a live scan."""
import asyncio, json, sys
import websockets
import requests

API = "http://localhost:8000"
WS  = "ws://localhost:8000"

event_counts = {"log": 0, "intel_event": 0, "entity_update": 0, "graph_node": 0,
                "vulnerability": 0, "scan_complete": 0}
log_messages = []
intel_payloads = []

async def listen_ws(scan_id: str):
    uri = f"{WS}/ws/{scan_id}"
    try:
        async with websockets.connect(uri) as ws:
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=120)
                    msg = json.loads(raw)
                    t = msg.get("type", "unknown")
                    event_counts[t] = event_counts.get(t, 0) + 1
                    if t == "log":
                        log_messages.append(f"  [{msg.get('agent','?')}] {msg.get('message','')}")
                    elif t == "intel_event":
                        p = msg.get("payload", {})
                        intel_payloads.append(f"  [{p.get('what','?')}] {p.get('value','')}")
                    elif t == "scan_complete":
                        break
                except asyncio.TimeoutError:
                    break
    except Exception as e:
        print(f"WS error: {e}")

# Start scan
r = requests.post(f"{API}/api/scan/start", json={
    "target": "hcmute.edu.vn",
    "company_name": "HCMUTE",
    "max_iterations": 2,
    "rate_limit": 1.0,
})
print(f"Start: {r.status_code}")
data = r.json()
scan_id = data["scan_id"]
print(f"Scan ID: {scan_id}")

# Listen to WebSocket
asyncio.run(listen_ws(scan_id))

# Print results
print("\n=== WebSocket Event Counts ===")
for k, v in event_counts.items():
    if v > 0:
        print(f"  {k}: {v}")

print(f"\n=== Log Messages ({len(log_messages)}) ===")
for m in log_messages[:20]:
    print(m)

print(f"\n=== Intel Events ({len(intel_payloads)}) ===")
for m in intel_payloads[:10]:
    print(m)

# Final results
r2 = requests.get(f"{API}/api/scan/{scan_id}/results")
res = r2.json()
print(f"\n=== Final Results ===")
print(f"  entities:      {res.get('entity_count', 0)}")
print(f"  intel_events:  {res.get('intel_event_count', 0)}")
