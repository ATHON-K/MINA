"""Quick smoke test: planner produces structured What/Where/How tasks."""
import sys, json
print("Python:", sys.version, flush=True)

from core.planner import build_baseline_plan_for_lead, TOOL_ACTIVE_LEVEL, TOOL_EXPECTED_NEW_LEADS

# Fake lead + state
class FakeLead:
    type = "subdomain"
    value = "api.example.com"

state = {
    "engagement_spec": {
        "profile": "balanced",
        "enable_karma_v2": False,
        "features": {},
        "tool_options": {"httpx": {"timeout": 10}},
    },
    "tool_health_snapshot": {},
}

tasks = build_baseline_plan_for_lead(FakeLead(), state)
print(f"\n=== {len(tasks)} tasks for subdomain lead ===", flush=True)

# Verify first task has all required fields
required = ["tool", "target", "lead_type", "priority", "agent_category",
            "active_level", "collector_family", "expected_observations",
            "expected_new_leads", "tool_options", "reason"]
for t in tasks[:3]:
    print(json.dumps(t, indent=2, default=str), flush=True)
    missing = [f for f in required if f not in t]
    if missing:
        print(f"  MISSING FIELDS: {missing}", flush=True)
    else:
        print(f"  ✓ All fields present", flush=True)

# Check httpx got tool_options forwarded
httpx_tasks = [t for t in tasks if t["tool"] == "httpx"]
if httpx_tasks:
    opts = httpx_tasks[0].get("tool_options", {})
    print(f"\nhttpx tool_options: {opts}", flush=True)
    assert opts.get("timeout") == 10, "tool_options not forwarded!"
    print("✓ tool_options forwarded correctly", flush=True)

from core.graph import build_graph
g = build_graph()
print(f"\nGraph OK: {len(g.nodes)} nodes", flush=True)
