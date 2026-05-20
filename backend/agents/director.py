"""
Director Agent — Bộ não điều phối thật sự.
Route, plan, budget, dedup, stop — không chỉ nối flow.
"""
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from core.state import MINAState
from core.schemas import Lead, normalize_lead_type
from core.canonicalization import Canonicalizer
from core.config import config as _cfg
from core.planner import (
    build_baseline_plan_for_lead,
    augment_plan_with_llm,
    dedupe_plan,
    apply_agent_toggles,
    split_tasks_by_category,
)
from core.scope import is_garbage_lead
from prompts.director_prompts import DIRECTOR_SYSTEM, DIRECTOR_ANALYSIS_PROMPT

logger = logging.getLogger(__name__)


def _safe_format(template: str, **kwargs) -> str:
    """str.replace-based formatting that ignores JSON literal braces."""
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template


def get_llm_client():
    """Lazy-load OpenAI client. Raises if SDK unavailable or key missing."""
    try:
        from openai import OpenAI  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("openai SDK not installed") from exc
    return OpenAI(
        api_key=_cfg.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", ""),
        base_url=_cfg.deepseek_base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
    )


def _extract_json(text: str) -> Optional[dict]:
    """Extract first JSON object from LLM response."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def director_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Director Agent — hybrid deterministic + LLM planning."""
    if not state.get("lead_queue"):
        return state

    spec = state["engagement_spec"]

    # Get real-time log callback from LangGraph config
    _log = None
    if config is not None:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")

    # Capture full tool health snapshot on first director invocation.
    # Always run check_all_tools() and MERGE with any preflight entries.
    # Preflight entries (for binary failures) override check_all_tools() for the same key.
    if not state.get("_tool_health_full"):
        try:
            from core.tool_health import check_all_tools
            health = check_all_tools()
            # Merge: live check is the base; preflight-written entries take precedence
            existing = state.get("tool_health_snapshot", {})
            merged = {**health, **existing}
            state["tool_health_snapshot"] = merged
            state["_tool_health_full"] = True
            if _log:
                ready = [k for k, v in merged.items() if isinstance(v, dict) and v.get("ready")]
                _log({"agent": "Director", "level": "info",
                      "timestamp": datetime.now(timezone.utc).isoformat(),
                      "message": f"Tool health: {len(ready)}/{len(merged)} tools ready"})
        except Exception as exc:
            logger.warning("[Director] Tool health check failed: %s", exc)
            if not state.get("tool_health_snapshot"):
                state["tool_health_snapshot"] = {}

    # Take highest-priority lead
    current_lead = state["lead_queue"].pop(0)
    state["current_lead"] = current_lead

    # Reject garbage leads early
    if is_garbage_lead(current_lead.value):
        if _log:
            _log({"agent": "Director", "level": "warning",
                  "timestamp": datetime.now(timezone.utc).isoformat(),
                  "message": f"Rejected garbage lead: {current_lead.value[:60]}"})
        state["passive_tasks"] = []
        state["active_tasks"] = []
        return state

    # Step 1: Build deterministic baseline plan
    baseline_plan = build_baseline_plan_for_lead(current_lead, state)

    if _log:
        _log({"agent": "Director", "level": "info",
              "timestamp": datetime.now(timezone.utc).isoformat(),
              "message": f"Planning for [{current_lead.type}] {current_lead.value} — {len(baseline_plan)} baseline tasks"})

    # Step 2: Try LLM augmentation
    llm_tasks = []
    new_leads_data = []

    recent_events_summary = _summarize_recent_events(state, n=10)
    budget_remaining = spec.get("max_active_budget", 20) - state.get("active_budget_used", 0)

    # Compute ready tools from health snapshot
    health_snapshot = state.get("tool_health_snapshot", {})
    ready_tools_list = [k for k, v in health_snapshot.items() if isinstance(v, dict) and v.get("ready")]

    user_prompt = _safe_format(
        DIRECTOR_ANALYSIS_PROMPT,
        lead_type=current_lead.type,
        lead_value=current_lead.value,
        depth=current_lead.depth,
        confidence=current_lead.confidence,
        parent_id=current_lead.parent_lead_id or "seed",
        allowed_scope=spec.get("allowed_scope", []),
        active_enabled=spec.get("active_recon_enabled", False),
        profile=spec.get("profile", "balanced"),
        budget_remaining=budget_remaining,
        max_depth=spec.get("max_depth", 3),
        blocked_scope=spec.get("blocked_scope", []),
        ready_tools=", ".join(ready_tools_list) if ready_tools_list else "none",
        baseline_tools=", ".join(t["tool"] for t in baseline_plan),
        recent_events=recent_events_summary,
    )

    try:
        api_key = _cfg.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY", "")
        if not api_key or api_key in ("YOUR_DEEPSEEK_API_KEY_HERE",):
            raise ValueError("DEEPSEEK_API_KEY chưa được cấu hình")

        client = get_llm_client()
        response = client.chat.completions.create(
            model=_cfg.deepseek_model or os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            messages=[
                {"role": "system", "content": DIRECTOR_SYSTEM},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=2048,
        )
        content = response.choices[0].message.content or ""
        parsed = _extract_json(content)

        if parsed:
            # New format: tasks[] (unified) instead of passive_tasks[] + active_tasks[]
            llm_tasks = parsed.get("tasks", [])
            # Fallback: support old passive_tasks + active_tasks format
            if not llm_tasks:
                llm_tasks = parsed.get("passive_tasks", []) + parsed.get("active_tasks", [])
            new_leads_data = parsed.get("new_leads", [])
        else:
            logger.warning("[Director] LLM JSON parse failed, using baseline only")

    except Exception as exc:
        logger.error("[Director] LLM error: %s — using baseline only", exc)
        state.setdefault("error_log", []).append({
            "node": "director", "error": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    # Step 3: Merge baseline + LLM tasks, dedupe, filter by scope/toggles
    merged_plan = augment_plan_with_llm(current_lead, baseline_plan, llm_tasks)
    merged_plan = dedupe_plan(merged_plan)
    merged_plan = apply_agent_toggles(merged_plan, spec)

    # Step 4: Split into passive/active
    split = split_tasks_by_category(merged_plan)
    passive_tasks = split["passive_tasks"]
    active_tasks = split["active_tasks"]

    # Budget check / two-flag active guard
    # Flag 1: agents_enabled.active_recon — toggles the whole active_recon agent
    active_agent_enabled = spec.get("agents_enabled", {}).get("active_recon", True)
    # Flag 2: active_recon_enabled — global ROE (rules of engagement) flag
    roe_active = spec.get("active_recon_enabled", True)

    if not active_agent_enabled:
        # Active recon agent disabled — drop all active tasks entirely
        active_tasks = []
    elif not roe_active:
        # ROE forbids active scanning — drop active tasks
        active_tasks = []
    elif state.get("active_budget_used", 0) < spec.get("max_active_budget", 20):
        remaining = spec.get("max_active_budget", 20) - state.get("active_budget_used", 0)
        active_tasks = active_tasks[:remaining]
        state["active_budget_used"] = state.get("active_budget_used", 0) + len(active_tasks)
    else:
        active_tasks = []

    # Add new leads from LLM to queue with dedup
    new_leads = []
    for lead_data in new_leads_data:
        if not lead_data.get("value") or not lead_data.get("type"):
            continue
        # Reject garbage leads
        if is_garbage_lead(lead_data["value"]):
            continue
        try:
            canonical_value = Canonicalizer.canonicalize(lead_data["type"], lead_data["value"])
        except Exception:
            canonical_value = lead_data["value"].strip().lower()

        _norm_type = normalize_lead_type(lead_data["type"])
        dedup_key = f"{_norm_type}:{canonical_value}"
        if dedup_key in state.get("processed_lead_ids", set()):
            continue

        new_depth = current_lead.depth + 1
        if new_depth > spec.get("max_depth", 3):
            continue

        new_lead = Lead(
            type=_norm_type,
            value=canonical_value,
            raw_value=lead_data["value"],
            source="director",
            confidence=float(lead_data.get("confidence", 0.5)),
            priority=_calculate_priority(lead_data["type"], float(lead_data.get("confidence", 0.5)), new_depth),
            depth=new_depth,
            parent_lead_id=current_lead.lead_id,
            discovered_by="director_agent",
            scope_status="unknown"
        )
        new_leads.append(new_lead)

    state["passive_tasks"] = passive_tasks
    state["active_tasks"] = active_tasks
    state["lead_queue"].extend(new_leads)
    state["lead_queue"].sort(key=lambda l: l.priority)

    if new_leads:
        state["last_yield_iteration"] = state.get("iteration_count", 0)

    # Write planning summary to phase_log
    plan_msg = (f"Lead [{current_lead.type}] {current_lead.value} → "
                f"{len(passive_tasks)} passive, {len(active_tasks)} active tasks, "
                f"{len(new_leads)} new leads (baseline + LLM)")
    state.setdefault("phase_log", []).append({
        "phase": "director",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "info",
        "message": plan_msg,
    })
    if _log:
        _log({"agent": "Director", "level": "info",
              "timestamp": datetime.now(timezone.utc).isoformat(),
              "message": plan_msg})

    return state


def _calculate_priority(lead_type: str, confidence: float, depth: int) -> float:
    """Lead priority scoring: priority = (type_weight * 0.6 + confidence * 0.4) - (depth * 0.1)"""
    type_weights = {
        "domain": 1.0, "subdomain": 0.9, "webapp": 0.85,
        "ip": 0.8, "service": 0.75, "endpoint": 0.7,
        "email": 0.5, "person": 0.4, "document": 0.6, "repository": 0.7
    }
    weight = type_weights.get(lead_type, 0.5)
    depth_penalty = depth * 0.1
    return max(0.1, (weight * 0.6 + confidence * 0.4) - depth_penalty)


def _validate_tasks(tasks: list, spec: dict, active: bool) -> list:
    """Filter tasks according to allowed_sources and policy."""
    allowed = set(spec.get("allowed_sources", []))
    validated = []
    for task in tasks:
        tool = task.get("tool", "")
        if allowed and tool not in allowed:
            continue
        if active and not spec.get("active_recon_enabled", False):
            continue
        validated.append(task)
    return validated


def _default_passive_tasks(lead: Lead) -> list:
    """Fallback passive tasks when LLM call fails."""
    return [
        {"tool": "whois", "target": lead.value, "priority": 0.8},
        {"tool": "dns", "target": lead.value, "priority": 0.9},
        {"tool": "crt_sh", "target": lead.value, "priority": 0.85},
    ]


def _summarize_recent_events(state: MINAState, n: int = 10) -> str:
    """Tóm tắt N observations gần nhất để đưa vào context."""
    events = state.get("observations", [])[-n:]
    if not events:
        return "Chưa có observations."
    summary = []
    for obs in events:
        summary.append(f"- [{obs.type}] {obs.value} (confidence: {obs.confidence:.1f})")
    return "\n".join(summary)
