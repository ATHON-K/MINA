"""
3 Gates quan trọng trong MINA pipeline:
  Gate 1 — Policy Gate: validate scope trước khi director xử lý
  Gate 2 — Lead Quality Gate: loại bỏ lead rác, trùng, confidence thấp
  Gate 3 — Merge Conflict Gate: xử lý conflicts entity resolution
"""
from datetime import datetime, timezone
from core.state import MINAState
from core.schemas import Lead, Entity
from core.identity import make_entity_id, normalize_value


def setup_node(state: MINAState) -> MINAState:
    """Phase 0: Khởi tạo session, validate EngagementSpec, run preflight."""
    spec = state['engagement_spec']

    # Validate target là trong scope
    target = spec['target']
    if target not in spec['allowed_scope']:
        spec['allowed_scope'].append(target)

    # ── Preflight checks ─────────────────────────────────────────
    try:
        from core.preflight import run_preflight
        preflight = run_preflight(spec)
        state['preflight_report'] = preflight.to_dict()

        # Store unavailable tools for graceful degradation
        unavailable = []
        for chk in preflight.checks:
            if not chk.ok and chk.name.startswith("binary:"):
                tool_name = chk.name.split(":", 1)[1]
                unavailable.append(tool_name)

        # Merge into tool_health_snapshot for planner filtering
        health_snap = state.get('tool_health_snapshot', {})
        for tool_name in unavailable:
            health_snap[tool_name] = {"ready": False, "installed": False, "error": "preflight_fail"}
        state['tool_health_snapshot'] = health_snap

        # Log warnings for missing tools (graceful degradation — no abort)
        if unavailable:
            state.setdefault('phase_log', []).append({
                "phase": "preflight",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": f"Unavailable tools (will be skipped): {', '.join(unavailable)}",
            })

        # Only abort on critical failures (e.g. DEEPSEEK_API_KEY missing)
        if preflight.has_critical:
            state.setdefault('error_log', []).append({
                "phase": "preflight",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Critical preflight failure — scan may produce incomplete results",
                "critical_checks": [c.to_dict() for c in preflight.checks
                                    if not c.ok and c.severity == "critical"],
            })
    except Exception as exc:
        # Preflight itself failed — log and continue (don't block scan)
        state.setdefault('error_log', []).append({
            "phase": "preflight",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Preflight error (non-blocking): {exc}",
        })

    # Seed initial lead
    seed_lead = Lead(
        type="domain",
        value=target,
        raw_value=target,
        source="user_input",
        confidence=1.0,
        priority=1.0,
        depth=0,
        scope_status="in_scope"
    )

    # Create canonical root entity
    root_entity_id = make_entity_id("domain", target)
    root_canonical = normalize_value("domain", target)
    root_entity = Entity(
        session_id=spec.get("session_id", ""),
        entity_id=root_entity_id,
        type="domain",
        canonical_value=root_canonical,
        display_value=target,
        observation_ids=[],
        evidence_refs=[],
        confidence=1.0,
        source_collectors=["user_input"],
        last_seen=datetime.now(timezone.utc).isoformat(),
    )

    state['lead_queue'] = [seed_lead]
    state['processed_lead_ids'] = set()
    state['raw_events'] = []
    state['observations'] = []
    state['entities'] = [root_entity]
    state['entity_index'] = {root_canonical: root_entity_id}
    state['relationships'] = []
    state['findings'] = []
    state['iteration_count'] = 0
    state['active_budget_used'] = 0
    state['last_yield_iteration'] = 0
    state['collector_stats'] = {}
    state['phase_log'] = []
    state['error_log'] = []

    state['phase_log'].append({
        "phase": "setup",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"Session initialized for target: {target} (root_entity: {root_entity_id})"
    })

    return state


def policy_gate_node(state: MINAState) -> MINAState:
    """
    Gate 1 — Policy Gate: Chặn mọi action không hợp EngagementSpec.
    Validate lead_queue trước khi director xử lý.
    Uses core/scope.py for centralised scope checking.
    """
    from core.scope import is_in_scope, is_out_of_scope, is_garbage_lead

    spec = state['engagement_spec']
    valid_leads = []

    for lead in state['lead_queue']:
        # Reject garbage leads from LLM
        if is_garbage_lead(lead.value):
            continue

        if is_out_of_scope(lead.value, spec):
            lead = lead.model_copy(update={'status': 'out_of_scope',
                                           'scope_status': 'out_of_scope'})
        elif is_in_scope(lead.value, spec):
            lead = lead.model_copy(update={'status': 'approved',
                                           'scope_status': 'in_scope'})
        else:
            lead = lead.model_copy(update={'scope_status': 'unknown'})

        if lead.scope_status != 'out_of_scope':
            valid_leads.append(lead)

    state['lead_queue'] = sorted(valid_leads, key=lambda l: -l.priority)
    return state


def lead_quality_gate_node(state: MINAState, config=None) -> MINAState:
    """
    Gate 2 — Lead Quality Gate (enhanced):
    Loại bỏ lead rác, trùng, confidence thấp, ngoài scope, quá sâu.
    Also deduplicates across observation values to avoid re-scanning
    entities we already know about.
    """
    _log = None
    if config:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")

    state['iteration_count'] = state.get('iteration_count', 0) + 1
    spec = state.get('engagement_spec', {})
    max_depth = spec.get('max_depth', 3)

    seen_keys = set(state.get('processed_lead_ids', set()))

    # Build entity-value dedup set from existing entities
    entity_values = set()
    for ent in state.get('entities', []):
        cv = getattr(ent, 'canonical_value', '')
        if cv:
            entity_values.add(cv.lower())

    quality_queue = []
    dropped = {"duplicate": 0, "expired": 0, "low_conf": 0,
               "out_scope": 0, "too_deep": 0, "already_entity": 0}

    for lead in state.get('lead_queue', []):
        if lead.dedup_key in seen_keys:
            dropped["duplicate"] += 1
            continue
        if lead.is_expired():
            dropped["expired"] += 1
            continue
        if lead.confidence < 0.2:
            dropped["low_conf"] += 1
            continue
        if lead.scope_status == 'out_of_scope':
            dropped["out_scope"] += 1
            continue
        # Depth guard
        lead_depth = lead.depth if hasattr(lead, 'depth') else 0
        if lead_depth > max_depth:
            dropped["too_deep"] += 1
            continue
        # Already-known entity dedup
        if lead.value and lead.value.lower() in entity_values:
            dropped["already_entity"] += 1
            continue

        seen_keys.add(lead.dedup_key)
        quality_queue.append(lead)

    state['lead_queue'] = sorted(quality_queue, key=lambda l: -l.priority)
    state['processed_lead_ids'] = seen_keys

    if len(state['lead_queue']) > 0:
        state['last_yield_iteration'] = state['iteration_count']

    total_dropped = sum(dropped.values())
    if _log:
        _log({"type": "phase", "phase": "lead_quality_gate", "status": "done",
              "passed": len(quality_queue), "dropped": total_dropped,
              "dropped_reasons": dropped})

    return state


def stop_condition_node(state: MINAState, config=None) -> MINAState:
    """Ghi lý do dừng trước khi sang normalize"""
    _log = None
    if config and hasattr(config, "configurable"):
        _log = config.configurable.get("log_callback")

    spec = state['engagement_spec']
    reasons = []

    if not state.get('lead_queue'):
        reasons.append("lead_queue_empty")
    if state.get('iteration_count', 0) >= spec.get('max_iterations', 15):
        reasons.append(f"max_iterations_reached ({spec.get('max_iterations', 15)})")
    if state.get('active_budget_used', 0) >= spec.get('max_active_budget', 20):
        reasons.append(f"active_budget_exhausted ({spec.get('max_active_budget', 20)})")

    # No yield check
    no_yield_threshold = 3
    if state.get('iteration_count', 0) - state.get('last_yield_iteration', 0) >= no_yield_threshold:
        reasons.append(f"no_yield_for_{no_yield_threshold}_cycles")

    stop_reason = ", ".join(reasons) if reasons else "no_stop_condition_met"
    state['stop_reason'] = stop_reason

    if _log:
        _log({"type": "phase", "phase": "stop", "status": "done",
              "stop_reason": stop_reason,
              "iterations": state.get('iteration_count', 0)})

    state.setdefault('phase_log', []).append({
        "phase": "stop",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stop_reason": stop_reason,
        "stats": {
            "iterations": state.get('iteration_count', 0),
            "raw_events": len(state.get('raw_events', [])),
            "observations": len(state.get('observations', [])),
            "leads_processed": len(state.get('processed_lead_ids', set()))
        }
    })

    return state


def conflict_resolution_node(state: MINAState, config=None) -> MINAState:
    """
    Gate 3 — Conflict Resolution (enhanced from merge_conflict_gate):
    Handles:
      1. Standard entity merge conflicts (from correlator)
      2. Hostname ↔ IP mismatch detection
      3. Weak evidence domain filtering
    """
    _log = None
    if config and isinstance(config, dict):
        _log = config.get("configurable", {}).get("log_callback")
    elif config and hasattr(config, "configurable"):
        _log = config.configurable.get("log_callback")

    # ── Phase A: standard merge conflict resolution ──────────────
    resolved_conflicts = []

    for conflict in state.get('conflict_queue', []):
        obs_ids = conflict.get('observation_ids', [])

        conflicting_obs = [
            o for o in state.get('observations', [])
            if o.observation_id in obs_ids
        ]

        avg_confidence = (
            sum(o.confidence for o in conflicting_obs) / len(conflicting_obs)
            if conflicting_obs else 0
        )

        if avg_confidence >= 0.7:
            conflict['resolution'] = 'merged'
        elif avg_confidence >= 0.4:
            conflict['resolution'] = 'merged_low_confidence'
        else:
            conflict['resolution'] = 'needs_review'
            conflict['review_reason'] = f"Conflicting observations with avg confidence {avg_confidence:.2f}"

        resolved_conflicts.append(conflict)

    state['conflict_queue'] = resolved_conflicts

    # ── Phase B: hostname ↔ IP mismatch detection ────────────────
    ip_mismatches = 0
    relationships = state.get('relationships', [])
    entities = state.get('entities', [])

    # Build entity index
    ent_map = {}
    for ent in entities:
        eid = getattr(ent, 'entity_id', '')
        if eid:
            ent_map[eid] = ent

    # Check resolves_to relationships for multi-IP conflicts
    ip_by_host = {}
    for rel in relationships:
        rel_type = getattr(rel, 'relation_type', '')
        if rel_type != 'resolves_to':
            continue
        src_id = getattr(rel, 'from_entity_id', '')
        tgt_id = getattr(rel, 'to_entity_id', '')
        ip_by_host.setdefault(src_id, set()).add(tgt_id)

    for host_eid, ip_eids in ip_by_host.items():
        if len(ip_eids) > 3:
            ip_mismatches += 1
            state.setdefault('conflict_queue', []).append({
                'type': 'hostname_ip_mismatch',
                'host_entity': host_eid,
                'ip_entities': list(ip_eids),
                'resolution': 'needs_review',
                'review_reason': f"Host resolves to {len(ip_eids)} IPs — possible CDN/load-balancer or data conflict",
            })

    # ── Phase C: weak evidence pruning (mark, don't delete) ─────
    weak_entities = 0
    for ent in entities:
        src_collectors = getattr(ent, 'source_collectors', []) or []
        conf = getattr(ent, 'confidence', 0) or 0
        if len(src_collectors) <= 1 and conf < 0.3:
            weak_entities += 1
            if hasattr(ent, 'attributes'):
                attrs = ent.attributes or {}
                attrs['_weak_evidence'] = True
                ent.attributes = attrs
            elif isinstance(ent, dict):
                ent.setdefault('attributes', {})['_weak_evidence'] = True

    # ── Summary ──────────────────────────────────────────────────
    merged_count = sum(1 for c in resolved_conflicts if 'merged' in c.get('resolution', ''))
    review_count = sum(1 for c in resolved_conflicts if c.get('resolution') == 'needs_review')

    state.setdefault('phase_log', []).append({
        "phase": "conflict_resolution",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": (f"{merged_count} merged, {review_count} flagged, "
                    f"{ip_mismatches} IP mismatches, {weak_entities} weak entities"),
    })
    if _log:
        _log({"type": "phase", "phase": "conflict_resolution", "status": "done",
              "merged": merged_count, "needs_review": review_count,
              "ip_mismatches": ip_mismatches, "weak_entities": weak_entities})
    return state


# Keep backward compat alias
merge_conflict_gate_node = conflict_resolution_node
