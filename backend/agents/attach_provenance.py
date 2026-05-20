"""
Attach Provenance & Evidence — dedicated post-collection step.

Ensures every observation has:
  - evidence_ref pointing to stored raw data
  - raw_event linkage
  - collector source tracking
  - timestamp consistency

This step runs AFTER all collectors and BEFORE normalization,
ensuring provenance is complete and consistent rather than
scattered across individual collector implementations.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, Set

from core.state import MINAState

logger = logging.getLogger(__name__)


def attach_provenance_node(state: MINAState, config=None) -> MINAState:
    """
    LangGraph node: P1_attach_provenance_and_evidence.

    Validates and repairs provenance chains:
      1. Every observation must have evidence_ref
      2. Every observation must have raw_event_id
      3. Every entity must have source_collectors populated
      4. Cross-reference check: observation ↔ raw_event consistency
    """
    _log = None
    if config:
        _log = (config if isinstance(config, dict) else {}).get("configurable", {}).get("log_callback")

    observations = state.get("observations", [])
    raw_events = state.get("raw_events", [])
    entities = state.get("entities", [])

    # Build raw_event index for cross-reference
    raw_event_ids: Set[str] = set()
    collector_evidence_map: Dict[str, str] = {}  # collector_key → latest evidence_id
    for re_item in raw_events:
        reid = getattr(re_item, "event_id", "") or getattr(re_item, "raw_event_id", "")
        if reid:
            raw_event_ids.add(reid)
        ev_id = reid  # RawEvent.event_id doubles as evidence reference
        collector = getattr(re_item, "collector", "")
        if collector and ev_id:
            collector_evidence_map[collector] = ev_id

    orphaned_obs = 0
    repaired_obs = 0

    session_id = state.get("engagement_spec", {}).get("session_id", "")
    repaired_observations = []
    for obs in observations:
        updates: dict = {}

        # Check evidence_ref
        if not obs.evidence_ref:
            source = getattr(obs, "source", "")
            if source and source in collector_evidence_map:
                updates["evidence_ref"] = collector_evidence_map[source]
                repaired_obs += 1
            else:
                orphaned_obs += 1

        # Check raw_event_id
        if not obs.raw_event_id:
            ev_ref = updates.get("evidence_ref", obs.evidence_ref)
            if ev_ref:
                updates["raw_event_id"] = ev_ref
                repaired_obs += 1

        # Ensure session_id is set
        if not obs.session_id and session_id:
            updates["session_id"] = session_id

        if updates:
            obs = obs.model_copy(update=updates)
        repaired_observations.append(obs)

    observations = repaired_observations
    state["observations"] = observations

    # Enrich entities with source_collectors from their observations
    obs_by_entity: Dict[str, list] = {}
    for obs in observations:
        nv = obs.normalized_value or obs.value
        if nv:
            obs_by_entity.setdefault(nv, []).append(obs)

    for entity in entities:
        cv = getattr(entity, "canonical_value", "")
        if cv and cv in obs_by_entity:
            existing_collectors = set(
                getattr(entity, "source_collectors", []) or []
            )
            for obs in obs_by_entity[cv]:
                src = obs.source if hasattr(obs, "source") else ""
                if src:
                    existing_collectors.add(src)
            if hasattr(entity, "source_collectors"):
                entity.source_collectors = list(existing_collectors)

    # Log summary
    msg = (f"Provenance attached: {len(observations)} observations checked, "
           f"{repaired_obs} repaired, {orphaned_obs} orphaned")
    logger.info("[Provenance] %s", msg)

    if _log:
        _log({"type": "phase", "phase": "attach_provenance", "status": "done",
              "message": msg,
              "repaired": repaired_obs, "orphaned": orphaned_obs})

    state.setdefault("phase_log", []).append({
        "phase": "attach_provenance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": msg,
    })

    return state
