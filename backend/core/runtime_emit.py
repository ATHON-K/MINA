"""
core/runtime_emit.py — Runtime entity materialization.

Collectors call these helpers to create provisional entities, relationships,
and leads *during* collection — so they appear on the UI graph immediately,
rather than waiting for the normalizer phase.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from core.identity import make_entity_id, normalize_value, infer_entity_type
from core.schemas import Entity, Observation, Relationship, Lead
from core.schemas.raw_event import RawEvent
from core.validators import is_garbage_value
from core.scope import is_garbage_lead, is_in_scope

logger = logging.getLogger(__name__)


def materialize_entity_from_observation(
    state: dict,
    observation: Observation,
    parent_entity_id: Optional[str] = None,
) -> Optional[Entity]:
    """
    Create a provisional Entity from an Observation.

    - Infers entity type from observation.type / observation.value
    - Uses identity.py for stable canonical ID
    - Deduplicates against state["entity_index"]
    - Appends to state["entities"] if new
    - Returns the Entity (new or existing)
    """
    value = observation.normalized_value or observation.value
    if not value or is_garbage_value(value):
        return None

    # Map observation type → entity type
    entity_type = _obs_type_to_entity_type(observation.type, value)
    if not entity_type or entity_type == "unknown":
        return None

    canonical = normalize_value(entity_type, value)
    entity_id = make_entity_id(entity_type, canonical)

    # Check entity_index for existing
    entity_index = state.get("entity_index", {})
    if entity_id in entity_index:
        # Update existing entity: merge observation
        for ent in state.get("entities", []):
            eid = getattr(ent, "entity_id", "")
            if eid == entity_id:
                _merge_observation_into_entity(ent, observation)
                return ent
        return None

    # Create new provisional entity
    session_id = observation.session_id
    entity = Entity(
        entity_id=entity_id,
        session_id=session_id,
        type=entity_type,
        canonical_value=canonical,
        display_value=value,
        observation_ids=[observation.observation_id],
        evidence_refs=[observation.evidence_ref] if observation.evidence_ref else [],
        source_collectors=[observation.source],
        confidence=observation.confidence * 0.8,  # provisional penalty
        source_count=1,
        status="unknown",
        attributes=dict(observation.attributes) if observation.attributes else {},
        tags=["provisional"],
    )

    emit_runtime_entity(state, entity)
    return entity


def emit_runtime_entity(state: dict, entity: Entity) -> None:
    """Add entity to state, update entity_index. Deduplicate by entity_id."""
    entity_id = getattr(entity, "entity_id", "")
    entity_index = state.setdefault("entity_index", {})

    if entity_id in entity_index:
        return  # already tracked

    state.setdefault("entities", []).append(entity)
    entity_index[entity_id] = entity_id
    logger.debug("[RuntimeEmit] New entity: %s", entity_id)


def emit_runtime_relationship(
    state: dict,
    from_id: str,
    to_id: str,
    relation_type: str,
    confidence: float = 0.7,
    evidence_refs: Optional[list] = None,
    observation_ids: Optional[list] = None,
    derived_by: str = "runtime_emit",
) -> Optional[Relationship]:
    """Create and append a Relationship to state["relationships"]."""
    if not from_id or not to_id or from_id == to_id:
        return None

    # Dedup check
    dedup_key = f"{from_id}--{relation_type}--{to_id}"
    existing = state.get("relationships", [])
    for rel in existing:
        fid = getattr(rel, "from_entity_id", "")
        tid = getattr(rel, "to_entity_id", "")
        rt = getattr(rel, "relation_type", "")
        if fid == from_id and tid == to_id and rt == relation_type:
            return None  # duplicate

    session_id = state.get("engagement_spec", {}).get("session_id", "")
    rel = Relationship(
        session_id=session_id,
        from_entity_id=from_id,
        relation_type=relation_type,
        to_entity_id=to_id,
        observation_ids=observation_ids or [],
        evidence_refs=evidence_refs or [],
        derived_by=derived_by,
        confidence=confidence,
    )
    state.setdefault("relationships", []).append(rel)
    logger.debug("[RuntimeEmit] New relationship: %s --%s--> %s", from_id, relation_type, to_id)
    return rel


def emit_runtime_lead(
    state: dict,
    lead_type: str,
    value: str,
    source: str,
    parent_entity_id: Optional[str] = None,
    depth: int = 1,
    confidence: float = 0.7,
    priority: float = 0.6,
    evidence_refs: Optional[list] = None,
) -> Optional[Lead]:
    """
    Create a Lead and append to state["lead_queue"] if it passes
    garbage/scope checks and isn't a duplicate.
    """
    if not value or is_garbage_lead(value) or is_garbage_value(value):
        return None

    # Dedup check
    canonical = normalize_value(lead_type, value)
    dedup_key = f"{lead_type}:{canonical}"
    processed = state.get("processed_lead_ids", set())
    existing_keys = {
        getattr(l, "dedup_key", None)
        for l in state.get("lead_queue", [])
    }
    if dedup_key in processed or dedup_key in existing_keys:
        return None

    # Scope check
    spec = state.get("engagement_spec", {})
    if spec and not is_in_scope(canonical, spec):
        return None

    lead = Lead(
        type=lead_type,
        value=canonical,
        raw_value=value,
        source=source,
        confidence=confidence,
        priority=priority,
        depth=depth,
        discovered_by=source,
        evidence_refs=evidence_refs or [],
    )
    state.setdefault("lead_queue", []).append(lead)
    return lead


def emit_raw_event(
    state: dict,
    collector: str,
    tool: str,
    target: str,
    evidence_id: str,
    success: bool,
    extracted_count: int = 0,
    new_leads_count: int = 0,
    error_message: Optional[str] = None,
    duration_ms: int = 0,
    how: str = "API call",
) -> RawEvent:
    """
    Create a RawEvent and append to state["raw_events"].
    Every collector call should emit exactly one RawEvent.
    """
    spec = state.get("engagement_spec", {})
    session_id = spec.get("session_id", "")
    lead = state.get("current_lead")
    lead_id = ""
    if lead:
        lead_id = getattr(lead, "lead_id", "") or ""

    raw_event = RawEvent(
        session_id=session_id,
        lead_id=lead_id,
        collector=collector,
        what=f"{tool} results for {target}",
        where=tool,
        how=how,
        query=target,
        raw_response_path=evidence_id,
        success=success,
        error_message=error_message,
        duration_ms=duration_ms,
        extracted_count=extracted_count,
        new_leads_count=new_leads_count,
    )
    state.setdefault("raw_events", []).append(raw_event)
    logger.debug("[RuntimeEmit] RawEvent: %s → %s (ok=%s, items=%d)",
                 collector, target[:40], success, extracted_count)
    return raw_event


# ── Internal helpers ────────────────────────────────────────────────────────

_OBS_TO_ENTITY = {
    # Network / Infra
    "domain_found":             "domain",
    "subdomain_found":          "subdomain",
    "ip_found":                 "ip_address",
    "asn_found":                "asn",
    "service_detected":         "service",
    "port_open":                "service",

    # Web surface
    "webapp_alive":             "webapp",
    "url_found":                "endpoint",
    "endpoint_found":           "endpoint",
    "parameter_found":          "endpoint",
    "technology_found":         "technology",
    "waf_detected":             "technology",
    "header_found":             "webapp",

    # Assets
    "repo_found":               "repository",
    "document_found":           "document",

    # Security
    "vulnerability_found":      None,   # → Finding, not Entity
    "credential_signal_found":  None,

    # People / Org
    "person_found":             "person",
    "email_found":              "email_address",
    "org_found":                "organization",
    "cert_found":               "certificate",
}


def _obs_type_to_entity_type(obs_type: str, value: str) -> Optional[str]:
    """Map observation type to entity type, fallback to inference."""
    mapped = _OBS_TO_ENTITY.get(obs_type)
    if mapped:
        return mapped
    if mapped is None and obs_type in _OBS_TO_ENTITY:
        return None  # explicitly no entity (e.g. vulnerability_found)
    return infer_entity_type(value)


def _merge_observation_into_entity(entity, observation: Observation) -> None:
    """Update an existing entity with data from a new observation."""
    if hasattr(entity, "observation_ids"):
        obs_id = observation.observation_id
        if obs_id not in entity.observation_ids:
            entity.observation_ids.append(obs_id)
        if observation.evidence_ref and observation.evidence_ref not in entity.evidence_refs:
            entity.evidence_refs.append(observation.evidence_ref)
        if observation.source and observation.source not in entity.source_collectors:
            entity.source_collectors.append(observation.source)
        entity.source_count = len(entity.source_collectors)
        entity.confidence = min(1.0, entity.confidence + 0.05)
        entity.last_seen = datetime.now(timezone.utc)
        entity.last_updated = datetime.now(timezone.utc)
    else:
        # dict-style entity
        obs_ids = entity.get("observation_ids", [])
        if observation.observation_id not in obs_ids:
            obs_ids.append(observation.observation_id)
        entity["observation_ids"] = obs_ids
        ev = entity.get("evidence_refs", [])
        if observation.evidence_ref and observation.evidence_ref not in ev:
            ev.append(observation.evidence_ref)
        entity["evidence_refs"] = ev
        sc = entity.get("source_collectors", [])
        if observation.source and observation.source not in sc:
            sc.append(observation.source)
        entity["source_collectors"] = sc
        entity["source_count"] = len(sc)
        entity["confidence"] = min(1.0, entity.get("confidence", 0.5) + 0.05)
        entity["last_seen"] = datetime.now(timezone.utc).isoformat()
        entity["last_updated"] = datetime.now(timezone.utc).isoformat()
