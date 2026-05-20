"""
Normalizer Agent — Observation -> Entity conversion with dedup.
Source-weighted confidence aggregation + Rate-based confidence.

V5: Stronger dedup (endpoint dedup key), confidence bám Rate table,
    stale/active/missing evidence penalties and boosts.
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from core.state import MINAState
from core.schemas import Entity, EntityType, Observation
from core.canonicalization import Canonicalizer
from core.identity import make_entity_id
from core.validators import is_garbage_value

logger = logging.getLogger(__name__)

# ── Rate → base confidence mapping (V5) ─────────────────────────
RATE_BASE_CONFIDENCE = {
    "critical": 0.95,
    "high":     0.85,
    "medium":   0.65,
    "low":      0.45,
    "info":     0.30,
}

# Source weights for confidence aggregation
SOURCE_WEIGHTS = {
    "nmap": 0.95,
    "active/nmap": 0.95,
    "shodan": 0.85,
    "crt_sh": 0.80,
    "dns": 0.90,
    "subfinder": 0.75,
    "active/subfinder": 0.78,
    "bruteforce": 0.65,
    "permutation": 0.55,
    "web_surface": 0.70,
    "passive_recon": 0.72,
    "nuclei": 0.88,
    "active/nuclei": 0.88,
    "ssl": 0.80,
    "whois": 0.75,
    "osint": 0.65,
    # V4: New source weights
    "httpx": 0.90,
    "active/httpx": 0.90,
    "headers": 0.85,
    "active/headers": 0.85,
    "tech": 0.78,
    "active/tech": 0.78,
    "waf": 0.80,
    "active/waf": 0.80,
    "dirs": 0.72,
    "active/dirs": 0.72,
    "crawl": 0.75,
    "active/crawl": 0.75,
    "robots": 0.82,
    "active/robots": 0.82,
    "http_methods": 0.85,
    "active/http_methods": 0.85,
    "cloud": 0.70,
    "active/cloud": 0.70,
    "favicon": 0.65,
    "active/favicon": 0.65,
    "banner": 0.78,
    "active/banner": 0.78,
    "params": 0.68,
    "active/params": 0.68,
    "active/ssl": 0.82,
}
DEFAULT_SOURCE_WEIGHT = 0.60

# Active source families get a confidence boost (V5)
_ACTIVE_SOURCES = {s for s in SOURCE_WEIGHTS if s.startswith("active/")}

# Stale threshold: observations older than this get a penalty
_STALE_HOURS = 48

OBS_TYPE_TO_ENTITY_TYPE = {
    # ── Network / Infra ─────────────────────────────────────────
    "domain_found":             "domain",
    "subdomain_found":          "subdomain",
    "ip_found":                 "ip_address",
    "asn_found":                "asn",
    "service_detected":         "service",
    "port_open":                "service",

    # ── Web surface ─────────────────────────────────────────────
    "webapp_alive":             "webapp",
    "url_found":                "endpoint",
    "endpoint_found":           "endpoint",
    "parameter_found":          "endpoint",
    "technology_found":         "technology",
    "waf_detected":             "technology",
    "header_found":             None,       # metadata, not entity

    # ── Assets ──────────────────────────────────────────────────
    "repo_found":               "repository",
    "document_found":           "document",

    # ── Security ────────────────────────────────────────────────
    "vulnerability_found":      None,       # → Finding
    "credential_signal_found":  None,       # → Finding

    # ── People / Org ────────────────────────────────────────────
    "person_found":             "person",
    "email_found":              "email_address",
    "org_found":                "organization",
    "cert_found":               "certificate",
}


def normalizer_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Normalize observations into entities."""
    _log = None
    if config and hasattr(config, "configurable"):
        _log = config.configurable.get("log_callback")

    observations = state.get("observations", [])
    if not observations:
        return state

    session_id = state["engagement_spec"]["session_id"]
    if _log:
        _log({"type": "phase", "phase": "normalize", "status": "started",
              "message": f"Normalizing {len(observations)} observations"})
    existing_entities = {f"{e.type}:{e.canonical_value}": e for e in state.get("entities", [])}
    new_entities = []
    merged = 0

    # Group observations by normalized value + inferred entity type
    groups: dict = defaultdict(list)
    endpoint_dedup: dict = {}  # V5: dedup key → canonical key for endpoints
    for obs in observations:
        entity_type = _obs_to_entity_type(obs.type)
        if not entity_type:
            continue
        raw_val = obs.normalized_value or obs.value
        if is_garbage_value(raw_val):
            logger.debug("[Normalizer] Skipping garbage observation value: %s", raw_val[:80])
            continue
        norm_val = _normalize_entity_value(entity_type, raw_val)
        if is_garbage_value(norm_val):
            logger.debug("[Normalizer] Skipping garbage canonical value: %s", norm_val[:80])
            continue

        key = f"{entity_type}:{norm_val}"

        # V5: Endpoint dedup by path (ignore query params for grouping)
        if entity_type == "endpoint":
            dedup_key = Canonicalizer.endpoint_dedup_key(raw_val)
            if dedup_key in endpoint_dedup:
                key = endpoint_dedup[dedup_key]
            else:
                endpoint_dedup[dedup_key] = key

        groups[key].append(obs)

    for key, obs_list in groups.items():
        entity_type, canonical_value = key.split(":", 1)
        confidence = _aggregate_confidence(obs_list)
        obs_ids = [o.observation_id for o in obs_list]
        evidence_refs = list({r for o in obs_list for r in (o.evidence_ref,)
                              if o.evidence_ref})
        attributes = _merge_attributes(obs_list)

        # Generate canonical entity_id
        canonical_eid = make_entity_id(entity_type, canonical_value)

        entity_key = f"{entity_type}:{canonical_value}"
        if entity_key in existing_entities:
            # Update existing entity: merge obs_ids, recalculate confidence
            existing = existing_entities[entity_key]
            all_obs_ids = list(set(existing.observation_ids + obs_ids))
            all_evidence = list(set((existing.evidence_refs or []) + evidence_refs))
            updated = existing.model_copy(update={
                "entity_id": canonical_eid,
                "observation_ids": all_obs_ids,
                "evidence_refs": all_evidence,
                "confidence": _merge_confidence(existing.confidence, confidence),
                "attributes": {**(existing.attributes or {}), **attributes},
                "last_seen": datetime.now(timezone.utc),
            })
            existing_entities[entity_key] = updated
            merged += 1
        else:
            entity = Entity(
                session_id=session_id,
                entity_id=canonical_eid,
                type=entity_type,
                canonical_value=canonical_value,
                display_value=obs_list[0].value,
                observation_ids=obs_ids,
                evidence_refs=evidence_refs,
                confidence=confidence,
                attributes=attributes,
                source_collectors=list({o.source for o in obs_list if o.source}),
                last_seen=datetime.now(timezone.utc),
            )
            existing_entities[entity_key] = entity
            new_entities.append(entity)

    state["entities"] = list(existing_entities.values())

    # Rebuild entity_index with canonical IDs (keyed by type:canonical_value)
    state["entity_index"] = {
        f"{e.type}:{e.canonical_value}": e.entity_id for e in state["entities"]
    }

    logger.info("[Normalizer] +%d new entities, %d merged, total=%d",
                len(new_entities), merged, len(state["entities"]))

    state.setdefault("phase_log", []).append({
        "phase": "normalize",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"+{len(new_entities)} new entities, {merged} merged, total={len(state['entities'])}"
    })
    if _log:
        _log({"type": "phase", "phase": "normalize", "status": "done",
              "new_entities": len(new_entities), "merged": merged,
              "total_entities": len(state["entities"])})
    return state


def _obs_to_entity_type(obs_type: str) -> str:
    """Map observation type to entity type string."""
    return OBS_TYPE_TO_ENTITY_TYPE.get(obs_type, "")


def _normalize_entity_value(entity_type: str, value: str) -> str:
    """Apply canonicalization based on entity type."""
    try:
        return Canonicalizer.canonicalize(entity_type, value)
    except Exception:
        return value.lower().strip()


def _aggregate_confidence(obs_list: list) -> float:
    """
    V5: Confidence bám Rate table.
    1) rate → base_confidence (RATE_BASE_CONFIDENCE)
    2) source quality weight (SOURCE_WEIGHTS)
    3) multiple evidence boost: +5% per extra unique source (max +20%)
    4) missing evidence penalty: -10% if no evidence_ref
    5) stale evidence penalty: -15% if all obs older than _STALE_HOURS
    6) active verification boost: +10% if any source is active/*
    """
    if not obs_list:
        return 0.0

    weighted_sum = 0.0
    total_weight = 0.0
    unique_sources = set()
    has_evidence = False
    has_active = False
    all_stale = True
    now = datetime.now(timezone.utc)

    for obs in obs_list:
        # Base confidence from rate if available, else use obs.confidence
        rate = (obs.rate or "").lower() if hasattr(obs, "rate") and obs.rate else ""
        base = RATE_BASE_CONFIDENCE.get(rate, obs.confidence)

        w = SOURCE_WEIGHTS.get(obs.source, DEFAULT_SOURCE_WEIGHT)
        weighted_sum += base * w
        total_weight += w

        if obs.source:
            unique_sources.add(obs.source)
        if obs.evidence_ref:
            has_evidence = True
        if obs.source in _ACTIVE_SOURCES:
            has_active = True
        # Stale check
        obs_ts = obs.timestamp if hasattr(obs, "timestamp") else None
        if obs_ts:
            try:
                ts = obs_ts if isinstance(obs_ts, datetime) else datetime.fromisoformat(str(obs_ts))
                if (now - ts) < timedelta(hours=_STALE_HOURS):
                    all_stale = False
            except (ValueError, TypeError):
                all_stale = False  # unparseable timestamp → assume fresh
        else:
            all_stale = False  # no timestamp → assume fresh

    conf = weighted_sum / total_weight if total_weight > 0 else 0.0

    # Multiple evidence boost: +5% per extra source, max +20%
    extra_sources = max(0, len(unique_sources) - 1)
    conf += min(extra_sources * 0.05, 0.20)

    # Missing evidence penalty
    if not has_evidence:
        conf *= 0.90

    # Stale evidence penalty
    if all_stale and obs_list:
        conf *= 0.85

    # Active verification boost
    if has_active:
        conf += 0.10

    return round(min(max(conf, 0.0), 0.99), 4)


def _merge_confidence(existing: float, new: float) -> float:
    """Bayesian-style merge — multiple sources increase confidence."""
    combined = existing + new * (1 - existing)
    return round(min(combined, 0.99), 4)


def _merge_attributes(obs_list: list) -> dict:
    """Merge attribute dicts from all observations."""
    merged = {}
    for obs in obs_list:
        if obs.attributes:
            merged.update(obs.attributes)
    return merged
