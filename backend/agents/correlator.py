"""
Correlator Agent — Entity resolution and relationship building.
Detects conflicts, merges duplicates, builds Relationship graph.

V5: Enhanced conflict handling — low_confidence_link, unresolved_hostname,
    conflicting_org_match flags. Soft-merge (don't hard-merge when weak).

Relationship rules (15+):
  1. subdomain → ip_address     : resolves_to
  2. domain → subdomain         : contains
  3. ip_address → service       : hosts_service
  4. ip_address → asn           : announced_by
  5. service → endpoint         : exposes_endpoint
  6. endpoint → technology      : built_with
  7. organization → domain      : associated_with
  8. shares_ip (sibling)        : shares_ip
  9. repo → technology          : uses
 10. repo → organization        : associated_with
 11. document → domain          : references
 12. email_address → domain     : belongs_to
 13. subdomain → technology     : fronted_by (WAF/CDN)
 14. subdomain ↔ subdomain      : shares_cert
 15. endpoint → endpoint        : linked_to
"""
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.state import MINAState
from core.schemas import Entity, Relationship
from core.canonicalization import Canonicalizer
from core.identity import make_entity_id, make_relationship_id

logger = logging.getLogger(__name__)

# V5: Confidence thresholds for conflict handling
_LOW_CONFIDENCE_THRESHOLD = 0.40   # below this → low_confidence_link
_SOFT_MERGE_THRESHOLD = 0.50       # below this → don't hard-merge, flag needs_review


def correlator_node(state: MINAState, config=None) -> MINAState:
    """LangGraph node: Correlate entities, build relationships."""
    _log = None
    if config and hasattr(config, "configurable"):
        _log = config.configurable.get("log_callback")

    entities = state.get("entities", [])
    observations = state.get("observations", [])
    if not entities:
        return state

    session_id = state["engagement_spec"]["session_id"]
    if _log:
        _log({"type": "phase", "phase": "correlate", "status": "started",
              "message": f"Correlating {len(entities)} entities, {len(observations)} observations"})
    new_relationships: List[Relationship] = []
    conflict_items: List[Dict] = []

    # Entity resolution: merge near-duplicates before relationship building
    entities = _entity_resolution(entities)

    # Index entities by type for fast lookup
    by_type: dict = defaultdict(list)
    for e in entities:
        by_type[e.type].append(e)

    # Dedup helper: track already-created relationships
    _seen_rels: set = set()
    existing_rels = state.get("relationships", [])
    for r in existing_rels:
        fid = getattr(r, "from_entity_id", "")
        tid = getattr(r, "to_entity_id", "")
        rt = getattr(r, "relation_type", "")
        _seen_rels.add(f"{fid}--{rt}--{tid}")

    def _add_rel(from_id, to_id, rel_type, confidence=0.8, ev_refs=None, obs_ids=None,
                 unresolved_hostname=False, conflicting_org=False):
        key = f"{from_id}--{rel_type}--{to_id}"
        if key in _seen_rels or not from_id or not to_id or from_id == to_id:
            return
        _seen_rels.add(key)
        is_low = confidence < _LOW_CONFIDENCE_THRESHOLD
        needs_rev = is_low or unresolved_hostname or conflicting_org
        note_parts = []
        if is_low:
            note_parts.append(f"low confidence ({confidence:.2f})")
        if unresolved_hostname:
            note_parts.append("unresolved hostname")
        if conflicting_org:
            note_parts.append("conflicting org match")
        new_relationships.append(Relationship(
            session_id=session_id,
            relationship_id=make_relationship_id(from_id, rel_type, to_id),
            from_entity_id=from_id,
            to_entity_id=to_id,
            relation_type=rel_type,
            confidence=confidence,
            evidence_refs=ev_refs or [],
            observation_ids=obs_ids or [],
            needs_review=needs_rev,
            low_confidence_link=is_low,
            unresolved_hostname=unresolved_hostname,
            conflicting_org_match=conflicting_org,
            conflict_note="; ".join(note_parts) if note_parts else "",
        ))

    # ── Rule 1: subdomain → IP (resolves_to) ────────────────────
    for obs in observations:
        if obs.type == "ip_found" and obs.attributes:
            domain = obs.attributes.get("domain", "")
            ip = obs.normalized_value or obs.value

            domain_entity = _find_entity(by_type, "subdomain", domain) or _find_entity(by_type, "domain", domain)
            ip_entity = _find_entity(by_type, "ip_address", ip)

            if domain_entity and ip_entity:
                _add_rel(domain_entity.entity_id, ip_entity.entity_id, "resolves_to",
                         confidence=0.95,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                         obs_ids=[obs.observation_id])

    # ── Rule 2: domain → subdomain (contains) ───────────────────
    domains = by_type.get("domain", [])
    subdomains = by_type.get("subdomain", [])
    for dom_e in domains:
        dom_val = dom_e.canonical_value
        for sub_e in subdomains:
            sub_val = sub_e.canonical_value
            if sub_val.endswith(f".{dom_val}") or sub_val == dom_val:
                _add_rel(dom_e.entity_id, sub_e.entity_id, "contains", confidence=0.95)

    # ── Rule 3: ip_address → service (hosts_service) ─────────────
    for obs in observations:
        if obs.type == "port_open" and obs.attributes:
            host = obs.attributes.get("host", "")
            port = obs.attributes.get("port")
            if host and port:
                ip_entity = _find_entity(by_type, "ip_address", host)
                svc_entity = _find_entity(by_type, "service", f"{host}:{port}")
                if ip_entity and svc_entity:
                    _add_rel(ip_entity.entity_id, svc_entity.entity_id, "hosts_service",
                             confidence=0.9,
                             ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                             obs_ids=[obs.observation_id])

    # ── Rule 4: ip_address → asn (announced_by) ──────────────────
    for obs in observations:
        if obs.type in ("asn_found",) and obs.attributes:
            # Link ALL IP entities to this ASN
            asn_entity = _find_entity(by_type, "asn", obs.normalized_value or obs.value)
            if asn_entity:
                for ip_e in by_type.get("ip_address", []):
                    _add_rel(ip_e.entity_id, asn_entity.entity_id, "announced_by",
                             confidence=0.85,
                             ev_refs=[obs.evidence_ref] if obs.evidence_ref else [])

    # ── Rule 5: service → endpoint (exposes_endpoint) ─────────────
    for obs in observations:
        if obs.type in ("endpoint_found", "url_found",
                         "parameter_found") and obs.value:
            # Find parent service/subdomain entity
            parent = None
            for stype in ("subdomain", "domain", "service"):
                candidates = by_type.get(stype, [])
                for c in candidates:
                    if c.canonical_value and c.canonical_value in (obs.value or ""):
                        parent = c
                        break
                if parent:
                    break

            endpoint_entity = _find_entity(by_type, "endpoint", obs.normalized_value or obs.value)
            if parent and endpoint_entity:
                _add_rel(parent.entity_id, endpoint_entity.entity_id, "exposes_endpoint",
                         confidence=0.75,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                         obs_ids=[obs.observation_id])

    # ── Rule 6: endpoint/subdomain → technology (built_with) ──────
    for obs in observations:
        if obs.type == "technology_found" and obs.value:
            tech_entity = _find_entity(by_type, "technology", obs.normalized_value or obs.value)
            if not tech_entity:
                continue
            # Link tech to the closest parent (subdomain or endpoint)
            host_val = (obs.attributes or {}).get("host", "") or (obs.attributes or {}).get("domain", "")
            parent = None
            if host_val:
                parent = _find_entity(by_type, "subdomain", host_val) or _find_entity(by_type, "domain", host_val)
            if parent:
                _add_rel(parent.entity_id, tech_entity.entity_id, "built_with",
                         confidence=0.70,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [])

    # ── Rule 7: organization → domain (associated_with) ───────────
    # V5: Detect conflicting org → domain links
    domain_org_map: dict = defaultdict(list)  # domain_eid → list of org_eids
    for org_e in by_type.get("organization", []):
        for dom_e in domains:
            shared = set(org_e.observation_ids or []) & set(dom_e.observation_ids or [])
            if shared:
                domain_org_map[dom_e.entity_id].append(org_e.entity_id)
                is_conflicting = len(domain_org_map[dom_e.entity_id]) > 1
                _add_rel(org_e.entity_id, dom_e.entity_id, "associated_with",
                         confidence=0.70,
                         conflicting_org=is_conflicting)

    # ── Rule 8: shares_ip (sibling subdomains) ────────────────────
    ip_to_subdomains: dict = defaultdict(list)
    for rel in existing_rels + new_relationships:
        rt = getattr(rel, "relation_type", "")
        if rt == "resolves_to":
            fid = getattr(rel, "from_entity_id", "")
            tid = getattr(rel, "to_entity_id", "")
            ip_to_subdomains[tid].append(fid)

    for ip_id, sub_ids in ip_to_subdomains.items():
        if len(sub_ids) > 1:
            for i in range(len(sub_ids)):
                for j in range(i + 1, len(sub_ids)):
                    _add_rel(sub_ids[i], sub_ids[j], "shares_ip", confidence=0.8)

    # ── Rule 9: repo → technology (uses) ──────────────────────────
    for obs in observations:
        if obs.type == "repo_found" and obs.attributes:
            lang = (obs.attributes or {}).get("language", "")
            if lang:
                repo_entity = _find_entity(by_type, "repository", obs.normalized_value or obs.value)
                tech_entity = _find_entity(by_type, "technology", lang)
                if repo_entity and tech_entity:
                    _add_rel(repo_entity.entity_id, tech_entity.entity_id, "uses",
                             confidence=0.70)

    # ── Rule 10: repo → organization (associated_with) ────────────
    for repo_e in by_type.get("repository", []):
        for org_e in by_type.get("organization", []):
            shared = set(repo_e.observation_ids or []) & set(org_e.observation_ids or [])
            if shared:
                _add_rel(repo_e.entity_id, org_e.entity_id, "associated_with",
                         confidence=0.60)

    # ── Rule 11: email_address → domain (belongs_to) ──────────────
    for email_e in by_type.get("email_address", []):
        email_val = email_e.canonical_value or ""
        if "@" in email_val:
            email_domain = email_val.split("@")[1]
            dom_entity = _find_entity(by_type, "domain", email_domain) or _find_entity(by_type, "subdomain", email_domain)
            if dom_entity:
                _add_rel(email_e.entity_id, dom_entity.entity_id, "belongs_to",
                         confidence=0.85)

    # ── V4 Rule 12: subdomain → technology (fronted_by) for WAF/CDN ──
    for obs in observations:
        if obs.type in ("waf_detected",) and obs.value:
            tech_entity = _find_entity(by_type, "technology", obs.normalized_value or obs.value)
            host_val = (obs.attributes or {}).get("host", "")
            parent = None
            if host_val:
                parent = _find_entity(by_type, "subdomain", host_val) or _find_entity(by_type, "domain", host_val)
            if parent and tech_entity:
                _add_rel(parent.entity_id, tech_entity.entity_id, "fronted_by",
                         confidence=0.80,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                         obs_ids=[obs.observation_id])

    # ── V4 Rule 13: subdomain ↔ subdomain (shares_cert) ──────────
    cert_to_domains: dict = defaultdict(list)
    for obs in observations:
        if obs.type == "cert_found" and obs.attributes:
            san_domains = obs.attributes.get("san_domains", [])
            cert_key = obs.attributes.get("cert_issuer", "") + ":" + str(obs.attributes.get("cert_expiry_days", ""))
            for san_d in san_domains:
                san_entity = _find_entity(by_type, "subdomain", san_d) or _find_entity(by_type, "domain", san_d)
                if san_entity:
                    cert_to_domains[cert_key].append(san_entity.entity_id)
    for cert_k, domain_ids in cert_to_domains.items():
        unique_ids = list(set(domain_ids))
        if len(unique_ids) > 1:
            for i in range(len(unique_ids)):
                for j in range(i + 1, len(unique_ids)):
                    _add_rel(unique_ids[i], unique_ids[j], "shares_cert", confidence=0.75)

    # ── V4 Rule 14: subdomain/endpoint → technology (uses_technology) ──
    for obs in observations:
        if obs.type in ("technology_found",):
            tech_entity = _find_entity(by_type, "technology", obs.normalized_value or obs.value)
            host_val = (obs.attributes or {}).get("host", "") or (obs.attributes or {}).get("url", "")
            parent = None
            if host_val:
                parent = (_find_entity(by_type, "subdomain", host_val) or
                          _find_entity(by_type, "domain", host_val) or
                          _find_entity(by_type, "endpoint", host_val))
            if parent and tech_entity:
                _add_rel(parent.entity_id, tech_entity.entity_id, "uses_technology",
                         confidence=0.75,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                         obs_ids=[obs.observation_id])

    # ── V4 Rule 15: endpoint → endpoint (linked_to) for params ──
    for obs in observations:
        if obs.type in ("parameter_found", "endpoint_found") and obs.value:
            param_entity = _find_entity(by_type, "endpoint", obs.normalized_value or obs.value)
            host_val = (obs.attributes or {}).get("domain", "") or (obs.attributes or {}).get("host", "")
            parent = None
            if host_val:
                parent = _find_entity(by_type, "subdomain", host_val) or _find_entity(by_type, "endpoint", host_val)
            if parent and param_entity and parent.entity_id != param_entity.entity_id:
                _add_rel(parent.entity_id, param_entity.entity_id, "linked_to",
                         confidence=0.65,
                         ev_refs=[obs.evidence_ref] if obs.evidence_ref else [],
                         obs_ids=[obs.observation_id])

    # ── Conflict detection & queue population ─────────────────────
    obs_map: dict = {o.observation_id: o for o in observations if hasattr(o, "observation_id")}

    # V5: Build set of entity_ids that have resolves_to relationships
    resolved_entity_ids = set()
    for rel in existing_rels + new_relationships:
        rt = getattr(rel, "relation_type", "")
        if rt == "resolves_to":
            fid = getattr(rel, "from_entity_id", "")
            resolved_entity_ids.add(fid)

    for entity in entities:
        conflict = _check_status_conflict(entity, observations, obs_map)

        # V5: unresolved_hostname flag — only for high-confidence domains/subdomains
        # Low-confidence or provisional entities are expected to be unresolved
        is_unresolved = (entity.type in ("domain", "subdomain")
                         and entity.entity_id not in resolved_entity_ids
                         and entity.confidence >= _SOFT_MERGE_THRESHOLD)

        # V5: conflicting org match detection
        is_org_conflict = False
        if conflict and "Conflicting orgs" in conflict:
            is_org_conflict = True

        if conflict or is_unresolved:
            note = conflict or ""
            if is_unresolved:
                note = f"Unresolved hostname (no DNS record); {note}" if note else "Unresolved hostname (no DNS record)"
            entity_copy = entity.model_copy(update={
                "needs_review": True,
                "conflict_note": note,
            })
            idx = entities.index(entity)
            entities[idx] = entity_copy
            conflict_items.append({
                "entity_id": entity.entity_id,
                "entity_type": entity.type,
                "canonical_value": entity.canonical_value,
                "conflict_description": note,
                "flags": {
                    "unresolved_hostname": is_unresolved,
                    "conflicting_org_match": is_org_conflict,
                    "low_confidence": entity.confidence < _LOW_CONFIDENCE_THRESHOLD,
                },
                "observation_ids": entity.observation_ids[:5],
                "evidence_refs": (entity.evidence_refs or [])[:5],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    state["entities"] = entities
    state["relationships"] = existing_rels + new_relationships
    state.setdefault("conflict_queue", []).extend(conflict_items)

    logger.info("[Correlator] +%d relationships, %d conflicts flagged",
                len(new_relationships), len(conflict_items))

    state.setdefault("phase_log", []).append({
        "phase": "correlate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"+{len(new_relationships)} relationships, {len(conflict_items)} conflicts"
    })
    if _log:
        _log({"type": "phase", "phase": "correlate", "status": "done",
              "new_relationships": len(new_relationships),
              "conflicts": len(conflict_items)})
    return state


def _find_entity(by_type: dict, entity_type: str, value: str) -> Optional[Entity]:
    """Find entity by canonical value."""
    canonical = Canonicalizer.canonicalize(entity_type, value)
    for e in by_type.get(entity_type, []):
        if e.canonical_value == canonical:
            return e
    return None


def _check_status_conflict(entity: Entity, observations: list, obs_map: dict) -> Optional[str]:
    """
    V5: Enhanced conflict detection with specific categories:
    - conflicting statuses (open vs closed)
    - multiple IPs for same entity
    - confidence divergence > 0.3
    - unresolved hostname (IP entity with no DNS observation)
    - conflicting org match (same domain, different org assertions)
    Returns conflict description string or None.
    """
    relevant = [o for o in observations
                if o.observation_id in (entity.observation_ids or [])]
    if len(relevant) < 2:
        # Single-source: check if confidence is too low to trust
        if relevant and relevant[0].confidence < _SOFT_MERGE_THRESHOLD:
            return f"Single low-confidence source ({relevant[0].confidence:.2f})"
        return None

    reasons = []

    # Multiple IPs for same domain/subdomain
    if entity.type in ("domain", "subdomain"):
        ip_vals = set()
        for o in relevant:
            if o.type == "ip_found":
                ip_vals.add(o.normalized_value or o.value)
        if len(ip_vals) > 1:
            reasons.append(f"Multiple IPs: {ip_vals}")

    # Conflicting statuses
    statuses = {o.attributes.get("status") for o in relevant if o.attributes}
    statuses.discard(None)
    if len(statuses) > 1:
        reasons.append(f"Conflicting statuses: {statuses}")

    # Confidence divergence
    confidences = [o.confidence for o in relevant if o.confidence]
    if confidences and (max(confidences) - min(confidences) > 0.3):
        reasons.append(f"Confidence divergence: {min(confidences):.2f}–{max(confidences):.2f}")

    # Conflicting org assertions
    if entity.type in ("domain", "subdomain"):
        orgs = set()
        for o in relevant:
            org = (o.attributes or {}).get("organization", "")
            if org:
                orgs.add(org.lower().strip())
        if len(orgs) > 1:
            reasons.append(f"Conflicting orgs: {orgs}")

    return "; ".join(reasons) if reasons else None


def _entity_resolution(entities: list) -> list:
    """
    V5: Merge near-duplicate entities with soft-merge guard.
    If both entities have low confidence, don't hard-merge — flag needs_review.
    Returns deduplicated entity list.
    """
    seen_canonical = {}
    for entity in entities:
        key = f"{entity.type}:{entity.canonical_value}"
        if key in seen_canonical:
            existing = seen_canonical[key]
            # V5: Soft-merge guard — don't merge if both are low confidence
            if existing.confidence < _SOFT_MERGE_THRESHOLD and entity.confidence < _SOFT_MERGE_THRESHOLD:
                # Don't hard-merge; keep the higher-confidence one, flag for review
                keeper = existing if existing.confidence >= entity.confidence else entity
                loser = entity if keeper is existing else existing
                flagged = keeper.model_copy(update={
                    "needs_review": True,
                    "conflict_note": f"Soft-merge skipped: both entities low confidence "
                                     f"({existing.confidence:.2f} vs {entity.confidence:.2f})",
                    "merged_from": (keeper.merged_from or []) + [loser.entity_id],
                })
                seen_canonical[key] = flagged
                continue

            merged_obs = list(set(existing.observation_ids + entity.observation_ids))
            merged_evidence = list(set((existing.evidence_refs or []) + (entity.evidence_refs or [])))
            merged_collectors = list(set((existing.source_collectors or []) + (entity.source_collectors or [])))
            combined_conf = min(existing.confidence + entity.confidence * (1 - existing.confidence), 0.99)
            updated = existing.model_copy(update={
                "observation_ids": merged_obs,
                "evidence_refs": merged_evidence,
                "source_collectors": merged_collectors,
                "source_count": len(merged_collectors),
                "confidence": round(combined_conf, 4),
                "merged_from": (existing.merged_from or []) + [entity.entity_id],
            })
            seen_canonical[key] = updated
        else:
            seen_canonical[key] = entity

    return list(seen_canonical.values())
