"""
core/provenance.py — Provenance attachment utilities.

Provides attach_evidence() for stamping evidence/collector fields
onto Observation objects after collection.

Usage in agent code:
    obs = attach_evidence(obs, collector="passive/crt_sh",
                          evidence_id=eid, raw_event_id=eid)

The function is non-mutating: Pydantic models are frozen, so it
returns a new Observation via model_copy(update=...).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.schemas import Observation


def attach_evidence(
    obs: "Observation",
    collector: str,
    evidence_id: str,
    raw_event_id: str = "",
) -> "Observation":
    """
    Return a new Observation with provenance fields stamped.

    Fields set only when currently absent (does not overwrite):
      - evidence_ref   ← evidence_id
      - raw_event_id   ← raw_event_id (falls back to evidence_id)
      - source         ← collector

    Args:
        obs:          The Observation to stamp.
        collector:    Collector identifier string, e.g. "passive/crt_sh".
        evidence_id:  ID returned by EvidenceStore.store_raw().
        raw_event_id: Optional separate raw event ID; defaults to evidence_id.

    Returns:
        The same object if nothing changed, else a new model_copy.
    """
    updates: dict = {}

    if evidence_id and not obs.evidence_ref:
        updates["evidence_ref"] = evidence_id

    resolved_raw = raw_event_id or evidence_id
    if resolved_raw and not obs.raw_event_id:
        updates["raw_event_id"] = resolved_raw

    if collector and not obs.source:
        updates["source"] = collector

    if not updates:
        return obs

    return obs.model_copy(update=updates)
