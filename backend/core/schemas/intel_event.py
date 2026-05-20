"""
IntelEvent — Standardised raw intelligence event.

Every tool MUST return IntelEvent[] — no more ad-hoc formats.
Fields follow the What / Where / How / Rate / Impact framework.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


IntelEventRate = Literal["critical", "high", "medium", "low", "info"]


class DerivedLead(BaseModel):
    """A lead suggestion embedded inside an IntelEvent."""
    type: str
    value: str
    confidence: float = 0.5
    reason: str = ""


class IntelEvent(BaseModel):
    """
    Standardised intelligence event — the ONLY output format tools should produce.

    Semantic fields:
      what   — what was discovered (observation taxonomy type)
      where  — where it was found (target scope)
      how    — method / tool used to discover it
      rate   — severity/importance rating
      impact — potential impact description
    """
    event_id: str = Field(default_factory=lambda: f"iev_{uuid.uuid4().hex[:12]}")
    session_id: str = ""

    # ── What / Where / How / Rate / Impact ───────────────────────
    what: str                           # observation type (e.g. "subdomain_found")
    where: str                          # target context (e.g. "example.com")
    how: str                            # tool/method (e.g. "crt_sh API query")
    rate: IntelEventRate = "info"       # severity rating
    impact: str = ""                    # potential impact description

    # ── Provenance ───────────────────────────────────────────────
    source: str = ""                    # originating agent
    collector: str = ""                 # tool/collector name
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # ── Payload ──────────────────────────────────────────────────
    raw_payload: Dict[str, Any] = Field(default_factory=dict)  # full tool output
    evidence_ref: str = ""              # evidence_id in evidence store
    target: str = ""                    # specific target queried

    # ── Extracted intelligence ───────────────────────────────────
    value: str = ""                     # primary extracted value
    attributes: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0.0, le=1.0)

    # ── Derived leads ────────────────────────────────────────────
    derived_leads: List[DerivedLead] = Field(default_factory=list)

    class Config:
        frozen = True
