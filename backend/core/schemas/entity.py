from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional, Any
from datetime import datetime
import uuid

EntityType = Literal[
    "organization", "domain", "subdomain", "ip_address", "asn",
    "ip_range", "service", "webapp", "endpoint", "repository",
    "document", "person", "email_address", "certificate", "technology"
]

EntityStatus = Literal["active", "inactive", "unknown", "needs_review"]


class Entity(BaseModel):
    entity_id: str = Field(default_factory=lambda: f"ent_{uuid.uuid4().hex[:12]}")
    session_id: str
    type: EntityType
    canonical_value: str                # giá trị chuẩn sau normalize
    display_value: str                  # hiển thị cho người dùng

    # ── Aliases (same entity, different representations) ─────────
    aliases: List[str] = Field(default_factory=list)

    # ── Provenance (trace về đâu) ───────────────────────────────
    observation_ids: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    source_collectors: List[str] = Field(default_factory=list)

    # ── Scoring ─────────────────────────────────────────────────
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source_count: int = 1

    # ── Rich attributes ─────────────────────────────────────────
    attributes: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    status: EntityStatus = "unknown"

    # ── Conflict resolution ─────────────────────────────────────
    needs_review: bool = False
    review_reason: Optional[str] = None
    conflict_note: Optional[str] = None
    merged_from: List[str] = Field(default_factory=list)

    # ── Lifecycle timestamps ────────────────────────────────────
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
