from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional, Any
from datetime import datetime
import uuid

RelationType = Literal[
    "resolves_to",      # domain → ip
    "belongs_to",       # ip → asn, subdomain → domain, email → domain
    "hosted_on",        # webapp → ip
    "hosts_service",    # ip → service
    "exposes",          # host → service, webapp → endpoint
    "exposes_endpoint", # service/subdomain → endpoint
    "contains",         # domain → subdomain, webapp → endpoint, repo → secret
    "leaks",            # repo → secret, doc → email
    "mentions",         # doc → email, doc → hostname
    "linked_to",        # domain → domain (redirect, CNAME)
    "shares_cert",      # domain → domain (same cert)
    "shares_ip",        # domain → domain (same IP)
    "owned_by",         # domain → org
    "announced_by",     # ip → asn
    "associated_with",  # org → domain, repo → org
    "built_with",       # endpoint → technology
    "uses",             # repo → technology
    "employs",          # org → person
    "uses_technology",  # webapp → technology
    "similar_to"        # entity → entity (fuzzy match, low confidence)
]


class Relationship(BaseModel):
    relationship_id: str = Field(default_factory=lambda: f"rel_{uuid.uuid4().hex[:12]}")
    session_id: str
    from_entity_id: str
    relation_type: RelationType
    to_entity_id: str

    # ── Provenance ──────────────────────────────────────────────
    observation_ids: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    source_collectors: List[str] = Field(default_factory=list)
    derived_by: str = ""                # agent/method tạo relationship
    reason: str = ""                    # giải thích tại sao tạo relationship

    # ── Scoring ─────────────────────────────────────────────────
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source_count: int = 1

    # ── Conflict ────────────────────────────────────────────────
    needs_review: bool = False
    low_confidence_link: bool = False
    unresolved_hostname: bool = False
    conflicting_org_match: bool = False
    conflict_note: str = ""
    conflicting_observation_ids: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    attributes: Dict[str, Any] = Field(default_factory=dict)
