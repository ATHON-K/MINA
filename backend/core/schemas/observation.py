from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional, Any
from datetime import datetime
import uuid

# ── Fixed observation taxonomy ──────────────────────────────────
ObservationType = Literal[
    # ── Network / Infrastructure ────────────────────────────────
    "domain_found",
    "subdomain_found",
    "ip_found",
    "asn_found",
    "service_detected",
    "port_open",

    # ── Web surface ─────────────────────────────────────────────
    "webapp_alive",
    "url_found",
    "endpoint_found",
    "parameter_found",
    "technology_found",
    "waf_detected",
    "header_found",

    # ── Assets ──────────────────────────────────────────────────
    "repo_found",
    "document_found",

    # ── Security ────────────────────────────────────────────────
    "vulnerability_found",
    "credential_signal_found",

    # ── People / Org ────────────────────────────────────────────
    "person_found",
    "email_found",
    "org_found",
    "cert_found",
]


class Observation(BaseModel):
    """
    Tầng 2: Kết luận quan sát cụ thể từ RawEvent.
    Ví dụ: "subdomain api.example.com xuất hiện trong CT logs"
    """
    observation_id: str = Field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:12]}")
    session_id: str
    raw_event_id: str                   # trace về RawEvent gốc
    extractor: str                      # module nào extract observation này

    type: ObservationType
    value: str                          # giá trị quan sát (VD: "api.example.com")
    normalized_value: Optional[str] = None  # sau canonicalization

    # Context
    context: str = ""                   # mô tả ngắn (VD: "Found in CT log entry #42")
    source: str                         # nguồn gốc (crt.sh, nmap, shodan...)
    evidence_ref: str                   # evidence_id trong evidence store

    # Scoring
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    rate: Optional[str] = None          # Low/Medium/High/Critical

    # Attributes linh hoạt
    attributes: Dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        frozen = True
