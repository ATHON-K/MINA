"""
MINA Core Data Models
Data structures used throughout the multi-agent recon system.
"""

import operator
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from typing_extensions import TypedDict


@dataclass
class Lead:
    """A lead (manh moi) representing a recon target to investigate."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""          # domain | subdomain | ip | email | org
    value: str = ""
    source: str = "initial"
    confidence: float = 1.0
    ttl: int = 3600
    depth: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "Lead":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in valid})


@dataclass
class IntelEvent:
    """A raw intelligence event produced by a recon agent."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    what: str = ""           # finding type (subdomain_found, port_open, email_found …)
    where: str = ""          # target scoped to
    how: str = ""            # tool / method used
    value: str = ""          # actual finding value
    source_agent: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 1.0
    evidence_ref: str = ""   # path to raw evidence file
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "IntelEvent":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in valid})


@dataclass
class Entity:
    """A normalised, deduplicated intelligence entity."""

    entity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""           # subdomain | ip_address | email | service | organization | certificate
    canonical_value: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    sources: List[str] = field(default_factory=list)
    risk_level: str = "low"  # critical | high | medium | low
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "Entity":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in valid})


@dataclass
class Relationship:
    """A relationship between two entities."""

    from_entity: str = ""    # entity_id
    relation_type: str = ""  # resolves_to | hosted_on | belongs_to | related_to | has_service
    to_entity: str = ""      # entity_id
    confidence: float = 1.0
    evidence: str = ""
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Vulnerability:
    """A structured vulnerability / security issue."""

    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    severity: str = "medium"      # critical | high | medium | low | info
    category: str = ""
    target: str = ""
    description: str = ""
    source_agent: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence_ref: str = ""
    recommendation: str = ""
    # Legacy compat aliases kept for backward compatibility with older agent output
    asset: str = ""
    impact: str = ""
    vulnerability: str = ""
    type: str = ""
    cvss_estimated: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "Vulnerability":
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in valid})


# ---------------------------------------------------------------------------
# LangGraph State
# ---------------------------------------------------------------------------

class ReconState(TypedDict):
    """Shared state passed through all LangGraph nodes."""

    target: str
    engagement_spec: Dict[str, Any]

    # Lead queue management
    lead_queue: List[Dict]               # pending leads to process
    processed_leads: List[str]           # IDs of already-processed leads
    current_lead: Optional[Dict]         # lead being processed this iteration

    # Per-iteration routing
    leads_to_process_passive: List[Dict]
    leads_to_process_active: List[Dict]

    # Intelligence data  (use operator.add reducer → agents APPEND, never replace)
    intel_events: Annotated[List[Dict], operator.add]

    # Normalised output (replaced by normaliser)
    entities: List[Dict]
    relationships: List[Dict]

    # Final report
    report: str

    # Loop control
    iteration_count: int
    max_iterations: int
    scan_status: str   # running | complete | error

    # Streaming data (appended by every node)
    logs: Annotated[List[Dict], operator.add]
    graph_updates: Annotated[List[Dict], operator.add]
    vulns: Annotated[List[Dict], operator.add]

    # Global lead dedup — accumulates (type, value) key strings across all agents
    global_lead_keys: Annotated[List[str], operator.add]
