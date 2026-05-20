from pydantic import BaseModel, Field, validator
from typing import Literal, Optional, List
from datetime import datetime
import uuid

# ── Lead Kind — determines valid collector routing ────────────────
LeadKind = Literal[
    "org", "domain", "subdomain", "ip", "asn",
    "host", "repo", "doc", "webapp", "person",
]

# ── Lead Type — fine-grained classification ──────────────────────
LeadType = Literal[
    "org", "domain", "subdomain", "ip", "asn", "ip_range",
    "repo", "document", "webapp", "person", "email", "endpoint",
    "service", "certificate", "host",
]

_VALID_LEAD_TYPES: frozenset = frozenset(LeadType.__args__)  # type: ignore[attr-defined]

_LEAD_TYPE_ALIASES: dict = {
    "api_endpoint": "endpoint",
    "url":          "endpoint",
    "path":         "endpoint",
    "js_endpoint":  "endpoint",
    "hostname":     "subdomain",
    "port":         "service",
    "open_port":    "service",
    "server":       "service",
    "webapp_url":   "webapp",
    "site":         "webapp",
    "website":      "webapp",
    "network":      "ip_range",
    "cidr":         "ip_range",
    "contact":      "person",
    "secret":       "document",
    "credential":   "document",
    "organization": "org",
}

# ── Lead Kind → Allowed collectors routing table ─────────────────
LEAD_KIND_COLLECTORS: dict[str, frozenset[str]] = {
    "org": frozenset({
        "company_profile", "company_stack", "related_domains", "reverse_whois",
        "email_harvest", "public_contact", "team_harvest",
        "repo_discovery", "public_doc_discovery",
    }),
    "domain": frozenset({
        "dns", "whois", "crt_sh", "subdomain_discovery", "asn", "spf_dmarc",
        "reverse_dns", "wayback", "email_harvest", "dns_dumpster", "subfinder",
        "zone_transfer", "js_endpoints", "reverse_ip", "google_analytics_id",
        "reverse_whois", "company_profile", "public_contact",
        "repo_discovery", "public_doc_discovery", "infra_asn_enrich",
        "karma_ip", "karma_leaks", "karma_cve", "smap",
        "httpx", "headers", "tech", "ssl", "robots",
    }),
    "subdomain": frozenset({
        "dns", "httpx", "headers", "tech", "ssl", "robots", "http_methods",
        "favicon", "web_surface", "wayback", "js_endpoints", "params",
        "dirs", "crawl", "nuclei", "waf", "vhost", "banner", "cloud",
        "nmap", "shodan",
    }),
    "ip": frozenset({
        "reverse_dns", "shodan", "asn", "nmap", "ssl", "banner",
        "reverse_ip", "karma_ip", "smap",
    }),
    "asn": frozenset({
        "infra_asn_enrich", "shodan",
    }),
    "host": frozenset({
        "dns", "httpx", "headers", "tech", "ssl", "nmap", "banner",
        "shodan", "reverse_dns",
    }),
    "repo": frozenset({
        "github_dorks", "google_dorks", "repo_discovery",
    }),
    "doc": frozenset({
        "public_doc_discovery", "google_dorks",
    }),
    "webapp": frozenset({
        "httpx", "headers", "tech", "ssl", "robots", "http_methods",
        "favicon", "dirs", "crawl", "params", "waf", "nuclei",
        "js_endpoints", "web_surface", "cloud",
    }),
    "person": frozenset({
        "email_harvest", "public_contact", "team_harvest",
    }),
}

# ── Lead Kind inference from LeadType ────────────────────────────
_TYPE_TO_KIND: dict[str, str] = {
    "org": "org",
    "domain": "domain",
    "subdomain": "subdomain",
    "ip": "ip",
    "ip_range": "ip",
    "asn": "asn",
    "host": "host",
    "repo": "repo",
    "document": "doc",
    "webapp": "webapp",
    "person": "person",
    "email": "person",
    "endpoint": "webapp",
    "service": "host",
    "certificate": "domain",
}


def infer_lead_kind(lead_type: str) -> LeadKind:  # type: ignore[valid-type]
    """Infer lead_kind from lead type."""
    return _TYPE_TO_KIND.get(lead_type, "domain")  # type: ignore[return-value]


def get_allowed_collectors(lead_kind: str) -> frozenset[str]:
    """Return set of valid collector names for a given lead kind."""
    return LEAD_KIND_COLLECTORS.get(lead_kind, frozenset())


def normalize_lead_type(t: str) -> LeadType:  # type: ignore[valid-type]
    """Map any freeform type string to a valid LeadType, defaulting to 'endpoint'."""
    t = (t or "endpoint").lower().strip()
    if t in _VALID_LEAD_TYPES:
        return t  # type: ignore[return-value]
    return _LEAD_TYPE_ALIASES.get(t, "endpoint")  # type: ignore[return-value]

LeadStatus = Literal[
    "pending",      # chờ xử lý
    "approved",     # đã qua policy gate
    "running",      # đang được collector xử lý
    "exhausted",    # đã xử lý xong, không còn yield mới
    "merged",       # đã merge vào entity khác
    "rejected",     # bị gate reject (out of scope, low quality)
    "out_of_scope", # ngoài scope cho phép
    "duplicate",    # trùng với lead đã có
    "error"         # lỗi khi xử lý
]

class Lead(BaseModel):
    lead_id: str = Field(default_factory=lambda: f"lead_{uuid.uuid4().hex[:12]}")
    type: LeadType
    lead_kind: Optional[str] = None     # org|domain|subdomain|ip|asn|host|repo|doc|webapp|person
    value: str                          # giá trị canonical (lowercase, stripped)
    raw_value: str                      # giá trị gốc trước khi normalize
    source: str                         # agent/collector tạo ra lead này
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    priority: float = Field(0.5, ge=0.0, le=1.0)
    depth: int = Field(0, ge=0)
    ttl: int = Field(3, ge=0)
    reason: str = ""                    # lý do tạo lead này
    status: LeadStatus = "pending"
    attempts: int = 0
    parent_lead_id: Optional[str] = None
    parent_entity_id: Optional[str] = None  # entity cha sinh ra lead
    discovered_by: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    allowed_collectors: List[str] = Field(default_factory=list)  # auto-filled from lead_kind
    tags: List[str] = Field(default_factory=list)
    scope_status: Literal["in_scope", "out_of_scope", "unknown"] = "unknown"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_processed_at: Optional[datetime] = None
    dedup_key: Optional[str] = None

    @validator('value', pre=True)
    def normalize_value(cls, v, values):
        if isinstance(v, str):
            v = v.strip().lower()
            if v.endswith('.'):
                v = v[:-1]
        return v

    @validator('lead_kind', always=True, pre=False)
    def set_lead_kind(cls, v, values):
        if v is None and 'type' in values:
            return infer_lead_kind(values['type'])
        return v

    @validator('allowed_collectors', always=True, pre=False)
    def set_allowed_collectors(cls, v, values):
        if not v and values.get('lead_kind'):
            return list(get_allowed_collectors(values['lead_kind']))
        return v

    @validator('dedup_key', always=True)
    def set_dedup_key(cls, v, values):
        if v is None and 'type' in values and 'value' in values:
            return f"{values['type']}:{values['value']}"
        return v

    def is_expired(self) -> bool:
        return self.ttl <= 0

    def decrement_ttl(self) -> 'Lead':
        return self.model_copy(update={'ttl': self.ttl - 1, 'attempts': self.attempts + 1})

    def is_collector_allowed(self, collector_name: str) -> bool:
        """Check if a specific collector is valid for this lead kind."""
        if not self.allowed_collectors:
            return True  # no restriction
        return collector_name in self.allowed_collectors
