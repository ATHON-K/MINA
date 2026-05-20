from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime
import uuid

RiskLevel = Literal["critical", "high", "medium", "low", "info"]
FindingCategory = Literal[
    "credential_exposure", "secret_leakage", "infrastructure_exposure",
    "service_misconfiguration", "technology_disclosure", "endpoint_exposure",
    "admin_interface", "legacy_system", "cloud_misconfiguration",
    "email_harvesting", "social_engineering_surface", "supply_chain_risk"
]


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"find_{uuid.uuid4().hex[:12]}")
    session_id: str

    title: str
    description: str
    category: FindingCategory
    risk_level: RiskLevel

    # Impact framework (từ Word: Category → Items Drop → Impact)
    impact_category: str = ""
    impact_items: list = []
    impact_note: str = ""

    # Priority scoring
    priority_score: float = Field(0.0, ge=0.0, le=10.0)
    exposure_score: float = Field(0.0, ge=0.0, le=1.0)
    business_impact_score: float = Field(0.0, ge=0.0, le=1.0)
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    graph_centrality_score: float = Field(0.0, ge=0.0, le=1.0)

    # Traceable provenance (BẮT BUỘC)
    entity_ids: list = []
    observation_ids: list = []
    evidence_refs: list = []

    # Remediation
    recommendation: str = ""
    next_action: str = ""

    created_at: datetime = Field(default_factory=datetime.utcnow)

    def calculate_priority(self) -> float:
        """
        Formula: priority = exposure * impact * confidence * centrality_multiplier * 10
        centrality_multiplier: 1.0 (isolated) .. 2.0 (most connected)
        """
        cent_mult = 1.0 + self.graph_centrality_score
        return min(
            self.exposure_score * self.business_impact_score *
            self.confidence_score * cent_mult * 10,
            10.0
        )
