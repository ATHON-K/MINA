"""
ImpactInsight — Per-entity impact/priority scoring result.
"""
import uuid
from typing import List, Optional

from pydantic import BaseModel, Field


class ImpactInsight(BaseModel):
    """Structured impact result for a single entity."""
    impact_id: str = Field(default_factory=lambda: f"impact_{uuid.uuid4().hex[:12]}")
    entity_id: str = ""
    summary: str = ""
    impact_category: str = ""
    priority_score: float = 0.0
    impact_score: float = 0.0
    exposure_score: float = 0.0
    confidence_score: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    suggested_action: str = ""
