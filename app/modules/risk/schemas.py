"""
Pydantic schemas for the Risk module API.
"""
from typing import Optional

from pydantic import BaseModel, Field

CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
PORT_SEVERITIES = ("low", "medium", "high", "critical")


class ProfileUpdateRequest(BaseModel):
    criticality_level: Optional[str] = Field(
        None, description="One of: low, medium, high, critical"
    )
    zone_id: Optional[int] = Field(None, description="risk_zones.id, null to clear")
    reason: Optional[str] = Field(None, max_length=500)


class ZoneCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    score: float = Field(..., ge=0, le=100)


class ZoneUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    score: Optional[float] = Field(None, ge=0, le=100)


class PortUpdateRequest(BaseModel):
    severity: Optional[str] = Field(
        None, description="One of: low, medium, high, critical"
    )
    is_approved: Optional[bool] = None
    is_included_in_risk: Optional[bool] = None
    exclusion_reason: Optional[str] = Field(None, max_length=500)
