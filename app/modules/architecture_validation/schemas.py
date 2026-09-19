"""Pydantic schemas for the Architecture Validation module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ArchitectureFindingSummary(BaseModel):
    id: int
    rule_code: str
    title: str
    severity: str
    category: Optional[str]
    recommendation: Optional[str]
    asset_id: Optional[int]
    asset_name: Optional[str]
    status: str
    ignored_reason: Optional[str]
    created_at: Optional[datetime]
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class AnalyzeResult(BaseModel):
    findings: list[ArchitectureFindingSummary]
    asset_count: int
    finding_count: int


class ResolveFindingRequest(BaseModel):
    reason: Optional[str] = None
