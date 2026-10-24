"""Pydantic schemas for the Architecture Validation module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ArchitectureFindingSummary(BaseModel):
    """A finding of the architecture rules."""
    id: int
    rule_code: str
    title: str
    severity: str
    category: Optional[str]
    recommendation: Optional[str]
    evidence: Optional[str] = None
    asset_id: Optional[int]
    asset_name: Optional[str]
    status: str
    ignored_reason: Optional[str]
    created_at: Optional[datetime]
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class AnalyzeResult(BaseModel):
    """Result of an architecture analysis."""
    findings: list[ArchitectureFindingSummary]
    asset_count: int
    finding_count: int


class ResolveFindingRequest(BaseModel):
    """Body of ignoring a finding: an optional reason."""
    reason: Optional[str] = None


class RuleInfo(BaseModel):
    """One check of the rule set (rules/safe.yaml), for the page's list of what is checked."""
    code: str
    title: str
    severity: str
    category: Optional[str] = None
    place: Optional[str] = None
    evidence_label: Optional[str] = None
    recommendation: Optional[str] = None
