"""Pydantic schemas for the CVE vulnerability module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class CveRecordSummary(BaseModel):
    id: int
    cve_id: str
    vendor: str
    product: str
    product_keyword: str
    affected_version_min: Optional[str]
    affected_version_max: Optional[str]
    fixed_version: Optional[str]
    severity: str
    cvss_score: Optional[float]
    summary: str
    recommendation: Optional[str]
    reference_url: Optional[str]
    published_date: Optional[datetime]
    source: str

    class Config:
        from_attributes = True


class CveFinding(BaseModel):
    """One (asset, CVE) match, computed at read time - never persisted."""

    asset_id: int
    asset_name: Optional[str]
    manufacturer: Optional[str]
    os_name: Optional[str]
    os_version: Optional[str]
    cve: CveRecordSummary


class CveFindingsSummary(BaseModel):
    """Severity counts across the returned findings, for summary cards."""

    total: int
    critical: int
    high: int
    medium: int
    low: int


class CveFindingsResponse(BaseModel):
    summary: CveFindingsSummary
    findings: list[CveFinding]


class CveSyncResponse(BaseModel):
    records_added: int
    records_updated: int
    source: str
    message: Optional[str] = None


class CveSyncRequest(BaseModel):
    product_keyword: Optional[str] = None
