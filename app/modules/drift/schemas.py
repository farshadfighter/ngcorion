"""Pydantic schemas for the Configuration Drift module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class DriftRunSummary(BaseModel):
    """One drift analysis and how much drift it found."""
    id: int
    asset_id: int
    status: str
    assets_checked: int
    drift_found_count: int
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class DriftResultSummary(BaseModel):
    """A drift finding without its diff."""
    id: int
    run_id: int
    asset_id: int
    asset_name: Optional[str]
    technology: Optional[str]
    baseline_backup_id: Optional[int]
    lines_changed: int
    severity: str
    status: str
    ignored_reason: Optional[str]
    created_at: Optional[datetime]
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class DriftResultDetail(DriftResultSummary):
    """A drift finding with its diff."""
    diff: str


class AnalyzeAssetRequest(BaseModel):
    """Body of a drift analysis; the SSH credentials are used once and not stored."""
    asset_id: int
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22


class ResolveResultRequest(BaseModel):
    """Body of ignoring a drift: an optional reason."""
    reason: Optional[str] = None
