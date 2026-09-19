"""Pydantic schemas for the Configuration Drift module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class DriftRunSummary(BaseModel):
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
    diff: str


class AnalyzeAssetRequest(BaseModel):
    asset_id: int
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22


class ResolveResultRequest(BaseModel):
    reason: Optional[str] = None
