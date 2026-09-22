"""Pydantic schemas for the Scheduled Jobs module."""
from typing import Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class ScheduledJobCreate(BaseModel):
    job_name: str = Field(..., min_length=1, max_length=200)
    job_type: str = Field(..., pattern="^(discovery|audit)$")
    recurrence: str = Field("daily", pattern="^(once|hourly|daily|weekly)$")
    hour: Optional[int] = Field(None, ge=0, le=23)
    minute: int = Field(0, ge=0, le=59)
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="0=Monday .. 6=Sunday, weekly only")
    enabled: bool = True

    # Discovery jobs
    target: Optional[str] = None
    scan_type: Optional[str] = "well_known_ports"
    ports: Optional[str] = None
    protocol: Optional[str] = "TCP"
    version_detection: Optional[bool] = False

    # Audit jobs
    technology: Optional[str] = None
    asset_id: Optional[int] = None
    audit_params: Optional[dict[str, Any]] = None


class ScheduledJobUpdate(BaseModel):
    """Partial update. Only recurrence/enabled/audit credentials are meant
    to change after creation - job_type/technology/asset_id are not,
    since that would silently repoint an existing job's history."""
    job_name: Optional[str] = Field(None, min_length=1, max_length=200)
    recurrence: Optional[str] = Field(None, pattern="^(once|hourly|daily|weekly)$")
    hour: Optional[int] = Field(None, ge=0, le=23)
    minute: Optional[int] = Field(None, ge=0, le=59)
    day_of_week: Optional[int] = Field(None, ge=0, le=6)
    enabled: Optional[bool] = None

    target: Optional[str] = None
    scan_type: Optional[str] = None
    ports: Optional[str] = None
    protocol: Optional[str] = None
    version_detection: Optional[bool] = None

    audit_params: Optional[dict[str, Any]] = None


class ScheduledJobSummary(BaseModel):
    id: int
    job_name: str
    job_type: str
    technology: Optional[str]
    asset_id: Optional[int]
    asset_name: Optional[str] = None
    recurrence: str
    hour: Optional[int]
    minute: int
    day_of_week: Optional[int]
    enabled: bool
    next_run_at: datetime
    last_run_at: Optional[datetime]
    last_run_status: Optional[str]
    last_run_message: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScheduledJobRunSummary(BaseModel):
    id: int
    job_id: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    status: str
    message: Optional[str]
    result_ref: Optional[str]

    class Config:
        from_attributes = True
