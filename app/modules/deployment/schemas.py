"""Pydantic schemas for the Deployment module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class DeploymentJobSummary(BaseModel):
    id: int
    configuration_object_id: Optional[int]
    asset_id: Optional[int]
    asset_name: Optional[str]
    device_type: Optional[str]
    status: str
    backup_id: Optional[int]
    error_message: Optional[str]
    created_at: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class DeploymentJobDetail(DeploymentJobSummary):
    precheck_output: Optional[str]
    apply_output: Optional[str]
    verify_output: Optional[str]
    rollback_output: Optional[str]


class CreateJobRequest(BaseModel):
    configuration_object_id: int


class DeviceCredentialsRequest(BaseModel):
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22
