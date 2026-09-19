"""Pydantic schemas for the Configuration module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ConfigurationObjectSummary(BaseModel):
    id: int
    configuration_job_id: int
    design_component_id: Optional[int]
    asset_id: Optional[int]
    asset_name: Optional[str]
    device_type: Optional[str]
    generated_config: str
    apply_status: str
    apply_output: Optional[str]
    applied_at: Optional[datetime]

    class Config:
        from_attributes = True


class ConfigurationJobSummary(BaseModel):
    id: int
    design_version_id: Optional[int]
    name: str
    status: str
    created_at: Optional[datetime]
    object_count: int = 0

    class Config:
        from_attributes = True


class ConfigurationJobDetail(BaseModel):
    job: ConfigurationJobSummary
    objects: list[ConfigurationObjectSummary]


class GenerateJobRequest(BaseModel):
    design_version_id: int
    name: str


class ApplyObjectRequest(BaseModel):
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22
