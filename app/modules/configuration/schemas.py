"""Pydantic schemas for the Configuration module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ConfigurationObjectSummary(BaseModel):
    """The generated configuration of one component and the asset it targets."""
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
    """A configuration job."""
    id: int
    design_version_id: Optional[int]
    name: str
    status: str
    created_at: Optional[datetime]
    object_count: int = 0

    class Config:
        from_attributes = True


class ConfigurationJobDetail(BaseModel):
    """A configuration job with its objects."""
    job: ConfigurationJobSummary
    objects: list[ConfigurationObjectSummary]


class GenerateJobRequest(BaseModel):
    """Body of generating configurations from a design version."""
    design_version_id: int
    name: str


class ApplyObjectRequest(BaseModel):
    """SSH credentials for applying a configuration; used once and not stored."""
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    ssh_port: int = 22
