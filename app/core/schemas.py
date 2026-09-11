"""
Shared Pydantic Schemas

Common response models used across audit and hardening modules.
This eliminates duplication and ensures consistent API responses.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any




class AuditSessionResponse(BaseModel):
    """Unified audit session response for all device types."""

    session_id: int
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    target_ip: str
    device_type: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    compliance: dict
    connection_error: Optional[str] = None

    class Config:
        from_attributes = True


class AuditResultResponse(BaseModel):
    """Unified audit result response for all device types."""

    id: int
    check_number: str
    check_title: str
    severity: str
    level: str
    status: str
    evidence_snippet: Optional[str] = None
    checked_at: str

    class Config:
        from_attributes = True


class HardeningPreviewResponse(BaseModel):
    """Unified hardening preview response."""

    action_id: int
    check_number: str
    check_title: str
    commands: List[str]
    requires_config_mode: bool
    required_parameters: List[str]
    optional_parameters: List[str]
    warnings: List[str]


class HardeningExecuteResponse(BaseModel):
    """Unified hardening execution response."""

    action_id: int
    status: str  # "success", "failed"
    verification_passed: bool
    verification_evidence: str
    backup_created: bool
    commands_executed: List[str]
    error_message: Optional[str] = None


class HardeningActionResponse(BaseModel):
    """Unified hardening action record."""

    id: int
    audit_result_id: int
    asset_id: int
    check_number: str
    check_title: str
    action_type: str
    status: str
    requires_config_mode: bool
    verification_passed: Optional[bool] = None
    created_at: str
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True




class BatchExecuteResponse(BaseModel):
    """Unified batch execution response."""

    audit_session_id: int
    total_selected: int
    fixed_count: int
    failed_count: int
    skipped_count: int
    actions: List[int]
    results: List[Dict[str, Any]]


class AutoHardenPreviewResponse(BaseModel):
    """Unified auto-harden preview response."""

    session_id: int
    auto_fixable_count: int
    skipped_count: int
    checks_with_defaults: List[Dict[str, Any]]
    skipped_checks: List[Dict[str, Any]]


class AutoHardenDefaultsResponse(BaseModel):
    """Unified auto-harden execution response."""

    audit_session_id: int
    fixed_count: int
    skipped_count: int
    failed_count: int
    actions: List[int]
    fixed_checks: List[Dict[str, Any]]
    skipped_checks: List[Dict[str, Any]]


class SessionParametersResponse(BaseModel):
    """Unified session parameters response."""

    session_id: int
    total_failed: int
    selected_count: int
    fixable_count: int
    unfixable_count: int
    required_parameters: Dict[str, Any]
    auto_fixable_checks: List[Dict[str, Any]]
    needs_params_checks: List[Dict[str, Any]]
    no_template_checks: Optional[List[Dict[str, Any]]] = None
