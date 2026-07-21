"""
The Harden All wire contract.

One shape for every device family. The frontend renders entirely from these
models — it never branches on device type.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================
# Plan (GET /session/{id}/plan)
# ============================================================

class CredentialField(BaseModel):
    """One input in the credentials step, described by the backend.

    The UI renders the credentials form from this list, so adding a family (or a
    field to one) never requires a frontend change.
    """
    name: str
    label: str
    type: str = Field("text", description="text | password | number | select")
    required: bool = False
    default: Optional[str] = None
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None
    help: Optional[str] = None


class PlanParameter(BaseModel):
    """A remediation parameter aggregated across every check that uses it."""
    name: str
    label: Optional[str] = None
    description: Optional[str] = None
    type: str = "text"
    required: bool = False
    default: Optional[str] = None
    placeholder: Optional[str] = None
    options: Optional[List[str]] = None
    min_value: Optional[Any] = None
    max_value: Optional[Any] = None
    validation: Optional[str] = None
    checks: List[str] = Field(default_factory=list, description="Check numbers that consume this parameter")


class PlanCheck(BaseModel):
    """A single failed check, with everything the UI needs to show it."""
    result_id: int = Field(..., description="AuditResult row id — the unit of execution")
    check_number: str
    check_title: Optional[str] = None
    severity: Optional[str] = None
    level: Optional[str] = None
    vdom: Optional[str] = Field(None, description="FortiGate VDOM this finding belongs to")
    needs_params: bool = False
    parameters: List[str] = Field(default_factory=list, description="Parameter names this check consumes")


class SkippedCheck(BaseModel):
    """A failed check that Harden All cannot remediate."""
    result_id: int
    check_number: str
    check_title: Optional[str] = None
    vdom: Optional[str] = None
    reason: str = "No automated remediation is available for this check"


class PlanCapabilities(BaseModel):
    """Optional execution features this family supports."""
    backup: bool = Field(False, description="Device config can be backed up before changes")
    dry_run: bool = Field(False, description="Commands can be previewed without connecting")


class HardenAllPlan(BaseModel):
    """Everything needed to drive the Harden All wizard for one audit session."""
    session_id: int
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    target_ip: Optional[str] = None

    device_family: str = Field(..., description="cisco | fortinet | linux | apache | mongodb | mssql | windows")
    device_label: str
    sub_device_type: Optional[str] = None

    total_failed: int = 0
    fixable: List[PlanCheck] = Field(default_factory=list)
    skipped: List[SkippedCheck] = Field(default_factory=list)
    parameters: List[PlanParameter] = Field(default_factory=list)

    credential_fields: List[CredentialField] = Field(default_factory=list)
    capabilities: PlanCapabilities = Field(default_factory=PlanCapabilities)


# ============================================================
# Execute (POST /execute)
# ============================================================

class HardenAllRequest(BaseModel):
    session_id: int
    credentials: Dict[str, str] = Field(
        default_factory=dict,
        description="Values keyed by the plan's credential_fields[].name",
    )
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Values keyed by the plan's parameters[].name",
    )
    result_ids: Optional[List[int]] = Field(
        None,
        description="Subset of plan.fixable[].result_id to remediate. Omit for all of them.",
    )
    create_backup: bool = Field(False, description="Back up the device config first (families with capabilities.backup)")
    dry_run: bool = Field(False, description="Preview commands only (families with capabilities.dry_run)")


class CheckOutcome(BaseModel):
    result_id: Optional[int] = None
    check_number: str
    check_title: Optional[str] = None
    vdom: Optional[str] = None
    status: str = Field(..., description="success | failed | skipped")
    detail: Optional[str] = Field(None, description="Verification evidence, skip reason, or error message")
    commands: List[str] = Field(default_factory=list, description="Populated on dry runs")


class HardenAllResult(BaseModel):
    session_id: int
    device_family: str
    dry_run: bool = False
    total: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[CheckOutcome] = Field(default_factory=list)
    executed_at: Optional[str] = None
