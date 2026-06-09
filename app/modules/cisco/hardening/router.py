"""
Hardening API Router

RESTful endpoints for Cisco device hardening operations.

Endpoints:
- POST /api/hardening/preview - Preview hardening commands
- POST /api/hardening/execute - Execute hardening commands
- GET /api/hardening/actions - List hardening history
- GET /api/hardening/actions/{id} - Get specific action
- DELETE /api/hardening/actions/{id} - Delete action record
"""

from fastapi import APIRouter, Depends, HTTPException, status , Request
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
    require_quota,
    check_quota_available,
    consume_quota_on_success,
    ) 
from app.core.ssh_exceptions import (
    SSHConnectionError,
    SSHAuthenticationError,
    SSHConnectionTimeoutError,
    SSHNetworkError,
    SSHAlgorithmMismatchError,
    SSHHostKeyError
)
from app.models import User
from app.models import User, Asset, AuditResult, AuditSession, log_hardening_preview, log_hardening_execute, log_batch_hardening, log_auto_hardening
from .service import HardeningService, CheckAlreadyPassingError, MissingParametersError


def _log_preview_outcome(
    db: Session,
    *,
    audit_result_id: int,
    user_id: int,
    status_value: str,
    check_number: str = "",
    check_title: str = "",
    error: Optional[str] = None,
) -> None:
    """Best-effort hardening-preview audit log. Never raises."""
    try:
        audit_result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        asset = None
        session_id = None
        if audit_result:
            if audit_result.audit_session is not None:
                session_id = audit_result.audit_session.id
                asset = db.query(Asset).filter(Asset.id == audit_result.audit_session.asset_id).first()
            check_number = check_number or audit_result.check_number or ""
            check_title = check_title or audit_result.check_title or ""
        log_hardening_preview(
            db=db,
            user_id=user_id,
            asset_id=asset.id if asset else None,
            asset_name=asset.asset_name if asset else None,
            audit_session_id=session_id,
            device_type="cisco",
            check_number=check_number,
            check_title=check_title,
            status=status_value,
            error=error,
        )
    except Exception:
        pass


def _log_execute_outcome(
    db: Session,
    *,
    action_id: int,
    user_id: int,
    status_value: str,
    verification_passed: Optional[bool] = None,
    error: Optional[str] = None,
) -> None:
    """Best-effort hardening-execute audit log. Never raises."""
    try:
        from app.models import HardeningAction
        action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
        if not action:
            return
        asset = db.query(Asset).filter(Asset.id == action.asset_id).first() if action.asset_id else None
        log_hardening_execute(
            db=db,
            user_id=user_id,
            asset_id=action.asset_id,
            asset_name=asset.asset_name if asset else None,
            audit_session_id=action.audit_session_id,
            device_type="cisco",
            check_number=action.check_number or "",
            check_title=action.check_title or "",
            verification_passed=verification_passed,
            status=status_value,
            error=error,
        )
    except Exception:
        pass


# ========================= SCHEMAS =========================

# --- Existing hardening schemas ---

class HardeningPreviewRequest(BaseModel):
    """Request to preview hardening commands."""
    audit_result_id: int = Field(..., description="ID of failed audit result to fix")
    parameters: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional parameters for command generation"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "audit_result_id": 1523,
                "parameters": {
                    "TIMEOUT_MIN": "10"
                }
            }
        }


class HardeningPreviewResponse(BaseModel):
    """Preview of commands that will be executed."""
    action_id: int
    check_number: str
    check_title: str
    commands: List[str]
    requires_config_mode: bool
    required_parameters: List[str]
    optional_parameters: List[str]
    parameter_defaults: Dict[str, str] = {}
    warnings: List[str]

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": 4567,
                "check_number": "IOS-L1-001",
                "check_title": "Use 'enable secret' only",
                "commands": [
                    "configure terminal",
                    "no enable password",
                    "enable secret <STRONG_SECRET>",
                    "end",
                    "write memory"
                ],
                "requires_config_mode": True,
                "required_parameters": ["STRONG_SECRET"],
                "optional_parameters": [],
                "parameter_defaults": {},
                "warnings": ["This will remove the existing enable password"]
            }
        }


class HardeningExecuteRequest(BaseModel):
    """Request to execute hardening commands."""
    action_id: int = Field(..., description="ID from preview response")
    ssh_username: str = Field(..., min_length=1, description="Fresh SSH credentials")
    ssh_password: str = Field(..., min_length=1, description="Fresh SSH password")
    ssh_secret: Optional[str] = Field(None, description="Enable secret")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Required parameters (e.g., passwords, IPs)"
    )
    skip_backup: bool = Field(
        default=False,
        description="Skip config backup (NOT RECOMMENDED)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": 4567,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_secret": "********",
                "ssh_port": 22,
                "parameters": {
                    "STRONG_SECRET": "MyNewSecret123!"
                },
                "skip_backup": False
            }
        }


class HardeningExecuteResponse(BaseModel):
    """Result of hardening execution."""
    action_id: int
    status: str  # "success", "failed"
    verification_passed: bool
    verification_evidence: str
    backup_created: bool
    commands_executed: List[str]
    error_message: Optional[str]

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": 4567,
                "status": "success",
                "verification_passed": True,
                "verification_evidence": "enable secret <REDACTED>",
                "backup_created": True,
                "commands_executed": [
                    "configure terminal",
                    "no enable password",
                    "enable secret <REDACTED>",
                    "end",
                    "write memory"
                ],
                "error_message": None
            }
        }


class HardeningActionResponse(BaseModel):
    """Hardening action record."""
    id: int
    audit_result_id: int
    asset_id: int
    check_number: str
    check_title: str
    action_type: str
    status: str
    requires_config_mode: bool
    verification_passed: Optional[bool]
    created_at: str
    executed_at: Optional[str]
    completed_at: Optional[str]

    class Config:
        from_attributes = True


# --- Auto-hardening schemas ---

class AutoAuditRequest(BaseModel):
    """Request to auto-audit a device."""
    ip_address: str = Field(..., description="Device IP address")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_secret: Optional[str] = None
    profile: str = Field(default="FULL", pattern="^(L1|FULL)$")
    asset_id: Optional[int] = Field(None, description="Optional: link to existing asset")

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "192.168.1.1",
                "ssh_username": "admin",
                "ssh_password": "cisco123",
                "ssh_secret": "cisco123",
                "profile": "FULL"
            }
        }


class AutoAuditResponse(BaseModel):
    """Response from auto-audit."""
    audit_session_id: int
    device_ip: str
    total_checks: int
    passed: int
    failed: int
    compliance_pct: float
    fixable_failures: List[Dict[str, Any]]
    unfixable_failures: List[Dict[str, Any]]

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "device_ip": "192.168.1.1",
                "total_checks": 50,
                "passed": 42,
                "failed": 8,
                "compliance_pct": 84.0,
                "fixable_failures": [
                    {
                        "result_id": 1001,
                        "check_number": "IOS-L1-007",
                        "check_title": "SSH version 2 enabled",
                        "severity": "medium"
                    }
                ],
                "unfixable_failures": [
                    {
                        "result_id": 1002,
                        "check_number": "IOS-L1-001",
                        "check_title": "Use 'enable secret' only",
                        "severity": "high",
                        "missing_params": ["STRONG_SECRET"]
                    }
                ]
            }
        }


class AutoFixRequest(BaseModel):
    """Request to auto-fix all failures."""
    audit_session_id: int
    ssh_username: str
    ssh_password: str
    ssh_secret: Optional[str] = None
    parameters: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Optional parameters for checks that need them"
    )
    skip_backup: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "ssh_username": "admin",
                "ssh_password": "cisco123",
                "ssh_secret": "cisco123",
                "parameters": {
                    "STRONG_SECRET": "MyNewSecret123!"
                },
                "skip_backup": False
            }
        }


class AutoFixResponse(BaseModel):
    """Response from auto-fix."""
    audit_session_id: int
    total_failures: int
    fixed_count: int
    skipped_count: int
    failed_count: int
    actions: List[int]
    final_compliance_pct: float

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "total_failures": 8,
                "fixed_count": 6,
                "skipped_count": 1,
                "failed_count": 1,
                "actions": [4567, 4568, 4569, 4570, 4571, 4572],
                "final_compliance_pct": 96.0
            }
        }


# --- Three-Mode Hardening Schemas ---

class SessionParametersResponse(BaseModel):
    """Response with aggregated parameters for a session."""
    session_id: int
    total_failed: int
    selected_count: int
    fixable_count: int
    unfixable_count: int
    required_parameters: Dict[str, Any]
    auto_fixable_checks: List[Dict[str, Any]]
    needs_params_checks: List[Dict[str, Any]]
    no_template_checks: Optional[List[Dict[str, Any]]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 123,
                "total_failed": 8,
                "selected_count": 8,
                "fixable_count": 6,
                "unfixable_count": 2,
                "required_parameters": {
                    "STRONG_SECRET": {
                        "type": "password",
                        "label": "Enable Secret",
                        "description": "New enable secret password",
                        "required": True,
                        "checks": ["IOS-L1-001"]
                    }
                },
                "auto_fixable_checks": [
                    {"check_number": "IOS-L1-002", "result_id": 101}
                ],
                "needs_params_checks": [
                    {"check_number": "IOS-L1-001", "result_id": 102}
                ]
            }
        }


class AutoHardenPreviewResponse(BaseModel):
    """Preview of automatic hardening with defaults."""
    session_id: int
    auto_fixable_count: int
    skipped_count: int
    checks_with_defaults: List[Dict[str, Any]]
    skipped_checks: List[Dict[str, Any]]

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 123,
                "auto_fixable_count": 5,
                "skipped_count": 3,
                "checks_with_defaults": [
                    {
                        "check_number": "IOS-L1-002",
                        "check_title": "Set exec timeout",
                        "result_id": 101,
                        "defaults": {"TIMEOUT_MIN": "5", "TIMEOUT_SEC": "0"}
                    }
                ],
                "skipped_checks": [
                    {
                        "check_number": "IOS-L1-001",
                        "check_title": "Use enable secret",
                        "result_id": 102,
                        "reason": "Requires STRONG_SECRET parameter"
                    }
                ]
            }
        }


class AutoHardenDefaultsRequest(BaseModel):
    """Request to auto-harden with CIS defaults only."""
    audit_session_id: int
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_secret: Optional[str] = None
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    confirmed: bool = Field(
        default=False,
        description="User must confirm they reviewed the defaults"
    )
    skip_backup: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "ssh_username": "admin",
                "ssh_password": "cisco123",
                "ssh_port": 22,
                "confirmed": True,
                "skip_backup": False
            }
        }


class AutoHardenDefaultsResponse(BaseModel):
    """Response from auto-harden with defaults."""
    audit_session_id: int
    fixed_count: int
    skipped_count: int
    failed_count: int
    actions: List[int]
    fixed_checks: List[Dict[str, Any]]
    skipped_checks: List[Dict[str, Any]]

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "fixed_count": 5,
                "skipped_count": 3,
                "failed_count": 0,
                "actions": [101, 102, 103, 104, 105],
                "fixed_checks": [
                    {
                        "check_number": "IOS-L1-002",
                        "action_id": 101,
                        "defaults_applied": {"TIMEOUT_MIN": "5"}
                    }
                ],
                "skipped_checks": [
                    {
                        "check_number": "IOS-L1-001",
                        "reason": "Requires user input"
                    }
                ]
            }
        }


class BatchExecuteRequest(BaseModel):
    """Request to batch execute selected checks."""
    audit_session_id: int
    check_ids: List[int] = Field(
        ...,
        description="List of AuditResult IDs to fix"
    )
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="User-provided parameters for all checks"
    )
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_secret: Optional[str] = None
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    skip_backup: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "check_ids": [101, 102, 103],
                "parameters": {
                    "STRONG_SECRET": "MyNewSecret123!",
                    "BANNER_TEXT": "Authorized access only"
                },
                "ssh_username": "admin",
                "ssh_password": "cisco123",
                "ssh_port": 22,
                "skip_backup": False
            }
        }


class BatchExecuteResponse(BaseModel):
    """Response from batch execute."""
    audit_session_id: int
    total_selected: int
    fixed_count: int
    failed_count: int
    skipped_count: int
    actions: List[int]
    results: List[Dict[str, Any]]

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "total_selected": 5,
                "fixed_count": 4,
                "failed_count": 1,
                "skipped_count": 0,
                "actions": [201, 202, 203, 204],
                "results": [
                    {
                        "check_number": "IOS-L1-001",
                        "status": "success",
                        "action_id": 201
                    }
                ]
            }
        }



router = APIRouter(prefix="/api/hardening/cisco", tags=["Hardening - Cisco"])


@router.post("/preview", response_model=HardeningPreviewResponse)
async def preview_hardening(
    http_request: Request,
    request: HardeningPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))
):
    """
    Preview hardening commands for a failed check.

    **Workflow:**
    1. Validates that the check is currently failing
    2. Retrieves the CIS rule and remediation
    3. Parses remediation into executable commands
    4. Identifies required parameters
    5. Returns command preview with warnings

    **Permissions:** Requires HARDENING write permission

    **Response:** Command list with required parameters and warnings

    **Errors:**
    - 400: Check is already passing or invalid
    - 404: Audit result not found
    - 500: Internal error
    """
    consume_quota = consume_quota_on_success("harden")
    try:
        preview = HardeningService.preview_hardening(
            db=db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            parameters=request.parameters
        )

        _log_preview_outcome(
            db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            status_value="success",
            check_number=preview.get("check_number", ""),
            check_title=preview.get("check_title", ""),
        )
        consume_quota(http_request)
        return preview

    except CheckAlreadyPassingError as e:
        _log_preview_outcome(
            db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            status_value="failed",
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ValueError as e:
        _log_preview_outcome(
            db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            status_value="failed",
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        _log_preview_outcome(
            db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            status_value="failed",
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Preview failed: {str(e)}"
        )


@router.post("/execute", response_model=HardeningExecuteResponse)
def execute_hardening(
    request: HardeningExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("harden"))
):
    """
    Execute hardening commands on device.

    **Workflow:**
    1. Validates action exists and is in pending status
    2. Establishes SSH connection to device
    3. Backs up running configuration
    4. Executes hardening commands
    5. Saves configuration
    6. Verifies fix by re-running the check
    7. Returns execution results

    **Permissions:** Requires HARDENING write permission

    **Note:**
    - SSH credentials are used only for this session and never stored
    - A backup of the configuration is created before any changes
    - Post-execution verification confirms the fix worked

    **Errors:**
    - 400: Invalid action, check already passing, or missing parameters
    - 401: SSH authentication failed
    - 404: Action not found
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    try:
        result = HardeningService.execute_hardening(
            db=db,
            action_id=request.action_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            parameters=request.parameters,
            skip_backup=request.skip_backup,
            ssh_port=request.ssh_port,
        )

        verification_passed = result.get("verification_passed")
        succeeded = (
            result.get("status") == "success"
            and (verification_passed is None or verification_passed is True)
        )
        _log_execute_outcome(
            db,
            action_id=request.action_id,
            user_id=current_user.id,
            status_value="success" if succeeded else "failed",
            verification_passed=verification_passed,
            error=result.get("error_message"),
        )

        return result

    except CheckAlreadyPassingError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except MissingParametersError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SSHAuthenticationError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH authentication failed: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict()
        )
    except SSHConnectionTimeoutError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH connection timeout: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.to_dict()
        )
    except SSHNetworkError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH network error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.to_dict()
        )
    except SSHAlgorithmMismatchError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH algorithm mismatch: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHHostKeyError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH host key error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHConnectionError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=f"SSH connection error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except ValueError as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        _log_execute_outcome(
            db, action_id=request.action_id, user_id=current_user.id,
            status_value="failed", error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Execution failed: {str(e)}"
        )


@router.get("/actions", response_model=List[HardeningActionResponse])
def list_hardening_actions(
    asset_id: Optional[int] = None,
    user_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    List hardening action history with filters.

    Returns most recent hardening actions (both preview and execute).

    **Query Parameters:**
    - asset_id: Filter by asset ID
    - user_id: Filter by user ID
    - status_filter: Filter by status (pending, success, failed, blocked)
    - limit: Maximum number of actions to return (default: 50, max: 100)
    - offset: Number of actions to skip (default: 0)

    **Permissions:** Requires HARDENING read permission
    """
    # Cap limit at 100
    limit = min(limit, 100)

    actions = HardeningService.get_action_history(
        db=db,
        asset_id=asset_id,
        user_id=user_id,
        status=status_filter,
        limit=limit,
        offset=offset
    )

    return [
        {
            "id": a.id,
            "audit_result_id": a.audit_result_id,
            "asset_id": a.asset_id,
            "check_number": a.check_number,
            "check_title": a.check_title,
            "action_type": a.action_type,
            "status": a.status,
            "requires_config_mode": a.requires_config_mode or False,
            "verification_passed": a.verification_passed,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "executed_at": a.executed_at.isoformat() if a.executed_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None
        }
        for a in actions
    ]


@router.get("/actions/{action_id}")
def get_hardening_action(
    action_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific hardening action.

    Includes:
    - Action metadata
    - Commands executed
    - Execution output (with secrets redacted)
    - Backup configuration (if created)
    - Verification results

    **Permissions:** Requires HARDENING read permission
    """
    action = HardeningService.get_action_by_id(db, action_id)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hardening action {action_id} not found"
        )

    import json

    return {
        "id": action.id,
        "audit_result_id": action.audit_result_id,
        "asset_id": action.asset_id,
        "audit_session_id": action.audit_session_id,
        "check_number": action.check_number,
        "check_title": action.check_title,
        "action_type": action.action_type,
        "status": action.status,
        "commands": json.loads(action.commands_json) if action.commands_json else [],
        "requires_config_mode": action.requires_config_mode,
        "output": action.output,
        "backup_config": action.backup_config,
        "verification_passed": action.verification_passed,
        "verification_evidence": action.verification_evidence,
        "error_message": action.error_message,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "completed_at": action.completed_at.isoformat() if action.completed_at else None
    }


@router.delete("/actions/{action_id}")
def delete_hardening_action(
    action_id: int,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Delete a hardening action record.

    **Permissions:** Requires HARDENING write permission

    **Note:** This only deletes the hardening action record.
    It does NOT revert any changes made to the device.
    """
    try:
        HardeningService.delete_action(db, action_id)
        return {"message": f"Hardening action {action_id} deleted successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete action: {str(e)}"
        )


# ==================== AUTO-HARDENING ENDPOINTS ====================

@router.post("/auto-audit", response_model=AutoAuditResponse)
def auto_audit_device(
    request: AutoAuditRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Auto-audit a device without requiring pre-existing asset or audit.

    **Workflow:**
    1. Connects to device via SSH
    2. Runs full CIS audit
    3. Stores audit session and results
    4. Identifies which failures can be auto-fixed
    5. Returns summary with fixable vs unfixable checks

    **Use Case:** Quick audit + fix for devices not in asset inventory

    **Permissions:** Requires HARDENING write permission

    **Response:** Audit summary with fixable failures list

    **Errors:**
    - 400: Invalid request parameters
    - 401: SSH authentication failed
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    try:
        result = HardeningService.auto_audit_device(
            db=db,
            user_id=current_user.id,
            ip_address=request.ip_address,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            profile=request.profile,
            asset_id=request.asset_id
        )

        return result

    except SSHAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict()
        )
    except SSHConnectionTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.to_dict()
        )
    except SSHNetworkError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.to_dict()
        )
    except SSHAlgorithmMismatchError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHHostKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-audit failed: {str(e)}"
        )


@router.post("/auto-fix", response_model=AutoFixResponse)
def auto_fix_all_failures(
    request: AutoFixRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Automatically fix all failures from an auto-audit session.

    **Workflow:**
    1. Retrieves all failed checks from audit session
    2. For each failure:
       - Checks if template exists
       - Checks if parameters needed
       - Applies fix if possible
       - Skips if parameters required (unless provided)
    3. Verifies each fix by re-running the check
    4. Returns summary of what was fixed

    **Strategy:** Only fixes checks that don't require user input

    **Permissions:** Requires HARDENING write permission

    **Note:**
    - Creates backup before applying fixes (unless skip_backup=True)
    - All fixes are logged in hardening_actions table
    - Each fix is verified after execution

    **Response:** Summary of fixes applied with verification results

    **Errors:**
    - 400: Invalid audit session or missing parameters
    - 401: SSH authentication failed
    - 404: Audit session not found
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    try:
        result = HardeningService.auto_fix_all_failures(
            db=db,
            audit_session_id=request.audit_session_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            parameters=request.parameters,
            skip_backup=request.skip_backup
        )

        return result

    except SSHAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict()
        )
    except SSHConnectionTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.to_dict()
        )
    except SSHNetworkError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.to_dict()
        )
    except SSHAlgorithmMismatchError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHHostKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-fix failed: {str(e)}"
        )


# ==================== THREE-MODE HARDENING ENDPOINTS ====================

@router.get("/session/{session_id}/parameters", response_model=SessionParametersResponse)
def get_session_parameters(
    session_id: int,
    check_ids: Optional[str] = None,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get aggregated parameters needed for hardening a session.

    **Use Case:** "Fix All" mode - collect all required parameters
    before batch execution.

    **Query Parameters:**
    - check_ids: Optional comma-separated list of AuditResult IDs
                 (if not provided, includes all failed checks)

    **Response:**
    - required_parameters: All unique parameters with UI metadata
    - auto_fixable_checks: Checks that can be fixed without user input
    - needs_params_checks: Checks requiring user-provided parameters

    **Permissions:** Requires HARDENING read permission
    """
    try:
        # Parse check_ids if provided
        parsed_check_ids = None
        if check_ids:
            try:
                parsed_check_ids = [int(id.strip()) for id in check_ids.split(",")]
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="check_ids must be comma-separated integers"
                )

        result = HardeningService.get_session_parameters(
            db=db,
            audit_session_id=session_id,
            check_ids=parsed_check_ids
        )

        return result

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session parameters: {str(e)}"
        )


@router.get("/session/{session_id}/auto-preview", response_model=AutoHardenPreviewResponse)
def get_auto_harden_preview(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Preview automatic hardening with CIS defaults.

    **Use Case:** "Automatic Hardening" mode - show user what will be
    applied before execution.

    **Response:**
    - checks_with_defaults: Checks that will be fixed with their default values
    - skipped_checks: Checks that require user input (will be skipped)

    **Important:** User should review this before confirming auto-harden.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        result = HardeningService.get_auto_harden_preview(
            db=db,
            audit_session_id=session_id
        )

        return result

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get auto-harden preview: {str(e)}"
        )


@router.post("/auto-harden-defaults", response_model=AutoHardenDefaultsResponse)
def auto_harden_with_defaults(
    request: AutoHardenDefaultsRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Automatically harden device using CIS default values only.

    **Use Case:** "Automatic Hardening" mode - apply all checks that
    have default values without requiring user input.

    **Workflow:**
    1. User previews via GET /session/{id}/auto-preview
    2. User reviews default values that will be applied
    3. User confirms and calls this endpoint
    4. System applies only auto-fixable checks
    5. Checks requiring parameters are skipped

    **Important:**
    - confirmed must be true to proceed
    - Only applies checks where ALL parameters have defaults
    - Skips ALL checks requiring user input

    **Permissions:** Requires HARDENING write permission

    **Errors:**
    - 400: confirmed=false or invalid session
    - 401: SSH authentication failed
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    if not request.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must confirm by setting confirmed=true after reviewing defaults"
        )

    try:
        result = HardeningService.auto_harden_with_defaults(
            db=db,
            audit_session_id=request.audit_session_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            skip_backup=request.skip_backup,
            ssh_port=request.ssh_port,
        )

        # Log auto-harden operation
        try:
            session = db.query(AuditSession).filter(AuditSession.id == request.audit_session_id).first()
            if session:
                asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
                log_auto_hardening(
                    db=db,
                    user_id=current_user.id,
                    asset_id=session.asset_id,
                    asset_name=asset.asset_name if asset else None,
                    audit_session_id=request.audit_session_id,
                    device_type="cisco",
                    check_ids=result.get("check_ids", []),
                    success_count=result.get("success_count", 0),
                    failed_count=result.get("failed_count", 0),
                    details={"auto_defaults": True}
                )
        except Exception as log_err:
            pass

        return result

    except SSHAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict()
        )
    except SSHConnectionTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.to_dict()
        )
    except SSHNetworkError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.to_dict()
        )
    except SSHAlgorithmMismatchError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHHostKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-harden failed: {str(e)}"
        )


@router.post("/batch-execute", response_model=BatchExecuteResponse)
def batch_execute_selected(
    request: BatchExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute hardening for selected checks with user-provided parameters.

    **Use Case:** "Fix All" mode - user selects specific checks and
    provides all required parameters before execution.

    **Workflow:**
    1. User fetches parameters via GET /session/{id}/parameters
    2. User fills in required parameters
    3. User selects which checks to fix
    4. User calls this endpoint with check_ids and parameters
    5. System executes selected checks

    **Request:**
    - check_ids: List of AuditResult IDs to fix
    - parameters: All required parameter values

    **Permissions:** Requires HARDENING write permission

    **Errors:**
    - 400: Invalid check IDs or missing parameters
    - 401: SSH authentication failed
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    if not request.check_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No checks selected for execution"
        )

    try:
        result = HardeningService.batch_execute_selected(
            db=db,
            audit_session_id=request.audit_session_id,
            user_id=current_user.id,
            check_ids=request.check_ids,
            parameters=request.parameters,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            skip_backup=request.skip_backup,
            ssh_port=request.ssh_port,
        )

        # Log batch execute operation
        try:
            session = db.query(AuditSession).filter(AuditSession.id == request.audit_session_id).first()
            if session:
                asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
                log_batch_hardening(
                    db=db,
                    user_id=current_user.id,
                    asset_id=session.asset_id,
                    asset_name=asset.asset_name if asset else None,
                    audit_session_id=request.audit_session_id,
                    device_type="cisco",
                    check_ids=[str(cid) for cid in request.check_ids],
                    success_count=result.get("success_count", 0),
                    failed_count=result.get("failed_count", 0),
                    details={"total_checks": len(request.check_ids)}
                )
        except Exception as log_err:
            pass

        return result

    except SSHAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict()
        )
    except SSHConnectionTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.to_dict()
        )
    except SSHNetworkError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.to_dict()
        )
    except SSHAlgorithmMismatchError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHHostKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except SSHConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=e.to_dict()
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except MissingParametersError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execute failed: {str(e)}"
        )
