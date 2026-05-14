"""
FortiGate Hardening API Router

RESTful endpoints for FortiGate device hardening operations.

Endpoints:
- POST /api/hardening/fortinet/preview - Preview hardening commands
- POST /api/hardening/fortinet/execute - Execute hardening commands
- GET /api/hardening/fortinet/session/{id}/parameters - Get aggregated parameters
- GET /api/hardening/fortinet/session/{id}/auto-preview - Preview auto-hardening
- POST /api/hardening/fortinet/auto-harden-defaults - Execute auto-hardening
- POST /api/hardening/fortinet/batch-execute - Batch execute selected checks
- GET /api/hardening/fortinet/actions - List FortiGate hardening history
"""

from fastapi import APIRouter, Depends, HTTPException, status , Request
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
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
from .service import (
    FortiGateHardeningService,
    FortiGateCheckAlreadyPassingError,
    FortiGateMissingParametersError
)

class FortiGatePreviewRequest(BaseModel):
    """Request to preview FortiGate hardening commands."""
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
                    "ADMIN_TIMEOUT": "15"
                }
            }
        }


class FortiGatePreviewResponse(BaseModel):
    """Preview of FortiGate commands that will be executed."""
    action_id: int
    check_number: str
    check_title: str
    commands: List[str]
    vdom_context: str
    required_parameters: List[str]
    optional_parameters: List[str]
    warnings: List[str]

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": 4567,
                "check_number": "FG-BL-001",
                "check_title": "Admin HTTPS enabled",
                "commands": [
                    "config system global",
                    "set admin-https enable",
                    "end"
                ],
                "vdom_context": "global",
                "required_parameters": [],
                "optional_parameters": [],
                "warnings": ["Enables HTTPS access to FortiGate management interface"]
            }
        }


class FortiGateExecuteRequest(BaseModel):
    """Request to execute FortiGate hardening commands."""
    action_id: int = Field(..., description="ID from preview response")
    ssh_username: str = Field(..., min_length=1, description="SSH username")
    ssh_password: str = Field(..., min_length=1, description="SSH password")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Required parameters"
    )
    vdom: Optional[str] = Field(None, description="VDOM context (optional)")
    skip_backup: bool = Field(default=False, description="Skip config backup")

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": 4567,
                "ssh_username": "admin",
                "ssh_password": "********",
                "parameters": {},
                "vdom": None,
                "skip_backup": False
            }
        }


class FortiGateExecuteResponse(BaseModel):
    """Result of FortiGate hardening execution."""
    action_id: int
    status: str
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
                "verification_evidence": "set admin-https enable",
                "backup_created": True,
                "commands_executed": [
                    "config system global",
                    "set admin-https enable",
                    "end"
                ],
                "error_message": None
            }
        }


class FortiGateSessionParametersResponse(BaseModel):
    """Response with aggregated parameters for a FortiGate session."""
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
                    "ADMIN_TIMEOUT": {
                        "type": "number",
                        "label": "Admin Idle Timeout",
                        "description": "Idle timeout in minutes",
                        "required": False,
                        "default": "10",
                        "checks": ["FG-BL-004"]
                    }
                },
                "auto_fixable_checks": [
                    {"check_number": "FG-BL-001", "result_id": 101}
                ],
                "needs_params_checks": [
                    {"check_number": "FG-BL-041", "result_id": 102}
                ]
            }
        }


class FortiGateAutoHardenPreviewResponse(BaseModel):
    """Preview of FortiGate automatic hardening with defaults."""
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
                        "check_number": "FG-BL-004",
                        "check_title": "Admin idle timeout <= 10 minutes",
                        "result_id": 101,
                        "defaults": {"ADMIN_TIMEOUT": "10"}
                    }
                ],
                "skipped_checks": [
                    {
                        "check_number": "FG-BL-041",
                        "check_title": "NTP server configured",
                        "result_id": 102,
                        "reason": "Requires NTP_SERVER parameter"
                    }
                ]
            }
        }


class FortiGateAutoHardenRequest(BaseModel):
    """Request to auto-harden FortiGate with defaults only."""
    audit_session_id: int
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    vdom: Optional[str] = None
    confirmed: bool = Field(default=False, description="User must confirm")
    skip_backup: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "ssh_username": "admin",
                "ssh_password": "********",
                "confirmed": True,
                "skip_backup": False
            }
        }


class FortiGateAutoHardenResponse(BaseModel):
    """Response from FortiGate auto-harden with defaults."""
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
                        "check_number": "FG-BL-001",
                        "action_id": 101,
                        "defaults_applied": {}
                    }
                ],
                "skipped_checks": [
                    {
                        "check_number": "FG-BL-041",
                        "reason": "Requires user input"
                    }
                ]
            }
        }


class FortiGateBatchExecuteRequest(BaseModel):
    """Request to batch execute selected FortiGate checks."""
    audit_session_id: int
    check_ids: List[int] = Field(..., description="List of AuditResult IDs to fix")
    parameters: Dict[str, str] = Field(default_factory=dict, description="User parameters")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    vdom: Optional[str] = None
    skip_backup: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "audit_session_id": 123,
                "check_ids": [101, 102, 103],
                "parameters": {
                    "NTP_SERVER": "192.168.1.10",
                    "SYSLOG_SERVER": "192.168.1.100"
                },
                "ssh_username": "admin",
                "ssh_password": "********",
                "skip_backup": False
            }
        }


class FortiGateBatchExecuteResponse(BaseModel):
    """Response from FortiGate batch execute."""
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
                        "check_number": "FG-BL-001",
                        "status": "success",
                        "action_id": 201
                    }
                ]
            }
        }


class FortiGateActionResponse(BaseModel):
    """FortiGate hardening action record."""
    id: int
    audit_result_id: int
    asset_id: Optional[int]
    check_number: str
    check_title: str
    action_type: str
    status: str
    verification_passed: Optional[bool]
    created_at: str
    executed_at: Optional[str]
    completed_at: Optional[str]

    class Config:
        from_attributes = True


router = APIRouter(prefix="/api/hardening/fortinet", tags=["Hardening - FortiGate"])


@router.post("/preview", response_model=FortiGatePreviewResponse)
def preview_fortinet_hardening(
    request: FortiGatePreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
):
    """
    Preview hardening commands for a failed FortiGate check.

    **Workflow:**
    1. Validates that the check is currently failing
    2. Retrieves the FortiGate control and remediation
    3. Parses remediation into executable commands
    4. Identifies required parameters
    5. Returns command preview with warnings

    **Permissions:** Requires HARDENING write permission
    """
    
    try:
        preview = FortiGateHardeningService.preview_hardening(
            db=db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            parameters=request.parameters
        )
        return preview

    except FortiGateCheckAlreadyPassingError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Preview failed: {str(e)}"
        )


@router.post("/execute", response_model=FortiGateExecuteResponse)
async def execute_fortinet_hardening(
    http_request: Request,
    request: FortiGateExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))
):
    """
    Execute hardening commands on FortiGate device.

    **Workflow:**
    1. Validates action exists and is in pending status
    2. Establishes SSH connection to device
    3. Backs up configuration
    4. Executes hardening commands
    5. Verifies fix by re-running the check
    6. Returns execution results

    **Permissions:** Requires HARDENING write permission

    **Errors:**
    - 400: Invalid action or missing parameters
    - 401: SSH authentication failed
    - 502: SSH algorithm mismatch or host key error
    - 503: Device unreachable
    - 504: Connection timeout
    - 500: Other execution errors
    """
    consume_quota = consume_quota_on_success("harden")
    try:
        result = FortiGateHardeningService.execute_hardening(
            db=db,
            action_id=request.action_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            parameters=request.parameters,
            vdom=request.vdom,
            skip_backup=request.skip_backup
        )
        await consume_quota(http_request)
        return result

    except FortiGateCheckAlreadyPassingError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except FortiGateMissingParametersError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
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
            detail=f"Execution failed: {str(e)}"
        )


@router.get("/session/{session_id}/parameters", response_model=FortiGateSessionParametersResponse)
def get_fortinet_session_parameters(
    session_id: int,
    check_ids: Optional[str] = None,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get aggregated parameters needed for hardening a FortiGate session.

    **Use Case:** "Fix All" mode - collect all required parameters
    before batch execution.

    **Query Parameters:**
    - check_ids: Optional comma-separated list of AuditResult IDs

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

        result = FortiGateHardeningService.get_session_parameters(
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


@router.get("/session/{session_id}/auto-preview", response_model=FortiGateAutoHardenPreviewResponse)
def get_fortinet_auto_harden_preview(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Preview automatic FortiGate hardening with defaults.

    **Use Case:** "Automatic Hardening" mode - show user what will be
    applied before execution.

    **Response:**
    - checks_with_defaults: Checks that will be fixed with their default values
    - skipped_checks: Checks that require user input (will be skipped)

    **Permissions:** Requires HARDENING read permission
    """
    try:
        result = FortiGateHardeningService.get_auto_harden_preview(
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


@router.post("/auto-harden-defaults", response_model=FortiGateAutoHardenResponse)
async def auto_harden_fortinet_with_defaults(
    http_request: Request,
    request: FortiGateAutoHardenRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))
):
    """
    Automatically harden FortiGate using default values only.

    **Use Case:** "Automatic Hardening" mode - apply all checks that
    have default values without requiring user input.

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
    consume_quota = consume_quota_on_success("harden")
    try:
        result = FortiGateHardeningService.auto_harden_with_defaults(
            db=db,
            audit_session_id=request.audit_session_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            vdom=request.vdom,
            skip_backup=request.skip_backup
        )
        await consume_quota(http_request)

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


@router.post("/batch-execute", response_model=FortiGateBatchExecuteResponse)
async def batch_execute_fortinet_selected(
    http_request: Request,
    request: FortiGateBatchExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))
):
    """
    Execute hardening for selected FortiGate checks with user parameters.

    **Use Case:** "Fix All" mode - user selects specific checks and
    provides all required parameters before execution.

    **Workflow:**
    1. User fetches parameters via GET /session/{id}/parameters
    2. User fills in required parameters
    3. User selects which checks to fix
    4. User calls this endpoint with check_ids and parameters
    5. System executes selected checks

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
    consume_quota = consume_quota_on_success("harden")
    try:
        result = FortiGateHardeningService.batch_execute_selected(
            db=db,
            audit_session_id=request.audit_session_id,
            user_id=current_user.id,
            check_ids=request.check_ids,
            parameters=request.parameters,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            vdom=request.vdom,
            skip_backup=request.skip_backup
        )
        await consume_quota(http_request)
        
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
    except FortiGateMissingParametersError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execute failed: {str(e)}"
        )


@router.get("/actions", response_model=List[FortiGateActionResponse])
def list_fortinet_hardening_actions(
    asset_id: Optional[int] = None,
    session_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    List FortiGate hardening action history with filters.

    **Query Parameters:**
    - asset_id: Filter by asset ID
    - session_id: Filter by audit session ID
    - status_filter: Filter by status (pending, success, failed, blocked)
    - limit: Maximum number of actions to return (default: 50, max: 100)
    - offset: Number of actions to skip (default: 0)

    **Permissions:** Requires HARDENING read permission
    """
    # Cap limit at 100
    limit = min(limit, 100)

    actions = FortiGateHardeningService.get_action_history(
        db=db,
        asset_id=asset_id,
        audit_session_id=session_id,
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
            "verification_passed": a.verification_passed,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "executed_at": a.executed_at.isoformat() if a.executed_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None
        }
        for a in actions
    ]


@router.get("/actions/{action_id}")
def get_fortinet_hardening_action(
    action_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific FortiGate hardening action.

    **Permissions:** Requires HARDENING read permission
    """
    from app.models import HardeningAction
    import json

    action = db.query(HardeningAction).filter(
        HardeningAction.id == action_id,
        HardeningAction.check_number.like("FG-%")
    ).first()

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"FortiGate hardening action {action_id} not found"
        )

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
        "output": action.output,
        "backup_config": action.backup_config,
        "verification_passed": action.verification_passed,
        "verification_evidence": action.verification_evidence,
        "error_message": action.error_message,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "completed_at": action.completed_at.isoformat() if action.completed_at else None
    }
