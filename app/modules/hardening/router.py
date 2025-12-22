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

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User
from .service import HardeningService, CheckAlreadyPassingError, MissingParametersError


# ========================= SCHEMAS =========================

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
                "warnings": ["This will remove the existing enable password"]
            }
        }


class HardeningExecuteRequest(BaseModel):
    """Request to execute hardening commands."""
    action_id: int = Field(..., description="ID from preview response")
    ssh_username: str = Field(..., min_length=1, description="Fresh SSH credentials")
    ssh_password: str = Field(..., min_length=1, description="Fresh SSH password")
    ssh_secret: Optional[str] = Field(None, description="Enable secret")
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


# ========================= ROUTER =========================

router = APIRouter(prefix="/api/hardening", tags=["Hardening - Cisco"])


@router.post("/preview", response_model=HardeningPreviewResponse)
def preview_hardening(
    request: HardeningPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
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
    try:
        preview = HardeningService.preview_hardening(
            db=db,
            audit_result_id=request.audit_result_id,
            user_id=current_user.id,
            parameters=request.parameters
        )

        return preview

    except CheckAlreadyPassingError as e:
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


@router.post("/execute", response_model=HardeningExecuteResponse)
def execute_hardening(
    request: HardeningExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
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
    - 404: Action not found
    - 500: SSH connection failure or command execution error
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
            skip_backup=request.skip_backup
        )

        return result

    except CheckAlreadyPassingError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except MissingParametersError as e:
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
        "commands": json.loads(action.commands_json),
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
