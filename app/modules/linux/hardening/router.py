"""
Linux Hardening API Router

RESTful endpoints for Linux CIS hardening operations.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User
from .service import LinuxHardeningService


# ========================= SCHEMAS =========================

class SSHCredentials(BaseModel):
    """SSH credentials for hardening operations."""
    ssh_username: str = Field(..., min_length=1, description="SSH username")
    ssh_password: str = Field(..., min_length=1, description="SSH password")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")


class AutoHardenRequest(BaseModel):
    """Request for automatic hardening."""
    session_id: int = Field(..., description="Audit session ID with failed checks")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    sudo_password: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "sudo_password": "********"
            }
        }


class CheckWithParams(BaseModel):
    """Single check with its parameters."""
    check_id: str = Field(..., description="CIS check ID (e.g., LNX-L1-5.2.10)")
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter values")


class BatchExecuteRequest(BaseModel):
    """Request for batch hardening execution."""
    session_id: int = Field(..., description="Audit session ID")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    sudo_password: Optional[str] = None
    checks: List[CheckWithParams] = Field(..., description="Checks to execute with parameters")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "checks": [
                    {"check_id": "LNX-L1-5.2.10", "parameters": {}},
                    {"check_id": "LNX-L1-5.2.7", "parameters": {"SSH_MAX_AUTH_TRIES": "4"}}
                ]
            }
        }


class SingleFixRequest(BaseModel):
    """Request for single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    sudo_password: Optional[str] = None
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter values")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "check_id": "LNX-L1-5.2.10",
                "parameters": {}
            }
        }


# ========================= ROUTER =========================

router = APIRouter(prefix="/api/hardening/linux", tags=["Hardening - Linux"])


@router.get("/session/{session_id}/parameters")
def get_session_parameters(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get aggregated parameters needed for all failed checks in a session.

    Returns:
    - parameters: UI metadata for form generation
    - categorized_checks: Checks grouped by fixability
    - failed_checks: Details of each failed check

    **Permissions:** Requires HARDENING read permission
    """
    try:
        result = LinuxHardeningService.get_session_parameters(db, session_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get parameters: {str(e)}"
        )


@router.get("/session/{session_id}/auto-preview")
def get_auto_harden_preview(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get preview of what will be applied in automatic hardening mode.

    Shows which checks can be auto-fixed and their default values.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        result = LinuxHardeningService.get_auto_harden_preview(db, session_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get preview: {str(e)}"
        )


@router.post("/auto-harden-defaults")
def auto_harden_with_defaults(
    request: AutoHardenRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute automatic hardening using CIS default values only.

    This mode:
    - Only fixes checks that don't require user input
    - Uses CIS-recommended default values
    - Skips checks that need custom parameters (like banners, syslog servers)

    **Workflow:**
    1. Get failed checks from audit session
    2. Filter to auto-fixable checks only
    3. Execute fixes with default parameters
    4. Return results

    **Permissions:** Requires HARDENING write permission

    **Note:** SSH credentials are used only during execution and never stored.
    """
    try:
        result = LinuxHardeningService.auto_harden_with_defaults(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            sudo_password=request.sudo_password
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-hardening failed: {str(e)}"
        )


@router.post("/batch-execute")
def batch_execute_selected(
    request: BatchExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute hardening for selected checks with user-provided parameters.

    This mode allows:
    - Selecting specific checks to fix
    - Providing custom parameter values
    - Fixing checks that require user input

    **Permissions:** Requires HARDENING write permission
    """
    try:
        checks = [
            {"check_id": c.check_id, "parameters": c.parameters}
            for c in request.checks
        ]

        result = LinuxHardeningService.batch_execute_selected(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            sudo_password=request.sudo_password,
            checks=checks
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execution failed: {str(e)}"
        )


@router.post("/execute-single")
def execute_single_fix(
    request: SingleFixRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute hardening for a single check.

    **Permissions:** Requires HARDENING write permission
    """
    try:
        result = LinuxHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            sudo_password=request.sudo_password,
            check_id=request.check_id,
            parameters=request.parameters
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Single fix failed: {str(e)}"
        )


@router.get("/supported-checks")
def get_supported_checks(
    current_user: User = Depends(require_permission("HARDENING", "read"))
):
    """
    Get list of all checks that have hardening templates.

    Returns:
    - total_supported: Number of checks with templates
    - checks: List of check metadata including auto-fixability

    **Permissions:** Requires HARDENING read permission
    """
    return LinuxHardeningService.get_supported_checks()


@router.get("/check/{check_id}/template")
def get_check_template(
    check_id: str,
    current_user: User = Depends(require_permission("HARDENING", "read"))
):
    """
    Get hardening template details for a specific check.

    **Permissions:** Requires HARDENING read permission
    """
    from .linux_command_templates import get_linux_hardening_template
    from .linux_parameter_metadata import (
        get_linux_parameters_for_check,
        is_linux_check_auto_fixable,
        get_linux_check_defaults
    )

    template = get_linux_hardening_template(check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No template found for check {check_id}"
        )

    params = get_linux_parameters_for_check(check_id)
    param_info = [
        {
            "name": p.name,
            "type": p.input_type,
            "label": p.label,
            "description": p.description,
            "required": p.required and p.default is None,
            "default": p.default,
            "options": p.options
        }
        for p in params
    ]

    return {
        "check_id": check_id,
        "description": template.description,
        "commands": template.commands,
        "verify_commands": template.verify_commands,
        "requires_reboot": template.requires_reboot,
        "requires_service_restart": template.requires_service_restart,
        "distros": template.distros,
        "auto_fixable": is_linux_check_auto_fixable(check_id),
        "parameters": param_info,
        "defaults": get_linux_check_defaults(check_id)
    }
