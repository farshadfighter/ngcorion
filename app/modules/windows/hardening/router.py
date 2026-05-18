"""
Windows Server Hardening API Router

RESTful endpoints for Windows Server CIS hardening operations.
Credentials connect directly to Windows Server via WinRM (not SSH).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status , Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import(
    get_current_user,
    require_permission,
    check_quota_available,
    consume_quota_on_success
    )
    
from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome

from .service import WindowsHardeningService


class AutoHardenRequest(BaseModel):
    """Request for automatic hardening using CIS default values."""
    session_id: int = Field(..., description="Audit session ID with failed checks")
    asset_id: int = Field(..., description="Target asset ID")
    windows_username: str = Field(
        ..., min_length=1,
        description="Windows admin account (not stored)"
    )
    windows_password: str = Field(
        ..., min_length=1,
        description="Windows password (not stored)"
    )
    winrm_port: int = Field(
        5986, ge=1, le=65535,
        description="WinRM HTTPS port (default 5986)"
    )
    transport: str = Field(
        "ntlm",
        pattern="^(ntlm|kerberos|credssp|basic)$",
        description="WinRM transport"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "windows_username": "Administrator",
                "windows_password": "********",
                "winrm_port": 5986,
                "transport": "ntlm",
            }
        }


class CheckWithParams(BaseModel):
    """Single check with its parameter values."""
    check_id: str = Field(..., description="CIS check ID (e.g. WIN-L1-048)")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameter values for template substitution",
    )


class BatchExecuteRequest(BaseModel):
    """Request for batch hardening with user-supplied parameters."""
    session_id: int = Field(..., description="Audit session ID")
    asset_id: int = Field(..., description="Target asset ID")
    windows_username: str = Field(..., min_length=1)
    windows_password: str = Field(..., min_length=1)
    winrm_port: int = Field(5986, ge=1, le=65535)
    transport: str = Field("ntlm", pattern="^(ntlm|kerberos|credssp|basic)$")
    checks: List[CheckWithParams] = Field(
        ..., description="Checks to execute with their parameter values"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "windows_username": "Administrator",
                "windows_password": "********",
                "winrm_port": 5986,
                "transport": "ntlm",
                "checks": [
                    {"check_id": "WIN-L1-048", "parameters": {}},
                    {"check_id": "WIN-L1-027", "parameters": {"NEW_ADMIN_NAME": "WinAdmin"}},
                ],
            }
        }


class SingleFixRequest(BaseModel):
    """Request for a single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    windows_username: str = Field(..., min_length=1)
    windows_password: str = Field(..., min_length=1)
    winrm_port: int = Field(5986, ge=1, le=65535)
    transport: str = Field("ntlm", pattern="^(ntlm|kerberos|credssp|basic)$")
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 5,
                "windows_username": "Administrator",
                "windows_password": "********",
                "winrm_port": 5986,
                "transport": "ntlm",
                "check_id": "WIN-L1-048",
                "parameters": {},
            }
        }



router = APIRouter(
    prefix="/api/hardening/windows",
    tags=["Hardening - Windows Server"],
)


@router.get("/session/{session_id}/parameters")
def get_session_parameters(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Get aggregated parameter metadata for all failed checks in a Windows audit session.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return WindowsHardeningService.get_session_parameters(db, session_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session parameters: {str(exc)}",
        )


@router.get("/session/{session_id}/auto-preview")
def get_auto_harden_preview(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Preview what automatic hardening would apply (checks + default values).
    **No changes are made** to the target server.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return WindowsHardeningService.get_auto_harden_preview(db, session_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get preview: {str(exc)}",
        )


@router.post("/auto-harden-defaults")
async def auto_harden_with_defaults(
    http_request: Request,
    request: AutoHardenRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))

):
    """
    Execute automatic hardening using CIS default values.

    - Connects to Windows Server via WinRM (HTTPS, no SSH)
    - Only fixes checks that require no user input (or have sensible defaults)
    - Skips checks requiring custom parameters
    - Skips checks that are manual-only
    - Windows credentials are used only during execution and **never stored**

    **Permissions:** Requires HARDENING write permission
    """
    consume_quota = consume_quota_on_success("harden")
    try:
        result =  WindowsHardeningService.auto_harden_with_defaults(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            windows_username=request.windows_username,
            windows_password=request.windows_password,
            winrm_port=request.winrm_port,
            transport=request.transport,
        )

        await consume_quota(http_request)
        log_session_execute_outcome(
            db, device_type="windows", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id,
            success_count=(result or {}).get("success_count", 0) if isinstance(result, dict) else 0,
            failed_count=(result or {}).get("failed_count", 0) if isinstance(result, dict) else 0,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id, failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id, failed_count=1, error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-hardening failed: {str(exc)}",
        )


@router.post("/batch-execute")
async def batch_execute_selected(
    http_request: Request,
    request: BatchExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))
):
    """
    Execute hardening for selected checks with user-provided parameters.

    **Permissions:** Requires HARDENING write permission
    """
    consume_quota = consume_quota_on_success("harden")
    check_ids = [c.check_id for c in request.checks]
    try:
        checks = [
            {"check_id": c.check_id, "parameters": c.parameters}
            for c in request.checks
        ]
        result = WindowsHardeningService.batch_execute_selected(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            windows_username=request.windows_username,
            windows_password=request.windows_password,
            checks=checks,
            winrm_port=request.winrm_port,
            transport=request.transport,
        )

        await consume_quota(http_request)
        log_session_execute_outcome(
            db, device_type="windows", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=check_ids,
            success_count=(result or {}).get("success_count", 0) if isinstance(result, dict) else 0,
            failed_count=(result or {}).get("failed_count", 0) if isinstance(result, dict) else 0,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=check_ids,
            failed_count=len(check_ids) or 1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=check_ids,
            failed_count=len(check_ids) or 1, error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execution failed: {str(exc)}",
        )


@router.post("/execute-single")
async def execute_single_fix(
    http_request: Request,
    request: SingleFixRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden"))

):
    """
    Execute hardening for a single CIS check.

    **Permissions:** Requires HARDENING write permission
    """
    consume_quota = consume_quota_on_success("harden")
    try:
        result = WindowsHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            windows_username=request.windows_username,
            windows_password=request.windows_password,
            check_id=request.check_id,
            parameters=request.parameters,
            winrm_port=request.winrm_port,
            transport=request.transport,
        )

        await consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("status") == "success"
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=[request.check_id],
            failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=current_user.id, check_ids=[request.check_id],
            failed_count=1, error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Single fix failed: {str(exc)}",
        )


@router.get("/supported-checks")
def get_supported_checks(
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    List all CIS Windows Server checks that have a hardening template.

    **Permissions:** Requires HARDENING read permission
    """
    return WindowsHardeningService.get_supported_checks()


@router.get("/check/{check_id}/template")
def get_check_template(
    check_id: str,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Get hardening template details for a specific CIS Windows Server check.

    **Permissions:** Requires HARDENING read permission
    """
    from .command_templates import get_windows_hardening_template
    from .parameter_metadata import (
        get_windows_check_defaults,
        get_windows_parameters_for_check,
        is_windows_check_auto_fixable,
    )

    template = get_windows_hardening_template(check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {check_id}",
        )

    params = get_windows_parameters_for_check(check_id)
    param_info = [
        {
            "name": p.name,
            "type": p.input_type,
            "label": p.label,
            "description": p.description,
            "required": p.required and p.default is None,
            "default": p.default,
            "options": p.options,
            "min_value": p.min_value,
            "max_value": p.max_value,
        }
        for p in params
    ]

    return {
        "check_id": check_id,
        "description": template.description,
        "statements": template.statements,
        "verify_statements": template.verify_statements,
        "requires_restart": template.requires_restart,
        "manual_only": template.manual_only,
        "auto_fixable": is_windows_check_auto_fixable(check_id),
        "parameters": param_info,
        "defaults": get_windows_check_defaults(check_id),
    }
