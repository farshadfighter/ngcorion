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
from .command_templates import get_windows_hardening_template, get_windows_template_statements
from .parameter_metadata import (
    get_windows_parameters_for_check,
    is_windows_check_auto_fixable,
    get_windows_check_defaults,
)


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
    session_id: Optional[int] = Field(None, description="Audit session ID (updates AuditResult status on success)")
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


class WindowsPreviewRequest(BaseModel):
    check_id: str = Field(..., description="CIS check ID, e.g. WIN-L1-038")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameter values (uses defaults if omitted)")


@router.post("/preview")
def preview_windows_hardening(
    request: WindowsPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Preview the PowerShell/registry statements that will be executed for a Windows hardening check.

    Returns statements with parameters substituted using provided values or CIS defaults.

    **Permissions:** Requires HARDENING read permission
    """
    template = get_windows_hardening_template(request.check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {request.check_id}",
        )

    if template.manual_only:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Check {request.check_id} requires manual remediation and cannot be automated",
        )

    # Merge defaults under the caller's values (dropping empty strings) so the
    # preview shows the same statements execution would run — the UI sends {}
    # when the user has not typed anything.
    params = dict(get_windows_check_defaults(request.check_id))
    for k, v in (request.parameters or {}).items():
        if v is not None and str(v).strip() != "":
            params[k] = v
    commands = get_windows_template_statements(request.check_id, params)
    param_meta = get_windows_parameters_for_check(request.check_id)
    required = [p.name for p in param_meta if p.required and p.default is None]
    optional = [p.name for p in param_meta if not (p.required and p.default is None)]

    warnings = []
    if template.requires_restart:
        warnings.append("Requires Windows restart after execution")

    return {
        "check_id": request.check_id,
        "check_title": template.description,
        "commands": commands,
        "required_parameters": required,
        "optional_parameters": optional,
        "warnings": warnings,
        "auto_fixable": is_windows_check_auto_fixable(request.check_id),
    }


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
    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:
        result = WindowsHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            session_id=request.session_id,
            windows_username=request.windows_username,
            windows_password=request.windows_password,
            check_id=request.check_id,
            parameters=request.parameters,
            winrm_port=request.winrm_port,
            transport=request.transport,
        )

        consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("success") is True
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="windows", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
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
