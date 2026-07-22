"""
Linux Hardening API Router

RESTful endpoints for Linux CIS hardening operations.
"""

from fastapi import APIRouter, Depends, HTTPException, status , Request
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
    check_quota_available,
    consume_quota_on_success
    )

from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome
from .service import LinuxHardeningService
from .command_templates import get_linux_hardening_template, get_linux_template_commands
from .parameter_metadata import (
    get_linux_parameters_for_check,
    is_linux_check_auto_fixable,
    get_linux_check_defaults,
)


class SingleFixRequest(BaseModel):
    """Request for single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    session_id: Optional[int] = Field(None, description="Audit session ID (used to update AuditResult status)")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = None
    check_id: str = Field(..., description="CIS check ID to fix")
    sub_device_type: Optional[str] = Field(
        None,
        description="Distro variant from the audit, e.g. linux-ubuntu-22. When "
                    "provided, skips live distro detection to speed up the fix.",
    )
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter values")
    dry_run: bool = Field(False, description="Preview only: return the commands that would run, without connecting or changing anything")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "check_id": "LNX-L1-5.2.10",
                "sub_device_type": "linux-ubuntu-22",
                "parameters": {}
            }
        }



router = APIRouter(prefix="/api/hardening/linux", tags=["Hardening - Linux"])


class LinuxPreviewRequest(BaseModel):
    check_id: str = Field(..., description="CIS check ID, e.g. LNX-L1-5.2.10")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameter values (uses defaults if omitted)")


@router.post("/preview")
def preview_linux_hardening(
    request: LinuxPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Preview the commands that will be executed for a Linux hardening check.

    Returns commands with parameters substituted using provided values or CIS defaults.

    **Permissions:** Requires HARDENING read permission
    """
    template = get_linux_hardening_template(request.check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {request.check_id}",
        )

    if template.manual_only:
        detail = (
            f"Check {request.check_id} has no automated remediation and must be "
            f"applied manually.\n\n{template.manual_guidance}"
            if template.manual_guidance
            else f"Check {request.check_id} has no automated remediation and must be applied manually."
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    # Merge defaults *under* the caller's values and drop empty strings, so the
    # preview shows exactly what execution would run. The UI posts
    # `parameters: {}` on the first preview, and without this merge every
    # {PARAM} placeholder would be shown (and later substituted) unresolved.
    defaults = get_linux_check_defaults(request.check_id)
    params = dict(defaults)
    for k, v in (request.parameters or {}).items():
        if v is not None and str(v).strip() != "":
            params[k] = v
    commands = get_linux_template_commands(request.check_id, params)
    param_meta = get_linux_parameters_for_check(request.check_id)
    required = [p.name for p in param_meta if p.required and p.default is None]
    optional = [p.name for p in param_meta if not (p.required and p.default is None)]

    warnings = []
    if template.requires_service_restart:
        warnings.append("Requires service restart after execution")
    if template.requires_reboot:
        warnings.append("Requires system reboot after execution")

    return {
        "check_id": request.check_id,
        "check_title": template.description,
        "commands": commands,
        "required_parameters": required,
        "optional_parameters": optional,
        # Default values keyed by parameter name — the UI pre-fills optional
        # params from this so empty strings are never submitted.
        "parameter_defaults": defaults,
        "warnings": warnings,
        "auto_fixable": is_linux_check_auto_fixable(request.check_id),
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
    Execute hardening for a single check.

    **Permissions:** Requires HARDENING write permission
    """

    consume_quota = consume_quota_on_success("harden")

    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:
        result = LinuxHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            session_id=request.session_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            sudo_password=request.sudo_password,
            check_id=request.check_id,
            parameters=request.parameters,
            ssh_port=request.ssh_port,
            sub_device_type=request.sub_device_type,
            dry_run=request.dry_run,
        )
        if request.dry_run:
            return result
        consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("success") is True
        log_session_execute_outcome(
            db, device_type="linux", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result
    except ValueError as e:
        log_session_execute_outcome(
            db, device_type="linux", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(e),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        log_session_execute_outcome(
            db, device_type="linux", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(e),
        )
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
    from .command_templates import get_linux_hardening_template
    from .parameter_metadata import (
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
        "manual_only": template.manual_only,
        "manual_guidance": template.manual_guidance,
        "parameters": param_info,
        "defaults": get_linux_check_defaults(check_id)
    }
