"""
Apache Hardening API Router

RESTful endpoints for Apache HTTP Server CIS hardening operations.
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
from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome
from .service import ApacheHardeningService
from .command_templates import get_apache_hardening_template, get_apache_template_commands_for_distro
from .parameter_metadata import (
    get_apache_parameters_for_check,
    is_apache_check_auto_fixable,
    get_apache_check_defaults,
)

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
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 15,
                "asset_id": 30,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "sudo_password": "********"
            }
        }


class CheckWithParams(BaseModel):
    """Single check with its parameters."""
    check_id: str = Field(..., description="CIS check ID (e.g., APACHE-L1-9.1)")
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter values")


class BatchExecuteRequest(BaseModel):
    """Request for batch hardening execution."""
    session_id: int = Field(..., description="Audit session ID")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = None
    checks: List[CheckWithParams] = Field(..., description="Checks to execute with parameters")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 15,
                "asset_id": 30,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "checks": [
                    {"check_id": "APACHE-L1-9.1", "parameters": {}},
                    {"check_id": "APACHE-L1-8.3", "parameters": {"SSL_PROTOCOLS": "all -SSLv3 -TLSv1 -TLSv1.1"}}
                ]
            }
        }


class SingleFixRequest(BaseModel):
    """Request for single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    session_id: Optional[int] = Field(None, description="Audit session ID (updates AuditResult status on success)")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = None
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter values")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 30,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "check_id": "APACHE-L1-9.1",
                "parameters": {}
            }
        }


router = APIRouter(prefix="/api/hardening/apache", tags=["Hardening - Apache"])


class ApachePreviewRequest(BaseModel):
    check_id: str = Field(..., description="CIS check ID, e.g. APACHE-L1-2.1")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameter values (uses defaults if omitted)")
    distro: Optional[str] = Field("debian", description="Target distro family: 'debian' (Ubuntu/Debian) or 'rhel' (RHEL/Rocky)")


@router.post("/preview")
def preview_apache_hardening(
    request: ApachePreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Preview the commands that will be executed for an Apache hardening check.

    Returns commands substituted with parameter values or CIS defaults.
    Since distro cannot be detected without connecting, both Debian and RHEL
    command sets are returned. Specify `distro` to filter to one family.

    **Permissions:** Requires HARDENING read permission
    """
    template = get_apache_hardening_template(request.check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {request.check_id}",
        )

    params = request.parameters if request.parameters is not None else get_apache_check_defaults(request.check_id)
    distro = (request.distro or "debian").lower()

    commands_debian = get_apache_template_commands_for_distro(request.check_id, "debian", params)
    commands_rhel = get_apache_template_commands_for_distro(request.check_id, "rhel", params)

    # Return the requested distro's commands as the primary "commands" list
    if distro in ("rhel", "rocky", "redhat"):
        commands = commands_rhel
    else:
        commands = commands_debian

    param_meta = get_apache_parameters_for_check(request.check_id)
    required = [p.name for p in param_meta if p.required and p.default is None]
    optional = [p.name for p in param_meta if not (p.required and p.default is None)]

    warnings = []
    if template.requires_service_restart:
        warnings.append("Requires Apache service restart after execution")
    if template.requires_reboot:
        warnings.append("Requires system reboot after execution")
    if commands_debian != commands_rhel:
        warnings.append("Commands differ between Debian/Ubuntu and RHEL/Rocky — shown for selected distro family")

    return {
        "check_id": request.check_id,
        "check_title": template.description,
        "commands": commands,
        "commands_debian": commands_debian,
        "commands_rhel": commands_rhel,
        "required_parameters": required,
        "optional_parameters": optional,
        "warnings": warnings,
        "auto_fixable": is_apache_check_auto_fixable(request.check_id),
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
        result = ApacheHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            session_id=request.session_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_port=request.ssh_port,
            sudo_password=request.sudo_password,
            check_id=request.check_id,
            parameters=request.parameters
        )
        consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("success") is True
        log_session_execute_outcome(
            db, device_type="apache", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result

    except ValueError as e:
        log_session_execute_outcome(
            db, device_type="apache", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(e),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        log_session_execute_outcome(
            db, device_type="apache", action="execute_single",
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
    return ApacheHardeningService.get_supported_checks()


@router.get("/check/{check_id}/template")
def get_check_template(
    check_id: str,
    current_user: User = Depends(require_permission("HARDENING", "read"))
):
    """
    Get hardening template details for a specific check.

    **Permissions:** Requires HARDENING read permission
    """
    from .command_templates import get_apache_hardening_template
    from .parameter_metadata import (
        get_apache_parameters_for_check,
        is_apache_check_auto_fixable,
        get_apache_check_defaults
    )

    template = get_apache_hardening_template(check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No template found for check {check_id}"
        )

    params = get_apache_parameters_for_check(check_id)
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
        "commands_debian": template.commands_debian,
        "commands_rhel": template.commands_rhel,
        "verify_commands_debian": template.verify_commands_debian,
        "verify_commands_rhel": template.verify_commands_rhel,
        "requires_service_restart": template.requires_service_restart,
        "auto_fixable": is_apache_check_auto_fixable(check_id),
        "parameters": param_info,
        "defaults": get_apache_check_defaults(check_id)
    }
