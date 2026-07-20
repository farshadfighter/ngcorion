"""
MongoDB Hardening API Router

RESTful endpoints for MongoDB CIS hardening operations.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status , Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
    check_quota_available,
    consume_quota_on_success
    )

from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome

from .service import MongoDBHardeningService
from .command_templates import get_mongodb_hardening_template, get_mongodb_template_commands
from .parameter_metadata import (
    get_mongodb_parameters_for_check,
    is_mongodb_check_auto_fixable,
    get_mongodb_check_defaults,
)


class AutoHardenRequest(BaseModel):
    """Request for automatic hardening using CIS default values."""
    session_id: int = Field(..., description="Audit session ID with failed checks")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
            }
        }


class CheckWithParams(BaseModel):
    """Single check with its parameter values."""
    check_id: str = Field(..., description="CIS check ID (e.g. MONGO-L1-006)")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameter values for template substitution",
    )


class BatchExecuteRequest(BaseModel):
    """Request for batch hardening with user-supplied parameters."""
    session_id: int = Field(..., description="Audit session ID")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")
    checks: List[CheckWithParams] = Field(..., description="Checks to execute with parameters")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "checks": [
                    {"check_id": "MONGO-L1-006", "parameters": {}},
                    {"check_id": "MONGO-L1-008", "parameters": {"MONGO_PORT": "27018"}},
                ],
            }
        }


class SingleFixRequest(BaseModel):
    """Request for a single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    session_id: Optional[int] = Field(None, description="Audit session ID (updates AuditResult status on success)")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 5,
                "session_id": 10,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "check_id": "MONGO-L1-006",
                "parameters": {},
            }
        }


router = APIRouter(
    prefix="/api/hardening/mongodb",
    tags=["Hardening - MongoDB"],
)


class MongoDBPreviewRequest(BaseModel):
    check_id: str = Field(..., description="CIS check ID, e.g. MONGO-L1-003")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameter values (uses defaults if omitted)")


@router.post("/preview")
def preview_mongodb_hardening(
    request: MongoDBPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Preview the commands that will be executed for a MongoDB hardening check.

    Returns commands with parameters substituted using provided values or CIS defaults.

    **Permissions:** Requires HARDENING read permission
    """
    template = get_mongodb_hardening_template(request.check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {request.check_id}",
        )

    params = request.parameters if request.parameters is not None else get_mongodb_check_defaults(request.check_id)
    commands = get_mongodb_template_commands(request.check_id, params)
    param_meta = get_mongodb_parameters_for_check(request.check_id)
    required = [p.name for p in param_meta if p.required and p.default is None]
    optional = [p.name for p in param_meta if not (p.required and p.default is None)]

    warnings = []
    if template.requires_service_restart:
        warnings.append("Requires mongod service restart after execution")

    return {
        "check_id": request.check_id,
        "check_title": template.description,
        "commands": commands,
        "required_parameters": required,
        "optional_parameters": optional,
        "warnings": warnings,
        "auto_fixable": is_mongodb_check_auto_fixable(request.check_id),
    }


@router.get("/session/{session_id}/parameters")
def get_session_parameters(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Get aggregated parameter metadata needed for all failed checks in a session.

    Returns:
    - **parameters**: UI metadata for dynamic form generation
    - **categorized_checks**: Checks grouped by auto_fixable / needs_params / not_supported
    - **failed_checks**: Details of each failed check including template availability

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return MongoDBHardeningService.get_session_parameters(db, session_id)
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

    Shows which failed checks can be auto-fixed and what default parameter
    values will be used. No changes are made to the target system.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return MongoDBHardeningService.get_auto_harden_preview(db, session_id)
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

    - Only fixes checks that require no user input (or have sensible defaults)
    - Skips checks that need custom parameters (TLS certs, keyfile paths, etc.)
    - SSH credentials are used only during execution and **never stored**

    **Permissions:** Requires HARDENING write permission
    """

    consume_quota = consume_quota_on_success("harden")

    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:

        result = MongoDBHardeningService.auto_harden_with_defaults(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_port=request.ssh_port,
            sudo_password=request.sudo_password,
        )
        consume_quota(http_request)
        log_session_execute_outcome(
            db, device_type="mongodb", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id,
            success_count=(result or {}).get("successful", 0) if isinstance(result, dict) else 0,
            failed_count=(result or {}).get("failed", 0) if isinstance(result, dict) else 0,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id, failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="auto_harden",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id, failed_count=1, error=str(exc),
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

    Allows fixing checks that require custom values (TLS cert paths, port numbers, etc.).

    **Permissions:** Requires HARDENING write permission
    """
    consume_quota = consume_quota_on_success("harden")
    check_ids = [c.check_id for c in request.checks]
    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:
        checks = [
            {"check_id": c.check_id, "parameters": c.parameters}
            for c in request.checks
        ]
        result = MongoDBHardeningService.batch_execute_selected(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            checks=checks,
            ssh_port=request.ssh_port,
            sudo_password=request.sudo_password,
        )
        consume_quota(http_request)
        log_session_execute_outcome(
            db, device_type="mongodb", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id, check_ids=check_ids,
            success_count=(result or {}).get("successful", 0) if isinstance(result, dict) else 0,
            failed_count=(result or {}).get("failed", 0) if isinstance(result, dict) else 0,
        )
        return result
    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id, check_ids=check_ids,
            failed_count=len(check_ids) or 1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="batch_execute",
            session_id=request.session_id, asset_id=request.asset_id,
            user_id=user_id, check_ids=check_ids,
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
    Execute hardening for a single check.

    **Permissions:** Requires HARDENING write permission
    """
    consume_quota = consume_quota_on_success("harden")
    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:
        result = MongoDBHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            check_id=request.check_id,
            parameters=request.parameters,
            ssh_port=request.ssh_port,
            session_id=request.session_id,
            sudo_password=request.sudo_password,
        )

        consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("success") is True
        log_session_execute_outcome(
            db, device_type="mongodb", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result
    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="mongodb", action="execute_single",
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
    List all checks that have a MongoDB hardening template.

    Returns check metadata including auto-fixability and default parameters.

    **Permissions:** Requires HARDENING read permission
    """
    return MongoDBHardeningService.get_supported_checks()


@router.get("/check/{check_id}/template")
def get_check_template(
    check_id: str,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Get hardening template details for a specific check.

    **Permissions:** Requires HARDENING read permission
    """
    from .command_templates import get_mongodb_hardening_template
    from .parameter_metadata import (
        get_mongodb_check_defaults,
        get_mongodb_parameters_for_check,
        is_mongodb_check_auto_fixable,
    )

    template = get_mongodb_hardening_template(check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {check_id}",
        )

    params = get_mongodb_parameters_for_check(check_id)
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
        "commands": template.commands,
        "verify_commands": template.verify_commands,
        "requires_service_restart": template.requires_service_restart,
        "auto_fixable": is_mongodb_check_auto_fixable(check_id),
        "parameters": param_info,
        "defaults": get_mongodb_check_defaults(check_id),
    }
