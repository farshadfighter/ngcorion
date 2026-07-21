"""
SQL Server Hardening API Router

RESTful endpoints for SQL Server CIS hardening operations.
Credentials connect directly to SQL Server via T-SQL (not SSH).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import(get_current_user,
    require_permission,
    consume_quota_on_success,
    check_quota_available
    )
from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome

from .service import MSSQLHardeningService
from .command_templates import get_mssql_hardening_template, get_mssql_template_statements
from .parameter_metadata import (
    get_mssql_parameters_for_check,
    is_mssql_check_auto_fixable,
    get_mssql_check_defaults,
)

class AutoHardenRequest(BaseModel):
    """Request for automatic hardening using CIS default values."""
    session_id: int = Field(..., description="Audit session ID with failed checks")
    asset_id: int = Field(..., description="Target asset ID")
    mssql_username: str = Field(
        ..., min_length=1,
        description="SQL Server login with sysadmin privileges (not stored)"
    )
    mssql_password: str = Field(
        ..., min_length=1,
        description="SQL Server password (not stored)"
    )
    mssql_port: int = Field(
        1433, ge=1, le=65535,
        description="SQL Server TCP port (default 1433)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "mssql_username": "sa",
                "mssql_password": "********",
                "mssql_port": 1433,
            }
        }


class CheckWithParams(BaseModel):
    """Single check with its parameter values."""
    check_id: str = Field(..., description="CIS check ID (e.g. MSSQL-L1-010)")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameter values for template substitution",
    )


class BatchExecuteRequest(BaseModel):
    """Request for batch hardening with user-supplied parameters."""
    session_id: int = Field(..., description="Audit session ID")
    asset_id: int = Field(..., description="Target asset ID")
    mssql_username: str = Field(..., min_length=1)
    mssql_password: str = Field(..., min_length=1)
    mssql_port: int = Field(1433, ge=1, le=65535)
    checks: List[CheckWithParams] = Field(
        ..., description="Checks to execute with their parameter values"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "mssql_username": "sa",
                "mssql_password": "********",
                "mssql_port": 1433,
                "checks": [
                    {"check_id": "MSSQL-L1-010", "parameters": {}},
                    {"check_id": "MSSQL-L1-011", "parameters": {"DB_NAME": "SensitiveDB"}},
                ],
            }
        }


class SingleFixRequest(BaseModel):
    """Request for a single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    session_id: Optional[int] = Field(None, description="Audit session ID (updates AuditResult status on success)")
    mssql_username: str = Field(..., min_length=1)
    mssql_password: str = Field(..., min_length=1)
    mssql_port: int = Field(1433, ge=1, le=65535)
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 5,
                "session_id": 10,
                "mssql_username": "sa",
                "mssql_password": "********",
                "mssql_port": 1433,
                "check_id": "MSSQL-L1-010",
                "parameters": {},
            }
        }



router = APIRouter(
    prefix="/api/hardening/mssql",
    tags=["Hardening - SQL Server"],
)


class MSSQLPreviewRequest(BaseModel):
    check_id: str = Field(..., description="CIS check ID, e.g. MSSQL-L1-002")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameter values (uses defaults if omitted)")


@router.post("/preview")
def preview_mssql_hardening(
    request: MSSQLPreviewRequest,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Preview the T-SQL statements that will be executed for a SQL Server hardening check.

    Returns statements with parameters substituted using provided values or CIS defaults.

    **Permissions:** Requires HARDENING read permission
    """
    template = get_mssql_hardening_template(request.check_id)
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
    params = dict(get_mssql_check_defaults(request.check_id))
    for k, v in (request.parameters or {}).items():
        if v is not None and str(v).strip() != "":
            params[k] = v
    commands = get_mssql_template_statements(request.check_id, params)
    param_meta = get_mssql_parameters_for_check(request.check_id)
    required = [p.name for p in param_meta if p.required and p.default is None]
    optional = [p.name for p in param_meta if not (p.required and p.default is None)]

    warnings = []
    if template.requires_restart:
        warnings.append("Requires SQL Server service restart after execution")

    return {
        "check_id": request.check_id,
        "check_title": template.description,
        "commands": commands,
        "required_parameters": required,
        "optional_parameters": optional,
        "warnings": warnings,
        "auto_fixable": is_mssql_check_auto_fixable(request.check_id),
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

    Connects directly to SQL Server and runs the remediation T-SQL.

    **Permissions:** Requires HARDENING write permission
    """
    
    consume_quota = consume_quota_on_success("harden")

    # Read the id while the session is healthy: current_user may be expired,
    # and refreshing it inside an exception handler (after a failed flush)
    # raises PendingRollbackError, masking the real error.
    user_id = current_user.id
    try:
        result = MSSQLHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            mssql_username=request.mssql_username,
            mssql_password=request.mssql_password,
            check_id=request.check_id,
            parameters=request.parameters,
            mssql_port=request.mssql_port,
            session_id=request.session_id,
        )

        consume_quota(http_request)
        succeeded = isinstance(result, dict) and result.get("success") is True
        log_session_execute_outcome(
            db, device_type="mssql", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            success_count=1 if succeeded else 0,
            failed_count=0 if succeeded else 1,
            error=(result or {}).get("error_message") if isinstance(result, dict) else None,
        )
        return result

    except ValueError as exc:
        log_session_execute_outcome(
            db, device_type="mssql", action="execute_single",
            session_id=None, asset_id=request.asset_id,
            user_id=user_id, check_ids=[request.check_id],
            failed_count=1, error=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        log_session_execute_outcome(
            db, device_type="mssql", action="execute_single",
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
    List all CIS SQL Server checks that have a hardening template.

    Returns check metadata including auto-fixability, manual-only flag,
    restart requirement, and default parameters.

    **Permissions:** Requires HARDENING read permission
    """
    return MSSQLHardeningService.get_supported_checks()


@router.get("/check/{check_id}/template")
def get_check_template(
    check_id: str,
    current_user: User = Depends(require_permission("HARDENING", "read")),
):
    """
    Get hardening template details for a specific CIS SQL Server check.

    Returns the T-SQL statements, verification queries, parameters,
    and fixability metadata.

    **Permissions:** Requires HARDENING read permission
    """
    from .command_templates import get_mssql_hardening_template
    from .parameter_metadata import (
        get_mssql_check_defaults,
        get_mssql_parameters_for_check,
        is_mssql_check_auto_fixable,
    )

    template = get_mssql_hardening_template(check_id)
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hardening template found for check {check_id}",
        )

    params = get_mssql_parameters_for_check(check_id)
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
        "auto_fixable": is_mssql_check_auto_fixable(check_id),
        "parameters": param_info,
        "defaults": get_mssql_check_defaults(check_id),
    }
