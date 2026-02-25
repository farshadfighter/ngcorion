"""
SQL Server Hardening API Router

RESTful endpoints for SQL Server CIS hardening operations.
Credentials connect directly to SQL Server via T-SQL (not SSH).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User

from .service import MSSQLHardeningService


# ========================= REQUEST SCHEMAS =========================


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
    mssql_username: str = Field(..., min_length=1)
    mssql_password: str = Field(..., min_length=1)
    mssql_port: int = Field(1433, ge=1, le=65535)
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 5,
                "mssql_username": "sa",
                "mssql_password": "********",
                "mssql_port": 1433,
                "check_id": "MSSQL-L1-010",
                "parameters": {},
            }
        }


# ========================= ROUTER =========================

router = APIRouter(
    prefix="/api/hardening/mssql",
    tags=["Hardening - SQL Server"],
)


@router.get("/session/{session_id}/parameters")
def get_session_parameters(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Get aggregated parameter metadata for all failed checks in an MSSQL audit session.

    Returns:
    - **parameters**: UI metadata for dynamic form generation
    - **categorized_checks**: Checks grouped by auto_fixable / needs_params / not_supported
    - **failed_checks**: Details of each failed check including template and fixability info

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return MSSQLHardeningService.get_session_parameters(db, session_id)
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
    values will be used. **No changes are made** to the target server.

    **Permissions:** Requires HARDENING read permission
    """
    try:
        return MSSQLHardeningService.get_auto_harden_preview(db, session_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get preview: {str(exc)}",
        )


@router.post("/auto-harden-defaults")
def auto_harden_with_defaults(
    request: AutoHardenRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
):
    """
    Execute automatic hardening using CIS default values.

    - Connects directly to SQL Server via T-SQL (no SSH required)
    - Only fixes checks that require no user input (or have sensible defaults)
    - Skips checks requiring custom parameters (database names, login names, etc.)
    - Skips checks that are manual-only (auth mode, TDE, port change)
    - SQL Server credentials are used only during execution and **never stored**

    **Permissions:** Requires HARDENING write permission
    """
    try:
        return MSSQLHardeningService.auto_harden_with_defaults(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            mssql_username=request.mssql_username,
            mssql_password=request.mssql_password,
            mssql_port=request.mssql_port,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-hardening failed: {str(exc)}",
        )


@router.post("/batch-execute")
def batch_execute_selected(
    request: BatchExecuteRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
):
    """
    Execute hardening for selected checks with user-provided parameters.

    Allows fixing checks that require custom values (database names, login names,
    audit paths, etc.) via direct T-SQL execution against SQL Server.

    **Permissions:** Requires HARDENING write permission
    """
    try:
        checks = [
            {"check_id": c.check_id, "parameters": c.parameters}
            for c in request.checks
        ]
        return MSSQLHardeningService.batch_execute_selected(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            mssql_username=request.mssql_username,
            mssql_password=request.mssql_password,
            checks=checks,
            mssql_port=request.mssql_port,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execution failed: {str(exc)}",
        )


@router.post("/execute-single")
def execute_single_fix(
    request: SingleFixRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
):
    """
    Execute hardening for a single CIS check.

    Connects directly to SQL Server and runs the remediation T-SQL.

    **Permissions:** Requires HARDENING write permission
    """
    try:
        return MSSQLHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            mssql_username=request.mssql_username,
            mssql_password=request.mssql_password,
            check_id=request.check_id,
            parameters=request.parameters,
            mssql_port=request.mssql_port,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
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
