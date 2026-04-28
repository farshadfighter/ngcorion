"""
MongoDB Hardening API Router

RESTful endpoints for MongoDB CIS hardening operations.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission, require_quota
from app.models import User

from .service import MongoDBHardeningService


# ========================= REQUEST SCHEMAS =========================


class AutoHardenRequest(BaseModel):
    """Request for automatic hardening using CIS default values."""
    session_id: int = Field(..., description="Audit session ID with failed checks")
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "ssh_username": "admin",
                "ssh_password": "********",
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
    checks: List[CheckWithParams] = Field(..., description="Checks to execute with parameters")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": 10,
                "asset_id": 5,
                "ssh_username": "admin",
                "ssh_password": "********",
                "checks": [
                    {"check_id": "MONGO-L1-006", "parameters": {}},
                    {"check_id": "MONGO-L1-008", "parameters": {"MONGO_PORT": "27018"}},
                ],
            }
        }


class SingleFixRequest(BaseModel):
    """Request for a single check fix."""
    asset_id: int = Field(..., description="Target asset ID")
    ssh_username: str = Field(..., min_length=1)
    ssh_password: str = Field(..., min_length=1)
    check_id: str = Field(..., description="CIS check ID to fix")
    parameters: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 5,
                "ssh_username": "admin",
                "ssh_password": "********",
                "check_id": "MONGO-L1-006",
                "parameters": {},
            }
        }


# ========================= ROUTER =========================

router = APIRouter(
    prefix="/api/hardening/mongodb",
    tags=["Hardening - MongoDB"],
)


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
def auto_harden_with_defaults(
    request: AutoHardenRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
):
    """
    Execute automatic hardening using CIS default values.

    - Only fixes checks that require no user input (or have sensible defaults)
    - Skips checks that need custom parameters (TLS certs, keyfile paths, etc.)
    - SSH credentials are used only during execution and **never stored**

    **Permissions:** Requires HARDENING write permission
    """
    try:
        return MongoDBHardeningService.auto_harden_with_defaults(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
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
    _quota_check: None = Depends(require_quota("harden"))
):
    """
    Execute hardening for selected checks with user-provided parameters.

    Allows fixing checks that require custom values (TLS cert paths, port numbers, etc.).

    **Permissions:** Requires HARDENING write permission
    """
    try:
        checks = [
            {"check_id": c.check_id, "parameters": c.parameters}
            for c in request.checks
        ]
        return MongoDBHardeningService.batch_execute_selected(
            db=db,
            session_id=request.session_id,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            checks=checks,
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
    Execute hardening for a single check.

    **Permissions:** Requires HARDENING write permission
    """
    try:
        return MongoDBHardeningService.execute_single_fix(
            db=db,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            check_id=request.check_id,
            parameters=request.parameters,
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
