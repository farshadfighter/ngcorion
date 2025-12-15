"""
Audit API Router

RESTful endpoints for Cisco CIS security auditing.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User
from .service import AuditService


# ========================= SCHEMAS =========================

class CiscoAuditRequest(BaseModel):
    """Request to execute Cisco CIS audit."""

    asset_id: int = Field(..., description="Target asset ID from Asset List")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    ssh_secret: Optional[str] = Field(None, description="Enable secret (optional, not stored)")
    profile: str = Field("L1", pattern="^(L1|FULL)$", description="CIS profile: L1 or FULL")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_secret": "********",
                "profile": "L1"
            }
        }


class AuditSessionResponse(BaseModel):
    """Audit session response."""

    session_id: int
    asset_id: Optional[int]
    asset_name: Optional[str]
    target_ip: str
    device_type: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    compliance: dict
    connection_error: Optional[str]

    class Config:
        from_attributes = True


class AuditResultResponse(BaseModel):
    """Individual audit result."""

    id: int
    check_number: str
    check_title: str
    severity: str
    level: str
    status: str
    evidence_snippet: Optional[str]
    checked_at: str

    class Config:
        from_attributes = True


# ========================= ROUTER =========================

router = APIRouter(prefix="/api/audit", tags=["Audit - Cisco CIS"])


@router.post("/cisco/execute", response_model=AuditSessionResponse)
def execute_cisco_audit(
    request: CiscoAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute CIS compliance audit on a Cisco device.

    **Workflow:**
    1. User selects asset from Asset List
    2. User enters SSH credentials (not stored)
    3. System connects via SSH and runs ~40 targeted commands
    4. System evaluates ~50 CIS security checks
    5. Results stored permanently in database
    6. Returns compliance summary

    **Permissions:** Requires AUDIT write permission

    **Note:** SSH credentials are used only for the audit session and never stored.
    """
    try:
        session = AuditService.execute_cisco_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            profile=request.profile
        )

        # Get formatted summary
        summary = AuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        return summary

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.get("/sessions/{session_id}", response_model=AuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get audit session details and compliance summary.

    **Permissions:** Requires AUDIT read permission
    """
    summary = AuditService.get_session_summary(db, session_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    return summary


@router.get("/sessions/{session_id}/results", response_model=List[AuditResultResponse])
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed results for all checks in an audit session.

    Returns list of individual CIS check results with:
    - Check ID and title
    - Compliance status (PASS/FAIL)
    - Evidence snippet
    - Severity level

    **Permissions:** Requires AUDIT read permission
    """
    # Verify session exists
    session = AuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    results = AuditService.get_audit_results(db, session_id)

    return [
        {
            "id": r.id,
            "check_number": r.check_number,
            "check_title": r.check_title,
            "severity": r.severity,
            "level": r.level,
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat()
        }
        for r in results
    ]


@router.get("/asset/{asset_id}/history", response_model=List[AuditSessionResponse])
def get_asset_audit_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get audit history for a specific asset.

    Returns most recent audit sessions (up to limit).

    **Permissions:** Requires AUDIT read permission
    """
    from app.models import Asset

    # Verify asset exists
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found"
        )

    sessions = AuditService.get_asset_audit_history(db, asset_id, limit)

    return [
        AuditService.get_session_summary(db, s.id)
        for s in sessions
    ]
