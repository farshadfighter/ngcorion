"""
Linux Audit API Router

RESTful endpoints for Linux CIS security auditing.
Supports Ubuntu 22.04, Ubuntu 24.04, and Rocky Linux 8.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, log_audit_executed, log_audit_session_deleted
from .service import LinuxAuditService


# ========================= SCHEMAS =========================

class LinuxAuditRequest(BaseModel):
    """Request to execute Linux CIS audit."""

    asset_id: int = Field(..., description="Target asset ID from Asset List")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")
    profile: str = Field("L1", pattern="^(L1|FULL)$", description="CIS profile: L1 or FULL")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "sudo_password": "********",
                "profile": "L1"
            }
        }


class LinuxAuditSessionResponse(BaseModel):
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


class LinuxAuditResultResponse(BaseModel):
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


class LinuxFailedCheckResponse(BaseModel):
    """Failed check response."""

    id: int
    check_number: str
    check_title: str
    severity: str
    level: str
    evidence_snippet: Optional[str]

    class Config:
        from_attributes = True


class LinuxAuditStatisticsResponse(BaseModel):
    """Audit statistics response."""

    total_sessions: int
    by_status: dict
    success_rate: float
    average_compliance: float
    total_checks_run: int
    total_failures: int
    most_recent_session: Optional[dict]

    class Config:
        from_attributes = True


# ========================= ROUTER =========================

router = APIRouter(prefix="/api/audit/linux", tags=["Audit - Linux CIS"])


@router.post("/execute", response_model=LinuxAuditSessionResponse)
def execute_linux_audit(
    request: LinuxAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute CIS compliance audit on a Linux server.

    **Supported Distributions:**
    - Ubuntu 22.04 LTS
    - Ubuntu 24.04 LTS
    - Rocky Linux 8

    **Workflow:**
    1. User selects asset from Asset List
    2. User enters SSH credentials (not stored)
    3. System connects via SSH and detects distribution
    4. System runs 100+ targeted commands
    5. System evaluates 60+ CIS security checks
    6. Results stored permanently in database
    7. Returns compliance summary

    **Permissions:** Requires AUDIT write permission

    **Note:** SSH credentials are used only for the audit session and never stored.
    The sudo password defaults to the SSH password if not provided.
    """
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = LinuxAuditService.execute_linux_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            sudo_password=request.sudo_password,
            profile=request.profile
        )

        summary = LinuxAuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        log_audit_executed(
            db, current_user.id, session.id, request.asset_id, asset_name,
            session.target_ip, "linux_cis", request.profile,
            session.compliance_pct, "success"
        )

        return summary

    except ValueError as e:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "linux_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "linux_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.get("/sessions", response_model=List[LinuxAuditSessionResponse])
def list_linux_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    List all Linux audit sessions with pagination.

    **Query Parameters:**
    - limit: Maximum number of sessions to return (default: 50, max: 100)
    - offset: Number of sessions to skip (default: 0)

    **Permissions:** Requires AUDIT read permission
    """
    limit = min(limit, 100)
    sessions = LinuxAuditService.get_linux_sessions(db, limit, offset)

    summaries = []
    for s in sessions:
        summary = LinuxAuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.get("/sessions/count")
def get_linux_sessions_count(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get total count of Linux audit sessions.

    **Permissions:** Requires AUDIT read permission
    """
    count = LinuxAuditService.get_linux_sessions_count(db)
    return {"total": count}


@router.get("/sessions/{session_id}", response_model=LinuxAuditSessionResponse)
def get_linux_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get Linux audit session details and compliance summary.

    **Permissions:** Requires AUDIT read permission
    """
    summary = LinuxAuditService.get_session_summary(db, session_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    # Verify it's a Linux audit
    session = LinuxAuditService.get_audit_session(db, session_id)
    if session.device_type.value != "linux":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session {session_id} is not a Linux audit"
        )

    return summary


@router.get("/sessions/{session_id}/results", response_model=List[LinuxAuditResultResponse])
def get_linux_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed results for all checks in a Linux audit session.

    **Permissions:** Requires AUDIT read permission
    """
    session = LinuxAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    results = LinuxAuditService.get_audit_results(db, session_id)

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


@router.get("/sessions/{session_id}/failed", response_model=List[LinuxFailedCheckResponse])
def get_linux_failed_checks(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get only failed checks for a Linux audit session.

    Useful for hardening workflows - returns only the checks that need to be fixed.

    **Permissions:** Requires AUDIT read permission
    """
    session = LinuxAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    failed = LinuxAuditService.get_failed_checks(db, session_id)
    return failed


@router.get("/asset/{asset_id}/history", response_model=List[LinuxAuditSessionResponse])
def get_asset_linux_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get Linux audit history for a specific asset.

    **Permissions:** Requires AUDIT read permission
    """
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found"
        )

    sessions = LinuxAuditService.get_asset_linux_history(db, asset_id, limit)

    summaries = []
    for s in sessions:
        summary = LinuxAuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.delete("/sessions/{session_id}")
def delete_linux_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Delete a Linux audit session and all its results.

    **Permissions:** Requires AUDIT write permission
    """
    session = LinuxAuditService.get_audit_session(db, session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
    asset_name = asset.asset_name if asset else None

    try:
        LinuxAuditService.delete_audit_session(db, session_id)

        log_audit_session_deleted(
            db, current_user.id, session_id, session.asset_id,
            asset_name, session.target_ip
        )

        return {"message": f"Audit session {session_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete audit session: {str(e)}"
        )


@router.get("/statistics", response_model=LinuxAuditStatisticsResponse)
def get_linux_statistics(
    asset_id: Optional[int] = None,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive statistics about Linux audit sessions.

    **Query Parameters:**
    - asset_id: Optional filter by asset

    **Permissions:** Requires AUDIT read permission
    """
    stats = LinuxAuditService.get_audit_statistics(db, asset_id)
    return stats


@router.get("/supported-distros")
def get_supported_distros(
    current_user: User = Depends(require_permission("AUDIT", "read"))
):
    """
    Get list of supported Linux distributions.

    **Permissions:** Requires AUDIT read permission
    """
    return {
        "supported_distributions": [
            {
                "id": "ubuntu",
                "name": "Ubuntu",
                "versions": ["22.04 LTS", "24.04 LTS"],
                "benchmark": "CIS Ubuntu Linux Benchmark"
            },
            {
                "id": "rocky",
                "name": "Rocky Linux",
                "versions": ["8", "9"],
                "benchmark": "CIS Rocky Linux Benchmark"
            },
            {
                "id": "rhel",
                "name": "Red Hat Enterprise Linux",
                "versions": ["8", "9"],
                "benchmark": "CIS RHEL Linux Benchmark"
            }
        ],
        "notes": [
            "Distribution is auto-detected during audit",
            "CIS rules are automatically adjusted for each distribution",
            "Ubuntu uses AppArmor, Rocky/RHEL uses SELinux"
        ]
    }
