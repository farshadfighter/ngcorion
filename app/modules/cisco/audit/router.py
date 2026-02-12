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
from app.models import User, log_audit_executed, log_audit_session_deleted
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


class CiscoAuditSessionResponse(BaseModel):
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


class CiscoAuditResultResponse(BaseModel):
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


@router.post("/cisco/execute", response_model=CiscoAuditSessionResponse)
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
    # Get asset info for logging
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

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

        # Log successful audit
        log_audit_executed(
            db, current_user.id, session.id, request.asset_id, asset_name,
            session.target_ip, "cisco_cis", request.profile,
            session.compliance_pct, "success"
        )

        return summary

    except ValueError as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "cisco_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "cisco_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.get("/sessions", response_model=List[CiscoAuditSessionResponse])
def list_audit_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    List all audit sessions with pagination.

    Returns most recent audit sessions.

    **Query Parameters:**
    - limit: Maximum number of sessions to return (default: 50, max: 100)
    - offset: Number of sessions to skip (default: 0)

    **Permissions:** Requires AUDIT read permission
    """
    # Cap limit at 100 to prevent excessive queries
    limit = min(limit, 100)

    sessions = AuditService.get_all_sessions(db, limit, offset)

    # Build summaries efficiently (single call per session)
    summaries = []
    for s in sessions:
        summary = AuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.get("/sessions/count")
def get_audit_sessions_count(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get total count of audit sessions.

    Useful for pagination when combined with the sessions list endpoint.

    **Permissions:** Requires AUDIT read permission
    """
    count = AuditService.get_sessions_count(db)
    return {"total": count}


@router.get("/sessions/{session_id}", response_model=CiscoAuditSessionResponse)
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


@router.get("/sessions/{session_id}/results", response_model=List[CiscoAuditResultResponse])
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


@router.get("/asset/{asset_id}/history", response_model=List[CiscoAuditSessionResponse])
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

    # Build summaries efficiently
    summaries = []
    for s in sessions:
        summary = AuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Delete an audit session and all its results.

    **Permissions:** Requires AUDIT write permission

    **Note:** This permanently deletes the audit session and all associated results.
    """
    session = AuditService.get_audit_session(db, session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    # Get session info for logging before deletion
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
    asset_name = asset.asset_name if asset else None

    try:
        AuditService.delete_audit_session(db, session_id)

        # Log successful deletion
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


# ========================= CIS BENCHMARK TABLE ENDPOINTS =========================

class CISBenchmarkTableSection(BaseModel):
    """Single row in the CIS Benchmark table."""
    section: str = Field(..., description="CIS section number (e.g., '1.1.1')")
    recommendation: str = Field(..., description="CIS recommendation text")
    set_correctly: Optional[bool] = Field(None, description="True=Yes, False=No, None=Not evaluated")


class CISBenchmarkTableSummary(BaseModel):
    """Summary statistics for CIS Benchmark compliance."""
    total_checks: int
    passed: int
    failed: int
    compliance_percentage: float


class CISBenchmarkTableResponse(BaseModel):
    """Full CIS Benchmark table response matching PDF format."""
    session_id: int
    asset_id: Optional[int]
    asset_name: Optional[str]
    target_ip: str
    audit_date: Optional[str]
    benchmark_version: str
    sections: List[CISBenchmarkTableSection]
    summary: CISBenchmarkTableSummary

    class Config:
        from_attributes = True


@router.get("/sessions/{session_id}/cis-table", response_model=CISBenchmarkTableResponse)
def get_cis_benchmark_table(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get CIS Benchmark table format results for an audit session.

    Returns results in the official CIS Benchmark table format (pages 210-213)
    with section numbers (1.1.1, 1.1.2, etc.) and Yes/No checkmarks.

    **Permissions:** Requires AUDIT read permission
    """
    table = AuditService.get_cis_benchmark_table(db, session_id)

    if not table:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    return table


class CISBenchmarkAuditRequest(BaseModel):
    """Request to execute CIS Benchmark audit."""
    asset_id: int = Field(..., description="Target asset ID from Asset List")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    ssh_secret: Optional[str] = Field(None, description="Enable secret (optional, not stored)")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_secret": "********"
            }
        }


@router.post("/cisco/cis-benchmark/execute", response_model=CISBenchmarkTableResponse)
def execute_cis_benchmark_audit(
    request: CISBenchmarkAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute CIS Benchmark audit on a Cisco device.

    Uses the official CIS Cisco IOS 15 Benchmark v4.1.1 section numbers
    (1.1.1, 1.1.2, etc.) and returns results in the PDF table format.

    **Workflow:**
    1. User selects asset from Asset List
    2. User enters SSH credentials (not stored)
    3. System connects via SSH and runs targeted commands
    4. System evaluates 70+ CIS security checks
    5. Results stored permanently in database
    6. Returns CIS Benchmark table with Yes/No checkmarks

    **Response:** CIS Benchmark table format with compliance percentage

    **Permissions:** Requires AUDIT write permission

    **Note:** SSH credentials are used only for the audit session and never stored.
    """
    # Get asset info for logging
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = AuditService.execute_cis_benchmark_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret
        )

        # Return results in CIS Benchmark table format
        table = AuditService.get_cis_benchmark_table(db, session.id)

        if not table:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate CIS Benchmark table"
            )

        # Log successful audit
        log_audit_executed(
            db, current_user.id, session.id, request.asset_id, asset_name,
            session.target_ip, "cis_benchmark", "FULL",
            session.compliance_pct, "success"
        )

        return table

    except ValueError as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "cis_benchmark", "FULL", None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "cis_benchmark", "FULL", None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CIS Benchmark audit failed: {str(e)}"
        )
