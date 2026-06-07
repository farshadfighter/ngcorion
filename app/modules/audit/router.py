"""
Shared Audit Router

Cross-family endpoints for fetching, checking status of, and deleting audit
sessions by ID — without needing to know the device family in advance.

These replace the old Cisco-only deprecated redirects so that Linux, Windows,
MongoDB, etc. sessions are handled correctly.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission, assert_session_access
from app.models import User, Asset, log_action
from app.models.audit import AuditSession, AuditResult, CheckStatus


router = APIRouter(prefix="/api/audit", tags=["Audit - Shared"])


# ========================= RESPONSE SCHEMAS =========================


class SharedAuditSessionResponse(BaseModel):
    session_id: int
    job_name: Optional[str] = None
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    target_ip: str
    device_type: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    compliance: dict
    connection_error: Optional[str] = None

    class Config:
        from_attributes = True


class SharedAuditResultResponse(BaseModel):
    id: int
    check_number: str
    check_title: str
    severity: str
    level: str
    status: str
    evidence_snippet: Optional[str] = None
    checked_at: str

    class Config:
        from_attributes = True


# ========================= HELPERS =========================


def _build_session_response(db: Session, session: AuditSession) -> dict:
    asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
    results = db.query(AuditResult).filter(AuditResult.session_id == session.id).all()

    passed = sum(1 for r in results if r.status == CheckStatus.PASS)
    failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
    errors = sum(1 for r in results if r.status == CheckStatus.ERROR)

    duration = None
    if session.completed_at and session.started_at:
        duration = (session.completed_at - session.started_at).total_seconds()

    return {
        "session_id": session.id,
        "job_name": session.job_name,
        "asset_id": session.asset_id,
        "asset_name": asset.asset_name if asset else None,
        "target_ip": session.target_ip,
        "device_type": session.device_type.value,
        "status": session.status,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "duration_seconds": duration,
        "compliance": {
            "total_checks": session.total_checks,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "compliance_pct": session.compliance_pct,
            "weighted_compliance_pct": session.weighted_compliance_pct,
        },
        "connection_error": session.connection_error,
    }


# ========================= ENDPOINTS =========================


@router.get("/sessions/{session_id}", response_model=SharedAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Get audit session details by ID, works for any device family."""
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    assert_session_access(session, current_user)
    return _build_session_response(db, session)


@router.get(
    "/sessions/{session_id}/results",
    response_model=List[SharedAuditResultResponse],
)
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """Get detailed check results for any audit session."""
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    assert_session_access(session, current_user)

    results = db.query(AuditResult).filter(AuditResult.session_id == session_id).all()
    return [
        {
            "id": r.id,
            "check_number": r.check_number or "",
            "check_title": r.check_title or "",
            "severity": r.severity or "medium",
            "level": r.level or "L1",
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat() if r.checked_at else "",
        }
        for r in results
    ]


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
):
    """Delete an audit session and all its results, works for any device family."""
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    assert_session_access(session, current_user)

    asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
    asset_name = asset.asset_name if asset else None

    try:
        db.delete(session)
        db.commit()

        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_session_deleted",
            module=f"{session.device_type.value}_audit",
            target_id=session_id,
            ip_address=session.target_ip,
            result="success",
            detail=f"Asset ID: {session.asset_id}, Asset Name: {asset_name}",
        )

        return {"message": f"Audit session {session_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete audit session: {str(e)}",
        )
