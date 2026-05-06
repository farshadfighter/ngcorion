"""
MongoDB Audit API Router

RESTful endpoints for CIS MongoDB security auditing.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission, require_quota
from app.models import User, log_action

from .service import MongoDBSHAuditService


# ============================================================ #
#  Request / Response schemas                                   #
# ============================================================ #

class MongoDBSHAuditRequest(BaseModel):
    """Request body for executing a MongoDB CIS audit."""

    asset_id: int = Field(..., description="Asset ID of the MongoDB host server")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    mongo_username: Optional[str] = Field(
        None, description="MongoDB admin username (not stored)"
    )
    mongo_password: Optional[str] = Field(
        None, description="MongoDB admin password (not stored)"
    )
    mongo_port: int = Field(
        27017, ge=1, le=65535, description="MongoDB listen port (default 27017)"
    )
    profile: str = Field(
        "L1",
        pattern="^(L1|FULL)$",
        description="CIS profile: L1 (basic) or FULL (L1 + L2 checks)",
    )
    job_name: Optional[str] = Field(
        None, max_length=200, description="Optional human-readable label for this run"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "ssh_username": "ubuntu",
                "ssh_password": "********",
                "mongo_username": "admin",
                "mongo_password": "********",
                "mongo_port": 27017,
                "profile": "L1",
                "job_name": "Monthly MongoDB CIS Scan",
            }
        }


class MongoDBSHAuditSessionResponse(BaseModel):
    """Audit session summary returned after execution or on retrieval."""

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


class MongoDBSHAuditResultResponse(BaseModel):
    """Individual CIS check result."""

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


# ============================================================ #
#  Router                                                       #
# ============================================================ #

router = APIRouter(prefix="/api/audit/mongodb", tags=["Audit - MongoDB CIS"])


@router.post("/execute", response_model=MongoDBSHAuditSessionResponse)
def execute_mongodb_audit(
    request: MongoDBSHAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))
):
    """
    Execute a CIS compliance audit on a MongoDB instance.
    ...
    """
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = MongoDBSHAuditService.execute_mongodb_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            mongo_username=request.mongo_username,
            mongo_password=request.mongo_password,
            mongo_port=request.mongo_port,
            profile=request.profile,
            job_name=request.job_name,
        )

        summary = MongoDBSHAuditService.get_session_summary(db, session.id)
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary",
            )

        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mongodb_cis",
            target_id=session.id,
            result="success",
            detail=f"Asset ID: {request.asset_id}, Name: {asset_name}, IP: {session.target_ip}, Profile: {request.profile}, Compliance: {session.compliance_pct}%"
        )

        return summary

    except ValueError as exc:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mongodb_cis",
            target_id=request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    except Exception as exc:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mongodb_cis",
            target_id=request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(exc)}",
        )


@router.get("/sessions", response_model=List[MongoDBSHAuditSessionResponse])
def list_audit_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    limit = min(limit, 100)
    sessions = MongoDBSHAuditService.get_all_sessions(db, limit, offset)
    summaries = [MongoDBSHAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


@router.get("/sessions/count")
def get_sessions_count(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    return {"total": MongoDBSHAuditService.get_sessions_count(db)}


@router.get("/sessions/{session_id}", response_model=MongoDBSHAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    summary = MongoDBSHAuditService.get_session_summary(db, session_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )
    return summary


@router.get(
    "/sessions/{session_id}/results",
    response_model=List[MongoDBSHAuditResultResponse],
)
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    session = MongoDBSHAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )

    results = MongoDBSHAuditService.get_audit_results(db, session_id)
    return [
        {
            "id": r.id,
            "check_number": r.check_number,
            "check_title": r.check_title,
            "severity": r.severity,
            "level": r.level or "L1",
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None,
        }
        for r in results
    ]


@router.get(
    "/asset/{asset_id}/history",
    response_model=List[MongoDBSHAuditSessionResponse],
)
def get_asset_audit_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )

    sessions = MongoDBSHAuditService.get_asset_audit_history(db, asset_id, limit)
    summaries = [MongoDBSHAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
):
    session = MongoDBSHAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )

    from app.models import Asset

    asset = (
        db.query(Asset).filter(Asset.id == session.asset_id).first()
        if session.asset_id
        else None
    )

    try:
        MongoDBSHAuditService.delete_audit_session(db, session_id)

        log_action(
            db=db,
            user_id=current_user.id,
            action="delete_audit_session",
            module="mongodb_cis",
            target_id=session_id,
            result="success",
            detail=f"Deleted session for Asset ID: {session.asset_id}, Name: {asset.asset_name if asset else 'None'}, IP: {session.target_ip}"
        )

        return {"message": f"Audit session {session_id} deleted successfully"}

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete audit session: {str(exc)}",
        )
