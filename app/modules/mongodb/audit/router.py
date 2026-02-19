"""
MongoDB Audit API Router

RESTful endpoints for CIS MongoDB security auditing.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, log_audit_executed, log_audit_session_deleted

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
):
    """
    Execute a CIS compliance audit on a MongoDB instance.

    **Workflow:**
    1. Select the asset that hosts the MongoDB service
    2. Provide SSH credentials for the host OS and (optionally) MongoDB admin credentials
    3. The system SSHes into the host, reads configuration files, and runs
       MongoDB admin commands to collect security-relevant data
    4. ~25 CIS checks are evaluated against the collected data
    5. Results are stored permanently; a compliance summary is returned

    **Credentials:** SSH and MongoDB passwords are used only during the audit
    session and are never persisted.

    **Permissions:** Requires AUDIT write permission
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

        log_audit_executed(
            db,
            current_user.id,
            session.id,
            request.asset_id,
            asset_name,
            session.target_ip,
            "mongodb_cis",
            request.profile,
            session.compliance_pct,
            "success",
        )

        return summary

    except ValueError as exc:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "mongodb_cis", request.profile, None, "failed", str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    except Exception as exc:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "mongodb_cis", request.profile, None, "failed", str(exc),
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
    """
    List MongoDB audit sessions with pagination.

    Returns sessions ordered by most-recent first.

    **Permissions:** Requires AUDIT read permission
    """
    limit = min(limit, 100)
    sessions = MongoDBSHAuditService.get_all_sessions(db, limit, offset)
    return [
        MongoDBSHAuditService.get_session_summary(db, s.id)
        for s in sessions
        if MongoDBSHAuditService.get_session_summary(db, s.id)
    ]


@router.get("/sessions/count")
def get_sessions_count(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Total number of MongoDB audit sessions.

    Useful for client-side pagination.

    **Permissions:** Requires AUDIT read permission
    """
    return {"total": MongoDBSHAuditService.get_sessions_count(db)}


@router.get("/sessions/{session_id}", response_model=MongoDBSHAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Get summary and compliance metrics for a single audit session.

    **Permissions:** Requires AUDIT read permission
    """
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
    """
    Get all individual CIS check results for an audit session.

    Each result includes:
    - CIS check ID and title
    - Compliance status (PASS / FAIL)
    - Evidence snippet extracted from the configuration
    - Severity and CIS level

    **Permissions:** Requires AUDIT read permission
    """
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
            "level": r.level,
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat(),
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
    """
    Get the MongoDB audit history for a specific asset.

    Returns up to `limit` sessions ordered by most-recent first.

    **Permissions:** Requires AUDIT read permission
    """
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )

    sessions = MongoDBSHAuditService.get_asset_audit_history(db, asset_id, limit)
    return [
        MongoDBSHAuditService.get_session_summary(db, s.id)
        for s in sessions
        if MongoDBSHAuditService.get_session_summary(db, s.id)
    ]


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
):
    """
    Delete an audit session and all its associated results.

    This action is irreversible.

    **Permissions:** Requires AUDIT write permission
    """
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

        log_audit_session_deleted(
            db,
            current_user.id,
            session_id,
            session.asset_id,
            asset.asset_name if asset else None,
            session.target_ip,
        )

        return {"message": f"Audit session {session_id} deleted successfully"}

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete audit session: {str(exc)}",
        )
