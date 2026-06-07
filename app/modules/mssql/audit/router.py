"""
SQL Server Audit API Router

RESTful endpoints for CIS SQL Server security auditing.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
    assert_session_access,
    require_quota,
    check_quota_available,
    consume_quota_on_success)

from app.models import User, log_action

from .service import MSSQLAuditService


class MSSQLAuditRequest(BaseModel):
    """Request body for executing a SQL Server CIS audit."""

    asset_id: int = Field(..., description="Asset ID of the SQL Server host")
    mssql_username: str = Field(
        ..., min_length=1, description="SQL Server login (sa or sysadmin, not stored)"
    )
    mssql_password: str = Field(
        ..., min_length=1, description="SQL Server password (not stored)"
    )
    mssql_port: int = Field(
        1433, ge=1, le=65535, description="SQL Server TCP port (default 1433)"
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
                "mssql_username": "sa",
                "mssql_password": "********",
                "mssql_port": 1433,
                "profile": "L1",
                "job_name": "Monthly SQL Server CIS Scan",
            }
        }


class MSSQLAuditSessionResponse(BaseModel):
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


class MSSQLAuditResultResponse(BaseModel):
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


router = APIRouter(prefix="/api/audit/mssql", tags=["Audit - SQL Server CIS"])


@router.post("/execute", response_model=MSSQLAuditSessionResponse, dependencies=[Depends(check_quota_available("audit"))])
def execute_mssql_audit(
    audit_request: MSSQLAuditRequest,
    request: Request,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
    #_quota_check: None = Depends(require_quota("audit"))
):
    consume_quota = consume_quota_on_success("audit")
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = MSSQLAuditService.execute_mssql_audit(
            db=db,
            asset_id=audit_request.asset_id,
            user_id=current_user.id,
            mssql_username=audit_request.mssql_username,
            mssql_password=audit_request.mssql_password,
            mssql_port=audit_request.mssql_port,
            profile=audit_request.profile,
            job_name=audit_request.job_name,
        )

        summary = MSSQLAuditService.get_session_summary(db, session.id)
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary",
            )

        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mssql_cis",
            target_id=session.id,
            result="success",
            detail=f"Asset ID: {audit_request.asset_id}, Name: {asset_name}, IP: {session.target_ip}, Profile: {audit_request.profile}, Compliance: {session.compliance_pct}%"
        )

        consume_quota(request)

        return summary

    except ValueError as exc:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mssql_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    except PermissionError as exc:
        # SQL Server authentication failed (mssql_client raises PermissionError)
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mssql_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_type": "authentication_error", "message": "SQL Server authentication failed — check the username and password."},
        )
    except ConnectionError as exc:
        # SQL Server connect/timeout (mssql_client raises ConnectionError)
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mssql_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error_type": "connection_error", "message": "Could not connect to the device — check the host, port, and network."},
        )
    except Exception as exc:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="mssql_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(exc)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(exc)}",
        )


@router.get("/sessions", response_model=List[MSSQLAuditSessionResponse])
def list_audit_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    limit = min(limit, 100)
    sessions = MSSQLAuditService.get_all_sessions(db, limit, offset)
    summaries = [MSSQLAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


@router.get("/sessions/count")
def get_sessions_count(
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    return {"total": MSSQLAuditService.get_sessions_count(db)}


@router.get("/sessions/{session_id}", response_model=MSSQLAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    summary = MSSQLAuditService.get_session_summary(db, session_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )
    assert_session_access(MSSQLAuditService.get_audit_session(db, session_id), current_user)
    return summary


@router.get(
    "/sessions/{session_id}/results",
    response_model=List[MSSQLAuditResultResponse],
)
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    session = MSSQLAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)

    results = MSSQLAuditService.get_audit_results(db, session_id)
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
    response_model=List[MSSQLAuditSessionResponse],
)
def get_asset_audit_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )

    sessions = MSSQLAuditService.get_asset_audit_history(db, asset_id, limit)
    summaries = [MSSQLAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
):
    session = MSSQLAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)

    from app.models import Asset

    asset = (
        db.query(Asset).filter(Asset.id == session.asset_id).first()
        if session.asset_id
        else None
    )

    try:
        MSSQLAuditService.delete_audit_session(db, session_id)

        log_action(
            db=db,
            user_id=current_user.id,
            action="delete_audit_session",
            module="mssql_cis",
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
