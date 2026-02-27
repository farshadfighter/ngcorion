"""
Windows Server Audit API Router

RESTful endpoints for CIS Windows Server security auditing.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, log_audit_executed, log_audit_session_deleted

from .service import WindowsAuditService


# ============================================================ #
#  Request / Response schemas                                   #
# ============================================================ #

class WindowsAuditRequest(BaseModel):
    """Request body for executing a Windows Server CIS audit."""

    asset_id: int = Field(..., description="Asset ID of the Windows Server host")
    windows_username: str = Field(
        ..., min_length=1,
        description="Windows admin account (domain\\user or local user, not stored)"
    )
    windows_password: str = Field(
        ..., min_length=1,
        description="Windows password (not stored)"
    )
    winrm_port: int = Field(
        5986, ge=1, le=65535,
        description="WinRM HTTPS port (default 5986)"
    )
    transport: str = Field(
        "ntlm",
        pattern="^(ntlm|kerberos|credssp|basic)$",
        description="WinRM transport: ntlm, kerberos, credssp, or basic"
    )
    profile: str = Field(
        "L1",
        pattern="^(L1|FULL)$",
        description="CIS profile: L1 (basic) or FULL (L1 + L2 checks)",
    )
    job_name: Optional[str] = Field(
        None, max_length=200,
        description="Optional human-readable label for this run"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "windows_username": "Administrator",
                "windows_password": "********",
                "winrm_port": 5986,
                "transport": "ntlm",
                "profile": "L1",
                "job_name": "Monthly Windows Server CIS Scan",
            }
        }


class WindowsAuditSessionResponse(BaseModel):
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


class WindowsAuditResultResponse(BaseModel):
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

router = APIRouter(
    prefix="/api/audit/windows",
    tags=["Audit - Windows Server CIS"],
)


@router.post("/execute", response_model=WindowsAuditSessionResponse)
def execute_windows_audit(
    request: WindowsAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
):
    """
    Execute a CIS compliance audit on a Windows Server instance.

    **Workflow:**
    1. Select the asset that hosts the Windows Server
    2. Provide Windows admin credentials (local or domain account)
    3. The system connects via WinRM (HTTPS) and runs PowerShell commands
       to collect security policy, registry, services, firewall, and audit data
    4. ~80+ CIS checks are evaluated against the collected data (L1 profile)
       or ~110+ checks (FULL profile including L2 checks)
    5. Results are stored permanently; a compliance summary is returned

    **Credentials:** Windows credentials are used only during the audit
    session and are never persisted.

    **Permissions:** Requires AUDIT write permission
    """
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = WindowsAuditService.execute_windows_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            windows_username=request.windows_username,
            windows_password=request.windows_password,
            winrm_port=request.winrm_port,
            transport=request.transport,
            profile=request.profile,
            job_name=request.job_name,
        )

        summary = WindowsAuditService.get_session_summary(db, session.id)
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
            "windows_cis",
            request.profile,
            session.compliance_pct,
            "success",
        )

        return summary

    except ValueError as exc:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "windows_cis", request.profile, None, "failed", str(exc),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    except Exception as exc:
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "windows_cis", request.profile, None, "failed", str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(exc)}",
        )


@router.get("/sessions", response_model=List[WindowsAuditSessionResponse])
def list_audit_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    List Windows Server audit sessions with pagination.

    Returns sessions ordered by most-recent first.

    **Permissions:** Requires AUDIT read permission
    """
    limit = min(limit, 100)
    sessions = WindowsAuditService.get_all_sessions(db, limit, offset)
    summaries = [WindowsAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


@router.get("/sessions/count")
def get_sessions_count(
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Total number of Windows Server audit sessions.

    **Permissions:** Requires AUDIT read permission
    """
    return {"total": WindowsAuditService.get_sessions_count(db)}


@router.get("/sessions/{session_id}", response_model=WindowsAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Get summary and compliance metrics for a single audit session.

    **Permissions:** Requires AUDIT read permission
    """
    summary = WindowsAuditService.get_session_summary(db, session_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )
    return summary


@router.get(
    "/sessions/{session_id}/results",
    response_model=List[WindowsAuditResultResponse],
)
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Get all individual CIS check results for an audit session.

    **Permissions:** Requires AUDIT read permission
    """
    session = WindowsAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )

    results = WindowsAuditService.get_audit_results(db, session_id)
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
    response_model=List[WindowsAuditSessionResponse],
)
def get_asset_audit_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db),
):
    """
    Get the Windows Server audit history for a specific asset.

    **Permissions:** Requires AUDIT read permission
    """
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )

    sessions = WindowsAuditService.get_asset_audit_history(db, asset_id, limit)
    summaries = [WindowsAuditService.get_session_summary(db, s.id) for s in sessions]
    return [s for s in summaries if s]


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
    session = WindowsAuditService.get_audit_session(db, session_id)
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
        WindowsAuditService.delete_audit_session(db, session_id)

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
