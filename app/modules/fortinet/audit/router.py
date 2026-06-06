"""
FortiGate Audit API Router

RESTful endpoints for FortiGate CIS security auditing.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import (get_current_user,
    require_permission,
    require_quota ,
    consume_quota_on_success ,
    check_quota_available)
from app.core.ssh_exceptions import SSHConnectionError
from app.models import User, log_action
from .service import FortinetAuditService


# ========================= SCHEMAS =========================

class FortinetAuditRequest(BaseModel):
    """Request to execute FortiGate audit."""

    asset_id: int = Field(..., description="Target FortiGate asset ID")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    vdom: Optional[str] = Field(None, description="Optional VDOM name (root if omitted)")
    profile: str = Field("L1", pattern="^(L1|L2|FULL)$", description="Audit profile")
    job_name: Optional[str] = Field(None, max_length=200, description="User-friendly job name")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "vdom": "root",
                "profile": "L1"
            }
        }


class VDOMDiscoveryRequest(BaseModel):
    """Request to discover VDOMs on FortiGate."""

    asset_id: int = Field(..., description="Target FortiGate asset ID")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22
            }
        }


class FortinetAuditSessionResponse(BaseModel):
    """Audit session response."""

    session_id: int
    job_name: Optional[str] = None
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


class FortinetAuditResultResponse(BaseModel):
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


class VDOMDiscoveryResponse(BaseModel):
    """VDOM discovery response."""

    asset_id: int
    asset_name: str
    target_ip: str
    vdoms: List[str]

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "asset_name": "fw-hq-01",
                "target_ip": "192.168.1.1",
                "vdoms": ["root", "VDOM_1", "VDOM_2"]
            }
        }


# ========================= ROUTER =========================

router = APIRouter(prefix="/api/audit/fortinet", tags=["Audit - FortiGate"])


@router.post("/execute", response_model=FortinetAuditSessionResponse,dependencies=[Depends(check_quota_available("audit"))])
def execute_fortinet_audit(
    request: Request,
    audit_request: FortinetAuditRequest,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
    #_quota_check: None = Depends(require_quota("audit"))
):
    """
    Execute CIS compliance audit on a FortiGate device.
    """
    # Get asset info for logging
    consume_quota = consume_quota_on_success("audit")
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = FortinetAuditService.execute_fortinet_audit(
            db=db,
            asset_id=audit_request.asset_id,
            user_id=current_user.id,
            ssh_username=audit_request.ssh_username,
            ssh_password=audit_request.ssh_password,
            vdom=audit_request.vdom,
            profile=audit_request.profile,
            job_name=audit_request.job_name,
            ssh_port=audit_request.ssh_port,
        )

        # Get formatted summary
        summary = FortinetAuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        # Log successful audit
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="fortinet_cis",
            target_id=audit_request.asset_id,
            result="success",
            detail=f"Session: {session.id}, Asset: {asset_name}, IP: {session.target_ip}, Profile: {audit_request.profile}, Compliance: {session.compliance_pct}%"
        )
        consume_quota(request)

        return summary

    except ValueError as e:
        # Log failed audit
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="fortinet_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}, Error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except SSHConnectionError as e:
        # SSH connect/auth failure — surface the precise status (401/502/503/504)
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="fortinet_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}, Error: {str(e)}"
        )
        raise HTTPException(status_code=e.http_status, detail=e.to_dict())
    except Exception as e:
        # Log failed audit
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="fortinet_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}, Error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.post("/vdoms/discover", response_model=VDOMDiscoveryResponse)
def discover_vdoms(
    request: Request,
    audit_request: VDOMDiscoveryRequest,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    """
    Discover VDOMs on a FortiGate device.
    """
    # Get asset info
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset ID {audit_request.asset_id} not found"
        )

    try:
        vdoms = FortinetAuditService.discover_vdoms(
            db=db,
            asset_id=audit_request.asset_id,
            ssh_username=audit_request.ssh_username,
            ssh_password=audit_request.ssh_password,
            ssh_port=audit_request.ssh_port,
        )

        return {
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "target_ip": asset.ip_address,
            "vdoms": vdoms
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"VDOM discovery failed: {str(e)}"
        )


@router.get("/sessions", response_model=List[FortinetAuditSessionResponse])
def list_audit_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    """
    List all FortiGate audit sessions with pagination.
    """
    from app.models.audit import DeviceType

    sessions = FortinetAuditService.get_all_sessions(
        db=db,
        device_type=DeviceType.FORTINET,
        limit=limit,
        offset=offset
    )

    summaries = []
    for session in sessions:
        summary = FortinetAuditService.get_session_summary(db, session.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.get("/sessions/count")
def get_fortinet_sessions_count(
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get total count of FortiGate audit sessions.
    """
    from app.models.audit import DeviceType
    count = FortinetAuditService.get_sessions_count(db, DeviceType.FORTINET)
    return {"total": count}


@router.get("/sessions/{session_id}", response_model=FortinetAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get FortiGate audit session details and compliance summary.
    """
    summary = FortinetAuditService.get_session_summary(db, session_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    return summary


@router.get("/sessions/{session_id}/results", response_model=List[FortinetAuditResultResponse])
def get_audit_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed results for all checks in an audit session.
    """
    # Verify session exists
    session = FortinetAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    results = FortinetAuditService.get_audit_results(db, session_id)

    # Convert to response format
    return [
        {
            "id": r.id,
            "check_number": r.check_number,
            "check_title": r.check_title,
            "severity": r.severity,
            "level": r.level or "L1",
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None
        }
        for r in results
    ]


@router.delete("/sessions/{session_id}")
def delete_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db)
):
    """
    Delete an audit session and all its results.
    """
    # Verify session exists
    session = FortinetAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    # Get asset info for logging before deletion
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
    asset_name = asset.asset_name if asset else None

    # Delete session
    deleted = FortinetAuditService.delete_audit_session(db, session_id)

    if deleted:
        # Log deletion
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_session_deleted",
            module="fortinet_cis",
            target_id=session.asset_id,
            result="success",
            detail=f"Deleted session: {session_id}, Asset: {asset_name}, IP: {session.target_ip}"
        )

        return {
            "message": f"Audit session {session_id} deleted successfully",
            "session_id": session_id
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete audit session"
        )
