"""
FortiGate Audit API Router

RESTful endpoints for FortiGate CIS security auditing.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, log_audit_executed, log_audit_session_deleted
from .service import FortinetAuditService


# ========================= SCHEMAS =========================

class FortinetAuditRequest(BaseModel):
    """Request to execute FortiGate audit."""

    asset_id: int = Field(..., description="Target FortiGate asset ID")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    vdom: Optional[str] = Field(None, description="Optional VDOM name (root if omitted)")
    profile: str = Field("L1", pattern="^(L1|L2|FULL)$", description="Audit profile")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "ssh_username": "admin",
                "ssh_password": "********",
                "vdom": "root",
                "profile": "L1"
            }
        }


class VDOMDiscoveryRequest(BaseModel):
    """Request to discover VDOMs on FortiGate."""

    asset_id: int = Field(..., description="Target FortiGate asset ID")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 42,
                "ssh_username": "admin",
                "ssh_password": "********"
            }
        }


class FortinetAuditSessionResponse(BaseModel):
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


@router.post("/execute", response_model=FortinetAuditSessionResponse)
def execute_fortinet_audit(
    request: FortinetAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Execute CIS compliance audit on a FortiGate device.

    **Workflow:**
    1. User selects FortiGate asset from Asset List
    2. User enters SSH credentials (HTTPS encrypted, not stored)
    3. User optionally selects VDOM (defaults to root/global context)
    4. System connects via SSH
    5. System collects configuration and status commands
    6. System evaluates 65+ CIS security checks
    7. Results stored permanently in database
    8. Returns compliance summary

    **VDOM Support:**
    - If `vdom` is specified, audit runs in that VDOM context
    - If `vdom` is null/omitted, audit runs in global/root context
    - Use `/vdoms/discover` endpoint first to list available VDOMs

    **Permissions:** Requires AUDIT write permission

    **Note:** SSH credentials are used only for the audit session and never stored.
    """
    # Get asset info for logging
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = FortinetAuditService.execute_fortinet_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            vdom=request.vdom,
            profile=request.profile
        )

        # Get formatted summary
        summary = FortinetAuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        # Log successful audit
        log_audit_executed(
            db, current_user.id, session.id, request.asset_id, asset_name,
            session.target_ip, "fortinet_cis", request.profile,
            session.compliance_pct, "success"
        )

        return summary

    except ValueError as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "fortinet_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        # Log failed audit
        log_audit_executed(
            db, current_user.id, None, request.asset_id, asset_name,
            target_ip, "fortinet_cis", request.profile, None, "failed", str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.post("/vdoms/discover", response_model=VDOMDiscoveryResponse)
def discover_vdoms(
    request: VDOMDiscoveryRequest,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Discover VDOMs on a FortiGate device.

    **Use Case:**
    - Frontend calls this endpoint before executing an audit
    - Displays VDOM list in a dropdown selector
    - User can then choose which VDOM to audit

    **Workflow:**
    1. Establishes temporary SSH connection
    2. Executes `config global` and `get vdom` commands
    3. Parses VDOM list
    4. Disconnects
    5. Returns VDOM names

    **Permissions:** Requires AUDIT read permission

    **Note:** SSH credentials are used only for discovery and never stored.
    """
    # Get asset info
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset ID {request.asset_id} not found"
        )

    try:
        vdoms = FortinetAuditService.discover_vdoms(
            db=db,
            asset_id=request.asset_id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password
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
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    List all FortiGate audit sessions with pagination.

    **Permissions:** Requires AUDIT read permission

    Returns sessions in descending order (most recent first).
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


@router.get("/sessions/{session_id}", response_model=FortinetAuditSessionResponse)
def get_audit_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get FortiGate audit session details and compliance summary.

    **Permissions:** Requires AUDIT read permission

    Returns:
    - Session metadata (timestamps, status, etc.)
    - Compliance metrics (total, passed, failed, percentage)
    - Asset information
    - Error details (if failed)
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
    current_user: User = Depends(require_permission("AUDIT", "read")),
    db: Session = Depends(get_db)
):
    """
    Get detailed results for all checks in an audit session.

    **Permissions:** Requires AUDIT read permission

    Returns:
    - List of all security control evaluations
    - Each result includes:
      - Control ID (e.g., FG-BL-001)
      - Title and severity
      - Pass/Fail status
      - Evidence snippet
      - CIS Benchmark mapping
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
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    """
    Delete an audit session and all its results.

    **Permissions:** Requires AUDIT write permission

    **Warning:** This action is permanent and cannot be undone.
    """
    # Verify session exists
    session = FortinetAuditService.get_audit_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

    # Delete session
    deleted = FortinetAuditService.delete_audit_session(db, session_id)

    if deleted:
        # Log deletion
        log_audit_session_deleted(db, current_user.id, session_id, session.target_ip)

        return {
            "message": f"Audit session {session_id} deleted successfully",
            "session_id": session_id
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete audit session"
        )
