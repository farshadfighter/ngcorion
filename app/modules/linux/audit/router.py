"""
Linux Audit API Router

RESTful endpoints for Linux CIS security auditing.
Supports:
  Ubuntu:     20.04 LTS, 22.04 LTS, 24.04 LTS
  RHEL:       8, 9, 10
  Rocky:      8, 9, 10
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import( get_current_user, require_permission, require_quota,
    check_quota_available,
    consume_quota_on_success)

from app.core.ssh_exceptions import SSHConnectionError
from app.models import User, log_action
from .service import LinuxAuditService


# ========================= SCHEMAS =========================

class LinuxAuditRequest(BaseModel):
    """Request to execute Linux CIS audit."""

    asset_id: int = Field(..., description="Target asset ID from Asset List")
    ssh_username: str = Field(..., min_length=1, description="SSH username (not stored)")
    ssh_password: str = Field(..., min_length=1, description="SSH password (not stored)")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = Field(None, description="Sudo password (defaults to SSH password)")
    profile: str = Field("L1", pattern="^(L1|FULL)$", description="CIS profile: L1 or FULL")
    job_name: Optional[str] = Field(None, max_length=200, description="User-friendly job name")
    sub_device_type: Optional[str] = Field(None, description="UI device type variant, e.g. linux-ubuntu-22")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "sudo_password": "********",
                "profile": "L1"
            }
        }


class LinuxAuditSessionResponse(BaseModel):
    """Audit session response."""

    session_id: int
    job_name: Optional[str] = None
    asset_id: Optional[int]
    asset_name: Optional[str]
    target_ip: str
    device_type: str
    sub_device_type: Optional[str] = None
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


@router.post("/execute", response_model=LinuxAuditSessionResponse, dependencies=[Depends(check_quota_available("audit"))])
def execute_linux_audit(
    audit_request: LinuxAuditRequest,
    request: Request,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
    #_quota_check: None = Depends(require_quota("audit"))
):
    """
    Execute CIS compliance audit on a Linux server.
    ...
    """
    consume_quota = consume_quota_on_success("audit")
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = LinuxAuditService.execute_linux_audit(
            db=db,
            asset_id=audit_request.asset_id,
            user_id=current_user.id,
            ssh_username=audit_request.ssh_username,
            ssh_password=audit_request.ssh_password,
            sudo_password=audit_request.sudo_password,
            profile=audit_request.profile,
            job_name=audit_request.job_name,
            ssh_port=audit_request.ssh_port,
            sub_device_type=audit_request.sub_device_type,
        )

        summary = LinuxAuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="linux_cis",
            target_id=session.id,
            result="success",
            detail=f"Asset ID: {audit_request.asset_id}, Name: {asset_name}, IP: {session.target_ip}, Profile: {audit_request.profile}, Compliance: {session.compliance_pct}%"
        )

        consume_quota(request)

        return summary

    except ValueError as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="linux_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}"
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
            action="execute_audit",
            module="linux_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}"
        )
        raise HTTPException(status_code=e.http_status, detail=e.to_dict())
    except Exception as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="linux_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}"
        )


@router.get("/sessions", response_model=List[LinuxAuditSessionResponse])
def list_linux_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
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
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    count = LinuxAuditService.get_linux_sessions_count(db)
    return {"total": count}


@router.get("/sessions/{session_id}", response_model=LinuxAuditSessionResponse)
def get_linux_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    summary = LinuxAuditService.get_session_summary(db, session_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found"
        )

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
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
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
            "level": r.level or "L1",
            "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None
        }
        for r in results
    ]


@router.get("/sessions/{session_id}/failed", response_model=List[LinuxFailedCheckResponse])
def get_linux_failed_checks(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
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
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
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
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db)
):
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

        log_action(
            db=db,
            user_id=current_user.id,
            action="delete_audit_session",
            module="linux_cis",
            target_id=session_id,
            result="success",
            detail=f"Deleted session for Asset ID: {session.asset_id}, Name: {asset_name}, IP: {session.target_ip}"
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
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db)
):
    stats = LinuxAuditService.get_audit_statistics(db, asset_id)
    return stats


@router.get("/supported-distros")
def get_supported_distros(
    current_user: User = Depends(require_permission("AUDITING", "read"))
):
    return {
        "supported_distributions": [
            {
                "id": "ubuntu",
                "name": "Ubuntu",
                "versions": ["20.04 LTS", "22.04 LTS", "24.04 LTS"],
                "benchmark": "CIS Ubuntu Linux Benchmark",
                "mac": "AppArmor"
            },
            {
                "id": "rocky",
                "name": "Rocky Linux",
                "versions": ["8", "9", "10"],
                "benchmark": "CIS Rocky Linux Benchmark",
                "mac": "SELinux"
            },
            {
                "id": "rhel",
                "name": "Red Hat Enterprise Linux",
                "versions": ["8", "9", "10"],
                "benchmark": "CIS Red Hat Enterprise Linux Benchmark",
                "mac": "SELinux",
                "rhel10_notes": [
                    "Crypto policies enforced (no LEGACY/SHA1)",
                    "authselect for PAM management",
                    "pam_faillock replaces deprecated pam_tally2",
                    "dnf5 as default package manager",
                    "nftables as firewalld backend"
                ]
            }
        ],
        "notes": [
            "Distribution is auto-detected during audit",
            "CIS rules are automatically adjusted for each distribution",
            "Ubuntu uses AppArmor, Rocky/RHEL uses SELinux",
            "RHEL 10 includes additional checks: crypto-policies, authselect, SELinux enforcement, sudo hardening"
        ]
    }
