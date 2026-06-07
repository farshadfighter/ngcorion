"""
Apache Audit API Router

RESTful endpoints for Apache HTTP Server CIS security auditing.
Supports Apache 2.4.x on Ubuntu/Debian and RHEL/Rocky/CentOS.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    require_permission,
    assert_session_access,
    require_quota,
    check_quota_available,
    consume_quota_on_success,
)
from app.core.ssh_exceptions import SSHConnectionError
from app.models import User, log_action
from .service import ApacheAuditService, ApacheAuditNotInstalledError


# ========================= SCHEMAS =========================


class ApacheAuditRequest(BaseModel):
    """Request to execute Apache CIS audit."""

    asset_id: int = Field(..., description="Target asset ID from Asset List")
    ssh_username: str = Field(
        ..., min_length=1, description="SSH username (not stored)"
    )
    ssh_password: str = Field(
        ..., min_length=1, description="SSH password (not stored)"
    )
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port (default 22)")
    sudo_password: Optional[str] = Field(
        None, description="Sudo password (defaults to SSH password)"
    )
    profile: str = Field(
        "L1", pattern="^(L1|FULL)$", description="CIS profile: L1 or FULL"
    )
    job_name: Optional[str] = Field(
        None, max_length=200, description="User-friendly job name"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": 25,
                "ssh_username": "admin",
                "ssh_password": "********",
                "ssh_port": 22,
                "sudo_password": "********",
                "profile": "L1",
            }
        }


class ApacheAuditSessionResponse(BaseModel):
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


class ApacheAuditResultResponse(BaseModel):
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


class ApacheFailedCheckResponse(BaseModel):
    """Failed check response."""

    id: int
    check_number: str
    check_title: str
    severity: str
    level: str
    evidence_snippet: Optional[str]

    class Config:
        from_attributes = True


class ApacheAuditStatisticsResponse(BaseModel):
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

router = APIRouter(prefix="/api/audit/apache", tags=["Audit - Apache CIS"])


@router.post(
    "/execute",
    response_model=ApacheAuditSessionResponse,
    dependencies=[Depends(check_quota_available("audit"))],
)
def execute_apache_audit(
    audit_request: ApacheAuditRequest,
    request: Request,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
    # _quota_check: None = Depends(require_quota("audit"))
):
    """
    Execute CIS compliance audit on Apache HTTP Server.

    **Supported:**
    - Apache HTTP Server 2.4.x
    - Ubuntu 22.04/24.04 (apache2)
    - RHEL/Rocky/CentOS 8/9 (httpd)

    **Workflow:**
    1. User selects asset from Asset List
    2. User enters SSH credentials (not stored)
    3. System connects via SSH and detects distribution
    4. System verifies Apache is installed
    5. System runs 50+ targeted commands
    6. System evaluates 25+ CIS security checks
    7. Results stored permanently in database
    8. Returns compliance summary

    **Permissions:** Requires AUDIT write permission

    **Note:** SSH credentials are used only for the audit session and never stored.
    The sudo password defaults to the SSH password if not provided.
    """
    consume_quota = consume_quota_on_success("audit")
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = ApacheAuditService.execute_apache_audit(
            db=db,
            asset_id=audit_request.asset_id,
            user_id=current_user.id,
            ssh_username=audit_request.ssh_username,
            ssh_password=audit_request.ssh_password,
            sudo_password=audit_request.sudo_password,
            profile=audit_request.profile,
            job_name=audit_request.job_name,
            ssh_port=audit_request.ssh_port,
        )

        summary = ApacheAuditService.get_session_summary(db, session.id)

        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary",
            )

        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="apache_cis",
            target_id=session.id,
            result="success",
            detail=f"Asset ID: {audit_request.asset_id}, Name: {asset_name}, IP: {session.target_ip}, Profile: {audit_request.profile}, Compliance: {session.compliance_pct}%",
        )
        consume_quota(request)

        return summary

    except ApacheAuditNotInstalledError as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="apache_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}",
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="apache_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}",
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SSHConnectionError as e:
        # SSH connect/auth failure — surface the precise status (401/502/503/504)
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="apache_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}",
        )
        raise HTTPException(status_code=e.http_status, detail=e.to_dict())
    except Exception as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="execute_audit",
            module="apache_cis",
            target_id=audit_request.asset_id,
            result="failed",
            detail=f"Asset Name: {asset_name}, IP: {target_ip}, Profile: {audit_request.profile}. Error: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit execution failed: {str(e)}",
        )


@router.get("/sessions", response_model=List[ApacheAuditSessionResponse])
def list_apache_sessions(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    """
    List all Apache audit sessions with pagination.
    ...
    """
    limit = min(limit, 100)
    sessions = ApacheAuditService.get_apache_sessions(db, limit, offset)

    summaries = []
    for s in sessions:
        summary = ApacheAuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.get("/sessions/count")
def get_apache_sessions_count(
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    count = ApacheAuditService.get_apache_sessions_count(db)
    return {"total": count}


@router.get("/sessions/{session_id}", response_model=ApacheAuditSessionResponse)
def get_apache_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    summary = ApacheAuditService.get_session_summary(db, session_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit session {session_id} not found",
        )

    # Verify it's an Apache audit
    session = ApacheAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)
    if session.device_type.value != "apache":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session {session_id} is not an Apache audit",
        )

    return summary


@router.get(
    "/sessions/{session_id}/results", response_model=List[ApacheAuditResultResponse]
)
def get_apache_results(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    session = ApacheAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)

    results = ApacheAuditService.get_audit_results(db, session_id)

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
    "/sessions/{session_id}/failed", response_model=List[ApacheFailedCheckResponse]
)
def get_apache_failed_checks(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    session = ApacheAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)

    failed = ApacheAuditService.get_failed_checks(db, session_id)
    return failed


@router.get(
    "/asset/{asset_id}/history", response_model=List[ApacheAuditSessionResponse]
)
def get_asset_apache_history(
    asset_id: int,
    limit: int = 10,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    from app.models import Asset

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset {asset_id} not found"
        )

    sessions = ApacheAuditService.get_asset_apache_history(db, asset_id, limit)

    summaries = []
    for s in sessions:
        summary = ApacheAuditService.get_session_summary(db, s.id)
        if summary:
            summaries.append(summary)

    return summaries


@router.delete("/sessions/{session_id}")
def delete_apache_session(
    session_id: int,
    current_user: User = Depends(require_permission("AUDITING", "write")),
    db: Session = Depends(get_db),
):
    session = ApacheAuditService.get_audit_session(db, session_id)
    assert_session_access(session, current_user)

    from app.models import Asset

    asset = (
        db.query(Asset).filter(Asset.id == session.asset_id).first()
        if session.asset_id
        else None
    )
    asset_name = asset.asset_name if asset else None

    try:
        ApacheAuditService.delete_audit_session(db, session_id)

        log_action(
            db=db,
            user_id=current_user.id,
            action="delete_audit_session",
            module="apache_cis",
            target_id=session_id,
            result="success",
            detail=f"Deleted session for Asset ID: {session.asset_id}, Name: {asset_name}, IP: {session.target_ip}",
        )

        return {"message": f"Audit session {session_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete audit session: {str(e)}",
        )


@router.get("/statistics", response_model=ApacheAuditStatisticsResponse)
def get_apache_statistics(
    asset_id: Optional[int] = None,
    current_user: User = Depends(require_permission("AUDITING", "read")),
    db: Session = Depends(get_db),
):
    stats = ApacheAuditService.get_audit_statistics(db, asset_id)
    return stats


@router.get("/benchmark-info")
def get_benchmark_info(
    current_user: User = Depends(require_permission("AUDITING", "read")),
):
    from .cis_benchmark_map import get_benchmark_summary

    return get_benchmark_summary()


@router.get("/supported-configs")
def get_supported_configs(
    current_user: User = Depends(require_permission("AUDITING", "read")),
):
    return {
        "supported_distributions": [
            {
                "family": "debian",
                "distributions": [
                    "Ubuntu 22.04 LTS",
                    "Ubuntu 24.04 LTS",
                    "Debian 11/12",
                ],
                "service_name": "apache2",
                "config_dir": "/etc/apache2",
            },
            {
                "family": "rhel",
                "distributions": ["Rocky Linux 8/9", "RHEL 8/9", "CentOS Stream 8/9"],
                "service_name": "httpd",
                "config_dir": "/etc/httpd",
            },
        ],
        "apache_versions": ["2.4.x"],
        "benchmark": "CIS Apache HTTP Server 2.4 Benchmark",
        "notes": [
            "Distribution is auto-detected during audit",
            "Config paths are automatically adjusted for each distribution",
            "Debian/Ubuntu uses mods-enabled, RHEL uses conf.modules.d",
        ],
    }
