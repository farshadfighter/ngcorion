"""
Deployment Router

Queues and runs precheck -> backup -> apply -> verify deployment jobs for an
already-generated configuration object, plus a manual rollback action.
Deployment is gated by role only (admin/manager), per the user's decision -
there is no separate approval-request workflow.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin_or_manager
from app.models import User, ConfigurationObject
from app.modules.deployment.service import DeploymentService
from app.modules.deployment.schemas import (
    DeploymentJobSummary,
    DeploymentJobDetail,
    CreateJobRequest,
    DeviceCredentialsRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/deployment", tags=["Deployment"])


@router.get("/jobs", response_model=list[DeploymentJobSummary])
def list_jobs(
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db),
):
    return DeploymentService.list_jobs(db)


@router.post("/jobs", response_model=DeploymentJobSummary, status_code=201)
def create_job(
    request: CreateJobRequest,
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db),
):
    config_object = db.query(ConfigurationObject).filter(ConfigurationObject.id == request.configuration_object_id).first()
    if not config_object:
        raise HTTPException(status_code=404, detail="Configuration object not found")
    try:
        return DeploymentService.create_job(db, config_object, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/jobs/{job_id}", response_model=DeploymentJobDetail)
def get_job(
    job_id: int,
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db),
):
    job = DeploymentService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Deployment job not found")
    return job


@router.post("/jobs/{job_id}/start", response_model=DeploymentJobDetail)
def start_job(
    job_id: int,
    request: DeviceCredentialsRequest,
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db),
):
    job = DeploymentService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Deployment job not found")
    if job.status != "queued":
        raise HTTPException(status_code=400, detail=f"Job is already {job.status}, cannot start again")
    return DeploymentService.start_job(
        db, job,
        username=request.ssh_username, password=request.ssh_password,
        secret=request.ssh_secret, port=request.ssh_port,
        user_id=current_user.id,
    )


@router.post("/jobs/{job_id}/rollback", response_model=DeploymentJobDetail)
def rollback_job(
    job_id: int,
    request: DeviceCredentialsRequest,
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db),
):
    job = DeploymentService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Deployment job not found")
    if job.status not in ("apply_failed", "verify_failed", "rollback_failed"):
        raise HTTPException(status_code=400, detail=f"Job status '{job.status}' has nothing to roll back")
    try:
        return DeploymentService.rollback_job(
            db, job,
            username=request.ssh_username, password=request.ssh_password,
            secret=request.ssh_secret, port=request.ssh_port,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
