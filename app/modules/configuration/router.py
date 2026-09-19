"""
Configuration Router

Generates per-device configuration from a design version's mapped
components, and applies a generated configuration object to its real device.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User
from app.modules.design.service import DesignService
from app.modules.configuration.service import ConfigurationService
from app.modules.configuration.schemas import (
    ConfigurationJobSummary,
    ConfigurationJobDetail,
    ConfigurationObjectSummary,
    GenerateJobRequest,
    ApplyObjectRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/configuration", tags=["Configuration"])


def _job_summary(job) -> ConfigurationJobSummary:
    return ConfigurationJobSummary(
        id=job.id, design_version_id=job.design_version_id, name=job.name, status=job.status,
        created_at=job.created_at, object_count=len(job.objects),
    )


@router.get("/jobs", response_model=list[ConfigurationJobSummary])
def list_jobs(
    current_user: User = Depends(require_permission("design_configuration", "read")),
    db: Session = Depends(get_db),
):
    return [_job_summary(job) for job in ConfigurationService.list_jobs(db)]


@router.post("/jobs", response_model=ConfigurationJobDetail, status_code=201)
def generate_job(
    request: GenerateJobRequest,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    version = DesignService.get_version(db, request.design_version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Design version not found")
    job = ConfigurationService.generate_job(db, version, request.name, current_user.id)
    return ConfigurationJobDetail(job=_job_summary(job), objects=job.objects)


@router.get("/jobs/{job_id}", response_model=ConfigurationJobDetail)
def get_job(
    job_id: int,
    current_user: User = Depends(require_permission("design_configuration", "read")),
    db: Session = Depends(get_db),
):
    job = ConfigurationService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Configuration job not found")
    return ConfigurationJobDetail(job=_job_summary(job), objects=job.objects)


@router.post("/objects/{object_id}/apply", response_model=ConfigurationObjectSummary)
def apply_object(
    object_id: int,
    request: ApplyObjectRequest,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    obj = ConfigurationService.get_object(db, object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Configuration object not found")

    try:
        obj = ConfigurationService.apply_object(
            db, obj,
            username=request.ssh_username,
            password=request.ssh_password,
            secret=request.ssh_secret,
            port=request.ssh_port,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job = obj.job
    statuses = {o.apply_status for o in job.objects}
    if statuses == {"success"}:
        job.status = "applied"
    elif "success" in statuses:
        job.status = "partially_applied"
    db.commit()

    return obj
