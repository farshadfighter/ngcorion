"""
Scheduled Jobs Router.

A schedule is either a discovery scan (asset_auto_discovery permission) or
an audit (auditing permission) - gated by whichever module the job's own
job_type belongs to, same as the manual endpoints these jobs eventually
call.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset
from app.models.scheduling import JOB_TYPE_DISCOVERY, JOB_TYPE_AUDIT
from app.modules.scheduling.service import SchedulingService
from app.modules.scheduling.schemas import (
    ScheduledJobCreate,
    ScheduledJobUpdate,
    ScheduledJobSummary,
    ScheduledJobRunSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scheduling", tags=["Scheduled Jobs"])

_MODULE_FOR_JOB_TYPE = {
    JOB_TYPE_DISCOVERY: "asset_auto_discovery",
    JOB_TYPE_AUDIT: "auditing",
}


def _require_job_type_permission(job_type: str, permission_type: str, current_user: User, db: Session) -> None:
    module = _MODULE_FOR_JOB_TYPE.get(job_type)
    if module is None:
        raise HTTPException(status_code=400, detail=f"Unknown job_type: {job_type}")
    require_permission(module, permission_type)(current_user=current_user, db=db)


def _to_summary(job) -> ScheduledJobSummary:
    summary = ScheduledJobSummary.model_validate(job)
    if job.asset is not None:
        summary.asset_name = job.asset.asset_name
    return summary


@router.post("/jobs", response_model=ScheduledJobSummary)
def create_job(
    data: ScheduledJobCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_job_type_permission(data.job_type, "write", current_user, db)
    if data.job_type == JOB_TYPE_AUDIT and data.asset_id:
        asset = db.query(Asset).filter(Asset.id == data.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
    try:
        job = SchedulingService.create_job(db, data, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _to_summary(job)


@router.get("/jobs", response_model=list[ScheduledJobSummary])
def list_jobs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    jobs = []
    try:
        require_permission("asset_auto_discovery", "read")(current_user=current_user, db=db)
        jobs += SchedulingService.list_jobs(db, job_type=JOB_TYPE_DISCOVERY)
    except HTTPException:
        pass
    try:
        require_permission("auditing", "read")(current_user=current_user, db=db)
        jobs += SchedulingService.list_jobs(db, job_type=JOB_TYPE_AUDIT)
    except HTTPException:
        pass
    jobs.sort(key=lambda j: j.next_run_at)
    return [_to_summary(job) for job in jobs]


@router.get("/jobs/{job_id}", response_model=ScheduledJobSummary)
def get_job(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = SchedulingService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    _require_job_type_permission(job.job_type, "read", current_user, db)
    return _to_summary(job)


@router.patch("/jobs/{job_id}", response_model=ScheduledJobSummary)
def update_job(
    job_id: int,
    data: ScheduledJobUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = SchedulingService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    _require_job_type_permission(job.job_type, "write", current_user, db)
    try:
        job = SchedulingService.update_job(db, job, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _to_summary(job)


@router.delete("/jobs/{job_id}")
def delete_job(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = SchedulingService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    _require_job_type_permission(job.job_type, "delete", current_user, db)
    SchedulingService.delete_job(db, job)
    return {"detail": "Scheduled job deleted"}


@router.post("/jobs/{job_id}/run", response_model=ScheduledJobRunSummary)
def run_job_now(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = SchedulingService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    _require_job_type_permission(job.job_type, "write", current_user, db)
    run = SchedulingService.run_job_now(db, job)
    return run


@router.get("/jobs/{job_id}/runs", response_model=list[ScheduledJobRunSummary])
def list_runs(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = SchedulingService.get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled job not found")
    _require_job_type_permission(job.job_type, "read", current_user, db)
    return SchedulingService.list_runs(db, job_id)
