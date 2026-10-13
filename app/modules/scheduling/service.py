"""
Scheduled Jobs Service.

Job execution (run_job_now) is shared by the background scheduler loop
(app/modules/scheduling/scheduler.py) and a manual "Run Now" trigger, so a
schedule can always be dry-run on demand.

Discovery (nmap) and audit (Netmiko/paramiko/WinRM) I/O in this app is
synchronous/blocking - unlike NOC's poller, which is natively async SNMP -
so the scheduler loop that calls run_job_now offloads it to a thread
(asyncio.to_thread) rather than awaiting it directly.
"""
import json
import logging
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.credential_crypto import encrypt_json, decrypt_json
from app.models.scheduling import (
    ScheduledJob, ScheduledJobRun,
    JOB_TYPE_DISCOVERY, JOB_TYPE_AUDIT, JOB_TYPE_BACKUP, RECURRENCE_ONCE,
)
from app.modules.scheduling.recurrence import compute_next_run_at
from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES, REQUIRED_PARAMS, run_audit
from app.modules.scheduling.schemas import ScheduledJobCreate, ScheduledJobUpdate
from app.modules.discovery.service import DiscoveryService
from app.modules.discovery.schemas import ScanRequest

logger = logging.getLogger(__name__)


def _discovery_params(data) -> dict[str, Any]:
    return {
        "job_name": data.job_name,
        "target": data.target,
        "scan_type": data.scan_type or "well_known_ports",
        "ports": data.ports,
        "protocol": data.protocol or "TCP",
        "version_detection": bool(data.version_detection),
    }


def _validate_create(data: ScheduledJobCreate) -> None:
    if data.job_type == JOB_TYPE_DISCOVERY:
        if not data.target:
            raise ValueError("target is required for a discovery job")
        # ScanRequest's own validators (IP/CIDR format, port spec) run for real below.
    elif data.job_type == JOB_TYPE_AUDIT:
        if not data.technology or data.technology not in SUPPORTED_TECHNOLOGIES:
            raise ValueError(f"technology must be one of {sorted(SUPPORTED_TECHNOLOGIES)}")
        if data.group_id:
            # A group audit signs in with a credential profile: no credentials in the job itself.
            if not data.credential_profile_id:
                raise ValueError("credential_profile_id is required for a group audit job")
        else:
            if not data.asset_id:
                raise ValueError("asset_id is required for an audit job")
            params = data.audit_params or {}
            missing = REQUIRED_PARAMS[data.technology] - params.keys()
            if missing:
                raise ValueError(f"audit_params missing required field(s): {sorted(missing)}")
    elif data.job_type == JOB_TYPE_BACKUP:
        from app.modules.backup.collect import FAMILIES
        if data.technology not in FAMILIES:
            raise ValueError(f"technology must be one of {list(FAMILIES)}")
        if not data.group_id or not data.credential_profile_id:
            raise ValueError("group_id and credential_profile_id are required for a backup job")

    if data.recurrence == "weekly" and data.day_of_week is None:
        raise ValueError("day_of_week is required for a weekly recurrence")


def _start_group_run(db: Session, job: ScheduledJob, params: dict, kind: str = "audit"):
    """A scheduled group audit (or backup) only queues the run; the group-run worker does the assets."""
    from app.models.asset_groups import AssetGroup, CredentialProfile
    from app.models.security_audit_log import log_action
    from app.modules.asset_groups.runs import start_run
    group = db.get(AssetGroup, job.group_id)
    profile = db.get(CredentialProfile, job.credential_profile_id) if job.credential_profile_id else None
    if group is None or profile is None:
        raise ValueError("The group or credential profile of this schedule no longer exists")
    group_run = start_run(db, group, job.technology, profile, params.get("profile"), job.concurrency or 10,
                          None, scheduled_job_id=job.id, started_by_id=job.created_by, kind=kind)
    db.flush()
    if kind == "backup":
        log_action(db, user_id=job.created_by, action="group_run.start", module="backup", target_id=group_run.id,
                   detail=f"Scheduled job '{job.job_name}' started a {job.technology} configuration backup of "
                          f"group '{group.name}' with credential profile '{profile.name}'")
        return group_run
    log_action(db, user_id=job.created_by, action="group_run.start", module="auditing", target_id=group_run.id,
               detail=f"Scheduled job '{job.job_name}' started a {job.technology} audit of group '{group.name}' "
                      f"with credential profile '{profile.name}'")
    return group_run


class SchedulingService:
    """Scheduled Jobs Service."""

    @staticmethod
    def create_job(db: Session, data: ScheduledJobCreate, user_id: int) -> ScheduledJob:
        """Validate and store a job: discovery targets are checked with the scan request's own rules,
        audit credentials are encrypted, and the first run time is computed.
        """
        _validate_create(data)

        if data.job_type == JOB_TYPE_DISCOVERY:
            params = _discovery_params(data)
            # Validate against ScanRequest's own rules now, not at run time.
            ScanRequest(**params)
            technology = None
            asset_id = None
        elif data.job_type == JOB_TYPE_BACKUP:
            params = {}
            technology = data.technology
            asset_id = None
        elif data.group_id:
            params = {"profile": data.audit_profile} if data.audit_profile else {}
            technology = data.technology
            asset_id = None
        else:
            params = dict(data.audit_params or {})
            technology = data.technology
            asset_id = data.asset_id

        job = ScheduledJob(
            job_name=data.job_name,
            job_type=data.job_type,
            technology=technology,
            asset_id=asset_id,
            group_id=data.group_id if data.job_type in (JOB_TYPE_AUDIT, JOB_TYPE_BACKUP) else None,
            credential_profile_id=data.credential_profile_id if data.group_id else None,
            concurrency=(data.concurrency or 10) if data.group_id else None,
            params_encrypted=encrypt_json(json.dumps(params)),
            recurrence=data.recurrence,
            hour=data.hour,
            minute=data.minute,
            day_of_week=data.day_of_week,
            enabled=data.enabled,
            next_run_at=compute_next_run_at(data.recurrence, data.hour, data.minute, data.day_of_week, datetime.utcnow()),
            created_by=user_id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def update_job(db: Session, job: ScheduledJob, data: ScheduledJobUpdate) -> ScheduledJob:
        """Apply the changed fields; a schedule change recomputes the next run."""
        if data.job_name is not None:
            job.job_name = data.job_name
        if data.enabled is not None:
            job.enabled = data.enabled

        schedule_changed = False
        if data.recurrence is not None:
            job.recurrence = data.recurrence
            schedule_changed = True
        if data.hour is not None:
            job.hour = data.hour
            schedule_changed = True
        if data.minute is not None:
            job.minute = data.minute
            schedule_changed = True
        if data.day_of_week is not None:
            job.day_of_week = data.day_of_week
            schedule_changed = True
        if job.recurrence == "weekly" and job.day_of_week is None:
            raise ValueError("day_of_week is required for a weekly recurrence")

        if job.job_type == JOB_TYPE_DISCOVERY and any(
            v is not None for v in (data.target, data.scan_type, data.ports, data.protocol, data.version_detection)
        ):
            current = json.loads(decrypt_json(job.params_encrypted))
            if data.target is not None:
                current["target"] = data.target
            if data.scan_type is not None:
                current["scan_type"] = data.scan_type
            if data.ports is not None:
                current["ports"] = data.ports
            if data.protocol is not None:
                current["protocol"] = data.protocol
            if data.version_detection is not None:
                current["version_detection"] = data.version_detection
            current["job_name"] = job.job_name
            ScanRequest(**current)
            job.params_encrypted = encrypt_json(json.dumps(current))

        if job.group_id:
            if data.credential_profile_id is not None:
                job.credential_profile_id = data.credential_profile_id
            if data.concurrency is not None:
                job.concurrency = data.concurrency
        elif job.job_type == JOB_TYPE_AUDIT and data.audit_params is not None:
            current = json.loads(decrypt_json(job.params_encrypted))
            current.update(data.audit_params)
            missing = REQUIRED_PARAMS[job.technology] - current.keys()
            if missing:
                raise ValueError(f"audit_params missing required field(s): {sorted(missing)}")
            job.params_encrypted = encrypt_json(json.dumps(current))

        if schedule_changed:
            job.next_run_at = compute_next_run_at(job.recurrence, job.hour, job.minute, job.day_of_week, datetime.utcnow())

        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def list_jobs(db: Session, job_type: Optional[str] = None) -> list[ScheduledJob]:
        """Jobs, optionally of one type, by next run time."""
        query = db.query(ScheduledJob)
        if job_type:
            query = query.filter(ScheduledJob.job_type == job_type)
        return query.order_by(ScheduledJob.next_run_at).all()

    @staticmethod
    def get_job(db: Session, job_id: int) -> Optional[ScheduledJob]:
        return db.query(ScheduledJob).filter(ScheduledJob.id == job_id).first()

    @staticmethod
    def delete_job(db: Session, job: ScheduledJob) -> None:
        db.delete(job)
        db.commit()

    @staticmethod
    def list_runs(db: Session, job_id: int) -> list[ScheduledJobRun]:
        """A job's runs, newest first."""
        return (
            db.query(ScheduledJobRun)
            .filter(ScheduledJobRun.job_id == job_id)
            .order_by(ScheduledJobRun.started_at.desc())
            .all()
        )

    @staticmethod
    def due_jobs(db: Session, now: datetime) -> list[ScheduledJob]:
        """Enabled jobs whose next run time has come."""
        return (
            db.query(ScheduledJob)
            .filter(ScheduledJob.enabled.is_(True), ScheduledJob.next_run_at <= now)
            .all()
        )

    @staticmethod
    def claim_due_jobs(db: Session, now: datetime) -> list[int]:
        """Due jobs this caller may run. Each is claimed by moving its
        next_run_at forward (a one-off job: disabling it) only if nobody moved
        it first, so a job never starts twice - not from overlapping sweeps,
        not from several server processes."""
        claimed = []
        for job in SchedulingService.due_jobs(db, now):
            values = ({"enabled": False} if job.recurrence == RECURRENCE_ONCE else
                      {"next_run_at": compute_next_run_at(job.recurrence, job.hour, job.minute,
                                                          job.day_of_week, now)})
            res = db.execute(
                update(ScheduledJob)
                .where(ScheduledJob.id == job.id, ScheduledJob.enabled.is_(True),
                       ScheduledJob.next_run_at == job.next_run_at)
                .values(**values)
            )
            if res.rowcount == 1:
                claimed.append(job.id)
        db.commit()
        return claimed

    @staticmethod
    def run_job_now(db: Session, job: ScheduledJob) -> ScheduledJobRun:
        """Execute one job synchronously - shared by the scheduler loop
        (offloaded to a thread there) and a manual "Run Now" trigger."""
        run = ScheduledJobRun(job_id=job.id, status="running")
        db.add(run)
        db.flush()

        try:
            params = json.loads(decrypt_json(job.params_encrypted))
            if job.job_type == JOB_TYPE_DISCOVERY:
                scan = DiscoveryService.start_scan(db, ScanRequest(**params), job.created_by)
                DiscoveryService.execute_scan(db, scan["scan_id"])
                run.result_ref = f"scan:{scan['scan_id']}"
            elif job.group_id:
                group_run = _start_group_run(db, job, params,
                                             kind="backup" if job.job_type == JOB_TYPE_BACKUP else "audit")
                run.result_ref = f"group_run:{group_run.id}"
            else:
                session = run_audit(job.technology, db, job.asset_id, job.created_by, params)
                run.result_ref = f"audit_session:{session.id}"
            run.status = "success"
            job.last_run_status = "success"
            job.last_run_message = None
        except Exception as exc:
            logger.error("Scheduled job %s failed: %s", job.id, exc)
            run.status = "failed"
            run.message = str(exc)
            job.last_run_status = "failed"
            job.last_run_message = str(exc)

        now = datetime.utcnow()
        run.finished_at = now
        job.last_run_at = now
        if job.recurrence == RECURRENCE_ONCE:
            job.enabled = False
        else:
            job.next_run_at = compute_next_run_at(job.recurrence, job.hour, job.minute, job.day_of_week, now)

        db.commit()
        db.refresh(run)
        return run
