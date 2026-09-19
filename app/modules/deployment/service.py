"""
Deployment Service

Runs a DeploymentJob's precheck -> backup -> apply -> verify pipeline
synchronously (mirroring how Auditing/Hardening run their own device
sessions in this app - there is no background task queue). Every step reuses
the same per-tech hardening executors Configuration's direct-apply path
already relies on; the only new logic here is the pipeline itself and
persisting each step's outcome.
"""
import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import ConfigurationObject, DeploymentJob, DeviceBackup

logger = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = ("cisco", "fortinet")


def _executor(device_type: str, ip: str, username: str, password: str, secret: Optional[str], port: int):
    if device_type == "cisco":
        from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
        return CiscoHardeningExecutor(ip=ip, username=username, password=password, secret=secret)
    if device_type == "fortinet":
        from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
        return FortiGateHardeningExecutor(ip=ip, username=username, password=password, port=port)
    raise ValueError(f"Deployment is not supported for device type '{device_type}'")


class DeploymentService:
    """Deployment Job Service."""

    @staticmethod
    def list_jobs(db: Session):
        return db.query(DeploymentJob).order_by(DeploymentJob.created_at.desc()).all()

    @staticmethod
    def get_job(db: Session, job_id: int) -> Optional[DeploymentJob]:
        return db.query(DeploymentJob).filter(DeploymentJob.id == job_id).first()

    @staticmethod
    def create_job(db: Session, configuration_object: ConfigurationObject, user_id: Optional[int]) -> DeploymentJob:
        if configuration_object.device_type not in SUPPORTED_DEVICE_TYPES:
            raise ValueError(f"Deployment is not supported for device type '{configuration_object.device_type}'")
        if not configuration_object.asset_id:
            raise ValueError("This configuration object has no target asset")
        job = DeploymentJob(
            configuration_object_id=configuration_object.id,
            asset_id=configuration_object.asset_id,
            asset_name=configuration_object.asset_name,
            device_type=configuration_object.device_type,
            status="queued",
            created_by=user_id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @staticmethod
    def start_job(
        db: Session,
        job: DeploymentJob,
        username: str,
        password: str,
        secret: Optional[str],
        port: int,
        user_id: Optional[int],
    ) -> DeploymentJob:
        """Run the full precheck -> backup -> apply -> verify pipeline.

        Stops (and records why) at the first failing step; every prior step's
        output is kept either way, so a failure is diagnosable from the job
        alone.
        """
        asset = job.asset
        config_object = job.configuration_object
        if not asset or not asset.ip_address:
            job.status = "precheck_failed"
            job.error_message = "Target asset has no IP address configured"
            db.commit()
            db.refresh(job)
            return job
        if not config_object:
            job.status = "precheck_failed"
            job.error_message = "This job's configuration object no longer exists"
            db.commit()
            db.refresh(job)
            return job

        job.started_at = datetime.utcnow()
        job.status = "precheck"
        db.commit()

        try:
            with _executor(job.device_type, asset.ip_address, username, password, secret, port) as ex:
                reachable = ex.test_connectivity()
                job.precheck_output = "Device reachable" if reachable else "Device unreachable"
                if not reachable:
                    job.status = "precheck_failed"
                    job.error_message = "Precheck failed: device is not reachable"
                    job.completed_at = datetime.utcnow()
                    db.commit()
                    db.refresh(job)
                    return job

                job.status = "backup"
                db.commit()
                config_content = ex.backup_config()
                backup = DeviceBackup(
                    asset_id=asset.id,
                    asset_name=asset.asset_name,
                    device_ip=asset.ip_address,
                    device_type=job.device_type,
                    config_content=config_content,
                    source="deployment",
                    created_by=user_id,
                )
                db.add(backup)
                db.flush()
                job.backup_id = backup.id
                db.commit()

                job.status = "applying"
                db.commit()
                commands = config_object.generated_config.splitlines()
                result = ex.execute_commands(commands)
                job.apply_output = result.get("output") or "\n".join(result.get("errors", []))
                if not result.get("success"):
                    job.status = "apply_failed"
                    job.error_message = "Apply failed - see apply_output. A pre-change backup was taken (see backup_id)."
                    job.completed_at = datetime.utcnow()
                    db.commit()
                    db.refresh(job)
                    return job

                job.status = "verifying"
                db.commit()
                still_reachable = ex.test_connectivity()
                job.verify_output = "Device reachable after apply" if still_reachable else "Device unreachable after apply"
                if not still_reachable:
                    job.status = "verify_failed"
                    job.error_message = (
                        "Device did not respond after the change. A pre-change backup was taken "
                        "(see backup_id) - use the Rollback action to push it back."
                    )
                    job.completed_at = datetime.utcnow()
                    db.commit()
                    db.refresh(job)
                    return job

                job.status = "success"
                job.completed_at = datetime.utcnow()
                db.commit()
                db.refresh(job)
                return job

        except Exception as exc:
            logger.error(f"Deployment job {job.id} failed: {exc}")
            job.error_message = str(exc)
            if job.status in ("queued", "precheck"):
                job.status = "precheck_failed"
            elif job.status == "backup":
                job.status = "backup_failed"
            elif job.status == "applying":
                job.status = "apply_failed"
            elif job.status == "verifying":
                job.status = "verify_failed"
            job.completed_at = datetime.utcnow()
            db.commit()
            db.refresh(job)
            return job

    @staticmethod
    def rollback_job(
        db: Session,
        job: DeploymentJob,
        username: str,
        password: str,
        secret: Optional[str],
        port: int,
    ) -> DeploymentJob:
        """Push the job's pre-change backup back to the device.

        Best-effort: it replays the backed-up running-config as config-mode
        commands through the same execute_commands() apply already uses,
        there is no dedicated "restore full config" operation on these
        executors. Only meaningful once a backup was actually taken
        (status is apply_failed or verify_failed).
        """
        if not job.backup or not job.backup.config_content:
            raise ValueError("This job has no backup to roll back to")
        asset = job.asset
        if not asset or not asset.ip_address:
            raise ValueError("Target asset has no IP address configured")

        commands = [
            line for line in job.backup.config_content.splitlines()
            if line.strip() and not line.strip().startswith("!")
        ]

        try:
            with _executor(job.device_type, asset.ip_address, username, password, secret, port) as ex:
                result = ex.execute_commands(commands)
        except Exception as exc:
            logger.error(f"Rollback failed for deployment job {job.id}: {exc}")
            job.rollback_output = str(exc)
            job.status = "rollback_failed"
            db.commit()
            db.refresh(job)
            return job

        job.rollback_output = result.get("output") or "\n".join(result.get("errors", []))
        job.status = "rolled_back" if result.get("success") else "rollback_failed"
        db.commit()
        db.refresh(job)
        return job
