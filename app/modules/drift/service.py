"""
Drift Service

Connects to one asset's live device, pulls its current config via the same
backup_config() the manual/deployment backup paths already use, and diffs it
against the most recent DeviceBackup on file for that asset (the existing
backup table doubles as the drift baseline - no new baseline model).
"""
import logging
import difflib
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Asset, DeviceBackup, DriftRun, DriftResult

logger = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = ("cisco", "fortinet")


def _executor(device_type: str, ip: str, username: str, password: str, secret: Optional[str], port: int):
    if device_type == "cisco":
        from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
        return CiscoHardeningExecutor(ip=ip, username=username, password=password, secret=secret)
    if device_type == "fortinet":
        from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
        return FortiGateHardeningExecutor(ip=ip, username=username, password=password, port=port)
    raise ValueError(f"Drift analysis is not supported for device type '{device_type}'")


def _severity_for(lines_changed: int) -> str:
    if lines_changed > 20:
        return "high"
    if lines_changed > 5:
        return "medium"
    return "low"


class DriftService:
    """Configuration Drift Service."""

    @staticmethod
    def list_runs(db: Session):
        return db.query(DriftRun).order_by(DriftRun.started_at.desc()).all()

    @staticmethod
    def get_run(db: Session, run_id: int) -> Optional[DriftRun]:
        return db.query(DriftRun).filter(DriftRun.id == run_id).first()

    @staticmethod
    def list_results(db: Session, status: Optional[str] = None, severity: Optional[str] = None):
        query = db.query(DriftResult)
        if status:
            query = query.filter(DriftResult.status == status)
        if severity:
            query = query.filter(DriftResult.severity == severity)
        return query.order_by(DriftResult.created_at.desc()).all()

    @staticmethod
    def get_result(db: Session, result_id: int) -> Optional[DriftResult]:
        return db.query(DriftResult).filter(DriftResult.id == result_id).first()

    @staticmethod
    def resolve_result(db: Session, result: DriftResult, status: str, user_id: int, reason: str = None):
        result.status = status
        result.ignored_reason = reason
        result.resolved_by = user_id
        result.resolved_at = datetime.utcnow()
        db.commit()
        db.refresh(result)
        return result

    @staticmethod
    def analyze_asset(
        db: Session,
        asset: Asset,
        username: str,
        password: str,
        secret: Optional[str],
        port: int,
        user_id: Optional[int],
    ) -> DriftRun:
        """Run one drift check for a single asset.

        Requires an existing DeviceBackup for the asset - drift is measured
        against the most recent backup, not a fresh one, since the whole
        point is "did the live device change since we last captured it".
        """
        device_type = asset.inferred_device_type
        baseline = (
            db.query(DeviceBackup)
            .filter(DeviceBackup.asset_id == asset.id)
            .order_by(DeviceBackup.created_at.desc())
            .first()
        )

        run = DriftRun(asset_id=asset.id, triggered_by=user_id, status="running", assets_checked=1)
        db.add(run)
        db.flush()

        if not baseline:
            run.status = "failed"
            run.error_message = "No backup baseline exists for this asset yet - take one first (Configuration Backup)."
            run.completed_at = datetime.utcnow()
            db.commit()
            db.refresh(run)
            return run

        if not asset.ip_address:
            run.status = "failed"
            run.error_message = "Asset has no IP address configured"
            run.completed_at = datetime.utcnow()
            db.commit()
            db.refresh(run)
            return run

        try:
            with _executor(device_type, asset.ip_address, username, password, secret, port) as ex:
                live_config = ex.backup_config()
        except ValueError as exc:
            run.status = "failed"
            run.error_message = str(exc)
            run.completed_at = datetime.utcnow()
            db.commit()
            db.refresh(run)
            return run
        except Exception as exc:
            logger.error(f"Drift analysis failed for asset {asset.id}: {exc}")
            run.status = "failed"
            run.error_message = str(exc)
            run.completed_at = datetime.utcnow()
            db.commit()
            db.refresh(run)
            return run

        baseline_lines = baseline.config_content.splitlines()
        live_lines = live_config.splitlines()
        diff_lines = list(
            difflib.unified_diff(baseline_lines, live_lines, fromfile="baseline", tofile="live", lineterm="")
        )
        changed = sum(1 for line in diff_lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))

        if changed > 0:
            db.add(
                DriftResult(
                    run_id=run.id,
                    asset_id=asset.id,
                    asset_name=asset.asset_name,
                    technology=device_type,
                    baseline_backup_id=baseline.id,
                    diff="\n".join(diff_lines),
                    lines_changed=changed,
                    severity=_severity_for(changed),
                    status="open",
                )
            )
            run.drift_found_count = 1

        run.status = "completed"
        run.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(run)
        return run
