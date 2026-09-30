"""
Backup restore: preview and the background restore job.

Safety sequence of a restore (every step recorded as a job event):

  1. connect over SSH and re-read the live configuration; if it changed since
     the operator reviewed the diff, stop - nothing is written
  2. save the live configuration as a "Before restore" backup (the undo point)
  3. arm the device's auto-revert, then push only the differences
     (first rejected command stops the run and reverts)
  4. drop the session and reconnect - proving access survived - then compare
     the live configuration with the backup
  5. only then save on the device / disarm the auto-revert

If NGCorion cannot get back in, the armed auto-revert returns the device to its
previous configuration on its own; the job waits for that and verifies it.
"""
import hashlib
import json
import logging
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.secret_redaction import redact_text
from app.models import DeviceBackup
from app.models.backup_restore import RESTORE_ACTIVE_STATUSES, BackupRestore
from app.models.security_audit_log import log_action
from app.modules.backup.restore import config_tree, file_bundle
from app.modules.backup.restore.drivers import (
    Credentials,
    RestoreApplyError,
    RestorePlan,
    configs_match,
    make_driver,
)

logger = logging.getLogger(__name__)

RECONNECT_ATTEMPTS = 6
RECONNECT_DELAY_SECONDS = 10
REVERT_GRACE_SECONDS = 120
REVERT_POLL_SECONDS = 30
MAX_PREVIEW_LINES = 4000


def fingerprint(family: str, text: str) -> str:
    """Stable identity of a configuration, insensitive to capture noise."""
    if family == "cisco":
        body = "\n".join(f"{d}|{l}" for d, l in config_tree.parse_cisco(text).flatten())
    elif family == "fortinet":
        body = "\n".join(f"{d}|{l}" for d, l in config_tree.parse_fortios(text).flatten())
    else:
        body = json.dumps(file_bundle.parse_bundle(text), sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def serialize_plan(plan: RestorePlan) -> Dict:
    sections, total = [], 0
    for s in plan.diff.sections:
        if total >= MAX_PREVIEW_LINES:
            break
        lines = [{"op": l.op, "text": l.text} for l in s.lines[: MAX_PREVIEW_LINES - total]]
        total += len(lines)
        sections.append({"title": s.title, "lines": lines})
    return {
        "summary": {
            "added": plan.diff.added,
            "removed": plan.diff.removed,
            "sections": len(plan.diff.sections),
            "commands": len(plan.commands) if plan.commands else None,
        },
        "sections": sections,
        "truncated": total >= MAX_PREVIEW_LINES,
        "skipped": plan.diff.skipped,
        "risks": plan.risks,
        "no_changes": plan.is_empty,
    }


def preview(backup: DeviceBackup, creds: Credentials, driver_factory=make_driver) -> Dict:
    driver = driver_factory(backup.device_type, creds, 0)
    driver.open()
    try:
        live = driver.read_live()
        plan = driver.plan(backup.config_content, live)
        available, method = driver.auto_revert_available()
        return {
            **serialize_plan(plan),
            "live_fingerprint": fingerprint(backup.device_type, live),
            "source_ip": driver.source_ip(),
            "auto_revert": {"available": available, "method": method if available else None,
                            "reason": None if available else method},
        }
    finally:
        driver.close()


# --------------------------------------------------------------------------- #
#  Background job                                                             #
# --------------------------------------------------------------------------- #

class _Job:
    """Job row updates. Every message is redacted before it is stored: device
    errors can echo the rejected line, and that line can carry a secret."""

    def __init__(self, db: Session, job: BackupRestore, creds: Optional[Credentials] = None):
        self.db, self.job = db, job
        self.secrets = ({"password": creds.password, "secret": creds.secret,
                         "sudo_password": creds.sudo_password} if creds else None)

    def _clean(self, text: Optional[str]) -> Optional[str]:
        return redact_text(text, self.secrets) if text else text

    def status(self, status: str):
        self.job.status = status
        self.db.commit()

    def event(self, step: str, status: str, message: str):
        events = list(self.job.events or [])
        events.append({"at": datetime.utcnow().isoformat() + "Z", "step": step,
                       "status": status, "message": self._clean(message)})
        self.job.events = events
        self.db.commit()

    def finish(self, status: str, error: Optional[str] = None):
        self.job.status = status
        self.job.error = self._clean(error)
        self.job.finished_at = datetime.utcnow()
        self.db.commit()


def run_restore(job_id: int, creds: Credentials, expected_fingerprint: str,
                acknowledged_lockout: bool = False, allow_without_auto_revert: bool = False,
                driver_factory: Callable = make_driver, sleep: Callable = time.sleep,
                session_factory: Callable = SessionLocal) -> None:
    db = session_factory()
    driver = None
    try:
        job = db.get(BackupRestore, job_id)
        j = _Job(db, job, creds)
        family = job.device_type
        backup_text = job.backup.config_content
        job.started_at = datetime.utcnow()

        # 1. connect + re-read
        j.status("connecting")
        driver = driver_factory(family, creds, job.id)
        driver.open()
        j.event("connect", "done", f"Connected over SSH to {creds.host}:{creds.port}")
        live = driver.read_live()
        if fingerprint(family, live) != expected_fingerprint:
            j.event("connect", "failed", "The device's configuration changed after the changes were reviewed.")
            j.finish("failed", "The device's configuration changed after you reviewed it. "
                               "Nothing was changed - review the changes again.")
            return
        plan = driver.plan(backup_text, live)
        if plan.is_empty:
            j.event("verify", "done", "The device already matches the backup; nothing to change.")
            j.finish("succeeded")
            return
        # Re-checked here rather than trusted from the browser: these decide
        # whether a run may start at all.
        job.diff_summary = {"added": plan.diff.added, "removed": plan.diff.removed,
                            "sections": len(plan.diff.sections), "risks": plan.risks}
        lockouts = [r for r in plan.risks if r["severity"] == "lockout"]
        if lockouts and not acknowledged_lockout:
            j.event("connect", "failed", lockouts[0]["message"])
            j.finish("failed", "This restore may lock NGCorion out and that was not acknowledged. Nothing was changed.")
            return
        available, reason = driver.auto_revert_available()
        job.auto_revert = "armed" if available else "unavailable"
        db.commit()
        if not available and not allow_without_auto_revert:
            j.event("connect", "failed", reason)
            j.finish("failed", "Auto-revert is not available on this device and running without it was not "
                               "confirmed. Nothing was changed.")
            return

        # 2. undo point
        j.status("backing_up")
        pre_text = driver.snapshot()
        pre = DeviceBackup(
            asset_id=job.asset_id, asset_name=job.asset_name, device_ip=job.device_ip,
            device_type=family, config_content=pre_text, source="pre_restore",
            created_by=job.requested_by, created_at=datetime.utcnow(),
        )
        db.add(pre)
        db.flush()
        job.pre_restore_backup_id = pre.id
        db.commit()
        j.event("backup", "done", f"Current configuration saved as backup #{pre.id} (before restore)")

        # 3. apply
        j.status("applying")
        armed = job.auto_revert == "armed"
        minutes = job.revert_minutes if armed else None
        try:
            driver.apply(plan, minutes)
        except RestoreApplyError as exc:
            j.event("apply", "failed", str(exc))
            if armed:
                j.status("reverting")
                try:
                    driver.revert_now()
                    j.event("revert", "done", "Unsaved changes reverted immediately.")
                except Exception:  # noqa: BLE001
                    logger.exception("Immediate revert failed for restore %s", job_id)
                    j.event("revert", "info", f"Immediate revert failed; the device reverts on its own within {minutes} minutes.")
                j.finish("reverted", str(exc))
            else:
                j.finish("failed", f"{exc} Earlier changes in this run may be applied; "
                                   f"backup #{pre.id} holds the previous configuration.")
            return
        changed = plan.diff.added + plan.diff.removed
        j.event("apply", "done", f"{changed} changed line(s) applied" + (" in revert mode - not saved yet" if armed else ""))
        applied_at = time.monotonic()

        # 4. reconnect + verify
        j.status("verifying")
        driver.close()
        if not _reconnect(driver, sleep):
            _await_self_revert(j, driver, family, pre_text, armed, minutes, applied_at, sleep)
            return
        j.event("verify", "done", "Reconnected over SSH - access survived the restore")
        live_after = driver.read_live()
        ok, remaining = configs_match(family, backup_text, live_after)
        if not ok:
            j.event("verify", "failed", f"{remaining} line(s) still differ from the backup")
            if armed:
                j.status("reverting")
                driver.revert_now()
                j.event("revert", "done", "Changes reverted - the device is back on its previous configuration.")
                j.finish("reverted", f"Verification found {remaining} differing line(s); the restore was reverted.")
            else:
                j.finish("failed", f"Verification found {remaining} differing line(s). "
                                   f"Backup #{pre.id} holds the previous configuration.")
            return
        j.event("verify", "done", "Live configuration matches the backup (0 differences)")

        # 5. keep
        j.status("saving")
        driver.confirm()
        j.event("save", "done", "Saved on the device" + (" - auto-revert cancelled" if armed else ""))
        j.finish("succeeded")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Restore job %s failed", job_id)
        try:
            job = db.get(BackupRestore, job_id)
            failed = _Job(db, job, creds)
            failed.event("error", "failed", f"{type(exc).__name__}: {exc}")
            failed.finish("failed", f"{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            db.rollback()
    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            job = db.get(BackupRestore, job_id)
            if job:
                log_action(db, user_id=job.requested_by, action="backup.restore", module="backup",
                           target_id=job.asset_id,
                           result="success" if job.status == "succeeded" else "failed",
                           detail=f"Restore #{job.id} of backup #{job.backup_id} on {job.asset_name} "
                                  f"({job.device_ip}): {job.status}. Reason: {job.reason}")
        except Exception:  # noqa: BLE001
            logger.exception("Audit log for restore %s failed", job_id)
        db.close()


def _reconnect(driver, sleep) -> bool:
    for attempt in range(RECONNECT_ATTEMPTS):
        try:
            driver.open()
            return True
        except Exception:  # noqa: BLE001
            if attempt < RECONNECT_ATTEMPTS - 1:
                sleep(RECONNECT_DELAY_SECONDS)
    return False


def _await_self_revert(j: _Job, driver, family, pre_text, armed, minutes, applied_at, sleep):
    if not armed:
        j.event("verify", "failed", "NGCorion could not reconnect after applying the changes.")
        j.finish("failed", "Access was lost after the restore and no auto-revert was available. "
                           "Restore the 'before restore' backup from the device console.")
        return
    j.status("reverting")
    j.event("verify", "failed", f"Could not reconnect - waiting for the device to revert on its own ({minutes} min timer)")
    deadline = minutes * 60 + REVERT_GRACE_SECONDS
    while time.monotonic() - applied_at < deadline:
        sleep(REVERT_POLL_SECONDS)
    for _ in range(RECONNECT_ATTEMPTS * 2):
        try:
            driver.open()
            break
        except Exception:  # noqa: BLE001
            sleep(REVERT_POLL_SECONDS)
    else:
        j.finish("failed", "The device is still unreachable after its auto-revert window. Check it from the console.")
        return
    ok, _ = configs_match(family, pre_text, driver.read_live())
    if ok:
        j.event("revert", "done", "Access confirmed again - the device reverted to its previous configuration")
        j.finish("reverted", "Access was lost after applying; the device reverted automatically.")
    else:
        j.finish("failed", "The device is reachable again but matches neither the backup nor its previous configuration.")


def start_restore(job_id: int, creds: Credentials, expected_fingerprint: str,
                  acknowledged_lockout: bool, allow_without_auto_revert: bool) -> None:
    threading.Thread(
        target=run_restore,
        args=(job_id, creds, expected_fingerprint, acknowledged_lockout, allow_without_auto_revert),
        name=f"restore-{job_id}", daemon=True,
    ).start()


def fail_interrupted_restores(db: Session) -> int:
    """Jobs left mid-run by a server restart cannot resume (credentials were only
    in memory). The device's own auto-revert covers an unconfirmed change."""
    jobs = db.query(BackupRestore).filter(BackupRestore.status.in_(RESTORE_ACTIVE_STATUSES)).all()
    for job in jobs:
        events = list(job.events or [])
        events.append({"at": datetime.utcnow().isoformat() + "Z", "step": "error", "status": "failed",
                       "message": "Interrupted by a server restart. An armed auto-revert returns the device "
                                  "to its previous configuration on its own."})
        job.events = events
        job.status = "failed"
        job.error = "Interrupted by a server restart."
        job.finished_at = datetime.utcnow()
    if jobs:
        db.commit()
    return len(jobs)
