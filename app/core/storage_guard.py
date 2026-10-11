"""
Audit storage protection (Common Criteria FAU_STG.3 / FAU_STG.4).

The audit trail (audit_logs, login_logs) lives in PostgreSQL on the same disk as the application in
both supported installations (the appliance, and Docker with its volumes under the Docker root).
When that disk fills up, writing an audit record fails while the action it records may already be
done - an action that leaves no trace. Two levels prevent that:

- warning (FAU_STG.3): the "Disk space low" alert rule (app/modules/alerts/events.py, 2 GB by
  default) tells administrators while there is plenty of room to act;
- critical (FAU_STG.4): below settings.STORAGE_CRITICAL_MB free, every change (POST, PUT, PATCH,
  DELETE under /api) is refused with 507 to everyone except system administrators - the
  authorised users who free the space (delete old reports and backups, archive the audit trail
  with app/modules/audit_archive/) - and scheduled audits, discovery, reports and backups wait.
  Entering and leaving this state is itself recorded in the audit trail.

Free space is read at most every CHECK_SECONDS, so the guard costs nothing per request.
"""
import logging
import os
import shutil
import tempfile
import threading
import time
from typing import List, Optional, Tuple

from fastapi import HTTPException

from app.core.config import settings

logger = logging.getLogger(__name__)

CHECK_SECONDS = 30
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Ending a session must always work (it is also how a user gives up).
ALWAYS_ALLOWED = frozenset({"/auth/logout"})
REFUSED = ("The server is almost out of disk space: changes are paused until a system administrator "
           "frees space.")

_lock = threading.Lock()
_state = {"checked": 0.0, "free": None, "path": None, "critical": False}


def disk_paths() -> List[str]:
    """Where NGCorion writes: the data directory (CVE data, temporary files) and the application
    (in Docker, the container's disk, which shares the Docker root with the database volume)."""
    return [os.getenv("CVE_DATA_DIR") or tempfile.gettempdir(),
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))]


def _lowest_free() -> Tuple[Optional[int], Optional[str]]:
    lowest = (None, None)
    for path in disk_paths():
        try:
            free = shutil.disk_usage(path).free
        except OSError:
            continue
        if lowest[0] is None or free < lowest[0]:
            lowest = (free, path)
    return lowest


def _record(critical: bool, free: Optional[int], path: Optional[str]) -> None:
    """Put the change of state in the audit trail (best effort: the disk is nearly full)."""
    from app.core.database import SessionLocal
    from app.models.security_audit_log import log_action
    mb = (free or 0) // (1024 * 1024)
    db = SessionLocal()
    try:
        log_action(db, username="system", module="system",
                   action="system.storage_critical" if critical else "system.storage_recovered",
                   result="failed" if critical else "success",
                   detail=(f"{mb} MB free on {path}: changes paused for everyone but system administrators"
                           if critical else f"{mb} MB free on {path}: changes allowed again"))
    except Exception:
        logger.exception("[Storage] Could not record the storage state in the audit trail")
    finally:
        db.close()


def storage_state(force: bool = False) -> dict:
    """{"critical", "free" (bytes), "path", "limit" (bytes)}, read again after CHECK_SECONDS."""
    limit = max(0, int(settings.STORAGE_CRITICAL_MB)) * 1024 * 1024
    changed = None
    with _lock:
        now = time.monotonic()
        if force or now - _state["checked"] >= CHECK_SECONDS:
            free, path = _lowest_free()
            critical = bool(limit) and free is not None and free < limit
            if critical != _state["critical"]:
                changed = critical
            _state.update(checked=now, free=free, path=path, critical=critical)
        snapshot = dict(_state, limit=limit)
    if changed is not None:
        (logger.error if changed else logger.warning)(
            "[Storage] %s: %s bytes free on %s", "Critical" if changed else "Recovered",
            snapshot["free"], snapshot["path"])
        _record(changed, snapshot["free"], snapshot["path"])
    return snapshot


def storage_critical() -> bool:
    return storage_state()["critical"]


def check_request(request, user) -> None:
    """Refuse a change by anyone but a system administrator while storage is critical (507)."""
    if getattr(request, "method", None) not in WRITE_METHODS or request.url.path in ALWAYS_ALLOWED:
        return
    if getattr(getattr(user, "role", None), "value", None) == "admin":
        return
    if storage_critical():
        raise HTTPException(status_code=507, detail=REFUSED)
