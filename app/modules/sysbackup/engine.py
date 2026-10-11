"""
Background worker for the self-backup (SingletonTask "system-backup" in
app/main.py): makes queued backups one at a time, queues the scheduled
backup when its time comes, applies retention after it, runs the weekly
restore test, and once an hour tidies up after interrupted work.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import SessionLocal
from app.core.storage_guard import storage_critical
from app.models.system_backup import BK_READY, KIND_SCHEDULED, RESTORE_TEST, SystemBackup, SystemRestore
from app.modules.sysbackup import restore, service

logger = logging.getLogger(__name__)

POLL_SECONDS = 5
SCHEDULE_SECONDS = 60
HOUSEKEEPING_EVERY = timedelta(hours=1)
TEST_EVERY = timedelta(days=7)


def _with_session(fn):
    db = SessionLocal()
    try:
        return fn(db)
    except Exception:
        logger.exception("[sysbackup] %s failed", getattr(fn, "__name__", "task"))
        db.rollback()
        return None
    finally:
        db.close()


def build_next() -> bool:
    """Make one queued backup. True when there was one."""
    def work(db):
        """Claim the next queued backup and run it; after a scheduled one succeeds, apply retention.
        False when nothing was queued.
        """
        b = service.claim_next(db)
        if b is None:
            return False
        b = service.run_backup(db, b)
        if b is not None and b.kind == KIND_SCHEDULED and b.status == BK_READY:
            removed = service.apply_retention(db)
            if removed:
                logger.info("[sysbackup] retention removed %s old backups", removed)
            if _test_due(db, b):
                restore.run_test(b.id)
        return True
    return bool(_with_session(work))


def _test_due(db, b: SystemBackup) -> bool:
    """The weekly restore test runs after the weekly-day backup, or after any
    scheduled backup once the last automatic test is over a week old."""
    cfg = service.get_settings(db)
    if not cfg["restore_test"]:
        return False
    last = (db.query(SystemRestore).filter(SystemRestore.kind == RESTORE_TEST,
                                           SystemRestore.requested_by.is_(None))
            .order_by(SystemRestore.created_at.desc()).first())
    if last is not None and datetime.utcnow() - last.created_at < timedelta(days=1):
        return False
    weekly_day = service._local(db, b.created_at).weekday() == cfg["weekly_day"]
    return weekly_day or last is None or datetime.utcnow() - last.created_at >= TEST_EVERY + timedelta(days=1)


def queue_scheduled() -> None:
    """Queue the scheduled backup when its time slot has come and it has not run yet."""
    def work(db):
        if service.due_scheduled(db):
            b = service.queue_backup(db, KIND_SCHEDULED)
            logger.info("[sysbackup] scheduled backup %s queued (%s)", b.id, ", ".join(b.contents))
    _with_session(work)


def housekeeping() -> None:
    """Mark jobs whose worker died as failed, and backups whose file disappeared as missing."""
    def work(db):
        service.fail_stale(db)
        restore.fail_stale(db)
        service.mark_missing(db)
    _with_session(work)


class BackupWorker:
    """The background loop of system backups (one worker only, see app/core/singleton.py): runs queued
    backups, queues scheduled ones and does housekeeping.
    """
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        last_schedule, last_house = datetime.min, datetime.min
        while not self._stop.is_set():
            now = datetime.utcnow()
            if now - last_house >= HOUSEKEEPING_EVERY:
                await asyncio.to_thread(housekeeping)
                last_house = now
            # Disk nearly full (app/core/storage_guard.py): no scheduled backup is written; one an
            # administrator starts still is.
            if (now - last_schedule).total_seconds() >= SCHEDULE_SECONDS \
                    and not await asyncio.to_thread(storage_critical):
                await asyncio.to_thread(queue_scheduled)
                last_schedule = now
            if await asyncio.to_thread(build_next):
                continue
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=POLL_SECONDS)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="system-backup")

    async def stop(self) -> None:
        """Stop the loop, letting a running backup finish for up to 2 minutes."""
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=120)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[BackupWorker] = None


def start_backup_worker() -> None:
    """Start the backup loop (called by the SingletonTask of this worker when it becomes leader)."""
    global _worker
    if _worker is None:
        _worker = BackupWorker()
    _worker.start()


async def stop_backup_worker() -> None:
    if _worker is not None:
        await _worker.stop()
