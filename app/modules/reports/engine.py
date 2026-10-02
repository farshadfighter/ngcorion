"""
Background worker for reports (SingletonTask "report-worker" in app/main.py):
builds queued reports one at a time, queues scheduled reports when they are
due, and once an hour deletes reports older than the retention period.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import SessionLocal
from app.modules.reports import service

logger = logging.getLogger(__name__)

POLL_SECONDS = 5
SCHEDULE_SECONDS = 60
PURGE_EVERY = timedelta(hours=1)


def _with_session(fn):
    db = SessionLocal()
    try:
        return fn(db)
    except Exception:
        logger.exception("[reports] %s failed", fn.__name__)
        db.rollback()
        return None
    finally:
        db.close()


def build_next() -> bool:
    """Build one queued report. True when there was one."""
    def work(db):
        r = service.claim_next(db)
        if r is None:
            return False
        service.run(db, r)
        return True
    return bool(_with_session(work))


def run_schedules() -> None:
    _with_session(lambda db: service.run_due_schedules(db))


def housekeeping() -> None:
    def work(db):
        service.fail_stale(db)
        n = service.purge_old(db)
        if n:
            logger.info("[reports] deleted %s reports past the retention period", n)
    _with_session(work)


class ReportWorker:
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        last_schedule, last_purge = datetime.min, datetime.min
        while not self._stop.is_set():
            now = datetime.utcnow()
            if now - last_purge >= PURGE_EVERY:
                await asyncio.to_thread(housekeeping)
                last_purge = now
            if (now - last_schedule).total_seconds() >= SCHEDULE_SECONDS:
                await asyncio.to_thread(run_schedules)
                last_schedule = now
            busy = await asyncio.to_thread(build_next)
            if busy:
                continue
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=POLL_SECONDS)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="report-worker")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=60)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[ReportWorker] = None


def start_report_worker() -> None:
    global _worker
    if _worker is None:
        _worker = ReportWorker()
    _worker.start()


async def stop_report_worker() -> None:
    if _worker is not None:
        await _worker.stop()
