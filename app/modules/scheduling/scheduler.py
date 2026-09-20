"""
Background job scheduler.

Sweeps for due ScheduledJobs on a fixed interval and runs each one. Unlike
NOC's poller (natively async SNMP I/O), discovery (nmap subprocess) and
audit (Netmiko/paramiko/WinRM) I/O in this app is synchronous/blocking, so
each due job's run_job_now() is offloaded to a thread (asyncio.to_thread)
with its own DB session rather than awaited on the event loop directly -
one slow/hanging device must not delay every other job's due-check.
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional

from app.core.config import settings
from app.core.database import SessionLocal
from app.modules.scheduling.service import SchedulingService

logger = logging.getLogger(__name__)

SCHEDULER_SWEEP_INTERVAL_SECONDS = settings.SCHEDULER_SWEEP_INTERVAL_SECONDS


def _run_job_in_thread(job_id: int) -> None:
    """Runs in a worker thread: its own DB session (SQLAlchemy sessions are
    not thread-safe to share), independent of the sweep's own session."""
    db = SessionLocal()
    try:
        job = SchedulingService.get_job(db, job_id)
        if job is None:
            return
        SchedulingService.run_job_now(db, job)
    except Exception:
        logger.exception("[Scheduler] Job %d failed", job_id)
    finally:
        db.close()


class JobScheduler:
    def __init__(self, interval_seconds: Optional[int] = None):
        self.interval_seconds = interval_seconds if interval_seconds is not None else SCHEDULER_SWEEP_INTERVAL_SECONDS
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def _sweep_once(self) -> None:
        db = SessionLocal()
        try:
            due = SchedulingService.due_jobs(db, datetime.utcnow())
            job_ids = [job.id for job in due]
        finally:
            db.close()

        if not job_ids:
            return

        logger.info("[Scheduler] %d job(s) due", len(job_ids))
        await asyncio.gather(*(asyncio.to_thread(_run_job_in_thread, job_id) for job_id in job_ids))

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._sweep_once()
            except Exception:
                logger.exception("[Scheduler] Sweep failed")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass  # normal: interval elapsed, sweep again

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="job-scheduler")
        logger.info("[Scheduler] Started (interval: %ds)", self.interval_seconds)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        logger.info("[Scheduler] Stopped")


_scheduler: Optional[JobScheduler] = None


def start_job_scheduler() -> None:
    global _scheduler
    if _scheduler is None:
        _scheduler = JobScheduler()
    if not _scheduler.is_running():
        _scheduler.start()


async def stop_job_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        await _scheduler.stop()
