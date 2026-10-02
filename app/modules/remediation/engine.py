"""
Background sync for remediation tracking: every SYNC_SECONDS (and once at
start) the remediation items are brought in line with what CVE, audit and
architecture validation report. Runs in one worker (SingletonTask
"remediation-sync" in app/main.py).
"""
import asyncio
import logging
from typing import Optional

from app.core.database import SessionLocal
from app.modules.remediation import service

logger = logging.getLogger(__name__)

SYNC_SECONDS = 300


def run_sync() -> None:
    db = SessionLocal()
    try:
        stats = service.sync(db)
        if any(stats.values()):
            logger.info("[remediation] sync: %s", stats)
    except Exception:
        logger.exception("[remediation] sync failed")
        db.rollback()
    finally:
        db.close()


class RemediationSync:
    def __init__(self, interval: int = SYNC_SECONDS):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.to_thread(run_sync)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="remediation-sync")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=30)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[RemediationSync] = None


def start_remediation_sync() -> None:
    global _worker
    if _worker is None:
        _worker = RemediationSync()
    _worker.start()


async def stop_remediation_sync() -> None:
    if _worker is not None:
        await _worker.stop()
