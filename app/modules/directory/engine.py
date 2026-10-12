"""
The directory account check every CHECK_MINUTES (app/modules/directory/service.py
check_accounts): a directory account disabled, deleted or out of every mapped group stops working
within that time, and role changes in the directory reach NGCorion. Runs in one worker
(SingletonTask "directory-check" in app/main.py). It keeps running while the disk is nearly full
(app/core/storage_guard.py): it only ever takes access away.
"""
import asyncio
import logging
from typing import Optional

from app.core.database import SessionLocal

from . import service

logger = logging.getLogger(__name__)


def run_check() -> None:
    db = SessionLocal()
    try:
        status = service.check_accounts(db)
        if status.get("turned_off") or status.get("updated"):
            logger.info("[Directory] check: %s", status)
    except Exception:
        logger.exception("[Directory] check failed")
        db.rollback()
    finally:
        db.close()


class DirectoryCheck:
    def __init__(self, interval: int = service.CHECK_MINUTES * 60):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.to_thread(run_check)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="directory-check")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=30)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[DirectoryCheck] = None


def start_directory_check() -> None:
    global _worker
    if _worker is None:
        _worker = DirectoryCheck()
    _worker.start()


async def stop_directory_check() -> None:
    if _worker is not None:
        await _worker.stop()
