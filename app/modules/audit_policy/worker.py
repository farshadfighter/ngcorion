"""
Background scoring under the benchmark policy (app/modules/audit_policy/service.py): every few seconds
the completed audits waiting for it are scored, expired rules end, and once an hour the latest audits
of assets in rule groups are rechecked. Runs in one worker (SingletonTask "audit-policy" in app/main.py).
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional

from app.core.database import SessionLocal
from app.modules.audit_policy import service

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 15


def run_once() -> None:
    db = SessionLocal()
    try:
        service.refresh_groups(db, datetime.utcnow())
        stats = service.run_pending(db)
        if stats["changed"] or stats["expired"]:
            logger.info("[audit-policy] %s", stats)
    except Exception:
        logger.exception("[audit-policy] scoring failed")
        db.rollback()
    finally:
        db.close()


class PolicyWorker:
    def __init__(self, interval: int = INTERVAL_SECONDS):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.to_thread(run_once)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="audit-policy")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=30)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[PolicyWorker] = None


def start_policy_worker() -> None:
    global _worker
    if _worker is None:
        _worker = PolicyWorker()
    _worker.start()


async def stop_policy_worker() -> None:
    if _worker is not None:
        await _worker.stop()
