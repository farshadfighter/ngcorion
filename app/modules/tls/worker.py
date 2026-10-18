"""
The automatic TLS scan (app/modules/tls/service.py): once a minute it checks whether a scan is due (the
interval has passed, or someone asked for one) and runs it. One worker (SingletonTask "tls-scan" in
app/main.py).
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional

from app.core.database import SessionLocal
from app.modules.tls import service

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 60


def run_once() -> None:
    db = SessionLocal()
    try:
        if not service.due(db):
            return
        started = datetime.utcnow()
        service.set_state(db, running=True, requested=False, started=started.isoformat())
        try:
            stats = service.run_scan(db, now=started)
        except Exception:
            db.rollback()
            service.set_state(db, running=False, last_run=started.isoformat(), last_error="failed")
            raise
        service.set_state(db, running=False, last_run=started.isoformat(), last_stats=stats, last_error=None)
        logger.info("[tls-scan] %s", stats)
    except Exception:
        logger.exception("[tls-scan] scan failed")
        db.rollback()
    finally:
        db.close()


class ScanWorker:
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
            self._task = asyncio.create_task(self._loop(), name="tls-scan")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=60)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_worker: Optional[ScanWorker] = None


def start_tls_worker() -> None:
    global _worker
    if _worker is None:
        _worker = ScanWorker()
    _worker.start()


async def stop_tls_worker() -> None:
    if _worker is not None:
        await _worker.stop()
