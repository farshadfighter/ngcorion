"""
Background SNMP poller.

Sweeps every asset with an SNMP credential on a fixed interval and persists
the result (AssetSnmpStatus / AssetSnmpInterface). An asyncio task, not a
thread like app/core/heartbeat.py: SNMP polling here is I/O-bound over UDP
via `puresnmp`'s native async API, so a task on the existing event loop is
both simpler and cheaper than a second OS thread running its own loop.
"""
import asyncio
import logging
from typing import Optional

from app.core.config import settings
from app.core.database import SessionLocal
from app.modules.noc.service import NocService

logger = logging.getLogger(__name__)


class NocPoller:
    def __init__(self, interval_seconds: Optional[int] = None):
        self.interval_seconds = interval_seconds if interval_seconds is not None else settings.NOC_POLL_INTERVAL_SECONDS
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def _run_once(self) -> None:
        db = SessionLocal()
        try:
            count = await NocService.poll_all(db)
            if count:
                logger.info("[NOC] Polled %d asset(s)", count)
        except Exception:
            logger.exception("[NOC] Poll sweep failed")
        finally:
            db.close()

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            await self._run_once()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass  # normal: interval elapsed, poll again

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="noc-poller")
        logger.info("[NOC] Poller started (interval: %ds)", self.interval_seconds)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        logger.info("[NOC] Poller stopped")


_poller: Optional[NocPoller] = None


def start_noc_poller() -> None:
    global _poller
    if _poller is None:
        _poller = NocPoller()
    if not _poller.is_running():
        _poller.start()


async def stop_noc_poller() -> None:
    global _poller
    if _poller is not None:
        await _poller.stop()
