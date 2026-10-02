"""
Run a background task in exactly one process.

Production runs uvicorn with several workers (Dockerfile.ngcorion: --workers 4)
and every worker runs the app's lifespan. Background loops - the job
scheduler, the NOC poller, the metrics rollup, the CVE auto-update - must not
run once per worker: scheduled audits would fire four times, devices would be
polled four times.

Each loop is wrapped in a SingletonTask. Every worker keeps trying to take a
Postgres session-level advisory lock named after the task; the one that holds
it starts the loop, the others wait. The lock lives on a dedicated
connection, so it is released the moment that worker exits or its connection
drops - another worker then takes over within RETRY_SECONDS. While holding
it, the leader checks its connection; if the lock is lost the loop is stopped
before anyone else can start it.
"""
import asyncio
import hashlib
import logging
from typing import Awaitable, Callable, Optional

from sqlalchemy import text

from app.core.database import engine

logger = logging.getLogger(__name__)

RETRY_SECONDS = 30
PAUSE_CHECK_SECONDS = 5


def _maintenance_active() -> bool:
    """A self-backup restore is running (app/modules/sysbackup/maintenance.py)."""
    try:
        from app.modules.sysbackup.maintenance import state
        return state() is not None
    except Exception:
        return False


def lock_key(name: str) -> int:
    """A stable signed 64-bit key for pg_advisory_lock."""
    return int.from_bytes(hashlib.sha256(f"ngcorion:{name}".encode()).digest()[:8], "big", signed=True)


def _try_lock(key: int):
    """A connection holding the lock, or None."""
    conn = engine.connect()
    try:
        got = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar()
        conn.commit()
        if got:
            return conn
    except Exception:
        logger.exception("[Singleton] lock attempt failed")
    conn.close()
    return None


def _still_held(conn) -> bool:
    try:
        held = conn.execute(text(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted"
        )).scalar()
        conn.commit()
        return bool(held)
    except Exception:
        return False


def _release(conn, key: int) -> None:
    try:
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class SingletonTask:
    """start(): begin competing for the lock; stop(): stop the loop (if this
    process runs it) and give the lock back."""

    def __init__(self, name: str, start: Callable[[], None], stop: Callable[[], Awaitable[None]],
                 retry_seconds: int = RETRY_SECONDS):
        self.name = name
        self.key = lock_key(name)
        self._start, self._stop = start, stop
        self.retry_seconds = retry_seconds
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._conn = None
        self.leading = False
        self._paused = False

    async def _run(self):
        last_lock_check = 0.0
        loop = asyncio.get_running_loop()
        while not self._stopping.is_set():
            paused = _maintenance_active()
            if self.leading and paused != self._paused:
                # A restore is replacing the database: background work done
                # now would be lost (or land in the old tables), so the task
                # waits it out and resumes on its own afterwards.
                self._paused = paused
                if paused:
                    logger.info("[Singleton] %s paused for maintenance", self.name)
                    await self._stop()
                else:
                    logger.info("[Singleton] %s resumed after maintenance", self.name)
                    self._start()
            if loop.time() - last_lock_check >= self.retry_seconds:
                last_lock_check = loop.time()
                if self._conn is None:
                    self._conn = await asyncio.to_thread(_try_lock, self.key)
                    if self._conn is not None:
                        logger.info("[Singleton] this worker runs %s", self.name)
                        self.leading = True
                        self._paused = paused
                        if not paused:
                            self._start()
                elif not await asyncio.to_thread(_still_held, self._conn):
                    logger.warning("[Singleton] lost the lock for %s; stopping it here", self.name)
                    self.leading = False
                    if not self._paused:
                        await self._stop()
                    self._paused = False
                    await asyncio.to_thread(_release, self._conn, self.key)
                    self._conn = None
                    last_lock_check = 0.0       # compete again right away
                    continue
            try:
                await asyncio.wait_for(self._stopping.wait(),
                                       timeout=min(self.retry_seconds, PAUSE_CHECK_SECONDS))
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._run(), name=f"singleton-{self.name}")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        if self.leading:
            self.leading = False
            if not self._paused:
                await self._stop()
            self._paused = False
        if self._conn is not None:
            await asyncio.to_thread(_release, self._conn, self.key)
            self._conn = None


# ── which process runs a job ─────────────────────────────────────────────
# A job started by an API request runs in a thread of whichever worker took
# the request. At startup, a worker must fail only the jobs that really died:
# those of an earlier server run, or of a worker process that no longer
# exists - not the ones another live worker is running right now.

def _instance_id() -> str:
    """The running server: host + the uvicorn supervisor and its start time
    (a container restart can reuse the same PIDs)."""
    import os
    import socket
    ppid = os.getppid()
    try:
        with open(f"/proc/{ppid}/stat") as fh:
            started = fh.read().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        started = "?"
    return f"{socket.gethostname()}:{ppid}:{started}"


INSTANCE_ID = _instance_id()


def runner_tag() -> str:
    """Stored on a job when it starts."""
    import os
    return f"{INSTANCE_ID}|{os.getpid()}"


def runner_is_alive(tag) -> bool:
    """Whether the process that started a job is still running it."""
    import os
    if not tag or "|" not in tag:
        return False
    instance, pid = tag.rsplit("|", 1)
    if instance != INSTANCE_ID or not pid.isdigit():
        return False
    if int(pid) == os.getpid():
        return True
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
