"""
Maintenance mode while a restore runs: every API request answers 503 with
what is happening, so nobody makes changes the restore is about to replace.

The flag is a file in BACKUP_DIR so every uvicorn worker sees it. It carries
the runner and a heartbeat: a flag left by a process that died is ignored
(and removed) instead of locking the product out.
"""
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings

logger = logging.getLogger(__name__)

STALE_SECONDS = 30 * 60
STATUS_PATH = "/api/system-backup/maintenance"
# Answered from memory, never from the database: let them through so a page
# loaded during the restore does not take the 503 for a missing license.
PASS_THROUGH = ("/api/license/status",)

_cache = {"mtime": None, "state": None, "checked": 0.0}


def flag_path() -> Path:
    return Path(settings.BACKUP_DIR) / ".maintenance.json"


def on(**info) -> None:
    from app.core.singleton import runner_tag
    update(runner=runner_tag(), since=time.time(), **info)


def update(**info) -> None:
    path = flag_path()
    try:
        current = json.loads(path.read_text()) if path.exists() else {}
    except (OSError, ValueError):
        current = {}
    current.update(info)
    current["beat"] = time.time()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(current))
    os.replace(tmp, path)


def off() -> None:
    try:
        flag_path().unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("[sysbackup] could not clear maintenance mode: %s", exc)


def state() -> Optional[dict]:
    """The active maintenance state, or None. Cheap: one stat per call."""
    from app.core.singleton import runner_is_alive
    path = flag_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        _cache.update(mtime=None, state=None)
        return None
    if mtime != _cache["mtime"]:
        try:
            _cache.update(mtime=mtime, state=json.loads(path.read_text()))
        except (OSError, ValueError):
            return None
    data = _cache["state"]
    if not data:
        return None
    age = time.time() - float(data.get("beat") or 0)
    # A restore beats at least every few seconds. Only the server instance
    # that set the flag can tell whether its process is alive (a CLI restore
    # runs outside it), so a silent flag is trusted for two minutes before
    # the runner check may drop it, and never beyond STALE_SECONDS.
    if age > STALE_SECONDS or (age > 120 and not runner_is_alive(data.get("runner"))):
        logger.warning("[sysbackup] removing a maintenance flag left by a stopped restore")
        off()
        return None
    return {k: data.get(k) for k in ("reason", "step", "progress", "restore_id", "since")}


class MaintenanceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path not in PASS_THROUGH:
            current = state()
            if current is not None:
                if path == STATUS_PATH:
                    return JSONResponse({"maintenance": current})
                return JSONResponse(
                    {"detail": "NGCorion is restoring a backup. It will be back in a few minutes.",
                     "maintenance": current},
                    status_code=503, headers={"Retry-After": "15"})
        return await call_next(request)
