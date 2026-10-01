"""
Health of the running NGCorion.

  GET /health              public liveness/readiness: the API answers and the
                           database is reachable (503 when it is not). Used by
                           the container healthcheck; reveals nothing internal.
  GET /api/system/health   admin detail: database, schema migrations,
                           background tasks (is each one running in some
                           worker?), overdue scheduled jobs, CVE database,
                           license, disk.
"""
import os
import shutil
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal, get_db
from app.core.dependencies import require_admin
from app.core.singleton import lock_key
from app.models import User

public_router = APIRouter(tags=["Health"])
router = APIRouter(prefix="/api/system", tags=["Health"])

ALEMBIC_DIR = Path(__file__).resolve().parents[2] / "alembic"
OVERDUE_AFTER = timedelta(minutes=10)
LOW_DISK_BYTES = 2 * 1024 ** 3


def _ok(name, detail=None, **extra):
    return {"name": name, "status": "ok", "detail": detail, **extra}


def _warn(name, detail, **extra):
    return {"name": name, "status": "warning", "detail": detail, **extra}


def _fail(name, detail, **extra):
    return {"name": name, "status": "error", "detail": detail, **extra}


@public_router.get("/health")
def health():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # noqa: BLE001
        database = "unreachable"
    finally:
        db.close()
    body = {"status": "ok" if database == "ok" else "degraded", "version": settings.VERSION, "database": database}
    return JSONResponse(body, status_code=200 if database == "ok" else 503)


def _lock_held(db: Session, name: str) -> bool:
    key = lock_key(name) & 0xFFFFFFFFFFFFFFFF
    return bool(db.execute(text(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
        "AND classid = :hi AND objid = :lo AND objsubid = 1"
    ), {"hi": key >> 32, "lo": key & 0xFFFFFFFF}).scalar())


def _migrations(db: Session):
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(ALEMBIC_DIR))
        heads = set(ScriptDirectory.from_config(cfg).get_heads())
        current = {r[0] for r in db.execute(text("SELECT version_num FROM alembic_version"))}
    except Exception as exc:  # noqa: BLE001
        return _warn("migrations", f"Could not read the schema version: {exc.__class__.__name__}")
    if current == heads:
        return _ok("migrations", f"Up to date ({', '.join(sorted(current))})")
    return _fail("migrations", "The database schema is not at the code's version - run `alembic upgrade head`.",
                 current=sorted(current), expected=sorted(heads))


@router.get("/health")
def health_detail(request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    checks = []

    started = time.perf_counter()
    db.execute(text("SELECT 1"))
    checks.append(_ok("database", f"Reachable in {(time.perf_counter() - started) * 1000:.0f} ms",
                      size_bytes=db.execute(text("SELECT pg_database_size(current_database())")).scalar()))

    checks.append(_migrations(db))

    # Background tasks: each runs in one worker that holds its lock.
    mine = {t.name: t.leading for t in getattr(request.app.state, "singletons", [])}
    for name, label in (("job-scheduler", "Job scheduler"), ("noc-poller", "NOC poller"),
                        ("noc-metrics-retention", "NOC metrics rollup"), ("cve-auto-update", "CVE automatic update")):
        if _lock_held(db, name):
            where = "this worker" if mine.get(name) else "another worker"
            checks.append(_ok(f"task:{name}", f"{label} running ({where})"))
        else:
            checks.append(_fail(f"task:{name}", f"{label} is not running in any worker"))

    from app.models.scheduling import ScheduledJob
    overdue = db.query(ScheduledJob).filter(ScheduledJob.enabled.is_(True),
                                            ScheduledJob.next_run_at < datetime.utcnow() - OVERDUE_AFTER).count()
    checks.append(_warn("scheduled_jobs", f"{overdue} scheduled job(s) overdue by more than 10 minutes")
                  if overdue else _ok("scheduled_jobs", "No overdue scheduled job"))

    from app.modules.cve import settings as cve_settings
    from app.modules.cve.feeds import iso_to_dt
    watermark = iso_to_dt(cve_settings.get(db, cve_settings.WATERMARK))
    if watermark is None:
        checks.append(_warn("cve_database", "Not loaded - CVE findings are unavailable"))
    elif datetime.utcnow() - watermark > timedelta(days=7):
        checks.append(_warn("cve_database", f"Last updated {watermark:%Y-%m-%d} - more than 7 days ago"))
    else:
        checks.append(_ok("cve_database", f"Up to date as of {watermark:%Y-%m-%d %H:%M} UTC"))

    from app.core.license_state import get_license_state
    lic = get_license_state()
    checks.append(_ok("license", lic.message) if lic.valid else _fail("license", lic.message))

    for label, path in (("disk_data", os.getenv("CVE_DATA_DIR") or tempfile.gettempdir()),
                        ("disk_app", str(ALEMBIC_DIR.parent))):
        try:
            usage = shutil.disk_usage(path)
            detail = f"{usage.free / 1024 ** 3:.1f} GB free of {usage.total / 1024 ** 3:.1f} GB ({path})"
            checks.append(_warn(label, detail) if usage.free < LOW_DISK_BYTES else _ok(label, detail))
        except OSError as exc:
            checks.append(_warn(label, f"Cannot read {path}: {exc.strerror}"))

    worst = "error" if any(c["status"] == "error" for c in checks) else \
        "warning" if any(c["status"] == "warning" for c in checks) else "ok"
    return {"status": worst, "version": settings.VERSION, "checked_at": datetime.utcnow().isoformat() + "Z",
            "worker_pid": os.getpid(), "checks": checks}
