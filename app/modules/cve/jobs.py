"""
Loading and updating the CVE database.

Every change to the database is a CveUpdateJob, run in a background thread,
one at a time:

  online   download what NVD changed since the watermark (everything when the
           database is empty), then the current KEV list and EPSS scores
  full     the same, but download all of NVD again
  offline  import a signed package (.ngcve) uploaded by an admin
  bundle   import the signed snapshot shipped with the release (first run)
  export   write a signed package of this database, for an air-gapped site

An update downloads first (records are spooled to disk, so the network part
never holds a database transaction open), then writes everything - CVEs, KEV
flags, EPSS scores, the new watermark - in one transaction. A failed or
cancelled update therefore leaves the previous database exactly as it was;
running it again starts from the same watermark.

Progress is written through a second session, so the page can poll it while
the write transaction is still open.
"""
import asyncio
import gzip
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterator, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.singleton import lock_key, runner_is_alive, runner_tag
from app.models.cve import CVE_JOB_ACTIVE, CveEntry, CveUpdateJob
from app.models.security_audit_log import log_action
from app.modules.cve import feeds, package, settings, store

logger = logging.getLogger(__name__)

STEPS = {
    "online": ["connect", "download", "kev", "epss", "apply"],
    "full": ["connect", "download", "kev", "epss", "apply"],
    "offline": ["verify", "apply"],
    "bundle": ["verify", "apply"],
    "export": ["export"],
}
PROGRESS_INTERVAL = 1.0          # seconds between progress writes
CANCEL_CHECK_SECONDS = 2.0
AUTO_CHECK_SECONDS = 300
UPLOAD_TTL = timedelta(hours=24)
KEEP_EXPORTS = 3

_lock = threading.Lock()
_cancel: Dict[int, threading.Event] = {}


class JobBusy(RuntimeError):
    pass


class Cancelled(RuntimeError):
    pass


def data_dir(sub: str) -> str:
    base = os.getenv("CVE_DATA_DIR") or os.path.join(tempfile.gettempdir(), "ngcorion-cve")
    path = os.path.join(base, sub)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def bundle_path() -> str:
    return os.getenv("CVE_BUNDLE_PATH") or "/app/data/cve/bundle.ngcve"


def bundle_available() -> bool:
    return os.path.isfile(bundle_path())


def active_job(db: Session) -> Optional[CveUpdateJob]:
    return db.query(CveUpdateJob).filter(CveUpdateJob.status.in_(CVE_JOB_ACTIVE)).first()


def create_job(db: Session, kind: str, user_id: Optional[int], trigger: str = "manual",
               file_name: Optional[str] = None) -> CveUpdateJob:
    """Raises JobBusy when another job is queued or running - in any worker
    process: the check and the insert run under a Postgres advisory lock."""
    with _lock:
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key("cve-job-create")})
        running = active_job(db)
        if running is not None:
            raise JobBusy(f"Another database job (#{running.id}) is already running.")
        job = CveUpdateJob(kind=kind, trigger=trigger, status="queued", requested_by=user_id,
                           file_name=file_name, progress={"steps": STEPS[kind], "step": STEPS[kind][0]},
                           runner=runner_tag())
        db.add(job)
        db.commit()
        db.refresh(job)
        _cancel[job.id] = threading.Event()
        return job


def request_cancel(db: Session, job: CveUpdateJob) -> bool:
    if job.status not in CVE_JOB_ACTIVE:
        return False
    if not runner_is_alive(job.runner):
        # The process that ran it is gone - nothing to stop.
        job.status, job.error, job.finished_at = "cancelled", "Cancelled", datetime.utcnow()
        db.commit()
        return True
    # The job may run in another worker process: it reads this flag.
    job.cancel_requested = True
    db.commit()
    flag = _cancel.get(job.id)
    if flag is not None:
        flag.set()
    return True


def fail_interrupted_cve_jobs(db: Session) -> int:
    """A job cut off by a server restart wrote nothing (one transaction).
    Jobs another live worker process is running are left alone."""
    jobs = [j for j in db.query(CveUpdateJob).filter(CveUpdateJob.status.in_(CVE_JOB_ACTIVE))
            if not runner_is_alive(j.runner)]
    for job in jobs:
        job.status = "failed"
        job.error = "Interrupted by a server restart. The database was not changed - run it again."
        job.finished_at = datetime.utcnow()
    if jobs:
        db.commit()
    return len(jobs)


# ── progress ─────────────────────────────────────────────────────────────

class _Job:
    """The job row, written through its own session."""

    def __init__(self, job_id: int, session_factory: Callable):
        self.id = job_id
        self.db = session_factory()
        self.row = self.db.get(CveUpdateJob, job_id)
        self.kind = self.row.kind
        self.flag = _cancel.get(job_id) or threading.Event()
        self._last = 0.0
        self._last_cancel_check = 0.0
        self.stats: dict = {}
        self.file_name: Optional[str] = None

    def cancelled(self) -> bool:
        """The local flag, or - every couple of seconds - the job row, where
        a Cancel handled by another worker process leaves its request."""
        if not self.flag.is_set():
            now = datetime.utcnow().timestamp()
            if now - self._last_cancel_check >= CANCEL_CHECK_SECONDS:
                self._last_cancel_check = now
                if self.db.query(CveUpdateJob.cancel_requested).filter(CveUpdateJob.id == self.id).scalar():
                    self.flag.set()
        return self.flag.is_set()

    def check(self):
        if self.cancelled():
            raise Cancelled()

    def start(self):
        self.row.status = "running"
        self.row.started_at = datetime.utcnow()
        self.db.commit()

    def progress(self, step: str, done: Optional[int] = None, total: Optional[int] = None,
                 message: Optional[str] = None, force: bool = False):
        now = datetime.utcnow().timestamp()
        if not force and step == (self.row.progress or {}).get("step") and now - self._last < PROGRESS_INTERVAL:
            return
        self._last = now
        self.row.progress = {"steps": STEPS[self.kind], "step": step, "done": done, "total": total,
                             "message": message}
        self.db.commit()

    def finish(self, status: str, error: Optional[str] = None):
        self.db.rollback()
        self.row = self.db.get(CveUpdateJob, self.id)
        self.row.status = status
        self.row.error = error
        if self.file_name:
            self.row.file_name = self.file_name
        self.row.stats = self.stats
        self.row.finished_at = datetime.utcnow()
        progress = dict(self.row.progress or {})
        if status == "succeeded":
            progress.update(step="done", message=None)
        self.row.progress = progress
        self.db.commit()
        try:
            log_action(self.db, user_id=self.row.requested_by, action=f"cve.{self.kind}", module="cve",
                       target_id=self.id, result="success" if status == "succeeded" else "failed",
                       detail=_summary(self.kind, status, self.stats, error))
        except Exception:  # noqa: BLE001 - the audit row never fails the job
            logger.exception("[CVE] could not write the audit log for job %s", self.id)

    def close(self):
        self.db.close()
        _cancel.pop(self.id, None)


def _summary(kind: str, status: str, stats: dict, error: Optional[str]) -> str:
    if status != "succeeded":
        return f"{kind}: {status}" + (f" - {error}" if error else "")
    if kind == "export":
        return f"export: {stats.get('cves', 0)} CVEs written to {stats.get('file')}"
    return (f"{kind}: {stats.get('new', 0)} new, {stats.get('changed', 0)} updated, "
            f"{stats.get('removed', 0)} removed, {stats.get('kev', 0)} KEV, {stats.get('epss', 0)} EPSS")


def _run(job_id: int, session_factory: Callable, body: Callable[["_Job", Session], None]) -> None:
    j = _Job(job_id, session_factory)
    work = session_factory()
    try:
        j.start()
        body(j, work)
        j.finish("succeeded")
        if j.kind != "export":
            refresh_risk_scores(work)
    except Cancelled:
        work.rollback()
        j.finish("cancelled", "Cancelled - the database was not changed.")
    except (feeds.FeedError, package.PackageError) as exc:
        work.rollback()
        if j.flag.is_set():
            j.finish("cancelled", "Cancelled - the database was not changed.")
        else:
            j.finish("failed", str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("[CVE] job %s failed", job_id)
        work.rollback()
        j.finish("failed", f"Unexpected error: {exc.__class__.__name__}. The database was not changed.")
    finally:
        work.close()
        j.close()


def refresh_risk_scores(db: Session) -> None:
    """Known vulnerabilities are a risk factor (CV): after the database
    changes, recalculate every asset's risk score. Never fails the job."""
    import asyncio
    from app.modules.risk.service import recalculate_all
    try:
        result = asyncio.run(recalculate_all(db, background=False, trigger_type="cve_database_update"))
        logger.info("[CVE] risk scores recalculated: %s", result)
    except Exception:  # noqa: BLE001
        logger.exception("[CVE] risk recalculation after the update failed")
        db.rollback()


# ── online ───────────────────────────────────────────────────────────────

def make_client(api_key: Optional[str]) -> feeds.NvdClient:
    return feeds.NvdClient(api_key)


def _spooled(path: str) -> Iterator[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def _online(j: _Job, db: Session, full: bool) -> None:
    j.progress("connect", force=True)
    client = make_client(settings.api_key(db))
    watermark = feeds.iso_to_dt(settings.get(db, settings.WATERMARK))
    empty = db.query(CveEntry.cve_id).first() is None
    start = None if (full or empty or watermark is None) else watermark
    end = feeds.utcnow()

    spool = os.path.join(data_dir("spool"), f"job-{j.id}.jsonl.gz")
    try:
        downloaded = 0
        with gzip.open(spool, "wt", encoding="utf-8", compresslevel=1) as out:
            def on_page(done, total):
                j.progress("download", done, total, force=True)

            for records in client.pages(start, end, on_page=on_page, cancelled=j.cancelled):
                for r in records:
                    out.write(json.dumps(r, separators=(",", ":")) + "\n")
                downloaded += len(records)
        j.check()
        j.stats["downloaded"] = downloaded
        j.stats["mode"] = "full" if start is None else "incremental"

        # KEV and EPSS are enrichment: when one is unreachable the CVEs are
        # still applied and the previous KEV flags / EPSS scores are kept.
        warnings = []
        j.progress("kev", force=True)
        try:
            kev = feeds.fetch_kev()
        except feeds.FeedError as exc:
            kev = None
            warnings.append(f"{exc} - the previous KEV list was kept.")
        j.check()
        j.progress("epss", force=True)
        try:
            epss = feeds.fetch_epss()
        except feeds.FeedError as exc:
            epss = None
            warnings.append(f"{exc} - the previous EPSS scores were kept.")
        j.check()
        if warnings:
            j.stats["warnings"] = warnings

        j.progress("apply", 0, downloaded, force=True)
        _apply(j, db, _spooled(spool), downloaded, kev, epss)
        settings.put(db, settings.WATERMARK, end.isoformat())
        db.commit()
    finally:
        if os.path.exists(spool):
            os.remove(spool)


def _apply(j: _Job, db: Session, records, total: int, kev: Optional[dict], epss: Optional[dict]) -> None:
    """Stage CVEs, then KEV and EPSS, into `db` (the caller commits)."""
    def on_batch(t):
        j.check()
        j.progress("apply", t["new"] + t["changed"] + t["removed"], total)

    counts = store.apply_cves(db, records, on_batch=on_batch)
    j.stats.update(counts)
    j.check()

    if kev is not None:
        current = (settings.get(db, settings.KEV_INFO) or {}).get("released") or ""
        if (kev.get("released") or "") >= current:
            j.stats["kev"] = store.apply_kev(db, kev)
            settings.put(db, settings.KEV_INFO, {"version": kev.get("version"), "released": kev.get("released")})
    if epss is not None and epss.get("rows"):
        current = settings.get(db, settings.EPSS_DATE) or ""
        if (epss.get("date") or "") >= current:
            j.stats["epss"] = store.apply_epss(db, epss["rows"])
            settings.put(db, settings.EPSS_DATE, epss.get("date"))
    j.check()


def run_online(job_id: int, full: bool = False, session_factory: Callable = SessionLocal) -> None:
    _run(job_id, session_factory, lambda j, db: _online(j, db, full))


# ── offline / bundle ─────────────────────────────────────────────────────

def _import(j: _Job, db: Session, path: str) -> None:
    j.progress("verify", force=True)
    verified = package.verify(db, path)
    failed = [c for c in verified.checks if c.status == "fail"]
    if failed:
        raise package.PackageError(failed[0].detail)
    m = verified.manifest
    total = (m.get("counts") or {}).get("cves") or 0
    j.stats["signer"] = verified.signer
    j.stats["package"] = {"kind": m.get("kind"), "until": m.get("until"), "created_at": m.get("created_at")}
    j.check()

    j.progress("apply", 0, total, force=True)
    kev = package.read_kev(path)
    kev.setdefault("released", (m.get("kev") or {}).get("released"))
    epss = package.read_epss(path)
    epss["date"] = epss.get("date") or m.get("epss_date")
    _apply(j, db, package.read_cves(path), total, kev, epss)

    until = feeds.iso_to_dt(m.get("until"))
    current = feeds.iso_to_dt(settings.get(db, settings.WATERMARK))
    if until and (current is None or until > current):
        settings.put(db, settings.WATERMARK, until.isoformat())
    db.commit()


def run_import(job_id: int, path: str, remove_after: bool = True, session_factory: Callable = SessionLocal) -> None:
    try:
        _run(job_id, session_factory, lambda j, db: _import(j, db, path))
    finally:
        if remove_after and os.path.exists(path):
            os.remove(path)


# ── export ───────────────────────────────────────────────────────────────

def export_file(job: CveUpdateJob) -> Optional[str]:
    if job.kind != "export" or job.status != "succeeded" or not job.file_name:
        return None
    path = os.path.join(data_dir("exports"), os.path.basename(job.file_name))
    return path if os.path.isfile(path) else None


def _export(j: _Job, db: Session, kind: str, since: Optional[datetime]) -> None:
    j.progress("export", force=True)
    name = f"ngcorion-cve-{kind}-{datetime.utcnow():%Y%m%d-%H%M%S}{package.EXTENSION}"
    folder = data_dir("exports")
    path = os.path.join(folder, name)
    try:
        manifest = package.build(db, path, kind, since,
                                 on_progress=lambda done, total: (j.check(), j.progress("export", done, total)))
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    db.commit()  # the signing key, when this was its first use
    j.file_name = name
    j.stats.update({"cves": manifest["counts"]["cves"], "kev": manifest["counts"]["kev"],
                    "epss": manifest["counts"]["epss"], "file": name, "size": os.path.getsize(path),
                    "until": manifest["until"], "since": manifest["since"], "kind": kind})
    old = sorted((f for f in os.listdir(folder) if f.endswith(package.EXTENSION)),
                 key=lambda f: os.path.getmtime(os.path.join(folder, f)), reverse=True)
    for f in old[KEEP_EXPORTS:]:
        os.remove(os.path.join(folder, f))


def run_export(job_id: int, kind: str, since: Optional[datetime], session_factory: Callable = SessionLocal) -> None:
    _run(job_id, session_factory, lambda j, db: _export(j, db, kind, since))


# ── uploads ──────────────────────────────────────────────────────────────

def upload_path(token: str) -> str:
    if not token or not all(c in "0123456789abcdef" for c in token) or len(token) != 32:
        raise package.PackageError("Unknown upload.")
    return os.path.join(data_dir("uploads"), token + package.EXTENSION)


def new_upload() -> tuple:
    folder = data_dir("uploads")
    cutoff = datetime.utcnow() - UPLOAD_TTL
    for f in os.listdir(folder):
        p = os.path.join(folder, f)
        if datetime.utcfromtimestamp(os.path.getmtime(p)) < cutoff:
            os.remove(p)
    token = uuid.uuid4().hex
    return token, upload_path(token)


# ── starting ─────────────────────────────────────────────────────────────

def _thread(target, *args, name: str):
    threading.Thread(target=target, args=args, name=name, daemon=True).start()


def start_online(job: CveUpdateJob, full: bool):
    _thread(run_online, job.id, full, name=f"cve-{job.id}")


def start_import(job: CveUpdateJob, path: str, remove_after: bool = True):
    _thread(run_import, job.id, path, remove_after, name=f"cve-{job.id}")


def start_export(job: CveUpdateJob, kind: str, since: Optional[datetime]):
    _thread(run_export, job.id, kind, since, name=f"cve-{job.id}")


# ── automatic updates ────────────────────────────────────────────────────

def auto_update_due(db: Session, now: datetime) -> bool:
    """Once a day, at or after the configured server-local time, when the
    database is loaded and nothing else is running."""
    cfg = settings.auto_update(db)
    if not cfg["enabled"] or settings.get(db, settings.WATERMARK) is None:
        return False
    try:
        hour, minute = (int(x) for x in cfg["time"].split(":"))
    except ValueError:
        return False
    if (now.hour, now.minute) < (hour, minute):
        return False
    if settings.get(db, settings.LAST_AUTO_RUN) == now.date().isoformat():
        return False
    return active_job(db) is None


def _auto_tick(session_factory: Callable = SessionLocal) -> Optional[int]:
    db = session_factory()
    try:
        now = datetime.now()
        if not auto_update_due(db, now):
            return None
        settings.put(db, settings.LAST_AUTO_RUN, now.date().isoformat())
        db.commit()
        try:
            job = create_job(db, "online", None, trigger="automatic")
        except JobBusy:
            return None
        start_online(job, False)
        return job.id
    finally:
        db.close()


class _AutoUpdater:
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def _loop(self):
        while not self._stop.is_set():
            try:
                job_id = await asyncio.to_thread(_auto_tick)
                if job_id:
                    logger.info("[CVE] automatic update started (job %s)", job_id)
            except Exception:  # noqa: BLE001
                logger.exception("[CVE] automatic update check failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=AUTO_CHECK_SECONDS)
            except asyncio.TimeoutError:
                pass

    def start(self):
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cve-auto-update")

    async def stop(self):
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None


_updater: Optional[_AutoUpdater] = None


def start_auto_updater() -> None:
    global _updater
    if _updater is None:
        _updater = _AutoUpdater()
    _updater.start()


async def stop_auto_updater() -> None:
    if _updater is not None:
        await _updater.stop()
