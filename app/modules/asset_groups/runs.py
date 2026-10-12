"""
Group audit runs: one technology, one credential profile, every asset of a group, a few at a time.

start_run() makes a GroupRun with one GroupRunItem per asset ("queued"); assets without an address
are "skipped" at once. The worker (GroupRunWorker, SingletonTask "group-runs" in app/main.py) keeps
up to `concurrency` items of each run running in a thread pool, each through the technology's
normal audit (app/modules/scheduling/audit_dispatch.run_audit), so every asset gets its ordinary
audit session, results and risk recalculation. The queue lives in the database: a restart marks
the items that were running "failed / interrupted" and carries on with the rest.

An item ends "done" (an audit session with a score), "failed" with a reason, "skipped" (license or
no address) or "cancelled" (the run was stopped first). Reasons:

  auth         the device refused the sign-in (or sudo)
  unreachable  no connection: timeout, refused, no route
  license      the license does not cover the asset
  no_address   the asset has no IP address
  error        anything else; the detail says what
  interrupted  NGCorion restarted while the audit was running
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, ensure_session_usable
from app.models import Asset, AuditSession, User
from app.models.asset_groups import AssetGroup, CredentialProfile, GroupRun, GroupRunItem

from . import groups, profiles

logger = logging.getLogger(__name__)

MAX_CONCURRENCY = 50
MAX_ASSETS = 5000
TICK_SECONDS = 2
ACTIVE = ("queued", "running", "stopping")

_AUTH = ("authentication", "auth failed", "login failed", "login rejected", "permission denied",
         "access denied", "sudo was refused", "unauthorized", "401", "invalid credentials",
         "logon failure", "permissionerror")
_UNREACHABLE = ("timed out", "timeout", "unreachable", "connection refused", "no route", "connectionerror",
                "could not connect", "connection failed", "name or service not known", "network",
                "connection reset", "eof", "unable to connect")


class RunError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def classify(text: str) -> str:
    t = (text or "").lower()
    if any(m in t for m in _AUTH):
        return "auth"
    if any(m in t for m in _UNREACHABLE):
        return "unreachable"
    return "error"


def _clean(exc: BaseException) -> str:
    msg = str(exc)
    if any(k in msg.lower() for k in ("password", "secret", "token")):
        return f"{type(exc).__name__}: Authentication or connection error"
    return f"{type(exc).__name__}: {msg}"[:500]


def start_run(db: Session, group: AssetGroup, technology: str, profile: CredentialProfile,
              audit_profile: Optional[str], concurrency: int, user: Optional[User],
              scheduled_job_id: Optional[int] = None, started_by_id: Optional[int] = None) -> GroupRun:
    """Queue an audit of every asset of `group`. Raises RunError when it cannot start."""
    from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES
    if technology not in SUPPORTED_TECHNOLOGIES or profiles.kind_for(technology) is None:
        raise RunError("This technology cannot be audited with a credential profile")
    if profiles.kind_for(technology) != profile.kind:
        raise RunError("The credential profile is of a different kind than the technology needs")
    ids = groups.member_ids(db, group)
    if not ids:
        raise RunError("The group has no assets")
    if len(ids) > MAX_ASSETS:
        raise RunError(f"A group run covers at most {MAX_ASSETS} assets")
    run = GroupRun(group_id=group.id, group_name=group.name, technology=technology,
                   audit_profile=audit_profile, credential_profile_id=profile.id,
                   credential_profile_name=profile.name,
                   concurrency=max(1, min(int(concurrency or 10), MAX_CONCURRENCY)),
                   status="queued", started_by=user.id if user else started_by_id,
                   started_by_name=user.username if user else None, scheduled_job_id=scheduled_job_id)
    db.add(run)
    db.flush()
    for aid, name, ip in db.query(Asset.id, Asset.asset_name, Asset.ip_address).filter(Asset.id.in_(ids)) \
            .order_by(Asset.id):
        item = GroupRunItem(run_id=run.id, asset_id=aid, asset_name=name or f"#{aid}", ip_address=ip)
        if not (ip or "").strip():
            item.status, item.reason, item.finished_at = "skipped", "no_address", _now()
        db.add(item)
    return run


def counts(db: Session, run_ids: List[int]) -> Dict[int, Dict[str, int]]:
    out: Dict[int, Dict[str, int]] = {r: {} for r in run_ids}
    if run_ids:
        for rid, status, n in db.query(GroupRunItem.run_id, GroupRunItem.status, func.count()) \
                .filter(GroupRunItem.run_id.in_(run_ids)).group_by(GroupRunItem.run_id, GroupRunItem.status):
            out[rid][status] = n
    return out


def summary(run: GroupRun, c: Dict[str, int]) -> Dict:
    total = sum(c.values())
    finished = sum(c.get(s, 0) for s in ("done", "failed", "skipped", "cancelled"))
    return {
        "id": run.id, "group_id": run.group_id, "group_name": run.group_name, "technology": run.technology,
        "audit_profile": run.audit_profile, "credential_profile_id": run.credential_profile_id,
        "credential_profile_name": run.credential_profile_name, "concurrency": run.concurrency,
        "status": run.status, "started_by_name": run.started_by_name, "scheduled_job_id": run.scheduled_job_id,
        "created_at": run.created_at, "started_at": run.started_at, "finished_at": run.finished_at,
        "total": total, "finished": finished, "counts": c,
    }


def stop(db: Session, run: GroupRun) -> None:
    if run.status in ("queued", "running"):
        run.status = "stopping"


def retry_failed(db: Session, run: GroupRun) -> int:
    """Queue the failed items again (a finished or stopped run only)."""
    if run.status in ACTIVE:
        raise RunError("Wait for the run to finish or stop it first")
    n = db.query(GroupRunItem).filter(GroupRunItem.run_id == run.id, GroupRunItem.status == "failed") \
        .update({"status": "queued", "reason": None, "detail": None, "started_at": None,
                 "finished_at": None, "claimed": False}, synchronize_session=False)
    if n:
        run.status, run.finished_at = "running", None
    return n


def recover_interrupted(db: Session) -> int:
    """At start-up: audits that were running when NGCorion stopped did not finish."""
    n = db.query(GroupRunItem).filter(GroupRunItem.status == "running") \
        .update({"status": "failed", "reason": "interrupted", "finished_at": _now(),
                 "detail": "NGCorion restarted while this audit was running"}, synchronize_session=False)
    db.commit()
    return n


# ── one asset ────────────────────────────────────────────────────────────────

def _finish(db: Session, item: GroupRunItem, status: str, reason: Optional[str] = None,
            detail: Optional[str] = None, session: Optional[AuditSession] = None) -> None:
    item.status, item.reason, item.detail, item.finished_at = status, reason, detail, _now()
    if session is not None:
        item.session_id = session.id
        item.compliance = session.compliance_pct
    db.commit()


def run_item(item_id: int) -> None:
    """Audit one asset of a run (in a worker thread, with its own database session)."""
    from app.core.asset_entitlement import AssetLimitExceeded, require_licensed_asset
    from app.modules.scheduling.audit_dispatch import run_audit
    db = SessionLocal()
    try:
        item = db.get(GroupRunItem, item_id)
        if item is None:
            return
        run = db.get(GroupRun, item.run_id)
        if run.status == "stopping":
            _finish(db, item, "cancelled")
            return
        profile = db.get(CredentialProfile, run.credential_profile_id) if run.credential_profile_id else None
        if profile is None:
            _finish(db, item, "failed", "error", "The credential profile was deleted")
            return
        if item.asset_id is None:
            _finish(db, item, "failed", "error", "The asset was deleted")
            return
        try:
            require_licensed_asset(db, item.asset_id)
        except AssetLimitExceeded as exc:
            _finish(db, item, "skipped", "license", str(exc.detail)[:500])
            return
        user_id = run.started_by or _fallback_user(db)
        try:
            params = profiles.params_for(run.technology, profile, run.audit_profile,
                                         job_name=f"{run.group_name} #{run.id}")
            profiles.mark_used(db, profile.id)
            db.commit()
            session = run_audit(run.technology, db, item.asset_id, user_id, params)
        except Exception as exc:  # noqa: BLE001 - one asset's failure never stops the run
            ensure_session_usable(db)
            item = db.get(GroupRunItem, item_id)
            session = (db.query(AuditSession).filter(AuditSession.asset_id == item.asset_id,
                                                     AuditSession.started_at >= item.started_at.replace(tzinfo=None))
                       .order_by(AuditSession.id.desc()).first()) if item.started_at else None
            detail = (session.connection_error if session is not None and session.connection_error else _clean(exc))
            reason = "auth" if isinstance(exc, PermissionError) else classify(detail)
            _finish(db, item, "failed", reason, detail, session)
            return
        if session.status == "failed":
            _finish(db, item, "failed", classify(session.connection_error), session.connection_error, session)
        else:
            _finish(db, item, "done", session=session)
    except Exception:
        logger.exception("[GroupRun] item %s", item_id)
        ensure_session_usable(db)
        item = db.get(GroupRunItem, item_id)
        if item is not None and item.status == "running":
            _finish(db, item, "failed", "error", "Internal error")
    finally:
        db.close()


def _fallback_user(db: Session) -> Optional[int]:
    from app.models import UserRole
    row = db.query(User.id).filter(User.role == UserRole.ADMIN, User.is_active.is_(True)).order_by(User.id).first()
    return row[0] if row else None


# ── the queue ────────────────────────────────────────────────────────────────

def sweep(db: Session) -> List[int]:
    """One pass: start queued runs, finish stopped and completed ones, and claim as many queued items
    as each run's concurrency allows. Returns the claimed item ids (now "running")."""
    claimed: List[int] = []
    for run in db.query(GroupRun).filter(GroupRun.status.in_(ACTIVE)).order_by(GroupRun.id).all():
        c = counts(db, [run.id])[run.id]
        running, queued = c.get("running", 0), c.get("queued", 0)
        if run.status == "stopping":
            db.query(GroupRunItem).filter(GroupRunItem.run_id == run.id, GroupRunItem.status == "queued") \
                .update({"status": "cancelled", "finished_at": _now()}, synchronize_session=False)
            if running == 0:
                run.status, run.finished_at = "stopped", _now()
                _finished(db, run)
            continue
        if run.status == "queued":
            run.status, run.started_at = "running", _now()
        if queued == 0 and running == 0:
            run.status, run.finished_at = "done", _now()
            _finished(db, run)
            continue
        free = run.concurrency - running
        if free <= 0 or queued == 0:
            continue
        ids = [r[0] for r in db.query(GroupRunItem.id)
               .filter(GroupRunItem.run_id == run.id, GroupRunItem.status == "queued")
               .order_by(GroupRunItem.id).limit(free).with_for_update(skip_locked=True)]
        if ids:
            db.query(GroupRunItem).filter(GroupRunItem.id.in_(ids)).update(
                {"status": "running", "claimed": True, "started_at": _now(),
                 "attempts": GroupRunItem.attempts + 1}, synchronize_session=False)
            claimed.extend(ids)
    db.commit()
    return claimed


def _finished(db: Session, run: GroupRun) -> None:
    # The alert "audit.group_run_failed" (app/modules/alerts/events.py) picks up runs that end with
    # failed assets.
    logger.info("[GroupRun] %s %s: %s", run.id, run.status, counts(db, [run.id])[run.id])


class GroupRunWorker:
    def __init__(self, tick: int = TICK_SECONDS):
        self.tick = tick
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._pool: Optional[ThreadPoolExecutor] = None
        self._futures: set = set()

    def _sweep(self) -> Tuple[List[int], int]:
        db = SessionLocal()
        try:
            return sweep(db), 0
        except Exception:
            logger.exception("[GroupRun] sweep failed")
            db.rollback()
            return [], 1
        finally:
            db.close()

    async def _loop(self) -> None:
        db = SessionLocal()
        try:
            n = await asyncio.to_thread(recover_interrupted, db)
            if n:
                logger.warning("[GroupRun] %d audit(s) interrupted by a restart", n)
        finally:
            db.close()
        while not self._stop.is_set():
            ids, _ = await asyncio.to_thread(self._sweep)
            for item_id in ids:
                fut = self._pool.submit(run_item, item_id)
                self._futures.add(fut)
                fut.add_done_callback(self._futures.discard)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.tick)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENCY, thread_name_prefix="group-run")
            self._task = asyncio.create_task(self._loop(), name="group-runs")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=10)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        if self._pool is not None:
            # running audits finish on their own; the next start marks any that did not as interrupted
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None


_worker: Optional[GroupRunWorker] = None


def start_group_runs() -> None:
    global _worker
    if _worker is None:
        _worker = GroupRunWorker()
    _worker.start()


async def stop_group_runs() -> None:
    if _worker is not None:
        await _worker.stop()
