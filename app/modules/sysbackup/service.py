"""
NGCorion self-backup: settings, the passphrase, making and checking backups,
copies to destinations and the retention policy. Restores live in restore.py.

A backup is one encrypted .ngbak file in BACKUP_DIR (see container.py):
    manifest.json   what is inside: version, revision, tables, row counts
    secret.key      this server's SECRET_KEY, so a restore elsewhere can
                    re-encrypt stored secrets
    db/<table>.copy every table, from one consistent snapshot
    files/...       web certificate, pinned SSH host keys
    summary.json    size and SHA-256 of every entry above
"""
import json
import logging
import os
import re
import secrets
import shutil
import socket
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import psycopg
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.credential_crypto import PURPOSE_SYSTEM_CONFIG, decrypt, encrypt
from app.core.database import SessionLocal
from app.core.singleton import lock_key, runner_is_alive, runner_tag
from app.models.system_backup import (BK_FAILED, BK_MISSING, BK_PENDING, BK_QUEUED, BK_READY, BK_RUNNING,
                                      CONTENTS, KIND_MANUAL, KIND_SAFETY, KIND_SCHEDULED, KIND_UPLOADED,
                                      BackupDestination, SystemBackup)
from app.models.system_config import SystemConfigSetting
from app.modules.sysbackup import container, dbdump, files
from app.modules.sysbackup import destinations as dest_io

logger = logging.getLogger(__name__)

SECTION = dbdump.SETTINGS_SECTION
ENC = "enc:v1:"
EXT = ".ngbak"
MIN_PASSPHRASE = 12
MIN_FREE_BYTES = 256 * 1024 * 1024
STALE_AFTER = timedelta(minutes=10)

DEFAULT_SETTINGS = {
    "enabled": True,
    "frequency": "daily",           # daily | weekly (on weekly_day)
    "time": "02:00",
    "include_reports": True,
    "include_cve": "weekly",        # always | weekly | never
    "include_noc": "never",
    "weekly_day": 4,                # Friday (Monday = 0)
    "keep_daily": 7,
    "keep_weekly": 4,
    "keep_monthly": 6,
    "restore_test": True,
}
INCLUDE_CHOICES = ("always", "weekly", "never")


class BackupError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── settings and passphrase ──────────────────────────────────────────────

def _row(db: Session) -> Optional[SystemConfigSetting]:
    return db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()


def _stored(db: Session) -> Dict:
    row = _row(db)
    return dict(row.config_json or {}) if row else {}


def _write(db: Session, data: Dict, user_id: Optional[int]) -> None:
    row = _row(db)
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = data
    row.updated_by = user_id
    db.commit()


def get_settings(db: Session) -> Dict:
    stored = _stored(db)
    out = {k: stored.get(k, v) for k, v in DEFAULT_SETTINGS.items()}
    out["passphrase_set"] = bool(stored.get("key_id"))
    out["key_id"] = stored.get("key_id")
    out["passphrase_set_at"] = stored.get("passphrase_set_at")
    out["passphrase_set_by"] = stored.get("passphrase_set_by")
    out["next_run_at"] = _iso(next_scheduled(db, datetime.utcnow(), out)) if out["enabled"] else None
    return out


def save_settings(db: Session, payload: Dict, user_id: Optional[int]) -> Dict:
    stored = _stored(db)
    clean = {}
    clean["enabled"] = bool(payload.get("enabled"))
    if payload.get("frequency") not in ("daily", "weekly"):
        raise BackupError("Unknown frequency")
    clean["frequency"] = payload["frequency"]
    t = str(payload.get("time") or "")
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
        raise BackupError("Enter the time as HH:MM")
    clean["time"] = t
    clean["include_reports"] = bool(payload.get("include_reports"))
    for key in ("include_cve", "include_noc"):
        if payload.get(key) not in INCLUDE_CHOICES:
            raise BackupError("Unknown choice for %s" % key)
        clean[key] = payload[key]
    day = int(payload.get("weekly_day", 4))
    if not 0 <= day <= 6:
        raise BackupError("Unknown weekday")
    clean["weekly_day"] = day
    for key, lo, hi in (("keep_daily", 1, 60), ("keep_weekly", 0, 52), ("keep_monthly", 0, 60)):
        value = int(payload.get(key, DEFAULT_SETTINGS[key]))
        if not lo <= value <= hi:
            raise BackupError(f"Keep between {lo} and {hi}")
        clean[key] = value
    clean["restore_test"] = bool(payload.get("restore_test"))
    stored.update(clean)
    _write(db, stored, user_id)
    return get_settings(db)


def validate_passphrase(passphrase: str) -> None:
    if not passphrase or len(passphrase) < MIN_PASSPHRASE:
        raise BackupError(f"The passphrase must be at least {MIN_PASSPHRASE} characters")
    if len(passphrase) > 256:
        raise BackupError("The passphrase is too long")


def set_passphrase(db: Session, passphrase: str, user_id: Optional[int], current: Optional[str] = None,
                   username: Optional[str] = None) -> Dict:
    """Set or change the passphrase new backups are encrypted with. Earlier
    passphrases stay in the keyring so older backups on this server open
    without typing them."""
    validate_passphrase(passphrase)
    stored = _stored(db)
    if stored.get("key_id"):
        if not current or not check_passphrase(db, current):
            raise BackupError("The current passphrase is not correct", 403)
    key_id = uuid.uuid4().hex[:12]
    stored[f"key:{key_id}"] = ENC + encrypt(passphrase, PURPOSE_SYSTEM_CONFIG)
    stored["key_id"] = key_id
    stored["passphrase_set_at"] = datetime.utcnow().isoformat() + "Z"
    stored["passphrase_set_by"] = username
    _write(db, stored, user_id)
    return get_settings(db)


def passphrase_for(db: Session, key_id: Optional[str]) -> Optional[str]:
    if not key_id:
        return None
    value = _stored(db).get(f"key:{key_id}")
    if not isinstance(value, str) or not value.startswith(ENC):
        return None
    try:
        return decrypt(value[len(ENC):], PURPOSE_SYSTEM_CONFIG)
    except ValueError:
        return None


def current_passphrase(db: Session) -> Tuple[Optional[str], Optional[str]]:
    key_id = _stored(db).get("key_id")
    return passphrase_for(db, key_id), key_id


def check_passphrase(db: Session, candidate: str) -> bool:
    current, _ = current_passphrase(db)
    return bool(current) and secrets.compare_digest(current.encode(), (candidate or "").encode())


# ── storage ───────────────────────────────────────────────────────────────

def backup_dir() -> Path:
    path = Path(settings.BACKUP_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def file_path(b: SystemBackup) -> Path:
    if not b.filename or "/" in b.filename or "\\" in b.filename or b.filename.startswith("."):
        raise BackupError("The backup has no file", 404)
    return backup_dir() / b.filename


def disk(path: Optional[Path] = None) -> Dict:
    try:
        usage = shutil.disk_usage(path or backup_dir())
        return {"total": usage.total, "free": usage.free, "used": usage.used}
    except OSError:
        return {"total": None, "free": None, "used": None}


def label(b: SystemBackup) -> str:
    return b.filename or f"#{b.id}"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


# ── the job lock: one backup, restore or test at a time ──────────────────

class JobLock:
    """A Postgres advisory lock held on its own connection, so it spans
    uvicorn workers and the CLI. The restore spares advisory-lock holders
    when it disconnects everyone else."""

    KEY = lock_key("system-backup-job")

    def __init__(self):
        self.conn = None

    def acquire(self) -> bool:
        conn = dbdump.connect(autocommit=True)
        if conn.execute("SELECT pg_try_advisory_lock(%s)", (self.KEY,)).fetchone()[0]:
            self.conn = conn
            return True
        conn.close()
        return False

    def release(self) -> None:
        if self.conn is not None:
            try:
                self.conn.execute("SELECT pg_advisory_unlock(%s)", (self.KEY,))
            except Exception:
                pass
            self.conn.close()
            self.conn = None

    def __enter__(self):
        if not self.acquire():
            raise BackupError("Another backup, restore or restore test is running; try again when it finishes", 409)
        return self

    def __exit__(self, *exc):
        self.release()


def job_running() -> bool:
    key = JobLock.KEY & 0xFFFFFFFFFFFFFFFF
    with dbdump.connect(autocommit=True) as conn:
        row = conn.execute("SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted "
                           "AND classid = %s AND objid = %s AND objsubid = 1",
                           (key >> 32, key & 0xFFFFFFFF)).fetchone()
        return row is not None


# ── progress, written on short sessions so a restore's swap never strands one

def update_row(model, row_id: int, **fields) -> None:
    db = SessionLocal()
    try:
        db.query(model).filter(model.id == row_id).update(fields, synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("[sysbackup] could not record progress")
    finally:
        db.close()


class Throttle:
    def __init__(self, fn: Callable, every: float = 2.0):
        self.fn, self.every, self.last = fn, every, 0.0

    def __call__(self, *args, force: bool = False, **kw):
        now = time.monotonic()
        if force or now - self.last >= self.every:
            self.last = now
            self.fn(*args, **kw)


# ── making a backup ───────────────────────────────────────────────────────

def contents_for(db: Session, kind: str, requested: Optional[Iterable[str]] = None,
                 now: Optional[datetime] = None) -> List[str]:
    """Parts of a backup. Manual: what the admin picked. Safety: everything.
    Scheduled: the settings, with "weekly" parts on the weekly day (or when
    the last backup holding them is over a week old)."""
    if kind == KIND_SAFETY:
        return list(CONTENTS)
    if requested is not None:
        parts = [c for c in CONTENTS if c in set(requested)]
        return ["essential"] + [c for c in parts if c != "essential"]
    cfg = get_settings(db)
    now = now or datetime.utcnow()
    local = _local(db, now)
    out = ["essential"]
    if cfg["include_reports"]:
        out.append("reports")
    for part, key in (("cve", "include_cve"), ("noc_history", "include_noc")):
        mode = cfg[key]
        if mode == "always":
            out.append(part)
        elif mode == "weekly":
            if local.weekday() == cfg["weekly_day"] or not _has_recent(db, part, now - timedelta(days=7)):
                out.append(part)
    return out


def _has_recent(db: Session, part: str, since: datetime) -> bool:
    rows = (db.query(SystemBackup.contents).filter(SystemBackup.status == BK_READY,
                                                    SystemBackup.created_at >= since).all())
    return any(part in (r[0] or []) for r in rows)


def queue_backup(db: Session, kind: str, contents: Optional[Iterable[str]] = None, note: Optional[str] = None,
                 user=None, destination_ids: Optional[List[int]] = None) -> SystemBackup:
    passphrase, key_id = current_passphrase(db)
    if not passphrase:
        raise BackupError("Set the backup passphrase first", 409)
    if db.query(SystemBackup).filter(SystemBackup.status.in_(BK_PENDING),
                                     SystemBackup.kind == kind).count() >= 2:
        raise BackupError("A backup is already waiting to run", 429)
    b = SystemBackup(kind=kind, status=BK_QUEUED, contents=contents_for(db, kind, contents),
                     note=(note or "").strip()[:300] or None, destinations=[], key_id=key_id,
                     created_by=getattr(user, "id", None), created_by_name=getattr(user, "username", None),
                     targets=list(destination_ids) if destination_ids is not None else None)
    if kind == KIND_SCHEDULED:
        b.tier = _tier_for(db, datetime.utcnow())
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


def claim_next(db: Session) -> Optional[SystemBackup]:
    b = (db.query(SystemBackup).filter(SystemBackup.status == BK_QUEUED).order_by(SystemBackup.id)
         .with_for_update(skip_locked=True).first())
    if b is None:
        db.rollback()
        return None
    b.status, b.started_at, b.progress, b.step, b.runner = BK_RUNNING, datetime.utcnow(), 1, "prepare", runner_tag()
    db.commit()
    return b


def _filename(kind: str, when: datetime) -> str:
    return f"ngcorion-{when.strftime('%Y%m%d-%H%M%S')}-{kind}{EXT}"


def write_backup(backup_id: int, passphrase: str, key_id: Optional[str], contents: List[str], kind: str,
                 progress: Optional[Callable[[int, str], None]] = None) -> Dict:
    """Write the archive for row backup_id. Returns the fields to store."""
    progress = progress or (lambda pct, step: None)
    folder = backup_dir()
    if disk(folder)["free"] is not None and disk(folder)["free"] < MIN_FREE_BYTES:
        raise BackupError("Less than 256 MB free in the backup folder")
    started = datetime.utcnow()
    name = _filename(kind, started)
    final = folder / name
    part = folder / (name + ".part")
    host = socket.gethostname()
    with dbdump.connect() as conn:
        dbdump.begin_snapshot(conn)
        plan = dbdump.snapshot(conn, contents)
        file_list = list(files.collect()) if "essential" in contents else []
        header = {"app_version": settings.VERSION, "db_revision": plan["revision"], "contents": contents,
                  "created_at": started.isoformat() + "Z", "source_host": host, "key_id": key_id, "kind": kind}
        manifest = dict(header, tables=plan["tables"], sequences=plan["sequences"],
                        files=[{"entry": e, "mode": m} for e, _, m in file_list])
        total_rows = sum(t["rows"] for t in plan["tables"].values()) or 1
        done = 0
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                w = container.Writer(out, passphrase, header)
                w.add("manifest.json", json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
                w.add("secret.key", settings.SECRET_KEY.encode("utf-8"))
                progress(3, "database")
                n_tables = len(plan["tables"])
                for i, (table, info) in enumerate(plan["tables"].items(), 1):
                    progress(3 + int(82 * done / total_rows), f"tables {i}/{n_tables} {table} {info['rows']}")
                    w.begin(f"db/{table}.copy")
                    for block in dbdump.copy_out(conn, table, info["columns"]):
                        w.write(block)
                    w.end()
                    done += info["rows"]
                conn.rollback()         # end the snapshot
                progress(86, "files")
                for entry, path, _mode in file_list:
                    try:
                        w.add(entry, path.read_bytes())
                    except OSError as exc:
                        logger.warning("[sysbackup] skipped %s: %s", path, exc)
                w.add("summary.json", json.dumps({"entries": w.entries}).encode("utf-8"))
                progress(88, "encrypt")
                sha = w.close()
                os.fsync(out.fileno())
            os.replace(part, final)
        except BaseException:
            try:
                part.unlink()
            except OSError:
                pass
            raise
    rows = {t: i["rows"] for t, i in plan["tables"].items()}
    by_part: Dict[str, int] = {}
    for t, info in plan["tables"].items():
        by_part[info["category"]] = by_part.get(info["category"], 0) + info["rows"]
    return {"filename": name, "size_bytes": final.stat().st_size, "sha256": sha,
            "app_version": settings.VERSION, "db_revision": plan["revision"], "source_host": host,
            "summary": {"tables": len(rows), "rows": sum(rows.values()), "rows_by_part": by_part,
                        "files": len(file_list), "table_rows": rows}}


def run_backup(db: Session, b: SystemBackup) -> SystemBackup:
    """Build a claimed backup, then copy it to the destinations."""
    passphrase = passphrase_for(db, b.key_id)
    if not passphrase:
        update_row(SystemBackup, b.id, status=BK_FAILED, error="The backup passphrase is not set",
                   finished_at=datetime.utcnow())
        db.refresh(b)
        return b
    tick = Throttle(lambda pct, step: update_row(SystemBackup, b.id, progress=pct, step=step))
    try:
        with JobLock():
            fields = write_backup(b.id, passphrase, b.key_id, list(b.contents or ["essential"]), b.kind, tick)
    except Exception as exc:
        logger.exception("[sysbackup] backup %s failed", b.id)
        message = str(exc) if isinstance(exc, (BackupError, OSError, psycopg.Error)) else \
            f"Unexpected error: {exc.__class__.__name__}"
        update_row(SystemBackup, b.id, status=BK_FAILED, error=message[:2000], finished_at=datetime.utcnow(),
                   progress=0, step=None)
        db.expire_all()
        return db.get(SystemBackup, b.id)
    # Read the new file back once: a backup that cannot be opened is worth
    # knowing about tonight, not on the day it is needed.
    update_row(SystemBackup, b.id, progress=90, step="verify", **fields)
    try:
        verify_file(backup_dir() / fields["filename"], passphrase)
        checked = {"verify_status": "ok", "verify_error": None}
    except (container.BackupFormatError, OSError) as exc:
        checked = {"verify_status": "failed", "verify_error": str(exc)[:1000]}
    checked["verified_at"] = datetime.utcnow()
    update_row(SystemBackup, b.id, status=BK_READY, progress=95, finished_at=datetime.utcnow(), error=None,
               step="send" if b.targets is None or b.targets else None, **checked)
    db.expire_all()
    b = db.get(SystemBackup, b.id)
    deliver(db, b, b.targets, progress=lambda name: update_row(SystemBackup, b.id, step=f"send {name}"))
    update_row(SystemBackup, b.id, progress=100, step=None)
    db.expire_all()
    return db.get(SystemBackup, b.id)


def make_safety_backup(passphrase: str, key_id: Optional[str], note: str, progress=None) -> SystemBackup:
    """Taken right before a restore, inside the restore's job lock."""
    db = SessionLocal()
    try:
        b = SystemBackup(kind=KIND_SAFETY, status=BK_RUNNING, contents=list(CONTENTS), destinations=[],
                         key_id=key_id, note=note[:300], started_at=datetime.utcnow(), runner=runner_tag())
        db.add(b)
        db.commit()
        db.refresh(b)
        backup_id = b.id
    finally:
        db.close()
    fields = write_backup(backup_id, passphrase, key_id, list(CONTENTS), KIND_SAFETY, progress)
    # The way back if the restore goes wrong: it must open, so it is checked
    # before the restore touches anything.
    verify_file(backup_dir() / fields["filename"], passphrase)
    update_row(SystemBackup, backup_id, status=BK_READY, progress=100, finished_at=datetime.utcnow(),
               verify_status="ok", verified_at=datetime.utcnow(), **fields)
    db = SessionLocal()
    try:
        return db.get(SystemBackup, backup_id)
    finally:
        db.close()


def fail_stale(db: Session) -> int:
    """Backups left running by a process that stopped; leftover .part files."""
    rows = db.query(SystemBackup).filter(SystemBackup.status == BK_RUNNING).all()
    n = 0
    for b in rows:
        if not runner_is_alive(b.runner):
            b.status, b.error, b.finished_at, b.step = BK_FAILED, "The backup was interrupted", datetime.utcnow(), None
            n += 1
    if n:
        db.commit()
        try:
            for p in backup_dir().glob("*.part"):
                if time.time() - p.stat().st_mtime > STALE_AFTER.total_seconds():
                    p.unlink()
        except OSError:
            pass
    return n


def mark_missing(db: Session) -> int:
    n = 0
    for b in db.query(SystemBackup).filter(SystemBackup.status == BK_READY).all():
        try:
            exists = file_path(b).is_file()
        except BackupError:
            exists = False
        if not exists:
            b.status, b.error = BK_MISSING, "The file is no longer in the backup folder"
            n += 1
    if n:
        db.commit()
    return n


# ── reading a backup ──────────────────────────────────────────────────────

def read_header(path: Path) -> dict:
    with open(path, "rb") as f:
        header, _ = container.read_header(f)
    return header


def open_manifest(path: Path, passphrase: str) -> dict:
    """Header plus the manifest - cheap: only the first entry is decrypted."""
    with open(path, "rb") as f:
        reader = container.Reader(f, passphrase)
        for name, blocks in reader.entries():
            if name != "manifest.json":
                raise container.BackupFormatError("the backup does not start with its manifest")
            return json.loads(container.read_entry(blocks).decode("utf-8"))
    raise container.BackupFormatError("the backup is empty")


def sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_file(path: Path, passphrase: str, progress: Optional[Callable[[int], None]] = None) -> Dict:
    """Decrypt every entry and check it against the manifest and summary."""
    total = path.stat().st_size or 1
    with open(path, "rb") as f:
        reader = container.Reader(f, passphrase, progress=(lambda pos: progress(int(100 * pos / total)))
                                  if progress else None)
        manifest, summary, seen = None, None, []
        for name, blocks in reader.entries():
            if name == "manifest.json":
                manifest = json.loads(container.read_entry(blocks).decode("utf-8"))
            elif name == "summary.json":
                summary = json.loads(container.read_entry(blocks).decode("utf-8"))
            else:
                for _ in blocks:
                    pass
            seen.append(name)
    if manifest is None or summary is None:
        raise container.BackupFormatError("the manifest or summary is missing")
    expected = summary.get("entries") or {}
    for name, info in expected.items():
        got = reader.entry_hashes.get(name)
        if got != info:
            raise container.BackupFormatError(f"{name} does not match its recorded checksum")
    missing = [f"db/{t}.copy" for t in manifest.get("tables", {}) if f"db/{t}.copy" not in expected]
    if missing:
        raise container.BackupFormatError("tables missing from the backup: " + ", ".join(missing[:5]))
    return {"entries": len(seen), "manifest": manifest}


def verify(db: Session, b: SystemBackup, passphrase: Optional[str] = None) -> SystemBackup:
    path = file_path(b)
    if not path.is_file():
        raise BackupError("The backup file is missing", 404)
    passphrase = passphrase or passphrase_for(db, b.key_id)
    if not passphrase:
        raise BackupError("Enter the passphrase this backup was made with", 422)
    try:
        if b.sha256 and sha256_file(path) != b.sha256:
            raise container.BackupFormatError("the file changed since it was written")
        verify_file(path, passphrase)
        b.verify_status, b.verify_error = "ok", None
    except container.WrongPassphrase:
        raise BackupError("The passphrase does not open this backup", 422)
    except container.BackupFormatError as exc:
        b.verify_status, b.verify_error = "failed", str(exc)
    b.verified_at = datetime.utcnow()
    db.commit()
    return b


# ── uploads ───────────────────────────────────────────────────────────────

def register_upload(db: Session, tmp: Path, original_name: str, user=None) -> SystemBackup:
    """A file uploaded by an admin: check it is a backup, keep it."""
    try:
        header = read_header(tmp)
    except container.BackupFormatError as exc:
        tmp.unlink(missing_ok=True)
        raise BackupError(f"This is not a usable NGCorion backup: {exc}")
    when = datetime.utcnow()
    name = _filename("uploaded", when)
    final = backup_dir() / name
    os.replace(tmp, final)
    contents = [c for c in header.get("contents") or [] if c in CONTENTS] or ["essential"]
    b = SystemBackup(kind=KIND_UPLOADED, status=BK_READY, progress=100, contents=contents, filename=name,
                     size_bytes=final.stat().st_size, sha256=sha256_file(final),
                     app_version=header.get("app_version"), db_revision=header.get("db_revision"),
                     key_id=header.get("key_id"), source_host=header.get("source_host"),
                     note=(f"Uploaded: {original_name}")[:300], destinations=[],
                     created_by=getattr(user, "id", None), created_by_name=getattr(user, "username", None),
                     started_at=when, finished_at=when,
                     summary={"original_created_at": header.get("created_at")})
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


def compatibility(b: SystemBackup) -> Dict:
    """Whether this server can restore the backup."""
    if not b.db_revision:
        return {"ok": False, "reason": "unknown_revision"}
    if not dbdump.known_revision(b.db_revision):
        return {"ok": False, "reason": "newer_version"}
    head = dbdump.head_revision()
    return {"ok": True, "same_version": b.db_revision == head}


# ── delivery to destinations ──────────────────────────────────────────────

def deliver(db: Session, b: SystemBackup, only: Optional[List[int]] = None,
            progress: Optional[Callable[[str], None]] = None) -> List[dict]:
    """Copy to the enabled destinations - all of them, or those in `only`
    (an empty list means none)."""
    if b.status != BK_READY:
        return []
    q = db.query(BackupDestination).filter(BackupDestination.enabled.is_(True))
    if only is not None:
        if not only:
            return b.destinations or []
        q = q.filter(BackupDestination.id.in_(only))
    targets = q.order_by(BackupDestination.id).all()
    results = {d.get("id"): d for d in (b.destinations or [])}
    path = file_path(b)
    for d in targets:
        if progress:
            progress(d.name)
        now = datetime.utcnow()
        entry = {"id": d.id, "name": d.name, "type": d.type, "at": now.isoformat() + "Z"}
        try:
            where, host_key = dest_io.upload(d, str(path), b.filename, b.size_bytes or path.stat().st_size)
            if d.type == "sftp" and not d.host_key and host_key:
                d.host_key = host_key
            entry.update(status="ok", path=where, error=None)
            d.last_status, d.last_error = "ok", None
        except dest_io.DestinationError as exc:
            entry.update(status="failed", error=str(exc)[:500])
            d.last_status, d.last_error = "failed", str(exc)[:1000]
            logger.warning("[sysbackup] copy of %s to %s failed: %s", b.filename, d.name, exc)
        d.last_at = now
        results[d.id] = entry
    b.destinations = list(results.values())
    db.commit()
    return b.destinations


def delete_backup(db: Session, b: SystemBackup, remote: bool = True) -> None:
    if b.status in BK_PENDING:
        raise BackupError("The backup is still being written", 409)
    if b.filename:
        try:
            file_path(b).unlink(missing_ok=True)
        except (BackupError, OSError) as exc:
            logger.warning("[sysbackup] could not delete %s: %s", b.filename, exc)
    if remote and b.filename:
        for entry in b.destinations or []:
            if entry.get("status") != "ok":
                continue
            d = db.get(BackupDestination, entry.get("id"))
            if d is None:
                continue
            try:
                dest_io.remove(d, b.filename)
            except dest_io.DestinationError as exc:
                logger.warning("[sysbackup] could not delete the copy on %s: %s", d.name, exc)
    db.delete(b)
    db.commit()


# ── schedule and retention ────────────────────────────────────────────────

def _local_tz(db: Session):
    from app.modules.alerts.channels import local_timezone
    return local_timezone(db)


def _local(db: Session, utc: datetime) -> datetime:
    tz = _local_tz(db)
    if tz is None:
        return utc
    return utc.replace(tzinfo=timezone.utc).astimezone(tz).replace(tzinfo=None)


def _to_utc(db: Session, local: datetime) -> datetime:
    tz = _local_tz(db)
    if tz is None:
        return local
    return local.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)


def _slot_days(cfg: Dict) -> Callable[[date], bool]:
    if cfg.get("frequency") == "weekly":
        return lambda d: d.weekday() == cfg["weekly_day"]
    return lambda d: True


def next_scheduled(db: Session, after_utc: datetime, cfg: Optional[Dict] = None) -> datetime:
    cfg = cfg or get_settings(db)
    hh, mm = (int(x) for x in cfg["time"].split(":"))
    runs_on = _slot_days(cfg)
    local_now = _local(db, after_utc)
    when = local_now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    for _ in range(9):
        if when > local_now and runs_on(when.date()):
            break
        when += timedelta(days=1)
    return _to_utc(db, when)


def last_slot(db: Session, now_utc: datetime, cfg: Dict) -> Optional[datetime]:
    hh, mm = (int(x) for x in cfg["time"].split(":"))
    runs_on = _slot_days(cfg)
    local_now = _local(db, now_utc)
    when = local_now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    for _ in range(8):
        if when <= local_now and runs_on(when.date()):
            return _to_utc(db, when)
        when -= timedelta(days=1)
    return None


def due_scheduled(db: Session, now: Optional[datetime] = None) -> bool:
    """True once the latest scheduled time has passed and no scheduled
    backup was made (or is waiting) since then. A slot missed while the
    server was down runs as soon as it is back."""
    cfg = get_settings(db)
    if not cfg["enabled"] or not cfg["passphrase_set"]:
        return False
    now = now or datetime.utcnow()
    slot = last_slot(db, now, cfg)
    if slot is None or now - slot > timedelta(days=1):
        return False
    exists = (db.query(SystemBackup.id).filter(SystemBackup.kind == KIND_SCHEDULED,
                                               SystemBackup.created_at >= slot - timedelta(minutes=1))
              .first())
    return exists is None


def _tier_for(db: Session, now: datetime) -> str:
    local = _local(db, now)
    month_start = _to_utc(db, local.replace(day=1, hour=0, minute=0, second=0, microsecond=0))
    week_start = _to_utc(db, (local - timedelta(days=local.weekday())).replace(hour=0, minute=0, second=0,
                                                                                microsecond=0))
    q = db.query(SystemBackup.id).filter(SystemBackup.kind == KIND_SCHEDULED,
                                         SystemBackup.status.in_((BK_READY,) + BK_PENDING))
    if q.filter(SystemBackup.created_at >= month_start).first() is None:
        return "monthly"
    if q.filter(SystemBackup.created_at >= week_start).first() is None:
        return "weekly"
    return "daily"


def retention_plan(db: Session, now: Optional[datetime] = None) -> Tuple[List[SystemBackup], Dict[int, List[str]]]:
    """Grandfather-father-son over scheduled backups: the newest of each of
    the last N days, the first of each of the last N weeks and months.
    Returns (to delete, {kept id: [reasons]}). Manual, safety and uploaded
    backups are never removed automatically."""
    cfg = get_settings(db)
    rows = (db.query(SystemBackup).filter(SystemBackup.kind == KIND_SCHEDULED, SystemBackup.status == BK_READY)
            .order_by(SystemBackup.created_at.desc()).all())
    keep: Dict[int, List[str]] = {}

    def pick(keyfn, limit, newest: bool, why: str):
        groups: Dict = {}
        for b in rows:
            groups.setdefault(keyfn(_local(db, b.created_at)), []).append(b)
        for k in sorted(groups, reverse=True)[:limit]:
            members = groups[k]
            chosen = members[0] if newest else members[-1]
            keep.setdefault(chosen.id, []).append(why)

    pick(lambda d: d.date(), cfg["keep_daily"], True, "daily")
    pick(lambda d: d.isocalendar()[:2], cfg["keep_weekly"], False, "weekly")
    pick(lambda d: (d.year, d.month), cfg["keep_monthly"], False, "monthly")
    return [b for b in rows if b.id not in keep], keep


def apply_retention(db: Session) -> int:
    doomed, _ = retention_plan(db)
    for b in doomed:
        delete_backup(db, b)
    return len(doomed)


# ── overview ──────────────────────────────────────────────────────────────

def estimates() -> Dict[str, int]:
    """On-disk size of each part, a rough upper bound for the archive
    (compression typically shrinks it several times)."""
    out = {c: 0 for c in CONTENTS}
    try:
        with dbdump.connect(autocommit=True) as conn:
            rows = conn.execute("""SELECT c.relname, pg_total_relation_size(c.oid) FROM pg_class c
                                   JOIN pg_namespace n ON n.oid = c.relnamespace
                                   WHERE n.nspname = 'public' AND c.relkind = 'r'""").fetchall()
        for name, size in rows:
            if name in dbdump.SKIP_TABLES:
                continue
            out[dbdump.category_of(name)] += int(size)
    except psycopg.Error:
        pass
    total_files = 0
    for _, path, _ in files.collect():
        try:
            total_files += path.stat().st_size
        except OSError:
            pass
    out["files"] = total_files
    return out


def overview(db: Session) -> Dict:
    cfg = get_settings(db)
    q = db.query(SystemBackup)
    last_ok = q.filter(SystemBackup.status == BK_READY).order_by(SystemBackup.created_at.desc()).first()
    last_any = q.filter(SystemBackup.status.in_((BK_READY, BK_FAILED))).order_by(
        SystemBackup.created_at.desc()).first()
    ready = q.filter(SystemBackup.status == BK_READY).all()
    from app.models.system_backup import SystemRestore, RESTORE_TEST
    last_test = (db.query(SystemRestore).filter(SystemRestore.kind == RESTORE_TEST)
                 .order_by(SystemRestore.created_at.desc()).first())
    dests = db.query(BackupDestination).order_by(BackupDestination.id).all()
    now = datetime.utcnow()
    age_h = (now - last_ok.finished_at).total_seconds() / 3600 if last_ok and last_ok.finished_at else None
    if not cfg["passphrase_set"]:
        health = "setup"
    elif last_any and last_any.status == BK_FAILED:
        health = "failed"
    elif age_h is None or age_h > 48:
        health = "stale"
    elif any(d.enabled and d.last_status == "failed" for d in dests):
        health = "warning"
    elif last_test and last_test.status == "failed":
        health = "warning"
    else:
        health = "ok"
    return {
        "health": health,
        "settings": cfg,
        "last_success": _brief(last_ok),
        "last_attempt": _brief(last_any),
        "count": len(ready),
        "total_bytes": sum(b.size_bytes or 0 for b in ready),
        "disk": disk(),
        "estimates": estimates(),
        "backup_dir": str(backup_dir()),
        "destinations": {"total": len([d for d in dests if d.enabled]),
                         "failing": len([d for d in dests if d.enabled and d.last_status == "failed"])},
        "last_test": {"status": last_test.status, "at": _iso(last_test.finished_at or last_test.created_at),
                      "backup_id": last_test.backup_id} if last_test else None,
        "running": job_running(),
        "app_version": settings.VERSION,
        "db_revision": dbdump.head_revision(),
    }


def _brief(b: Optional[SystemBackup]) -> Optional[Dict]:
    if b is None:
        return None
    return {"id": b.id, "status": b.status, "kind": b.kind, "at": _iso(b.finished_at or b.created_at),
            "size_bytes": b.size_bytes, "filename": b.filename, "error": b.error}
