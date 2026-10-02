"""
Restoring a backup onto this server, and the weekly restore test.

Restore, step by step (each recorded on the SystemRestore row):
  validate     header, passphrase, manifest; the backup's version is known
  maintenance  the API answers 503 from here on
  safety       a full backup of the system as it is now
  staging      schema "ngrestore" built by the migrations at the backup's revision
  load         every table copied in, row counts compared with the manifest
  check        foreign keys validated, entry checksums compared
  upgrade      staging migrated to this version
  carry        parts the backup does not hold kept from the running system
  rekey        stored secrets re-encrypted if the backup came from another key
  swap         staging renamed to public in one transaction
  files        certificate and SSH host keys written back
  finish       maintenance off, the old schema dropped

Up to the swap the running system is untouched: a failure drops the staging
schema and leaves everything as it was. The restore test runs the same steps
up to "upgrade" in schema "ngtest" and drops it.
"""
import json
import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.singleton import runner_is_alive, runner_tag
from app.models.system_backup import (BK_READY, CONTENTS, RESTORE, RESTORE_TEST, RS_FAILED, RS_PENDING,
                                      RS_QUEUED, RS_RUNNING, RS_SUCCEEDED, SystemBackup, SystemRestore)
from app.modules.sysbackup import container, dbdump, files, maintenance, rekey, service
from app.modules.sysbackup.service import BackupError, JobLock, update_row

logger = logging.getLogger(__name__)

RESTORE_STEPS = ("validate", "maintenance", "safety", "staging", "load", "check", "upgrade", "carry", "rekey",
                 "swap", "files", "finish")
TEST_STEPS = ("validate", "staging", "load", "check", "upgrade", "rekey", "cleanup")


class _Progress:
    """Records steps on the row and mirrors them into the maintenance flag."""

    def __init__(self, restore_id: int, steps, in_maintenance: bool):
        self.id = restore_id
        self.steps = [{"key": k, "status": "pending"} for k in steps]
        self.maint = in_maintenance
        self.current: Optional[str] = None
        self.pct = 0
        self._last = 0.0

    def _save(self, **extra):
        update_row(SystemRestore, self.id, steps=json.loads(json.dumps(self.steps)), step=self.current,
                   progress=self.pct, **extra)
        if self.maint and maintenance.flag_path().exists():
            maintenance.update(step=self.current, progress=self.pct)

    def start(self, key: str, pct: int):
        for s in self.steps:
            if s["key"] == self.current and s["status"] == "running":
                s["status"] = "done"
                s["at"] = datetime.utcnow().isoformat() + "Z"
        self.current, self.pct = key, pct
        for s in self.steps:
            if s["key"] == key:
                s["status"] = "running"
        self._save()

    def detail(self, text: str):
        for s in self.steps:
            if s["key"] == self.current:
                s["detail"] = text
        self._save()

    def tick(self, pct: int):
        """Heartbeat inside a long step."""
        now = time.monotonic()
        if now - self._last >= 3:
            self._last = now
            self.pct = max(self.pct, pct)
            self._save()

    def finish(self, ok: bool, **extra):
        for s in self.steps:
            if s["status"] == "running":
                s["status"] = "done" if ok else "failed"
            elif ok and s["status"] == "pending":
                s["status"] = "skipped"
        self.pct = 100 if ok else self.pct
        self._save(status=RS_SUCCEEDED if ok else RS_FAILED, finished_at=datetime.utcnow(), **extra)


def _open_reader(path, passphrase: str, progress=None):
    f = open(path, "rb")
    try:
        return f, container.Reader(f, passphrase, progress=progress)
    except Exception:
        f.close()
        raise


def _load(schema: str, path, passphrase: str, manifest: dict, prog: _Progress, lo: int, hi: int) -> dict:
    """Copy the backup's tables into `schema` (foreign keys already dropped).
    Returns {"old_key", "files": [(entry, bytes, mode)], "summary"}."""
    size = path.stat().st_size or 1
    f, reader = _open_reader(path, passphrase, progress=lambda pos: prog.tick(lo + int((hi - lo) * pos / size)))
    tables = manifest.get("tables") or {}
    modes = {x["entry"]: x.get("mode", 0o600) for x in manifest.get("files") or []}
    out = {"old_key": None, "files": [], "summary": None}
    try:
        with dbdump.connect() as conn:
            cur = conn.cursor()
            for name, blocks in reader.entries():
                if name.startswith("db/") and name.endswith(".copy"):
                    table = name[3:-5]
                    info = tables.get(table)
                    if info is None:
                        raise container.BackupFormatError(f"{table} is not in the manifest")
                    dbdump.copy_in(cur, schema, table, info["columns"], blocks)
                elif name == "secret.key":
                    out["old_key"] = container.read_entry(blocks, 4096).decode("utf-8")
                elif name.startswith("files/"):
                    out["files"].append((name, container.read_entry(blocks, files.MAX_FILE), modes.get(name, 0o600)))
                elif name == "summary.json":
                    out["summary"] = json.loads(container.read_entry(blocks).decode("utf-8"))
            conn.commit()
            expected = (out["summary"] or {}).get("entries") or {}
            if not expected:
                raise container.BackupFormatError("the backup has no summary")
            for entry, info in expected.items():
                if reader.entry_hashes.get(entry) != info:
                    raise container.BackupFormatError(f"{entry} does not match its recorded checksum")
            mismatched = []
            for table, info in tables.items():
                got = dbdump.count(cur, schema, table)
                if got != info["rows"]:
                    mismatched.append(f"{table} ({got} of {info['rows']})")
            if mismatched:
                raise container.BackupFormatError("row counts differ: " + ", ".join(mismatched[:5]))
    finally:
        f.close()
    return out


def _stage(schema: str, revision: str, manifest: dict, path, passphrase: str, prog: _Progress,
           pct: Dict[str, int]) -> dict:
    prog.start("staging", pct["staging"])
    with dbdump.connect(autocommit=True) as conn:
        dbdump.reset_schema(conn.cursor(), schema)
    dbdump.migrate(schema, revision)
    made = dbdump.create_missing(schema, (manifest.get("tables") or {}).keys())
    with dbdump.connect(autocommit=True) as conn:
        cur = conn.cursor()
        dbdump.truncate_all(cur, schema)
        fks = dbdump.drop_foreign_keys(cur, schema)

    prog.start("load", pct["load"])
    loaded = _load(schema, path, passphrase, manifest, prog, pct["load"], pct["check"] - 1)

    prog.start("check", pct["check"])
    with dbdump.connect(autocommit=True) as conn:
        cur = conn.cursor()
        dbdump.add_foreign_keys(cur, schema, fks)
        dbdump.validate_foreign_keys(cur, schema)

    prog.start("upgrade", pct["upgrade"])
    head = dbdump.head_revision()
    if revision != head:
        dbdump.migrate(schema, "head")
    dbdump.create_missing(schema, dbdump.model_tables())
    loaded["created_tables"] = made
    loaded["upgraded_from"] = revision if revision != head else None
    return loaded


def _prepare(db, backup: SystemBackup, passphrase: Optional[str]):
    if backup.status != BK_READY:
        raise BackupError("Only a finished backup can be restored", 409)
    path = service.file_path(backup)
    if not path.is_file():
        raise BackupError("The backup file is missing", 404)
    passphrase = passphrase or service.passphrase_for(db, backup.key_id)
    if not passphrase:
        raise BackupError("Enter the passphrase this backup was made with", 422)
    try:
        manifest = service.open_manifest(path, passphrase)
    except container.WrongPassphrase:
        raise BackupError("The passphrase does not open this backup", 422)
    except container.BackupFormatError as exc:
        raise BackupError(f"The backup cannot be read: {exc}", 422)
    revision = manifest.get("db_revision")
    if not revision or not dbdump.known_revision(revision):
        raise BackupError("This backup comes from a newer NGCorion version. Update this server first, "
                          "then restore it.", 409)
    return path, passphrase, manifest, revision


# ── restore ───────────────────────────────────────────────────────────────

def start_restore(db, backup: SystemBackup, passphrase: Optional[str], user) -> SystemRestore:
    """Check what can be checked up front, then run the restore in a thread
    of this worker (the passphrase stays in memory, never in the database)."""
    path, passphrase, manifest, revision = _prepare(db, backup, passphrase)
    if db.query(SystemRestore).filter(SystemRestore.status.in_(RS_PENDING)).count():
        raise BackupError("A restore is already running", 409)
    lock = JobLock()
    if not lock.acquire():
        raise BackupError("A backup or restore test is running; try again when it finishes", 409)
    try:
        r = SystemRestore(kind=RESTORE, backup_id=backup.id, backup_label=service.label(backup),
                          status=RS_RUNNING, steps=[], started_at=datetime.utcnow(), runner=runner_tag(),
                          requested_by=getattr(user, "id", None), requested_by_name=getattr(user, "username", None))
        db.add(r)
        db.commit()
        db.refresh(r)
    except Exception:
        lock.release()
        raise
    threading.Thread(target=_run_restore, name=f"sysrestore-{r.id}", daemon=True,
                     args=(r.id, backup.id, path, passphrase, manifest, revision, lock)).start()
    return r


def _run_restore(restore_id, backup_id, path, passphrase, manifest, revision, lock: JobLock) -> None:
    pct = {"validate": 1, "maintenance": 2, "safety": 3, "staging": 25, "load": 30, "check": 70, "upgrade": 75,
           "carry": 82, "rekey": 86, "swap": 90, "files": 95, "finish": 98}
    prog = _Progress(restore_id, RESTORE_STEPS, in_maintenance=True)
    result: Dict = {"backup_revision": revision, "contents": manifest.get("contents")}
    swapped, old_schema = False, None
    try:
        prog.start("validate", pct["validate"])
        maintenance.on(reason="restore", restore_id=restore_id, step="maintenance", progress=2)
        prog.start("maintenance", pct["maintenance"])

        prog.start("safety", pct["safety"])
        db = SessionLocal()
        try:
            current, key_id = service.current_passphrase(db)
        finally:
            db.close()
        # A fresh server has no passphrase yet: its safety backup is sealed
        # with the passphrase of the backup being restored.
        safety_pass, safety_key = (current, key_id) if current else (passphrase, manifest.get("key_id"))
        safety = service.make_safety_backup(
            safety_pass, safety_key, f"Before restoring {manifest.get('created_at', '')[:19]}",
            progress=lambda p, step: prog.tick(pct["safety"] + int(20 * p / 100)))
        update_row(SystemRestore, restore_id, safety_backup_id=safety.id)
        result["safety_backup"] = safety.filename

        loaded = _stage(dbdump.STAGING, revision, manifest, path, passphrase, prog, pct)
        result.update(created_tables=loaded["created_tables"], upgraded_from=loaded["upgraded_from"])

        prog.start("carry", pct["carry"])
        result["carried"] = _carry(set(manifest.get("contents") or ["essential"]), manifest.get("sequences") or {})

        prog.start("rekey", pct["rekey"])
        old_key = loaded["old_key"]
        if old_key and old_key != settings.SECRET_KEY:
            with dbdump.connect() as conn:
                result["secrets"] = rekey.rekey(conn.cursor(), dbdump.STAGING, old_key)
                conn.commit()
        else:
            result["secrets"] = {"rekeyed": 0, "same_key": True}

        prog.start("swap", pct["swap"])
        old_schema = dbdump.swap(dbdump.STAGING)
        swapped = True

        prog.start("files", pct["files"])
        written = []
        for entry, data, mode in loaded["files"]:
            try:
                written.append(files.write(entry, data, mode))
            except (OSError, ValueError) as exc:
                logger.warning("[sysbackup] could not restore %s: %s", entry, exc)
                result.setdefault("file_errors", []).append(f"{entry}: {exc}")
        files.after_restore(written)
        result["files"] = len(written)

        prog.start("finish", pct["finish"])
        dbdump.drop_schema(old_schema)
        prog.finish(True, result=result, error=None)
        _audit(restore_id, f"Restored {manifest.get('created_at', '')[:19]} backup; safety backup "
                           f"{result.get('safety_backup')}")
    except Exception as exc:
        logger.exception("[sysbackup] restore %s failed", restore_id)
        message = _message(exc)
        if not swapped:
            try:
                dbdump.drop_schema(dbdump.STAGING)
            except Exception:
                logger.exception("[sysbackup] could not drop the staging schema")
        else:
            message = "The backup was restored, but a final step failed: " + message
        prog.finish(False, result=result, error=message[:2000])
    finally:
        maintenance.off()
        lock.release()


def _audit(restore_id: int, detail: str) -> None:
    """Record the restore in the restored database's audit log (the log the
    backup brought back does not know about it)."""
    from app.models import log_action
    db = SessionLocal()
    try:
        r = db.get(SystemRestore, restore_id)
        log_action(db, user_id=None, username=r.requested_by_name if r else None, action="system_backup.restore",
                   module="system_backup", detail=detail[:500], result="success")
    except Exception:
        logger.exception("[sysbackup] could not record the restore in the audit log")
        db.rollback()
    finally:
        db.close()


def _carry(contents: set, sequences: Dict) -> Dict:
    """Keep what the backup does not hold: optional parts it left out, the
    backup catalog, and the self-backup settings and destinations."""
    out: Dict = {}
    with dbdump.connect() as conn:
        cur = conn.cursor()
        schema = dbdump.STAGING
        fks = dbdump.drop_foreign_keys(cur, schema)
        for part, tables in dbdump.CATEGORY_TABLES.items():
            if part in contents:
                continue
            for t in tables:
                n = dbdump.carry_over(cur, schema, t)
                if n:
                    out[t] = n
        for t in dbdump.LOCAL_TABLES:
            dbdump.carry_over(cur, schema, t)
        live = set(dbdump.tables(cur, "public"))
        for t in dbdump.ADOPT_TABLES:
            if t in live and dbdump.count(cur, "public", t):
                out[t] = dbdump.carry_over(cur, schema, t)
        out["settings_kept"] = dbdump.carry_over_setting(cur, schema)
        dbdump.add_foreign_keys(cur, schema, fks)
        orphans = dbdump.repair_orphans(cur, schema)
        if orphans:
            out["orphans_removed"] = orphans
        conn.commit()
        # Positions recorded in the backup; carried tables catch up from max().
        dbdump.set_sequences(cur, schema, sequences)
        conn.commit()
    return out


def _message(exc: Exception) -> str:
    if isinstance(exc, (BackupError, container.BackupFormatError, dbdump.RestoreError)):
        return str(exc)
    if isinstance(exc, container.WrongPassphrase):
        return "The passphrase does not open this backup"
    return f"{exc.__class__.__name__}: {exc}"


# ── restore test ──────────────────────────────────────────────────────────

def run_test(backup_id: int, passphrase: Optional[str] = None, requested_by=None) -> SystemRestore:
    """Load a backup into a scratch schema and drop it again. Runs in the
    caller's thread; takes the job lock."""
    db = SessionLocal()
    try:
        backup = db.get(SystemBackup, backup_id)
        r = SystemRestore(kind=RESTORE_TEST, backup_id=backup_id,
                          backup_label=service.label(backup) if backup else None, status=RS_RUNNING, steps=[],
                          started_at=datetime.utcnow(), runner=runner_tag(),
                          requested_by=getattr(requested_by, "id", None),
                          requested_by_name=getattr(requested_by, "username", None) or
                          (None if requested_by else "scheduler"))
        db.add(r)
        db.commit()
        db.refresh(r)
        restore_id = r.id
    finally:
        db.close()
    pct = {"validate": 1, "staging": 5, "load": 15, "check": 80, "upgrade": 85, "rekey": 92, "cleanup": 96}
    prog = _Progress(restore_id, TEST_STEPS, in_maintenance=False)
    ok, result, error = False, {}, None
    try:
        with JobLock():
            prog.start("validate", pct["validate"])
            db = SessionLocal()
            try:
                backup = db.get(SystemBackup, backup_id)
                if backup is None:
                    raise BackupError("The backup no longer exists", 404)
                path, passphrase, manifest, revision = _prepare(db, backup, passphrase)
            finally:
                db.close()
            try:
                loaded = _stage(dbdump.TEST_STAGING, revision, manifest, path, passphrase, prog, pct)
                prog.start("rekey", pct["rekey"])
                if loaded["old_key"] and loaded["old_key"] != settings.SECRET_KEY:
                    with dbdump.connect() as conn:
                        result["secrets"] = rekey.rekey(conn.cursor(), dbdump.TEST_STAGING, loaded["old_key"],
                                                        check_only=True)
                        conn.rollback()
                result.update(tables=len(manifest.get("tables") or {}),
                              rows=sum(t["rows"] for t in (manifest.get("tables") or {}).values()),
                              files=len(loaded["files"]), upgraded_from=loaded["upgraded_from"])
            finally:
                prog.start("cleanup", pct["cleanup"])
                dbdump.drop_schema(dbdump.TEST_STAGING)
            ok = True
    except Exception as exc:
        logger.exception("[sysbackup] restore test of backup %s failed", backup_id)
        error = _message(exc)
    prog.finish(ok, result=result, error=error[:2000] if error else None)
    update_row(SystemBackup, backup_id, tested_at=datetime.utcnow(), test_status="ok" if ok else "failed")
    db = SessionLocal()
    try:
        return db.get(SystemRestore, restore_id)
    finally:
        db.close()


def fail_stale(db) -> int:
    n = 0
    for r in db.query(SystemRestore).filter(SystemRestore.status.in_((RS_QUEUED, RS_RUNNING))).all():
        if not runner_is_alive(r.runner):
            r.status, r.error, r.finished_at = RS_FAILED, "The restore was interrupted", datetime.utcnow()
            n += 1
    if n:
        db.commit()
    return n
