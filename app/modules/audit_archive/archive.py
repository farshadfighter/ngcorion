"""
Archiving the audit trail (Common Criteria FAU_STG): move old audit events and sign-ins off the server
into a verifiable file, and only then remove them from the database.

    python -m app.modules.audit_archive export --before 2025-01-01 [--out DIR]
    python -m app.modules.audit_archive verify FILE
    python -m app.modules.audit_archive purge FILE [--yes]

In Docker: docker compose exec backend uv run python -m app.modules.audit_archive ...

export   writes every audit event and sign-in older than the start of --before (a day in the time zone
         set in System Configuration, as on the audit trail page) to a .zip: audit_logs.csv,
         login_logs.csv and manifest.json with the row counts and the SHA-256 of each CSV. Nothing is
         removed. Default folder: BACKUP_DIR/audit-archive.
verify   checks a file's CSVs against its manifest.
purge    removes from the database exactly the rows a verified archive holds: it locks the tables,
         rebuilds both CSVs from the database for the archive's cut-off and removes the rows only
         when they are byte for byte what the archive holds (nothing unarchived, nothing changed),
         then records the removal - counts, cut-off and the archive's SHA-256 - in the audit trail
         itself. audit_logs is append-only (trigger audit_logs_no_change): the trigger is disabled
         for this one statement inside the same transaction, so it is never off for anything else.

This is a command-line tool on purpose: removing audit records needs access to the server, not only
an administrator account in the web interface. Keep the archive file (and its SHA-256, printed by
export) outside the server, as for system backups.
"""
import csv
import hashlib
import io
import json
import os
import zipfile
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from sqlalchemy import text

FORMAT = "ngcorion-audit-archive/1"
# Column order of each CSV; changing it changes every hash, so it is part of FORMAT.
TABLES = {
    "audit_logs": ("id", "timestamp", "user_id", "username", "action", "module", "target_id", "ip_address",
                   "result", "detail"),
    "login_logs": ("id", "timestamp", "username", "success", "ip_address", "user_agent", "message"),
}
CHUNK_ROWS = 5000


class ArchiveError(Exception):
    pass


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def dump(db, table: str, cutoff: datetime, sink: Optional[Callable[[bytes], None]] = None) -> Dict:
    """Write the rows of `table` older than `cutoff` as CSV (ordered by id) to `sink`; return their
    count, first and last id and the SHA-256 of the CSV. The same rows always give the same bytes."""
    columns = TABLES[table]
    digest, rows, first, last = hashlib.sha256(), 0, None, None
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)

    def flush():
        data = buf.getvalue().encode("utf-8")
        digest.update(data)
        if sink:
            sink(data)
        buf.seek(0)
        buf.truncate()

    result = db.execute(text(f"SELECT {', '.join(columns)} FROM {table} "  # noqa: S608 - fixed names
                             "WHERE timestamp < :cutoff ORDER BY id").execution_options(yield_per=CHUNK_ROWS),
                        {"cutoff": cutoff})
    for row in result:
        writer.writerow([_cell(v) for v in row])
        rows += 1
        first = row[0] if first is None else first
        last = row[0]
        if rows % CHUNK_ROWS == 0:
            flush()
    flush()
    return {"rows": rows, "first_id": first, "last_id": last, "sha256": digest.hexdigest()}


def cutoff_for(db, before: date) -> datetime:
    """The start of `before` in the time zone set in System Configuration (UTC when none is set)."""
    from app.modules.alerts.channels import local_timezone
    tz = local_timezone(db) or timezone.utc
    return datetime.combine(before, time.min, tzinfo=tz)


def export(db, before: date, out_dir: Path) -> Tuple[Path, Dict]:
    """Write the archive of everything older than `before`; return its path and manifest."""
    from app.core.config import settings
    cutoff = cutoff_for(db, before)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"ngcorion-audit-before-{before.isoformat()}.zip"
    if path.exists():
        raise ArchiveError(f"{path} already exists")
    part = path.with_suffix(".zip.part")
    manifest = {"format": FORMAT, "product_version": settings.VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(), "before": before.isoformat(),
                "cutoff": cutoff.isoformat(), "tables": {}}
    try:
        with zipfile.ZipFile(part, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for table in TABLES:
                with zf.open(f"{table}.csv", "w", force_zip64=True) as member:
                    manifest["tables"][table] = dump(db, table, cutoff, member.write)
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        os.chmod(part, 0o600)
        part.rename(path)
    finally:
        part.unlink(missing_ok=True)
    return path, manifest


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path) -> Dict:
    """The manifest of an archive whose CSVs match it; ArchiveError otherwise."""
    try:
        with zipfile.ZipFile(path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
            if manifest.get("format") != FORMAT:
                raise ArchiveError(f"not an NGCorion audit archive ({manifest.get('format')})")
            for table in TABLES:
                expected = manifest["tables"][table]
                digest, rows = hashlib.sha256(), -1  # the header line is not a row
                with zf.open(f"{table}.csv") as member:
                    for line in member:
                        digest.update(line)
                        rows += 1
                if digest.hexdigest() != expected["sha256"]:
                    raise ArchiveError(f"{table}.csv does not match the manifest (SHA-256)")
                if rows < expected["rows"]:  # a detail may span lines; never fewer lines than rows
                    raise ArchiveError(f"{table}.csv holds fewer rows than the manifest says")
    except (KeyError, ValueError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"unreadable archive: {exc}") from exc
    return manifest


def purge(db, path: Path) -> Dict:
    """Remove from the database the rows `path` archives (see the module docstring); return counts."""
    manifest = verify(path)
    cutoff = datetime.fromisoformat(manifest["cutoff"])
    archive_sha = file_sha256(path)
    # Nothing is written to either table until the commit; the trigger is off only inside it.
    db.execute(text("LOCK TABLE audit_logs, login_logs IN SHARE ROW EXCLUSIVE MODE"))
    for table in TABLES:
        now = dump(db, table, cutoff)
        if now["sha256"] != manifest["tables"][table]["sha256"]:
            db.rollback()
            raise ArchiveError(f"{table} older than {cutoff.isoformat()} is not what the archive holds "
                               f"({now['rows']} rows now, {manifest['tables'][table]['rows']} archived): "
                               "nothing was removed. Export again.")
    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_change"))
    removed_events = db.execute(text("DELETE FROM audit_logs WHERE timestamp < :c"), {"c": cutoff}).rowcount
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_change"))
    removed_logins = db.execute(text("DELETE FROM login_logs WHERE timestamp < :c"), {"c": cutoff}).rowcount
    from app.models.security_audit_log import AuditLog
    db.add(AuditLog(username="system", module="logs", action="audit.archive_purge", result="success",
                    detail=(f"Removed {removed_events} audit events and {removed_logins} sign-ins older than "
                            f"{cutoff.isoformat()}, archived in {path.name} (SHA-256 {archive_sha})")))
    db.commit()
    return {"events": removed_events, "logins": removed_logins, "archive_sha256": archive_sha}
