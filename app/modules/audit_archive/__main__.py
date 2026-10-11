"""
Command line of the audit trail archive (app/modules/audit_archive/archive.py has the work):

    python -m app.modules.audit_archive export --before 2025-01-01 [--out DIR]
    python -m app.modules.audit_archive verify FILE
    python -m app.modules.audit_archive purge FILE [--yes]

Stays Python source in the production image (scripts/compile_app.py RUN_AS_MAIN): `python -m` needs a
code object, which a compiled module does not have.
"""
import argparse
import sys
from datetime import date
from pathlib import Path

from sqlalchemy import text

from app.modules.audit_archive.archive import ArchiveError, export, file_sha256, purge, verify


def _session():
    from app.core.database import SessionLocal
    return SessionLocal()


def cmd_export(args) -> int:
    from app.core.config import settings
    out = Path(args.out) if args.out else Path(settings.BACKUP_DIR) / "audit-archive"
    db = _session()
    try:
        path, manifest = export(db, date.fromisoformat(args.before), out)
    except (ArchiveError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()
    t = manifest["tables"]
    print(f"Archive written: {path}")
    print(f"  {t['audit_logs']['rows']} audit events and {t['login_logs']['rows']} sign-ins older than "
          f"{manifest['cutoff']}")
    print(f"  SHA-256 {file_sha256(path)}  - note it, and keep the file off this server")
    return 0


def cmd_verify(args) -> int:
    try:
        manifest = verify(Path(args.file))
    except (ArchiveError, OSError) as exc:
        print(f"NOT OK: {exc}", file=sys.stderr)
        return 1
    t = manifest["tables"]
    print(f"OK: {t['audit_logs']['rows']} audit events and {t['login_logs']['rows']} sign-ins older than "
          f"{manifest['cutoff']} (made by NGCorion {manifest['product_version']})")
    print(f"  SHA-256 {file_sha256(Path(args.file))}")
    return 0


def cmd_purge(args) -> int:
    path = Path(args.file)
    try:
        manifest = verify(path)
    except (ArchiveError, OSError) as exc:
        print(f"NOT OK: {exc}", file=sys.stderr)
        return 1
    t = manifest["tables"]
    if not args.yes:
        print(f"This removes {t['audit_logs']['rows']} audit events and {t['login_logs']['rows']} sign-ins older "
              f"than {manifest['cutoff']} from the database. Is a copy of {path.name} kept off this server?")
        if input("Type PURGE to continue: ").strip() != "PURGE":
            print("Cancelled")
            return 1
    db = _session()
    try:
        done = purge(db, path)
    except ArchiveError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"Removed {done['events']} audit events and {done['logins']} sign-ins; the removal is in the audit trail.")
    # Space goes back to PostgreSQL for new rows (not to the disk; see the admin guide for VACUUM FULL).
    from app.core.database import engine
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("VACUUM (ANALYZE) audit_logs"))
        conn.execute(text("VACUUM (ANALYZE) login_logs"))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.modules.audit_archive",
                                     description="Archive old audit events and sign-ins, then remove them.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("export", help="write everything older than a day to an archive file")
    p.add_argument("--before", required=True, help="YYYY-MM-DD: archive what is older than the start of this day")
    p.add_argument("--out", help="folder (default: BACKUP_DIR/audit-archive)")
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("verify", help="check an archive file against its manifest")
    p.add_argument("file")
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("purge", help="remove from the database exactly what an archive holds")
    p.add_argument("file")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_purge)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
