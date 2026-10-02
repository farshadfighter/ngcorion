"""
Self-backup from the command line, for when the web interface is not an
option (a broken upgrade, a fresh server before anyone can log in):

    python -m app.modules.sysbackup.cli list
    python -m app.modules.sysbackup.cli create [--with cve,noc_history] [--note TEXT]
    python -m app.modules.sysbackup.cli verify FILE
    python -m app.modules.sysbackup.cli restore FILE [--yes]

The passphrase is read from the terminal (or NGCORION_BACKUP_PASSPHRASE).
In Docker: docker compose exec backend uv run python -m app.modules.sysbackup.cli list
"""
import argparse
import getpass
import os
import shutil
import sys
import time
from pathlib import Path


def _passphrase(prompt: str = "Backup passphrase: ") -> str:
    value = os.environ.get("NGCORION_BACKUP_PASSPHRASE")
    return value if value else getpass.getpass(prompt)


def _size(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def cmd_list(args) -> int:
    from app.core.database import SessionLocal
    from app.models.system_backup import SystemBackup
    db = SessionLocal()
    try:
        for b in db.query(SystemBackup).order_by(SystemBackup.created_at.desc()).all():
            print(f"{b.id:>5}  {b.created_at:%Y-%m-%d %H:%M}  {b.kind:<9} {b.status:<8} {_size(b.size_bytes):>9}  "
                  f"{','.join(b.contents or [])}  {b.filename or ''}")
    finally:
        db.close()
    return 0


def cmd_create(args) -> int:
    from app.core.database import SessionLocal
    from app.modules.sysbackup import service
    db = SessionLocal()
    try:
        contents = ["essential", "reports"] + [c for c in (args.with_ or "").split(",") if c]
        b = service.queue_backup(db, "manual", contents, args.note or "Command line")
        b = service.claim_next(db)
        b = service.run_backup(db, b)
        if b.status != "ready":
            print(f"Backup failed: {b.error}", file=sys.stderr)
            return 1
        print(f"Backup written: {service.file_path(b)} ({_size(b.size_bytes)})")
        return 0
    except service.BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()


def cmd_verify(args) -> int:
    from app.modules.sysbackup import container, service
    path = Path(args.file)
    try:
        header = service.read_header(path)
        print(f"Made {header.get('created_at')} on {header.get('source_host')}, NGCorion {header.get('app_version')}")
        result = service.verify_file(path, _passphrase())
    except container.WrongPassphrase:
        print("The passphrase does not open this backup", file=sys.stderr)
        return 2
    except (container.BackupFormatError, OSError) as exc:
        print(f"Damaged or unreadable: {exc}", file=sys.stderr)
        return 1
    m = result["manifest"]
    print(f"OK: {result['entries']} entries, {len(m.get('tables', {}))} tables, "
          f"{sum(t['rows'] for t in m.get('tables', {}).values())} rows")
    return 0


def cmd_restore(args) -> int:
    from app.core.database import SessionLocal
    from app.models.system_backup import SystemRestore
    from app.modules.sysbackup import restore, service
    src = Path(args.file)
    if not src.is_file():
        print("No such file", file=sys.stderr)
        return 1
    passphrase = _passphrase()
    if not args.yes:
        answer = input("This replaces ALL data of this NGCorion server. Type RESTORE to continue: ")
        if answer.strip() != "RESTORE":
            print("Cancelled")
            return 1
    db = SessionLocal()
    try:
        tmp = service.backup_dir() / f".upload-cli-{os.getpid()}.part"
        shutil.copyfile(src, tmp)
        b = service.register_upload(db, tmp, src.name)
        r = restore.start_restore(db, b, passphrase, None)
        restore_id = r.id
    except service.BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()
    last = None
    while True:
        time.sleep(1)
        db = SessionLocal()
        try:
            r = db.get(SystemRestore, restore_id)
            state = (r.status, r.step, r.progress, r.error)
        except Exception:
            db.close()
            continue
        db.close()
        if state[:2] != last:
            print(f"  {state[2]:>3}%  {state[1]}")
            last = state[:2]
        if state[0] in ("succeeded", "failed"):
            print("Restore finished" if state[0] == "succeeded" else f"Restore failed: {state[3]}")
            return 0 if state[0] == "succeeded" else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.modules.sysbackup.cli", description="NGCorion self-backup")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list backups")
    c = sub.add_parser("create", help="make a backup now")
    c.add_argument("--with", dest="with_", help="extra parts: cve,noc_history")
    c.add_argument("--note")
    v = sub.add_parser("verify", help="check a backup file")
    v.add_argument("file")
    r = sub.add_parser("restore", help="restore a backup file onto this server")
    r.add_argument("file")
    r.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = p.parse_args(argv)
    return {"list": cmd_list, "create": cmd_create, "verify": cmd_verify, "restore": cmd_restore}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
