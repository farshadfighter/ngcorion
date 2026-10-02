"""
API of the self-backup: /api/system-backup/*. Admins only - a backup holds
every secret the product stores.
"""
import os
import socket
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Optional
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin
from app.core.security import verify_password
from app.models import User, log_action
from app.models.system_backup import (BK_PENDING, BK_READY, CONTENTS, DEST_TYPES, KINDS, RESTORE, RESTORE_TEST,
                                      RS_PENDING, BackupDestination, SystemBackup, SystemRestore)
from app.modules.sysbackup import container, dbdump
from app.modules.sysbackup import destinations as dest_io
from app.modules.sysbackup import restore as restore_mod
from app.modules.sysbackup import service
from app.modules.sysbackup.service import BackupError, _iso

router = APIRouter(prefix="/api/system-backup", tags=["System backup"])

MODULE = "system_backup"
MAX_UPLOAD = 50 * 1024 ** 3


def _fail(e: BackupError):
    raise HTTPException(status_code=e.status, detail=str(e))


def _log(db: Session, user: User, action: str, detail: str, result: str = "success", target_id=None):
    try:
        log_action(db, user_id=user.id, username=user.username, action=action, module=MODULE,
                   target_id=target_id, detail=detail[:500], result=result)
    except Exception:
        db.rollback()


def _get_backup(db: Session, backup_id: int) -> SystemBackup:
    b = db.get(SystemBackup, backup_id)
    if b is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    return b


# ── serialisers ──────────────────────────────────────────────────────────

def _backup_out(b: SystemBackup, keep: Optional[Dict[int, List[str]]] = None) -> Dict:
    return {
        "id": b.id, "kind": b.kind, "tier": b.tier, "status": b.status, "step": b.step, "progress": b.progress,
        "contents": b.contents or [], "filename": b.filename, "size_bytes": b.size_bytes, "sha256": b.sha256,
        "app_version": b.app_version, "db_revision": b.db_revision, "key_id": b.key_id,
        "source_host": b.source_host, "summary": b.summary, "destinations": b.destinations or [],
        "targets": b.targets, "started_at": _iso(b.started_at),
        "verified_at": _iso(b.verified_at), "verify_status": b.verify_status, "verify_error": b.verify_error,
        "tested_at": _iso(b.tested_at), "test_status": b.test_status, "note": b.note, "error": b.error,
        "created_by": b.created_by_name, "created_at": _iso(b.created_at), "finished_at": _iso(b.finished_at),
        "retention": None if keep is None or b.kind != "scheduled" or b.status != BK_READY
        else (keep.get(b.id) or ["expiring"]),
    }


def _restore_out(r: SystemRestore) -> Dict:
    return {
        "id": r.id, "kind": r.kind, "backup_id": r.backup_id, "backup_label": r.backup_label, "status": r.status,
        "step": r.step, "progress": r.progress, "steps": r.steps or [], "safety_backup_id": r.safety_backup_id,
        "result": r.result, "error": r.error, "requested_by": r.requested_by_name,
        "created_at": _iso(r.created_at), "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
    }


def _dest_out(d: BackupDestination) -> Dict:
    return {
        "id": d.id, "name": d.name, "type": d.type, "host": d.host, "port": d.port, "username": d.username,
        "domain": d.domain, "share": d.share, "path": d.path, "auth": d.auth, "has_secret": bool(d.secret_encrypted),
        "host_key_fingerprint": dest_io.fingerprint(d.host_key), "enabled": d.enabled,
        "last_status": d.last_status, "last_error": d.last_error, "last_at": _iso(d.last_at),
    }


# ── overview, settings, passphrase ───────────────────────────────────────

@router.get("/maintenance")
def maintenance_state(_: User = Depends(require_admin)):
    # While a restore runs, MaintenanceMiddleware answers this path itself.
    return {"maintenance": None}


@router.get("/overview")
def get_overview(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return service.overview(db)


class SettingsIn(BaseModel):
    enabled: bool
    frequency: Literal["daily", "weekly"] = "daily"
    time: str
    include_reports: bool
    include_cve: Literal["always", "weekly", "never"]
    include_noc: Literal["always", "weekly", "never"]
    weekly_day: int = Field(ge=0, le=6)
    keep_daily: int
    keep_weekly: int
    keep_monthly: int
    restore_test: bool


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return service.get_settings(db)


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    try:
        out = service.save_settings(db, body.model_dump(), user.id)
    except BackupError as e:
        _fail(e)
    _log(db, user, "system_backup.settings", "Backup settings changed")
    return out


class PassphraseIn(BaseModel):
    passphrase: str = Field(max_length=256)
    current: Optional[str] = Field(default=None, max_length=256)


@router.post("/passphrase")
def set_passphrase(body: PassphraseIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    try:
        out = service.set_passphrase(db, body.passphrase, user.id, body.current, user.username)
    except BackupError as e:
        _log(db, user, "system_backup.passphrase", "Backup passphrase change refused", "failure")
        _fail(e)
    _log(db, user, "system_backup.passphrase", "Backup passphrase set")
    return out


class CheckIn(BaseModel):
    passphrase: str = Field(max_length=256)


@router.post("/passphrase/check")
def check_passphrase(body: CheckIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return {"ok": service.check_passphrase(db, body.passphrase)}


# ── backups ───────────────────────────────────────────────────────────────

@router.get("/backups")
def list_backups(kind: Optional[str] = Query(None), status: Optional[str] = Query(None),
                 db: Session = Depends(get_db), _: User = Depends(require_admin)):
    q = db.query(SystemBackup)
    if kind:
        q = q.filter(SystemBackup.kind == kind)
    if status:
        q = q.filter(SystemBackup.status == status)
    rows = q.order_by(SystemBackup.created_at.desc()).limit(500).all()
    _, keep = service.retention_plan(db)
    return {"items": [_backup_out(b, keep) for b in rows]}


class BackupIn(BaseModel):
    contents: List[str] = Field(default_factory=lambda: ["essential"])
    destination_ids: Optional[List[int]] = None
    note: Optional[str] = Field(default=None, max_length=300)


@router.post("/backups", status_code=201)
def create_backup(body: BackupIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    unknown = [c for c in body.contents if c not in CONTENTS]
    if unknown:
        raise HTTPException(status_code=400, detail="Unknown backup content")
    try:
        b = service.queue_backup(db, "manual", body.contents, body.note, user, body.destination_ids)
    except BackupError as e:
        _fail(e)
    _log(db, user, "system_backup.create", f"Backup #{b.id} queued ({', '.join(b.contents)})", target_id=b.id)
    return _backup_out(b)


@router.get("/backups/{backup_id}")
def get_backup(backup_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    _, keep = service.retention_plan(db)
    return _backup_out(_get_backup(db, backup_id), keep)


@router.get("/backups/{backup_id}/download")
def download_backup(backup_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    b = _get_backup(db, backup_id)
    if b.status != BK_READY:
        raise HTTPException(status_code=409, detail="The backup is not ready")
    try:
        path = service.file_path(b)
    except BackupError as e:
        _fail(e)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="The backup file is missing")
    _log(db, user, "system_backup.download", f"Downloaded {b.filename}", target_id=b.id)
    return FileResponse(path, media_type="application/octet-stream", filename=b.filename)


class PassIn(BaseModel):
    passphrase: Optional[str] = Field(default=None, max_length=256)


@router.post("/backups/{backup_id}/verify")
def verify_backup(backup_id: int, body: PassIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    b = _get_backup(db, backup_id)
    if b.status != BK_READY:
        raise HTTPException(status_code=409, detail="The backup is not ready")
    try:
        b = service.verify(db, b, body.passphrase)
    except BackupError as e:
        _fail(e)
    _log(db, user, "system_backup.verify", f"Checked {b.filename}: {b.verify_status}", target_id=b.id,
         result="success" if b.verify_status == "ok" else "failure")
    return _backup_out(b)


@router.post("/backups/{backup_id}/inspect")
def inspect_backup(backup_id: int, body: PassIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """What is inside, and whether this server can restore it."""
    b = _get_backup(db, backup_id)
    try:
        path = service.file_path(b)
        passphrase = body.passphrase or service.passphrase_for(db, b.key_id)
        if not passphrase:
            return {"needs_passphrase": True, "compatibility": service.compatibility(b)}
        manifest = service.open_manifest(path, passphrase)
    except BackupError as e:
        _fail(e)
    except container.WrongPassphrase:
        raise HTTPException(status_code=422, detail="The passphrase does not open this backup")
    except container.BackupFormatError as e:
        raise HTTPException(status_code=422, detail=f"The backup cannot be read: {e}")
    except OSError:
        raise HTTPException(status_code=404, detail="The backup file is missing")
    tables = manifest.get("tables") or {}
    by_part: Dict[str, int] = {}
    for info in tables.values():
        by_part[info["category"]] = by_part.get(info["category"], 0) + info["rows"]
    pick = lambda *names: sum((tables.get(n) or {}).get("rows", 0) for n in names)  # noqa: E731
    return {
        "needs_passphrase": False,
        "created_at": manifest.get("created_at"), "source_host": manifest.get("source_host"),
        "app_version": manifest.get("app_version"), "db_revision": manifest.get("db_revision"),
        "contents": manifest.get("contents"), "tables": len(tables), "rows": sum(by_part.values()),
        "rows_by_part": by_part, "files": len(manifest.get("files") or []),
        "highlights": {"assets": pick("asset_inventory"), "audit_sessions": pick("audit_sessions"),
                       "device_backups": pick("device_backups"), "users": pick("users"),
                       "remediation_items": pick("remediation_items"), "reports": pick("reports"),
                       "alerts": pick("alerts"), "logs": pick("audit_logs", "login_logs")},
        "compatibility": service.compatibility(b),
        "same_server": manifest.get("source_host") == socket.gethostname(),
    }


class ResendIn(BaseModel):
    destination_ids: Optional[List[int]] = None


@router.post("/backups/{backup_id}/resend")
def resend_backup(backup_id: int, body: ResendIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    b = _get_backup(db, backup_id)
    if b.status != BK_READY:
        raise HTTPException(status_code=409, detail="The backup is not ready")
    try:
        service.deliver(db, b, body.destination_ids)
    except BackupError as e:
        _fail(e)
    _log(db, user, "system_backup.resend", f"Copied {b.filename} to destinations", target_id=b.id)
    return _backup_out(b)


@router.post("/backups/{backup_id}/test", status_code=202)
def test_backup(backup_id: int, body: PassIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    b = _get_backup(db, backup_id)
    if b.status != BK_READY:
        raise HTTPException(status_code=409, detail="The backup is not ready")
    if service.job_running():
        raise HTTPException(status_code=409, detail="Another backup, restore or restore test is running; "
                                                    "try again when it finishes")
    if not body.passphrase and not service.passphrase_for(db, b.key_id):
        raise HTTPException(status_code=422, detail="Enter the passphrase this backup was made with")
    holder = type("U", (), {"id": user.id, "username": user.username})()
    threading.Thread(target=restore_mod.run_test, args=(b.id, body.passphrase, holder), daemon=True,
                     name=f"sysbackup-test-{b.id}").start()
    _log(db, user, "system_backup.test", f"Restore test of {b.filename} started", target_id=b.id)
    return {"started": True}


@router.delete("/backups/{backup_id}", status_code=204)
def delete_backup(backup_id: int, remote: bool = Query(True), db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    b = _get_backup(db, backup_id)
    name = b.filename or f"#{b.id}"
    try:
        service.delete_backup(db, b, remote=remote)
    except BackupError as e:
        _fail(e)
    _log(db, user, "system_backup.delete", f"Deleted {name}", target_id=backup_id)


@router.post("/upload", status_code=201)
async def upload_backup(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """The raw file as the request body (streamed to disk, never held in
    memory); X-Filename carries the original name."""
    original = os.path.basename(unquote(request.headers.get("x-filename") or "backup.ngbak"))[:150]
    folder = service.backup_dir()
    tmp = folder / f".upload-{uuid.uuid4().hex}.part"
    size = 0
    try:
        with open(tmp, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(status_code=413, detail="The file is too large")
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="The file is empty")
        b = service.register_upload(db, tmp, original, user)
    except BackupError as e:
        tmp.unlink(missing_ok=True)
        _fail(e)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _log(db, user, "system_backup.upload", f"Uploaded {original} as {b.filename}", target_id=b.id)
    return _backup_out(b)


# ── restores ──────────────────────────────────────────────────────────────

@router.get("/restores")
def list_restores(kind: Optional[str] = Query(None), db: Session = Depends(get_db), _: User = Depends(require_admin)):
    q = db.query(SystemRestore)
    if kind:
        q = q.filter(SystemRestore.kind == kind)
    return {"items": [_restore_out(r) for r in q.order_by(SystemRestore.created_at.desc()).limit(200).all()]}


@router.get("/restores/{restore_id}")
def get_restore(restore_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    r = db.get(SystemRestore, restore_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Restore not found")
    return _restore_out(r)


class RestoreIn(BaseModel):
    backup_id: int
    passphrase: Optional[str] = Field(default=None, max_length=256)
    confirm: str
    password: str = Field(max_length=256)


@router.post("/restores", status_code=202)
def create_restore(body: RestoreIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if body.confirm.strip().upper() != "RESTORE":
        raise HTTPException(status_code=400, detail="Type RESTORE to confirm")
    if not verify_password(body.password, user.hashed_password):
        _log(db, user, "system_backup.restore", "Restore refused: wrong password", "failure")
        raise HTTPException(status_code=403, detail="Your password is not correct")
    b = _get_backup(db, body.backup_id)
    _log(db, user, "system_backup.restore", f"Restore of {b.filename} started", target_id=b.id)
    try:
        r = restore_mod.start_restore(db, b, body.passphrase, user)
    except BackupError as e:
        _fail(e)
    return _restore_out(r)


# ── destinations ──────────────────────────────────────────────────────────

class DestinationIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: Literal["sftp", "smb"]
    host: str = Field(min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = Field(default=None, max_length=255)
    domain: Optional[str] = Field(default=None, max_length=120)
    share: Optional[str] = Field(default=None, max_length=255)
    path: Optional[str] = Field(default=None, max_length=500)
    auth: Literal["password", "key"] = "password"
    secret: Optional[str] = Field(default=None, max_length=16384)   # empty on edit = keep
    enabled: bool = True


def _apply(d: BackupDestination, body: DestinationIn) -> None:
    host = body.host.strip()
    if any(c in host for c in "/\\ @"):
        raise HTTPException(status_code=400, detail="Enter only the server name or address")
    if body.type == "smb" and not (body.share or "").strip():
        raise HTTPException(status_code=400, detail="Enter the share name")
    if d.host and (d.host != host or (d.port or None) != (body.port or None)):
        d.host_key = None           # another server: pin its key afresh
    d.name, d.type, d.host, d.port = body.name.strip(), body.type, host, body.port
    d.username = (body.username or "").strip() or None
    d.domain = (body.domain or "").strip() or None
    d.share = (body.share or "").strip().strip("\\/") or None
    d.path = (body.path or "").strip() or None
    d.auth = body.auth if body.type == "sftp" else "password"
    d.enabled = body.enabled
    if body.secret:
        d.secret_encrypted = dest_io.seal(body.secret)
    d.updated_at = datetime.utcnow()


@router.get("/destinations")
def list_destinations(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return {"items": [_dest_out(d) for d in db.query(BackupDestination).order_by(BackupDestination.id).all()]}


@router.post("/destinations", status_code=201)
def create_destination(body: DestinationIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = BackupDestination(host="")
    _apply(d, body)
    db.add(d)
    db.commit()
    db.refresh(d)
    _log(db, user, "system_backup.destination", f"Destination {d.name} added", target_id=d.id)
    return _dest_out(d)


@router.put("/destinations/{dest_id}")
def update_destination(dest_id: int, body: DestinationIn, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    d = db.get(BackupDestination, dest_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    _apply(d, body)
    db.commit()
    _log(db, user, "system_backup.destination", f"Destination {d.name} changed", target_id=d.id)
    return _dest_out(d)


@router.delete("/destinations/{dest_id}", status_code=204)
def delete_destination(dest_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = db.get(BackupDestination, dest_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    name = d.name
    db.delete(d)
    db.commit()
    _log(db, user, "system_backup.destination", f"Destination {name} removed", target_id=dest_id)


@router.post("/destinations/{dest_id}/test")
def test_destination(dest_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = db.get(BackupDestination, dest_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    d.last_at = datetime.utcnow()
    try:
        host_key, fp = dest_io.test(d)
        if d.type == "sftp" and not d.host_key and host_key:
            d.host_key = host_key
        d.last_status, d.last_error = "ok", None
        db.commit()
        return {"ok": True, "fingerprint": fp, "destination": _dest_out(d)}
    except dest_io.DestinationError as e:
        d.last_status, d.last_error = "failed", str(e)[:1000]
        db.commit()
        return {"ok": False, "error": str(e), "destination": _dest_out(d)}


@router.post("/destinations/{dest_id}/clear-host-key")
def clear_host_key(dest_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    d = db.get(BackupDestination, dest_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    d.host_key = None
    db.commit()
    _log(db, user, "system_backup.destination", f"Pinned host key of {d.name} cleared", target_id=d.id)
    return _dest_out(d)
