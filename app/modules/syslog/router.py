"""
Syslog API (/api/syslog): received messages with filters and paging, CSV export, an overview
(listener status, counts, which assets send and which addresses outside the inventory try to),
and the settings. Reading needs the NOC permission; changing the settings - which opens or closes
a network port - is for system administrators only and is recorded in the audit trail.
"""
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from app.core.config import settings as app_settings
from app.core.database import get_db
from app.core.dependencies import require_admin, require_permission
from app.models import Asset, User
from app.models.syslog import SEVERITIES, SyslogMessage, SyslogSource, SyslogStatus
from app.modules.syslog import settings as syslog_settings
from app.utils.excel_utils import neutralize_formula

router = APIRouter(prefix="/api/syslog", tags=["Syslog"])

STATUS_FRESH = timedelta(seconds=60)
EXPORT_MAX = 50000


class SyslogSettings(BaseModel):
    enabled: bool
    udp: bool
    tcp: bool
    retention_days: int = Field(..., ge=1, le=365)
    storage_budget_gb: int = Field(..., ge=1, le=500)
    store_max_severity: int = Field(..., ge=0, le=7)
    backup_on_change: bool = True


class MessageOut(BaseModel):
    id: int
    asset_id: int
    asset_name: Optional[str] = None
    received_at: datetime
    source_ip: str
    protocol: str
    facility: Optional[int] = None
    severity: int
    device_time: Optional[datetime] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    message: str


class MessagePage(BaseModel):
    items: List[MessageOut]
    next_before_id: Optional[int] = None


class ListenerStatus(BaseModel):
    enabled: bool
    listening: bool
    udp: bool
    tcp: bool
    port: Optional[int] = None
    published_port: int = 514
    error: Optional[str] = None
    updated_at: Optional[datetime] = None
    queue_dropped: int = 0


class AssetSource(BaseModel):
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    received: int
    dropped: int
    last_24h: int = 0
    last_hostname: Optional[str] = None


class UnknownSource(BaseModel):
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    dropped: int
    last_hostname: Optional[str] = None


class Overview(BaseModel):
    status: ListenerStatus
    settings: SyslogSettings
    last_24h: int
    by_severity_24h: List[int]          # index = severity 0..7
    stored: int
    assets: List[AssetSource]
    unknown: List[UnknownSource]


def _naive(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def listener_status(db: Session, now: Optional[datetime] = None) -> ListenerStatus:
    now = now or datetime.utcnow()
    row = db.get(SyslogStatus, 1)
    cfg = syslog_settings.get_settings(db)
    fresh = row is not None and row.updated_at is not None and now - row.updated_at <= STATUS_FRESH
    udp, tcp = (bool(row.udp), bool(row.tcp)) if fresh else (False, False)
    return ListenerStatus(enabled=cfg["enabled"], listening=udp or tcp, udp=udp, tcp=tcp,
                          port=row.port if row else app_settings.SYSLOG_PORT,
                          error=row.error if row and fresh else None,
                          updated_at=row.updated_at if row else None,
                          queue_dropped=int(row.queue_dropped or 0) if row else 0)


def _filtered(db: Session, asset_id, severity, q, since, until):
    query = db.query(SyslogMessage, Asset.asset_name).join(Asset, Asset.id == SyslogMessage.asset_id)
    if asset_id is not None:
        query = query.filter(SyslogMessage.asset_id == asset_id)
    if severity is not None:
        query = query.filter(SyslogMessage.severity <= severity)
    if since is not None:
        query = query.filter(SyslogMessage.received_at >= _naive(since))
    if until is not None:
        query = query.filter(SyslogMessage.received_at < _naive(until))
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.filter(or_(SyslogMessage.message.ilike(like, escape="\\"),
                                 SyslogMessage.app_name.ilike(like, escape="\\"),
                                 SyslogMessage.hostname.ilike(like, escape="\\")))
    return query


def _out(m: SyslogMessage, name: Optional[str]) -> MessageOut:
    return MessageOut(id=m.id, asset_id=m.asset_id, asset_name=name, received_at=m.received_at,
                      source_ip=m.source_ip, protocol=m.protocol, facility=m.facility, severity=m.severity,
                      device_time=m.device_time, hostname=m.hostname, app_name=m.app_name, message=m.message)


@router.get("/messages", response_model=MessagePage)
def list_messages(asset_id: Optional[int] = None,
                  severity: Optional[int] = Query(None, ge=0, le=7, description="this severity or more severe"),
                  q: Optional[str] = Query(None, max_length=200),
                  since: Optional[datetime] = None, until: Optional[datetime] = None,
                  before_id: Optional[int] = None, limit: int = Query(100, ge=1, le=500),
                  current_user: User = Depends(require_permission("noc", "read")),
                  db: Session = Depends(get_db)):
    """Newest first; pass the returned next_before_id to get the next page."""
    query = _filtered(db, asset_id, severity, q, since, until)
    if before_id is not None:
        query = query.filter(SyslogMessage.id < before_id)
    rows = query.order_by(SyslogMessage.id.desc()).limit(limit + 1).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return MessagePage(items=[_out(m, n) for m, n in rows], next_before_id=rows[-1][0].id if more else None)


@router.get("/messages/export.csv")
def export_messages(request: Request, asset_id: Optional[int] = None,
                    severity: Optional[int] = Query(None, ge=0, le=7),
                    q: Optional[str] = Query(None, max_length=200),
                    since: Optional[datetime] = None, until: Optional[datetime] = None,
                    current_user: User = Depends(require_permission("noc", "read")),
                    db: Session = Depends(get_db)):
    """The filtered messages as CSV (newest first, at most 50,000)."""
    from app.models.security_audit_log import log_action
    rows = _filtered(db, asset_id, severity, q, since, until).order_by(SyslogMessage.id.desc()).limit(EXPORT_MAX).all()
    out = io.StringIO()
    out.write("﻿")
    writer = csv.writer(out)
    writer.writerow(["received_at_utc", "asset", "source_ip", "protocol", "severity", "facility", "device_time",
                     "hostname", "app", "message"])
    for m, name in rows:
        writer.writerow([neutralize_formula("" if v is None else (v.isoformat() if isinstance(v, datetime) else v))
                         for v in (m.received_at, name, m.source_ip, m.protocol, SEVERITIES[m.severity],
                                   m.facility, m.device_time, m.hostname, m.app_name, m.message)])
    log_action(db, user_id=current_user.id, username=current_user.username, action="syslog.export", module="noc",
               ip_address=request.client.host if request.client else None,
               detail=f"Exported {len(rows)} syslog messages")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(out.getvalue().encode("utf-8"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="syslog-{stamp}.csv"'})


@router.get("/overview", response_model=Overview)
def overview(current_user: User = Depends(require_permission("noc", "read")), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    day = now - timedelta(hours=24)
    by_sev = [0] * 8
    for sev, n in (db.query(SyslogMessage.severity, func.count(SyslogMessage.id))
                   .filter(SyslogMessage.received_at >= day).group_by(SyslogMessage.severity)):
        if 0 <= sev <= 7:
            by_sev[sev] = n
    recent = dict(db.query(SyslogMessage.asset_id, func.count(SyslogMessage.id))
                  .filter(SyslogMessage.received_at >= day).group_by(SyslogMessage.asset_id).all())
    assets = [AssetSource(asset_id=a.id, asset_name=a.asset_name, ip_address=a.ip_address, source_ip=s.source_ip,
                          first_seen=s.first_seen, last_seen=s.last_seen, received=int(s.received or 0),
                          dropped=int(s.dropped or 0), last_24h=recent.get(a.id, 0), last_hostname=s.last_hostname)
              for s, a in (db.query(SyslogSource, Asset).join(Asset, Asset.id == SyslogSource.asset_id)
                           .order_by(SyslogSource.last_seen.desc()).limit(1000))]
    unknown = [UnknownSource(source_ip=s.source_ip, first_seen=s.first_seen, last_seen=s.last_seen,
                             dropped=int(s.dropped or 0), last_hostname=s.last_hostname)
               for s in (db.query(SyslogSource).filter(SyslogSource.asset_id.is_(None))
                         .order_by(SyslogSource.last_seen.desc()).limit(200))]
    # the planner's estimate (an exact count of a large table is slow); exact while the table is small
    # or not analysed yet
    stored = int(db.execute(text(
        "SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE relname = 'syslog_messages'")).scalar() or 0)
    if stored < 100000:
        stored = db.query(func.count(SyslogMessage.id)).scalar() or 0
    return Overview(status=listener_status(db, now), settings=SyslogSettings(**syslog_settings.get_settings(db)),
                    last_24h=sum(by_sev), by_severity_24h=by_sev, stored=stored, assets=assets, unknown=unknown)


@router.get("/settings", response_model=SyslogSettings)
def get_settings(current_user: User = Depends(require_permission("noc", "read")), db: Session = Depends(get_db)):
    return syslog_settings.get_settings(db)


@router.put("/settings", response_model=SyslogSettings)
def save_settings(body: SyslogSettings, request: Request, current_user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Turn the intake on or off, choose UDP/TCP, retention and storage. Takes effect within 15
    seconds, without a restart."""
    from app.models.security_audit_log import log_action
    if body.enabled and not (body.udp or body.tcp):
        raise HTTPException(status_code=400, detail="Choose UDP, TCP or both")
    before = syslog_settings.get_settings(db)
    saved = syslog_settings.save_settings(db, body.model_dump(), current_user.id)
    ip = request.client.host if request.client else None
    if saved["enabled"] != before["enabled"]:
        log_action(db, user_id=current_user.id, username=current_user.username, action="syslog.settings",
                   module="system_config", ip_address=ip,
                   detail=("Syslog intake turned on" if saved["enabled"] else "Syslog intake turned off"))
    if saved["backup_on_change"] != before["backup_on_change"]:
        log_action(db, user_id=current_user.id, username=current_user.username, action="syslog.settings",
                   module="system_config", ip_address=ip,
                   detail=("Backup on a reported configuration change turned on" if saved["backup_on_change"]
                           else "Backup on a reported configuration change turned off"))
    protocols = " + ".join(p for p, on in (("UDP", saved["udp"]), ("TCP", saved["tcp"])) if on) or "-"
    days, gb, level = saved["retention_days"], saved["storage_budget_gb"], SEVERITIES[saved["store_max_severity"]]
    log_action(db, user_id=current_user.id, username=current_user.username, action="syslog.settings",
               module="system_config", ip_address=ip,
               detail=f"Syslog intake settings: {protocols}, kept {days} days, at most {gb} GB, levels up to {level}")
    return saved


class AssignSource(BaseModel):
    """The asset an unknown syslog sender is: its address becomes one of the asset's addresses."""
    asset_id: int


@router.post("/sources/{source_ip}/assign")
def assign_source(source_ip: str, body: AssignSource, request: Request,
                  current_user: User = Depends(require_permission("asset_list", "write")),
                  db: Session = Depends(get_db)):
    """An unknown sender is one of the assets (it sends from another interface than its inventory
    address): the address is added to the asset's addresses, and its messages are kept from the next
    minute on (what it sent before was not stored)."""
    from app.models.security_audit_log import log_action
    from app.modules.assets import addresses
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    try:
        row = addresses.add(db, asset, source_ip, "Syslog sender", current_user.id)
    except addresses.AddressError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    source = db.get(SyslogSource, row.address)
    if source is not None:
        source.asset_id = asset.id
        db.commit()
    address = row.address
    log_action(db, user_id=current_user.id, username=current_user.username, action="syslog.source_assigned",
               module="asset_list", target_id=asset.id, ip_address=request.client.host if request.client else None,
               detail=f"Syslog sender {address} assigned to {asset.asset_name}")
    return addresses.as_dict(row)
