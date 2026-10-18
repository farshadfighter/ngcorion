"""
Unknown devices (NOC): addresses the monitored routers and switches see that are no asset
(app/modules/noc/endpoints.py). List them, add one as an asset, ignore it, read the tables now,
and the discovery settings.
"""
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, aliased, joinedload

from app.core.database import get_db
from app.core.dependencies import require_admin, require_permission
from app.models import Asset, User
from app.models.noc import NetworkDiscoverySource, NetworkEndpoint
from app.modules.noc import endpoints

router = APIRouter(prefix="/api/noc/endpoints", tags=["NOC"])

NEW_HOURS = 24


class AssetRef(BaseModel):
    id: int
    name: str


class SeenBy(BaseModel):
    asset_id: int
    name: str
    port: Optional[str] = None
    vlan: Optional[int] = None


class EndpointOut(BaseModel):
    id: int
    mac: str
    ip: Optional[str] = None
    other_ips: List[str] = []
    vendor: Optional[str] = None
    private_mac: bool = False
    guess_kind: Optional[str] = None
    guess_icon: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    is_new: bool = False
    seen_by: Optional[SeenBy] = None
    seen_via: Optional[str] = None
    asset: Optional[AssetRef] = None
    state: str
    ignore_note: Optional[str] = None
    ignored_at: Optional[datetime] = None
    ignored_by: Optional[str] = None


class SourceOut(BaseModel):
    asset_id: int
    name: str
    last_read_at: Optional[datetime] = None
    ok: bool
    error: Optional[str] = None
    arp_entries: int
    mac_entries: int


class Counts(BaseModel):
    unknown: int
    new: int
    ignored: int
    known: int


class EndpointPage(BaseModel):
    items: List[EndpointOut]
    total: int
    counts: Counts
    sources: List[SourceOut]
    enabled: bool
    interval_minutes: int
    last_read_at: Optional[datetime] = None


class IgnoreBody(BaseModel):
    ids: List[int] = Field(default_factory=list, max_length=1000)
    note: Optional[str] = Field(None, max_length=255)


class AddAssetBody(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=255)
    asset_type_id: int
    hostname: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)


class DiscoverySettings(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(15, ge=5, le=1440)


def _out(r: NetworkEndpoint, now: datetime, users: dict) -> EndpointOut:
    seen = None
    if r.seen_by is not None:
        seen = SeenBy(asset_id=r.seen_by.id, name=r.seen_by.asset_name, port=r.seen_port, vlan=r.seen_vlan)
    return EndpointOut(
        id=r.id, mac=r.mac, ip=r.ip, other_ips=r.other_ips or [], vendor=r.vendor, private_mac=r.private_mac,
        guess_kind=r.guess_kind, guess_icon=r.guess_icon, first_seen_at=r.first_seen_at,
        last_seen_at=r.last_seen_at,
        is_new=r.matched_asset_id is None and not r.baseline and r.first_seen_at >= now - timedelta(hours=NEW_HOURS),
        seen_by=seen, seen_via=r.seen_via,
        asset=AssetRef(id=r.matched_asset.id, name=r.matched_asset.asset_name) if r.matched_asset else None,
        state=r.state, ignore_note=r.ignore_note, ignored_at=r.ignored_at, ignored_by=users.get(r.ignored_by),
    )


def _status_filter(q, status: str, now: datetime):
    unknown = (NetworkEndpoint.matched_asset_id.is_(None)) & (NetworkEndpoint.state == "open")
    if status == "unknown":
        return q.filter(unknown)
    if status == "new":
        return q.filter(unknown, NetworkEndpoint.baseline.is_(False),
                        NetworkEndpoint.first_seen_at >= now - timedelta(hours=NEW_HOURS))
    if status == "ignored":
        return q.filter(NetworkEndpoint.state == "ignored")
    if status == "known":
        return q.filter(NetworkEndpoint.matched_asset_id.isnot(None), NetworkEndpoint.state == "open")
    return q


@router.get("", response_model=EndpointPage)
def list_endpoints(
    status: str = Query("unknown", pattern="^(unknown|new|ignored|known|all)$"),
    q: Optional[str] = Query(None, max_length=100),
    id: Optional[int] = Query(None, description="Only this device (the alert links here)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_permission("noc", "read")),
    db: Session = Depends(get_db),
):
    """Addresses seen on the network: unknown (default), new in the last 24 hours, ignored, known or
    all (or the one device `id`); with the counts of each, the devices whose tables are read and when."""
    now = datetime.utcnow()
    base = db.query(NetworkEndpoint)
    counts = Counts(**{s: _status_filter(base, s, now).count() for s in ("unknown", "new", "ignored", "known")})
    query = _status_filter(base, status, now) if id is None else base.filter(NetworkEndpoint.id == id)
    if q:
        like = f"%{q.strip().lower()}%"
        seen_on = aliased(Asset)                # the switch or router it was seen on, by name
        query = query.outerjoin(seen_on, seen_on.id == NetworkEndpoint.seen_by_asset_id).filter(or_(
            func.lower(NetworkEndpoint.mac).like(like), NetworkEndpoint.ip.like(like),
            func.lower(NetworkEndpoint.vendor).like(like), func.lower(NetworkEndpoint.seen_port).like(like),
            func.lower(seen_on.asset_name).like(like)))
    total = query.count()
    rows = (query.options(joinedload(NetworkEndpoint.seen_by), joinedload(NetworkEndpoint.matched_asset))
            .order_by(NetworkEndpoint.first_seen_at.desc(), NetworkEndpoint.id.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    user_ids = {r.ignored_by for r in rows if r.ignored_by}
    users = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids))} if user_ids else {}
    sources = (db.query(NetworkDiscoverySource).options(joinedload(NetworkDiscoverySource.asset))
               .order_by(NetworkDiscoverySource.asset_id).all())
    cfg = endpoints.get_settings(db)
    last = max((s.last_read_at for s in sources if s.last_read_at), default=None)
    return EndpointPage(
        items=[_out(r, now, users) for r in rows], total=total, counts=counts,
        sources=[SourceOut(asset_id=s.asset_id, name=s.asset.asset_name if s.asset else f"#{s.asset_id}",
                           last_read_at=s.last_read_at, ok=s.ok, error=s.error, arp_entries=s.arp_entries,
                           mac_entries=s.mac_entries) for s in sources],
        enabled=cfg["enabled"], interval_minutes=cfg["interval_minutes"], last_read_at=last,
    )


@router.post("/read-now")
async def read_now(current_user: User = Depends(require_permission("noc", "write")),
                   db: Session = Depends(get_db)):
    """Read the ARP and MAC tables of every monitored device now, instead of waiting for the interval."""
    return await endpoints.sweep(db)


@router.post("/ignore")
def ignore(body: IgnoreBody, request: Request, current_user: User = Depends(require_permission("noc", "write")),
           db: Session = Depends(get_db)):
    """Ignore addresses (a known guest network, a lab): they leave the unknown list and raise no alert."""
    from app.models.security_audit_log import log_action
    rows = db.query(NetworkEndpoint).filter(NetworkEndpoint.id.in_(body.ids)).all() if body.ids else []
    if not rows:
        raise HTTPException(status_code=404, detail="No such device")
    note = (body.note or "").strip() or None
    now = datetime.utcnow()
    for r in rows:
        r.state, r.ignore_note, r.ignored_by, r.ignored_at = "ignored", note, current_user.id, now
    db.commit()
    ip = request.client.host if request.client else None
    for r in rows:
        mac = r.mac
        log_action(db, user_id=current_user.id, username=current_user.username, action="noc.endpoint_ignored",
                   module="noc", target_id=r.id, ip_address=ip, detail=f"Ignored the unknown device {mac}")
    return {"ignored": len(rows)}


@router.post("/{endpoint_id}/unignore")
def unignore(endpoint_id: int, request: Request, current_user: User = Depends(require_permission("noc", "write")),
             db: Session = Depends(get_db)):
    """Put an ignored address back on the unknown list."""
    from app.models.security_audit_log import log_action
    r = db.get(NetworkEndpoint, endpoint_id)
    if r is None:
        raise HTTPException(status_code=404, detail="No such device")
    r.state, r.ignore_note, r.ignored_by, r.ignored_at = "open", None, None, None
    db.commit()
    mac = r.mac
    log_action(db, user_id=current_user.id, username=current_user.username, action="noc.endpoint_unignored",
               module="noc", target_id=r.id, ip_address=request.client.host if request.client else None,
               detail=f"No longer ignoring the device {mac}")
    return {"ok": True}


@router.post("/{endpoint_id}/asset")
def add_as_asset(endpoint_id: int, body: AddAssetBody,
                 current_user: User = Depends(require_permission("noc", "write")),
                 db: Session = Depends(get_db)):
    """Add an unknown device to the inventory with its IP, MAC and manufacturer filled in. Needs
    write access to the asset list too, and room in the license like any other new asset."""
    from app.models.asset_log import log_asset_created
    from app.models.asset_types import AssetType
    from app.modules.assets.schemas import AssetCreate
    from app.modules.assets.service import AssetService

    require_permission("ASSET_LIST", "write")(current_user=current_user, db=db)
    r = db.get(NetworkEndpoint, endpoint_id)
    if r is None:
        raise HTTPException(status_code=404, detail="No such device")
    if r.matched_asset_id is not None:
        raise HTTPException(status_code=409, detail="This device is already an asset")
    if db.get(AssetType, body.asset_type_id) is None:
        raise HTTPException(status_code=400, detail="Unknown asset type")
    try:
        data = AssetCreate(asset_name=body.asset_name.strip(), asset_type_id=body.asset_type_id,
                           hostname=(body.hostname or "").strip() or None, ip_address=r.ip, mac_address=r.mac,
                           manufacturer=(r.vendor or "")[:100] or None,
                           description=(body.description or "").strip() or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    values = data.model_dump()
    values["user_id"] = current_user.id
    try:
        asset = AssetService.create_asset(db, values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_asset_created(db, current_user.id, asset.id, asset.asset_name, asset.ip_address)
    r.matched_asset_id = asset.id
    db.commit()
    endpoints.rematch(db)
    return {"asset_id": asset.id}


@router.get("/settings", response_model=DiscoverySettings)
def get_discovery_settings(current_user: User = Depends(require_permission("noc", "read")),
                           db: Session = Depends(get_db)):
    return endpoints.get_settings(db)


@router.put("/settings", response_model=DiscoverySettings)
def save_discovery_settings(body: DiscoverySettings, request: Request,
                            current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Turn reading the ARP / MAC tables on or off and set how often (system administrators)."""
    from app.models.security_audit_log import log_action
    saved = endpoints.save_settings(db, body.model_dump(), current_user.id)
    minutes = saved["interval_minutes"]
    log_action(db, user_id=current_user.id, username=current_user.username, action="noc.discovery_settings",
               module="system_config", ip_address=request.client.host if request.client else None,
               detail=(f"Unknown device discovery turned on, every {minutes} minutes" if saved["enabled"]
                       else "Unknown device discovery turned off"))
    return saved

