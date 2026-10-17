"""
LLDP / CDP neighbours (app/modules/noc/topology_discovery.py): what each monitored device reports is
cabled to its ports, the links it makes on the Topology map, adding a neighbour as an asset or its
link to the map, reading now, and the settings.
"""
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.dependencies import require_admin, require_permission
from app.models import User
from app.models.noc import TopologyDiscoverySource, TopologyNeighbor
from app.models.topology import TopologyLink
from app.modules.noc import oui, topology_discovery as td

router = APIRouter(prefix="/api/topology/discovery", tags=["Topology"])

# What a neighbour says it is (LLDP / CDP capabilities) -> an icon, most specific first.
_CAPABILITY_ICONS = [("phone", "ip_phone"), ("wlan_ap", "wireless"), ("router", "router"), ("bridge", "switch"),
                     ("station", "workstation")]


class Ref(BaseModel):
    id: int
    name: str


class NeighborOut(BaseModel):
    id: int
    protocol: str
    device: Ref
    local_port: str
    remote_name: Optional[str] = None
    remote_port: Optional[str] = None
    remote_port_desc: Optional[str] = None
    remote_mgmt_ip: Optional[str] = None
    remote_description: Optional[str] = None
    chassis_id: Optional[str] = None
    chassis_kind: Optional[str] = None
    capabilities: List[str] = []
    guess_icon: str = "other"
    vendor: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    current: bool = True                 # in the device's last read
    asset: Optional[Ref] = None
    link_id: Optional[int] = None
    link_missing: bool = False
    suppressed: bool = False


class SourceOut(BaseModel):
    asset_id: int
    name: str
    last_read_at: Optional[datetime] = None
    ok: bool
    error: Optional[str] = None
    lldp: bool
    cdp: bool
    neighbors: int


class Counts(BaseModel):
    linked: int
    unlinked: int
    unknown: int
    suppressed: int


class NeighborPage(BaseModel):
    items: List[NeighborOut]
    total: int
    counts: Counts
    sources: List[SourceOut]
    enabled: bool
    interval_minutes: int
    auto_links: bool
    last_read_at: Optional[datetime] = None
    found_links: int
    missing_links: int


class AddAssetBody(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=255)
    asset_type_id: int
    hostname: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)


class DiscoverySettings(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(60, ge=5, le=1440)
    auto_links: bool = True


def guess_icon(row: TopologyNeighbor) -> str:
    caps = row.capabilities or []
    for cap, icon in _CAPABILITY_ICONS:
        if cap in caps:
            return icon
    if row.chassis_kind == "mac" and row.chassis_id:
        return oui.guess(row.chassis_id, oui.vendor_of(row.chassis_id))[1]
    return "other"


def _vendor(row: TopologyNeighbor) -> Optional[str]:
    return oui.vendor_of(row.chassis_id) if row.chassis_kind == "mac" and row.chassis_id else None


def _filter(q, status: str):
    if status == "linked":
        return q.filter(TopologyNeighbor.link_id.isnot(None))
    if status == "unlinked":
        return q.filter(TopologyNeighbor.matched_asset_id.isnot(None), TopologyNeighbor.link_id.is_(None),
                        TopologyNeighbor.suppressed.is_(False))
    if status == "unknown":
        return q.filter(TopologyNeighbor.matched_asset_id.is_(None))
    if status == "suppressed":
        return q.filter(TopologyNeighbor.suppressed.is_(True))
    return q


@router.get("/neighbors", response_model=NeighborPage)
def list_neighbors(
    status: str = Query("all", pattern="^(all|linked|unlinked|unknown|suppressed)$"),
    q: Optional[str] = Query(None, max_length=100),
    asset_id: Optional[int] = Query(None, description="Only what this device reports, or reports about it"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_permission("topology", "read")),
    db: Session = Depends(get_db),
):
    """The neighbours every monitored device reports over LLDP / CDP, with the asset each one is and
    the Topology link it makes; counts per kind, the devices read, and the settings."""
    base = db.query(TopologyNeighbor)
    if asset_id is not None:
        base = base.filter(or_(TopologyNeighbor.asset_id == asset_id, TopologyNeighbor.matched_asset_id == asset_id))
    counts = Counts(**{s: _filter(base, s).count() for s in ("linked", "unlinked", "unknown", "suppressed")})
    query = _filter(base, status)
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(func.lower(TopologyNeighbor.remote_name).like(like),
                                 func.lower(TopologyNeighbor.local_port).like(like),
                                 func.lower(TopologyNeighbor.remote_port).like(like),
                                 TopologyNeighbor.remote_mgmt_ip.like(like),
                                 func.lower(TopologyNeighbor.chassis_id).like(like),
                                 func.lower(TopologyNeighbor.remote_description).like(like)))
    total = query.count()
    rows = (query.options(joinedload(TopologyNeighbor.asset), joinedload(TopologyNeighbor.matched_asset))
            .order_by(TopologyNeighbor.asset_id, TopologyNeighbor.local_port, TopologyNeighbor.id)
            .offset((page - 1) * page_size).limit(page_size).all())
    sources = (db.query(TopologyDiscoverySource).options(joinedload(TopologyDiscoverySource.asset))
               .order_by(TopologyDiscoverySource.asset_id).all())
    last_read = {s.asset_id: s.last_read_at for s in sources}
    missing = {lid for (lid,) in db.query(TopologyLink.id).filter(TopologyLink.missing_since.isnot(None))}
    items = [NeighborOut(
        id=r.id, protocol=r.protocol, device=Ref(id=r.asset_id, name=r.asset.asset_name if r.asset else f"#{r.asset_id}"),
        local_port=r.local_port, remote_name=r.remote_name, remote_port=r.remote_port,
        remote_port_desc=r.remote_port_desc, remote_mgmt_ip=r.remote_mgmt_ip,
        remote_description=r.remote_description, chassis_id=r.chassis_id, chassis_kind=r.chassis_kind,
        capabilities=r.capabilities or [], guess_icon=guess_icon(r), vendor=_vendor(r),
        first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at,
        current=last_read.get(r.asset_id) is None or r.last_seen_at >= last_read[r.asset_id],
        asset=Ref(id=r.matched_asset.id, name=r.matched_asset.asset_name) if r.matched_asset else None,
        link_id=r.link_id, link_missing=r.link_id in missing, suppressed=r.suppressed,
    ) for r in rows]
    cfg = td.get_settings(db)
    found = db.query(TopologyLink).filter(TopologyLink.origin != "manual").count()
    return NeighborPage(
        items=items, total=total, counts=counts,
        sources=[SourceOut(asset_id=s.asset_id, name=s.asset.asset_name if s.asset else f"#{s.asset_id}",
                           last_read_at=s.last_read_at, ok=s.ok, error=s.error, lldp=s.lldp, cdp=s.cdp,
                           neighbors=s.neighbors) for s in sources],
        enabled=cfg["enabled"], interval_minutes=cfg["interval_minutes"], auto_links=cfg["auto_links"],
        last_read_at=max((s.last_read_at for s in sources if s.last_read_at), default=None),
        found_links=found, missing_links=len(missing),
    )


@router.post("/read-now")
async def read_now(current_user: User = Depends(require_permission("topology", "write")),
                   db: Session = Depends(get_db)) -> Dict:
    """Read the LLDP and CDP tables of every monitored device now, instead of waiting for the interval."""
    return await td.sweep(db)


@router.post("/neighbors/{neighbor_id}/link")
def add_to_map(neighbor_id: int, current_user: User = Depends(require_permission("topology", "write")),
               db: Session = Depends(get_db)):
    """Draw the link this neighbour report describes (or bring back one removed from the map)."""
    from app.models.topology_log import log_topology_link_created
    row = db.get(TopologyNeighbor, neighbor_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such neighbour")
    if row.matched_asset_id is None:
        raise HTTPException(status_code=400, detail="This neighbour is not an asset yet")
    link = td.link_from_neighbor(db, row, current_user.id)
    log_topology_link_created(db, current_user.id, link.id, link.source_asset_id, link.destination_asset_id)
    return {"link_id": link.id}


@router.post("/neighbors/{neighbor_id}/asset")
def add_as_asset(neighbor_id: int, body: AddAssetBody,
                 current_user: User = Depends(require_permission("topology", "write")),
                 db: Session = Depends(get_db)):
    """Add a neighbour that is not an asset to the inventory (its management address, MAC and maker
    filled in), then its link to the map. Needs write access to the asset list too, and room in the
    license like any other new asset."""
    from app.models.asset_log import log_asset_created
    from app.models.asset_types import AssetType
    from app.modules.assets.schemas import AssetCreate
    from app.modules.assets.service import AssetService

    require_permission("ASSET_LIST", "write")(current_user=current_user, db=db)
    row = db.get(TopologyNeighbor, neighbor_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such neighbour")
    if row.matched_asset_id is not None:
        raise HTTPException(status_code=409, detail="This neighbour is already an asset")
    if db.get(AssetType, body.asset_type_id) is None:
        raise HTTPException(status_code=400, detail="Unknown asset type")
    mac = row.chassis_id if row.chassis_kind == "mac" else None
    try:
        data = AssetCreate(asset_name=body.asset_name.strip(), asset_type_id=body.asset_type_id,
                           hostname=(body.hostname or "").strip() or None, ip_address=row.remote_mgmt_ip,
                           mac_address=mac, manufacturer=(_vendor(row) or "")[:100] or None,
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
    td.rematch(db)
    db.refresh(row)
    if row.matched_asset_id is None:              # nothing to match on (no address, a different name)
        row.matched_asset_id = asset.id
        db.commit()
    link_id = None
    if td.get_settings(db)["auto_links"]:
        link_id = td.link_from_neighbor(db, row, current_user.id).id
    return {"asset_id": asset.id, "link_id": link_id}


@router.get("/settings", response_model=DiscoverySettings)
def get_discovery_settings(current_user: User = Depends(require_permission("topology", "read")),
                           db: Session = Depends(get_db)):
    return td.get_settings(db)


@router.put("/settings", response_model=DiscoverySettings)
def save_discovery_settings(body: DiscoverySettings, request: Request,
                            current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Turn reading the LLDP / CDP tables on or off, set how often, and whether found links go on the
    map by themselves (system administrators)."""
    from app.models.security_audit_log import log_action
    saved = td.save_settings(db, body.model_dump(), current_user.id)
    minutes = saved["interval_minutes"]
    log_action(db, user_id=current_user.id, username=current_user.username, action="topology.discovery_settings",
               module="system_config", ip_address=request.client.host if request.client else None,
               detail=("LLDP/CDP topology discovery turned off" if not saved["enabled"] else
                       f"LLDP/CDP topology discovery turned on, every {minutes} minutes, links added to the map automatically"
                       if saved["auto_links"] else
                       f"LLDP/CDP topology discovery turned on, every {minutes} minutes, links added by hand"))
    return saved
