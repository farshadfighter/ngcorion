"""
Which assets a report covers: all of them, or those of some asset types,
sites, owners, risk zones, or a hand-picked list. One filter at a time, as
in the builder.
"""
from typing import Dict, List

from sqlalchemy.orm import Session, joinedload

from app.models import Asset
from app.models.asset_locations import AssetLocation
from app.models.asset_owners import AssetOwner
from app.models.asset_types import AssetType
from app.models.risk import AssetRiskProfile, RiskZone

MODES = ("all", "types", "sites", "owners", "zones", "assets")


class ScopeError(ValueError):
    pass


def normalize(scope: Dict) -> Dict:
    scope = dict(scope or {})
    mode = scope.get("mode") or "all"
    if mode not in MODES:
        raise ScopeError("Unknown asset filter")
    values = scope.get("values") or []
    if mode != "all" and not values:
        raise ScopeError("Choose at least one item for the asset filter")
    if mode != "sites":
        try:
            values = [int(v) for v in values]
        except (TypeError, ValueError) as exc:
            raise ScopeError("Unknown asset filter") from exc
    else:
        values = [str(v) for v in values]
    return {"mode": mode, "values": values}


def assets(db: Session, scope: Dict) -> List[Asset]:
    scope = normalize(scope)
    q = db.query(Asset).options(joinedload(Asset.asset_type), joinedload(Asset.location))
    mode, values = scope["mode"], scope["values"]
    if mode == "types":
        q = q.filter(Asset.asset_type_id.in_(values))
    elif mode == "sites":
        q = q.join(AssetLocation, Asset.location_id == AssetLocation.id).filter(AssetLocation.site_name.in_(values))
    elif mode == "owners":
        q = q.filter(Asset.owner_id.in_(values))
    elif mode == "zones":
        q = q.join(AssetRiskProfile, AssetRiskProfile.asset_id == Asset.id).filter(AssetRiskProfile.zone_id.in_(values))
    elif mode == "assets":
        q = q.filter(Asset.id.in_(values))
    return q.order_by(Asset.asset_name).all()


def describe(db: Session, scope: Dict, count: int, tr) -> str:
    """"15 assets" or "Asset type: Firewall, Switch · 6 assets"."""
    scope = normalize(scope)
    n = tr("{count} assets", count=count) if count != 1 else tr("1 asset")
    mode, values = scope["mode"], scope["values"]
    if mode == "all":
        return n
    if mode == "types":
        names = [r[0] for r in db.query(AssetType.type_name).filter(AssetType.id.in_(values)).all()]
        label = tr("Asset type")
    elif mode == "sites":
        names, label = values, tr("Site")
    elif mode == "owners":
        names = [r[0] for r in db.query(AssetOwner.full_name).filter(AssetOwner.id.in_(values)).all()]
        label = tr("Owner")
    elif mode == "zones":
        names = [r[0] for r in db.query(RiskZone.name).filter(RiskZone.id.in_(values)).all()]
        label = tr("Zone")
    else:
        return tr("Selected assets") + " · " + n
    shown = "، ".join(names[:4]) if tr.lang == "fa" else ", ".join(names[:4])
    if len(names) > 4:
        shown += " …"
    return f"{label}: {shown} · {n}"


def options(db: Session) -> Dict:
    """What the builder offers in each filter."""
    from sqlalchemy import func
    sites = [r[0] for r in db.query(AssetLocation.site_name).filter(AssetLocation.site_name.isnot(None))
             .distinct().order_by(AssetLocation.site_name).all() if r[0]]
    return {
        "total": db.query(func.count(Asset.id)).scalar() or 0,
        "types": [{"id": t.id, "name": t.type_name} for t in db.query(AssetType).order_by(AssetType.type_name)],
        "sites": [{"id": s, "name": s} for s in sites],
        "owners": [{"id": o.id, "name": o.full_name} for o in db.query(AssetOwner).order_by(AssetOwner.full_name)],
        "zones": [{"id": z.id, "name": z.name} for z in db.query(RiskZone).order_by(RiskZone.name)],
        "assets": [{"id": a.id, "name": a.asset_name, "ip": a.ip_address}
                   for a in db.query(Asset).order_by(Asset.asset_name)],
    }
