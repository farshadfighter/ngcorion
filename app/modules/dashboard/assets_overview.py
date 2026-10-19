"""
The assets overview: what the inventory holds, how well it is described, and how much of it the other
modules cover. Read with the asset list permission; the coverage figures of other modules and the
unknown devices only with the permission of their own module.

  totals       assets by status, added in the last 7 and 30 days, and the license use.
  quality      assets missing an owner, an IP address, an operating system, a location, or a network
               zone chosen for their risk score (the risk module then assumes one).
  coverage     audited in the last 90 days, recent configuration backup, SNMP monitoring, and known
               end-of-life status (the software of the asset was matched to the catalog).
  breakdowns   by type, vendor, operating system and zone, each value with the filter that lists it.
  newest       the assets added last.
  unknown      devices NOC saw on the network that are not assets (open, and first seen this week).
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models import Asset, User
from app.models.asset_types import AssetType
from app.models.noc import NetworkEndpoint
from app.models.risk import AssetRiskProfile, RiskZone
from app.modules.dashboard.overview import coverage
from app.modules.reports.service import can_read

TOP = 8
NEWEST = 6

# Missing details: key -> (filter on Asset, link to the asset list showing them).
_EMPTY = lambda col: or_(col.is_(None), func.trim(col) == "")  # noqa: E731
QUALITY = (
    ("no_owner", lambda: Asset.owner_id.is_(None), "/assets/inventory?missing=owner"),
    ("no_ip", lambda: _EMPTY(Asset.ip_address), "/assets/inventory?missing=ip"),
    ("no_os", lambda: _EMPTY(Asset.os_name), "/assets/inventory?missing=os"),
    ("no_location", lambda: Asset.location_id.is_(None), "/assets/inventory?missing=location"),
)


def _rows(pairs, link, limit=TOP) -> List[Dict]:
    """[(key, label, count)] -> the biggest `limit`, then the rest as one "other" row (key None)."""
    pairs = sorted(pairs, key=lambda p: (-p[2], str(p[1]).lower()))
    out = [{"key": k, "name": name, "count": int(c), "link": link(k) if k is not None else None}
           for k, name, c in pairs[:limit]]
    rest = sum(c for _, _, c in pairs[limit:])
    if rest:
        out.append({"key": None, "name": None, "count": int(rest), "link": None, "other": True})
    return out


def _merged(rows) -> List[tuple]:
    """(text, count) rows with surrounding spaces ignored and empty text as None."""
    out: Dict[Optional[str], int] = {}
    for value, count in rows:
        key = (value or "").strip() or None
        out[key] = out.get(key, 0) + count
    return list(out.items())


def breakdowns(db: Session) -> Dict:
    from urllib.parse import quote
    types = (db.query(Asset.asset_type_id, AssetType.type_name, func.count(Asset.id))
             .outerjoin(AssetType, AssetType.id == Asset.asset_type_id)
             .group_by(Asset.asset_type_id, AssetType.type_name).all())
    vendors = _merged(db.query(Asset.manufacturer, func.count(Asset.id)).group_by(Asset.manufacturer))
    systems = _merged(db.query(Asset.os_name, func.count(Asset.id)).group_by(Asset.os_name))
    zones = (db.query(RiskZone.id, RiskZone.name, func.count(Asset.id))
             .select_from(Asset)
             .outerjoin(AssetRiskProfile, AssetRiskProfile.asset_id == Asset.id)
             .outerjoin(RiskZone, RiskZone.id == AssetRiskProfile.zone_id)
             .group_by(RiskZone.id, RiskZone.name).all())
    return {
        "by_type": _rows([(i, n, c) for i, n, c in types if i is not None],
                         lambda k: f"/assets/inventory?type={k}"),
        "by_vendor": _rows([(v, v, c) for v, c in vendors if v],
                           lambda k: f"/assets/inventory?vendor={quote(k)}"),
        "by_os": _rows([(o, o, c) for o, c in systems if o],
                       lambda k: f"/assets/inventory?os={quote(k)}"),
        # zones are set on the risk pages, so the link goes there
        "by_zone": _rows([(i, n, c) for i, n, c in zones if i is not None], lambda k: "/risk/assets"),
        "unclassified": {
            "type": int(sum(c for i, _, c in types if i is None)),
            "vendor": int(sum(c for v, c in vendors if not v)),
            "os": int(sum(c for o, c in systems if not o)),
        },
    }


def quality(db: Session, user: User) -> List[Dict]:
    out = [{"key": key, "count": int(db.query(func.count(Asset.id)).filter(cond()).scalar() or 0), "link": link}
           for key, cond, link in QUALITY]
    if can_read(db, user, "risk"):
        # no profile, or a zone the risk module filled in by default
        unset = (db.query(func.count(Asset.id))
                 .outerjoin(AssetRiskProfile, AssetRiskProfile.asset_id == Asset.id)
                 .filter(or_(AssetRiskProfile.id.is_(None), AssetRiskProfile.zone_id.is_(None),
                             AssetRiskProfile.zone_is_default.is_(True))).scalar())
        out.append({"key": "no_zone", "count": int(unset or 0), "link": "/risk/assets"})
    return out


def overview(db: Session, user: User, now: Optional[datetime] = None) -> Dict:
    from app.core.asset_entitlement import usage
    now = now or datetime.utcnow()
    total = int(db.query(func.count(Asset.id)).scalar() or 0)
    by_status = {(s.value if hasattr(s, "value") else str(s)): int(c)
                 for s, c in db.query(Asset.status, func.count(Asset.id)).group_by(Asset.status)}

    cover = coverage(db, user, now, total)
    from app.modules.eol import service as eol
    existing = {i for (i,) in db.query(Asset.id)}
    comps = [c for c in eol.components(db, today=now.date()) if c.asset_id in existing]
    known = {c.asset_id for c in comps if c.status != "unknown"}   # matched to the catalog
    cover.append({"key": "eol_known", "covered": len(known), "total": total,
                  "link": "/assets/software/lifecycle"})

    newest = (db.query(Asset, AssetType.type_name).outerjoin(AssetType, AssetType.id == Asset.asset_type_id)
              .order_by(Asset.created_at.desc(), Asset.id.desc()).limit(NEWEST).all())

    unknown = None
    if can_read(db, user, "noc"):
        q = db.query(func.count(NetworkEndpoint.id)).filter(NetworkEndpoint.matched_asset_id.is_(None),
                                                             NetworkEndpoint.state == "open")
        unknown = {"open": int(q.scalar() or 0),
                   "new_7d": int(q.filter(NetworkEndpoint.first_seen_at >= now - timedelta(days=7)).scalar() or 0),
                   "link": "/noc/unknown-devices"}

    return {
        "totals": {
            "total": total,
            "by_status": by_status,
            "new_7d": int(db.query(func.count(Asset.id)).filter(Asset.created_at >= now - timedelta(days=7)).scalar()),
            "new_30d": int(db.query(func.count(Asset.id)).filter(Asset.created_at >= now - timedelta(days=30)).scalar()),
        },
        "license": usage(db),
        "quality": quality(db, user),
        "coverage": cover,
        **breakdowns(db),
        "newest": [{"id": a.id, "name": a.asset_name, "ip_address": a.ip_address, "type": t,
                    "created_at": a.created_at.isoformat() + "Z" if a.created_at else None} for a, t in newest],
        "unknown_devices": unknown,
    }
