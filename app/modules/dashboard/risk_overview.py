"""
The risk overview: how much risk there is, what builds it, where it sits and where it is heading.
Read with the risk permission; everything comes from asset_risk_scores and asset_risk_history.

  totals      scored assets, the average score, assets per level, incomplete ones and those with
              exploited (KEV) vulnerabilities.
  factors     the average contribution of each of the seven factors to the scores, and its share of
              the average score: what builds the risk across the estate.
  matrix      assets per zone and level, each cell a filter of the risk list.
  trend       90 days of the average score and of the critical and high counts, one point every 5 days,
              each point the latest score of every asset at that moment.
  incomplete  why scores are incomplete (never audited, no port scan, no zone, ...) with the page that
              fixes each reason, and the first incomplete assets.
  top_assets  the ten riskiest assets with their main factor (as on the dashboard).
"""
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.models import Asset, User
from app.models.risk import AssetRiskScore
from app.modules.dashboard.overview import FACTORS, _points, top_assets

LEVELS = ("critical", "high", "medium", "low", "informational")
INCOMPLETE_SHOWN = 10

# Why a score is incomplete (app/modules/risk/service.py) -> the page that fixes it.
REASON_LINKS = {
    "missing_audit": "/assets/groups",
    "missing_port_scan": "/assets/discovery",
    "missing_zone": "/risk/assets?incomplete=1",
    "missing_criticality": "/risk/assets?incomplete=1",
    "missing_asset_risk": "/assets/inventory",
}


def _f(v) -> float:
    return float(v) if v is not None else 0.0


def totals(db: Session) -> Dict:
    count, avg, incomplete, kev = db.query(
        func.count(AssetRiskScore.id), func.avg(AssetRiskScore.final_risk_score),
        func.count(AssetRiskScore.id).filter(AssetRiskScore.incomplete_data.is_(True)),
        func.count(AssetRiskScore.id).filter(AssetRiskScore.cve_kev_count > 0),
    ).one()
    levels = dict(db.query(AssetRiskScore.risk_level, func.count(AssetRiskScore.id))
                  .group_by(AssetRiskScore.risk_level).all())
    return {"scored": int(count), "average": round(_f(avg), 1) if count else None,
            "by_level": {lv: int(levels.get(lv, 0)) for lv in LEVELS},
            "incomplete": int(incomplete), "kev_assets": int(kev)}


def factors(db: Session) -> List[Dict]:
    avgs = db.query(*[func.avg(func.coalesce(getattr(AssetRiskScore, col), 0)) for _, col in FACTORS]).one()
    values = [_f(v) for v in avgs]
    whole = sum(values)
    return [{"key": key, "average": round(v, 1), "share": round(100 * v / whole) if whole else 0}
            for (key, _), v in zip(FACTORS, values)]


def matrix(db: Session) -> List[Dict]:
    """[{zone_id, zone_name, counts: {level: n}, total}], biggest zone first; no zone last."""
    rows: Dict[Optional[int], Dict] = {}
    for zone_id, zone_name, level, n in (db.query(AssetRiskScore.zone_id, AssetRiskScore.zone_name,
                                                  AssetRiskScore.risk_level, func.count(AssetRiskScore.id))
                                         .group_by(AssetRiskScore.zone_id, AssetRiskScore.zone_name,
                                                   AssetRiskScore.risk_level)):
        r = rows.setdefault(zone_id, {"zone_id": zone_id, "zone_name": zone_name if zone_id else None,
                                      "counts": {lv: 0 for lv in LEVELS}, "total": 0})
        if level in r["counts"]:
            r["counts"][level] += int(n)
        r["total"] += int(n)
    return sorted(rows.values(), key=lambda r: (r["zone_id"] is None, -r["total"], str(r["zone_name"])))


_TREND = text("""
    SELECT p.t AS at, ROUND(AVG(h.risk_score)::numeric, 1) AS value, COUNT(*) AS assets,
           COUNT(*) FILTER (WHERE h.risk_level = 'critical') AS critical,
           COUNT(*) FILTER (WHERE h.risk_level = 'high') AS high
    FROM unnest(CAST(:points AS timestamp[])) AS p(t)
    JOIN LATERAL (
        SELECT DISTINCT ON (asset_id) risk_score, risk_level
        FROM asset_risk_history
        WHERE calculated_at <= p.t
        ORDER BY asset_id, calculated_at DESC, id DESC
    ) h ON TRUE
    GROUP BY p.t
""")


def trend(db: Session, now: datetime) -> List[Dict]:
    points = _points(now)
    found = {r["at"]: r for r in db.execute(_TREND, {"points": points}).mappings()}
    return [{"at": p.isoformat() + "Z", "value": float(found[p]["value"]), "assets": int(found[p]["assets"]),
             "critical": int(found[p]["critical"]), "high": int(found[p]["high"])}
            for p in points if p in found]


def incomplete(db: Session) -> Dict:
    rows = (db.query(AssetRiskScore, Asset).join(Asset, Asset.id == AssetRiskScore.asset_id)
            .filter(AssetRiskScore.incomplete_data.is_(True))
            .order_by(AssetRiskScore.final_risk_score.desc(), Asset.asset_name).all())
    reasons: Dict[str, int] = {}
    for score, _ in rows:
        for r in score.incomplete_reasons_json or []:
            reasons[r] = reasons.get(r, 0) + 1
    return {
        "total": len(rows),
        "reasons": [{"key": k, "count": n, "link": REASON_LINKS.get(k, "/risk/assets?incomplete=1")}
                    for k, n in sorted(reasons.items(), key=lambda kv: -kv[1])],
        "assets": [{"asset_id": a.id, "asset_name": a.asset_name, "ip_address": a.ip_address,
                    "reasons": list(s.incomplete_reasons_json or [])} for s, a in rows[:INCOMPLETE_SHOWN]],
    }


def overview(db: Session, user: User, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    return {
        "totals": totals(db),
        "factors": factors(db),
        "matrix": matrix(db),
        "trend": trend(db, now),
        "incomplete": incomplete(db),
        "top_assets": top_assets(db, user),
    }
