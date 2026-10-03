"""
Read side of the software inventory: the fleet's products, one asset's
inventory and its changes, and CPE suggestions for unidentified products.
"""
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models import Asset
from app.models.cve import CveCpeMatch
from app.models.software import (FULL_COLLECTORS, MAP_CPE, MAP_INTERNAL, SoftwareChange, SoftwareCollection,
                                 SoftwareItem, SoftwareProductMap)
from app.modules.cve import findings as cve_findings
from app.modules.software import catalog
from app.modules.software.identify import Resolved, load_maps, resolve

LISTED = ("known", "unknown", "internal", "distro")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class SoftwareError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _resolver(maps):
    cache: Dict[tuple, Resolved] = {}

    def get(it) -> Resolved:
        key = (it.kind, it.name, it.source_package, it.source, it.vkind, it.version)
        r = cache.get(key)
        if r is None:
            r = cache[key] = resolve(it, maps)
        return r
    return get


def _findings_by_asset_product(db: Session, asset_id: Optional[int] = None):
    """{(asset_id, vendor, product): [finding]} for findings from the inventory."""
    out = defaultdict(list)
    for f in cve_findings.compute(db, asset_id)["findings"]:
        if f["identity_source"] == "inventory":
            out[(f["asset_id"], f["vendor"], f["product_key"])].append(f)
    return out


def _cve_summary(found: List[dict]) -> Optional[dict]:
    if not found:
        return None
    ids = {f["cve_id"] for f in found}
    worst = max((f.get("severity") for f in found), key=lambda s: SEVERITY_RANK.get(s or "", 0))
    fixed = sorted({f["fixed_in"] for f in found if f.get("fixed_in")})
    return {"count": len(ids), "severity": worst, "kev": any(f.get("kev") for f in found),
            "top_priority": min(f["priority"] for f in found), "fixed_in": fixed[:3],
            "affected_versions": sorted({f["installed"] for f in found if f.get("installed")})}


# ── the fleet ─────────────────────────────────────────────────────────────

def products(db: Session, asset_ids: Optional[List[int]] = None) -> Dict:
    """The fleet's products; `asset_ids` limits it to some assets (reports)."""
    maps = load_maps(db)
    get = _resolver(maps)
    findings = _findings_by_asset_product(db)
    groups: Dict[tuple, dict] = {}
    package_count = 0
    q = db.query(SoftwareItem).filter(SoftwareItem.kind.notin_(("hotfix", "os")))
    if asset_ids is not None:
        q = q.filter(SoftwareItem.asset_id.in_(list(asset_ids) or [-1]))
    for it in q.all():
        package_count += 1
        r = get(it)
        if r.status not in LISTED:
            continue
        gkey = (r.status, r.label if r.status == "known" else r.key)
        g = groups.get(gkey)
        if g is None:
            g = groups[gkey] = {
                "key": r.key, "label": r.label, "status": r.status, "cpes": [f"{v}:{p}" for v, p in r.cpes],
                "mapped_by": r.mapped_by, "names": set(), "publishers": set(), "sources": set(), "origins": set(),
                "versions": defaultdict(set), "assets": set(), "nvd": False, "findings": [],
            }
        g["names"].add(it.name)
        if it.publisher:
            g["publishers"].add(it.publisher)
        g["sources"].add(it.source)
        if it.origin:
            g["origins"].add(it.origin)
        g["versions"][it.version or ""].add(it.asset_id)
        if it.asset_id not in g["assets"] and r.status == "known" and r.nvd:
            for v, p in r.cpes:
                g["findings"].extend(findings.get((it.asset_id, v, p), []))
        g["assets"].add(it.asset_id)
        g["nvd"] = g["nvd"] or r.nvd

    rows = []
    for g in groups.values():
        versions = sorted(({"version": v or None, "assets": len(a)} for v, a in g["versions"].items()),
                          key=lambda x: -x["assets"])
        cve = _cve_summary(g["findings"])
        rows.append({
            "key": g["key"], "label": g["label"], "status": g["status"], "cpes": g["cpes"],
            "mapped_by": g["mapped_by"], "names": sorted(g["names"])[:6], "name_count": len(g["names"]),
            "publisher": sorted(g["publishers"])[0] if g["publishers"] else None,
            "sources": sorted(g["sources"]), "origins": sorted(g["origins"])[:4],
            "versions": versions, "asset_count": len(g["assets"]), "nvd": g["nvd"], "cve": cve,
        })
    rows.sort(key=lambda r: (-(SEVERITY_RANK.get((r["cve"] or {}).get("severity"), 0)),
                             -((r["cve"] or {}).get("count") or 0), r["status"] != "unknown",
                             r["sources"] == ["distro"], r["label"].lower()))

    cq = db.query(SoftwareCollection).filter(SoftwareCollection.status == "ok")
    if asset_ids is not None:
        cq = cq.filter(SoftwareCollection.asset_id.in_(list(asset_ids) or [-1]))
        assets_total = len(set(asset_ids))
    else:
        assets_total = db.query(func.count(Asset.id)).scalar() or 0
    with_inventory = cq.with_entities(func.count(func.distinct(SoftwareCollection.asset_id))).scalar() or 0
    last = cq.with_entities(func.max(SoftwareCollection.collected_at)).scalar()
    counts = {
        "all": len(rows),
        "outside_distro": sum(1 for r in rows if any(s in ("third_party", "manual", "service", "firmware")
                                                     for s in r["sources"])),
        "distro": sum(1 for r in rows if "distro" in r["sources"]),
        "windows": sum(1 for r in rows if "windows" in r["sources"]),
        "vulnerable": sum(1 for r in rows if r["cve"]),
        "multi_version": sum(1 for r in rows if len(r["versions"]) > 1),
        "unidentified": sum(1 for r in rows if r["status"] == "unknown"),
    }
    return {
        "summary": {
            "assets_total": assets_total, "assets_with_inventory": with_inventory, "packages": package_count,
            "products": len(rows), "outside_distro": counts["outside_distro"],
            "vulnerable_products": counts["vulnerable"],
            "findings": sum((r["cve"] or {}).get("count", 0) for r in rows),
            "kev_products": sum(1 for r in rows if (r["cve"] or {}).get("kev")),
            "unidentified": counts["unidentified"], "last_collected_at": _iso(last),
            "catalog_size": catalog.catalog_size(),
        },
        "counts": counts,
        "items": rows,
    }


def product_assets(db: Session, key: str, status: str, label: Optional[str] = None) -> List[dict]:
    """Which assets run a product, with their versions."""
    maps = load_maps(db)
    get = _resolver(maps)
    out = defaultdict(list)
    names = {}
    for it in db.query(SoftwareItem).filter(SoftwareItem.kind.notin_(("hotfix", "os"))).all():
        r = get(it)
        if r.status != status or (status == "known" and r.label != label) or (status != "known" and r.key != key):
            continue
        out[it.asset_id].append({"name": it.name, "version": it.version, "source": it.source, "origin": it.origin})
    if out:
        for a in db.query(Asset).filter(Asset.id.in_(list(out))).all():
            names[a.id] = (a.asset_name, a.ip_address)
    return [{"asset_id": aid, "asset_name": names.get(aid, ("?", None))[0], "ip_address": names.get(aid, (None,) * 2)[1],
             "items": rows} for aid, rows in sorted(out.items(), key=lambda kv: names.get(kv[0], ("",))[0] or "")]


# ── one asset ─────────────────────────────────────────────────────────────

def asset_inventory(db: Session, asset_id: int) -> Dict:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise SoftwareError("Asset not found", 404)
    maps = load_maps(db)
    get = _resolver(maps)
    findings = _findings_by_asset_product(db, asset_id)
    items = []
    for it in (db.query(SoftwareItem).filter(SoftwareItem.asset_id == asset_id)
               .order_by(SoftwareItem.kind, SoftwareItem.name).all()):
        r = get(it)
        found = []
        if r.status == "known" and r.nvd:
            for v, p in r.cpes:
                found.extend(findings.get((asset_id, v, p), []))
        items.append({
            "id": it.id, "name": it.name, "version": it.version, "arch": it.arch, "kind": it.kind,
            "source": it.source, "origin": it.origin, "publisher": it.publisher, "collector": it.collector,
            "status": r.status, "label": r.label, "match_key": r.key, "cpes": [f"{v}:{p}" for v, p in r.cpes],
            "nvd": r.nvd, "cve": _cve_summary(found), "first_seen": _iso(it.first_seen),
        })
    collections = (db.query(SoftwareCollection).filter(SoftwareCollection.asset_id == asset_id)
                   .order_by(SoftwareCollection.collected_at.desc()).limit(30).all())
    latest = {}
    for c in collections:
        latest.setdefault(c.collector, c)
    full = next((latest[c] for c in FULL_COLLECTORS if c in latest), None)
    by_source = defaultdict(int)
    for i in items:
        if i["kind"] in ("package", "program"):
            by_source[i["source"]] += 1
    return {
        "asset": {"id": asset.id, "name": asset.asset_name, "ip_address": asset.ip_address,
                  "os_name": asset.os_name, "os_version": asset.os_version},
        "summary": {
            "packages": sum(1 for i in items if i["kind"] in ("package", "program")),
            "hotfixes": sum(1 for i in items if i["kind"] == "hotfix"),
            "by_source": dict(by_source),
            "outside_distro": sum(v for k, v in by_source.items() if k != "distro"),
            "vulnerable": sum(1 for i in items if i["cve"]),
            "unidentified": sum(1 for i in items if i["status"] == "unknown"),
            "last": _collection(full) if full else None,
            "previous_at": _iso(next((c.collected_at for c in collections
                                      if full and c.collector == full.collector and c.id != full.id
                                      and c.status == "ok"), None)),
        },
        "items": items,
        "collections": [_collection(c) for c in collections],
    }


def assets_overview(db: Session) -> List[dict]:
    """One line per asset that has software: what the Software tab of the
    asset list shows."""
    rows: Dict[int, dict] = {}

    def row(aid):
        r = rows.get(aid)
        if r is None:
            r = rows[aid] = {"asset_id": aid, "packages": 0, "hotfixes": 0, "outside_distro": 0, "unidentified": 0,
                             "cves": 0, "kev": False, "os": None, "firmware": None, "last": None, "last_failed": None}
        return r

    q = (db.query(SoftwareItem.asset_id, SoftwareItem.kind, SoftwareItem.source, func.count(SoftwareItem.id))
         .group_by(SoftwareItem.asset_id, SoftwareItem.kind, SoftwareItem.source))
    for aid, kind, source, n in q.all():
        r = row(aid)
        if kind in ("package", "program"):
            r["packages"] += n
            if source != "distro":
                r["outside_distro"] += n
        elif kind == "hotfix":
            r["hotfixes"] += n
    maps = load_maps(db)
    get = _resolver(maps)
    for it in db.query(SoftwareItem).filter(SoftwareItem.source != "distro",
                                            SoftwareItem.kind.notin_(("hotfix",))).all():
        r = get(it)
        if r.status == "unknown":
            row(it.asset_id)["unidentified"] += 1
        if it.kind == "os":
            row(it.asset_id)["os"] = f"{it.name} {it.version or ''}".strip()
        if it.kind == "firmware":
            row(it.asset_id)["firmware"] = f"{it.name} {it.version or ''}".strip()
    found = defaultdict(set)
    for f in cve_findings.compute(db)["findings"]:
        if f["identity_source"] == "inventory":
            found[f["asset_id"]].add(f["cve_id"])
            if f.get("kev"):
                row(f["asset_id"])["kev"] = True
    for aid, ids in found.items():
        row(aid)["cves"] = len(ids)
    # newest first: the latest good collection, and a failure newer than it
    for c in db.query(SoftwareCollection).order_by(SoftwareCollection.collected_at.desc()).limit(5000).all():
        r = row(c.asset_id)
        if r["last"] is not None:
            continue
        if c.status == "ok":
            r["last"] = _collection(c)
        elif r["last_failed"] is None:
            r["last_failed"] = _collection(c)
    return list(rows.values())


def _collection(c: SoftwareCollection) -> Dict:
    return {"id": c.id, "collector": c.collector, "trigger": c.trigger, "audit_session_id": c.audit_session_id,
            "collected_at": _iso(c.collected_at), "status": c.status, "error": c.error, "items": c.item_count,
            "added": c.added, "removed": c.removed, "updated": c.updated, "summary": c.summary}


def changes(db: Session, asset_id: int, collection_id: Optional[int] = None, limit: int = 300) -> List[dict]:
    q = db.query(SoftwareChange).filter(SoftwareChange.asset_id == asset_id)
    if collection_id:
        q = q.filter(SoftwareChange.collection_id == collection_id)
    rows = q.order_by(SoftwareChange.at.desc(), SoftwareChange.change, SoftwareChange.name).limit(limit).all()
    return [{"id": r.id, "collection_id": r.collection_id, "change": r.change, "kind": r.kind, "name": r.name,
             "old_version": r.old_version, "new_version": r.new_version, "source": r.source, "origin": r.origin,
             "at": _iso(r.at)} for r in rows]


# ── identifying products ──────────────────────────────────────────────────

def suggest(db: Session, text: str, limit: int = 12) -> List[dict]:
    """vendor:product pairs from the local CVE database that look like `text`,
    with how many CVEs each has."""
    words = [w for w in re.split(r"[^a-z0-9+.]+", (text or "").lower()) if len(w) >= 2][:4]
    if not words:
        return []
    conds = [or_(CveCpeMatch.product.ilike(f"%{w}%"), CveCpeMatch.vendor.ilike(f"%{w}%")) for w in words]
    q = (db.query(CveCpeMatch.vendor, CveCpeMatch.product, func.count(func.distinct(CveCpeMatch.cve_id)))
         .filter(*conds).group_by(CveCpeMatch.vendor, CveCpeMatch.product)
         .order_by(func.count(func.distinct(CveCpeMatch.cve_id)).desc()).limit(limit))
    out = [{"vendor": v, "product": p, "cves": n} for v, p, n in q.all()]
    if not out and len(words) > 1:
        # all words at once found nothing: any of them
        q = (db.query(CveCpeMatch.vendor, CveCpeMatch.product, func.count(func.distinct(CveCpeMatch.cve_id)))
             .filter(or_(*[CveCpeMatch.product.ilike(f"%{w}%") for w in words]))
             .group_by(CveCpeMatch.vendor, CveCpeMatch.product)
             .order_by(func.count(func.distinct(CveCpeMatch.cve_id)).desc()).limit(limit))
        out = [{"vendor": v, "product": p, "cves": n} for v, p, n in q.all()]
    return out


_CPE_PART = re.compile(r"^[a-z0-9_.\-\\+!~/()%]+$")


def save_map(db: Session, match_key: str, status: str, vendor: Optional[str], product: Optional[str],
             label: Optional[str], user_id: Optional[int]) -> SoftwareProductMap:
    key = (match_key or "").strip().lower()
    if not key or len(key) > 300:
        raise SoftwareError("Unknown product")
    if status not in (MAP_CPE, MAP_INTERNAL):
        raise SoftwareError("Unknown choice")
    if status == MAP_CPE:
        vendor, product = (vendor or "").strip().lower(), (product or "").strip().lower()
        if not vendor or not product or not _CPE_PART.match(vendor) or not _CPE_PART.match(product):
            raise SoftwareError("Enter the vendor and product the way NVD writes them, e.g. vendor:product")
    else:
        vendor = product = None
    row = db.query(SoftwareProductMap).filter(SoftwareProductMap.match_key == key).first()
    if row is None:
        row = SoftwareProductMap(match_key=key, created_by=user_id)
        db.add(row)
    row.status, row.vendor, row.product = status, vendor, product
    row.label = (label or "").strip()[:200] or None
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def maps_list(db: Session) -> List[dict]:
    return [{"id": m.id, "match_key": m.match_key, "status": m.status, "vendor": m.vendor, "product": m.product,
             "label": m.label, "updated_at": _iso(m.updated_at)}
            for m in db.query(SoftwareProductMap).order_by(SoftwareProductMap.match_key).all()]
