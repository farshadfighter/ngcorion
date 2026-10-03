"""
Asset ↔ CVE findings, computed at read time from the local database.

For every asset: its products (cpe.identities_for) → the CVE criteria for
those vendor/products → keep the ones whose version range contains the
asset's version. One query per table for the whole inventory.

Priority, so the list reads "fix this first":
  P1  in CISA KEV - exploited in the wild
  P2  CVSS >= 9, or EPSS >= 0.5
  P3  CVSS >= 7, or EPSS >= 0.1
  P4  everything else
"""
from collections import defaultdict
from typing import Dict, List, Optional

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session, joinedload

from app.models import Asset
from app.models.cve import AssetSoftware, CveCpeMatch, CveEntry
from app.modules.cve import versions
from app.modules.cve.cpe import identities_for

SEVERITIES = ("critical", "high", "medium", "low")


def _inventory(db: Session, asset_id: Optional[int] = None):
    """Per asset: the inventory's NVD identities, and which assets have a
    complete package list (app/modules/software)."""
    from sqlalchemy import or_
    from app.models.software import FULL_COLLECTORS, NVD_SOURCES, SoftwareCollection, SoftwareItem
    from app.modules.software.identify import load_maps, nvd_identities
    # Distribution packages are not matched in phase 1: leave them in the table.
    q = db.query(SoftwareItem).filter(or_(SoftwareItem.source.in_(NVD_SOURCES), SoftwareItem.kind == "os"),
                                      SoftwareItem.kind != "hotfix")
    fq = db.query(SoftwareCollection.asset_id).filter(SoftwareCollection.status == "ok",
                                                      SoftwareCollection.collector.in_(FULL_COLLECTORS))
    if asset_id is not None:
        q = q.filter(SoftwareItem.asset_id == asset_id)
        fq = fq.filter(SoftwareCollection.asset_id == asset_id)
    items = defaultdict(list)
    for it in q.all():
        items[it.asset_id].append(it)
    maps = load_maps(db) if items else {}
    return ({aid: nvd_identities(rows, maps) for aid, rows in items.items()},
            {r[0] for r in fq.distinct().all()})


def priority(entry: CveEntry) -> int:
    score = entry.cvss_score or 0
    epss = entry.epss or 0
    if entry.kev:
        return 1
    if score >= 9 or epss >= 0.5:
        return 2
    if score >= 7 or epss >= 0.1:
        return 3
    return 4


def _fixed_in(m: CveCpeMatch) -> Optional[str]:
    if m.end_excl:
        return m.end_excl
    if m.end_incl:
        return f"after {m.end_incl}"
    return None


def compute(db: Session, asset_id: Optional[int] = None) -> Dict:
    q = db.query(Asset).options(joinedload(Asset.asset_type))
    if asset_id is not None:
        q = q.filter(Asset.id == asset_id)
    assets = q.order_by(Asset.asset_name).all()

    software = defaultdict(list)
    sq = db.query(AssetSoftware)
    if asset_id is not None:
        sq = sq.filter(AssetSoftware.asset_id == asset_id)
    for s in sq.all():
        software[s.asset_id].append(s)

    inventory, full = _inventory(db, asset_id)
    per_asset = {a.id: identities_for(a, software[a.id], inventory.get(a.id, ()), a.id in full) for a in assets}
    pairs = {(i.vendor, i.product) for ids in per_asset.values() for i in ids}

    by_product = defaultdict(list)
    if pairs:
        pair_list = list(pairs)
        for k in range(0, len(pair_list), 500):
            chunk = pair_list[k:k + 500]
            for m in db.scalars(select(CveCpeMatch).where(
                    tuple_(CveCpeMatch.vendor, CveCpeMatch.product).in_(chunk))):
                by_product[(m.vendor, m.product)].append(m)

    raw = []  # (asset, identity, match)
    for a in assets:
        seen = set()
        for ident in per_asset[a.id]:
            for m in by_product.get((ident.vendor, ident.product), ()):
                if m.cve_id in seen:
                    continue
                if versions.matches(ident.version, exact=m.version, start_incl=m.start_incl,
                                    start_excl=m.start_excl, end_incl=m.end_incl, end_excl=m.end_excl):
                    seen.add(m.cve_id)
                    raw.append((a, ident, m))

    cve_ids = list({m.cve_id for _, _, m in raw})
    entries = {}
    for k in range(0, len(cve_ids), 1000):
        for e in db.scalars(select(CveEntry).where(CveEntry.cve_id.in_(cve_ids[k:k + 1000]))):
            entries[e.cve_id] = e

    findings: List[dict] = []
    for a, ident, m in raw:
        e = entries.get(m.cve_id)
        if e is None:
            continue
        findings.append({
            "asset_id": a.id, "asset_name": a.asset_name, "asset_icon": a.resolved_icon,
            "ip_address": a.ip_address,
            "product": ident.label, "vendor": ident.vendor, "product_key": ident.product,
            "installed": ident.version, "identity_source": ident.source,
            "fixed_in": _fixed_in(m),
            "cve_id": e.cve_id, "description": e.description, "severity": e.severity,
            "cvss": e.cvss_score, "cvss_version": e.cvss_version, "kev": e.kev, "kev_due": e.kev_due,
            "epss": e.epss, "epss_percentile": e.epss_percentile, "published": e.published,
            "priority": priority(e),
        })
    findings.sort(key=lambda f: (f["priority"], -(f["cvss"] or 0), -(f["epss"] or 0), f["asset_name"] or ""))

    summary = {"total": len(findings), "fix_now": sum(1 for f in findings if f["priority"] == 1),
               "affected_assets": len({f["asset_id"] for f in findings})}
    for s in SEVERITIES:
        summary[s] = sum(1 for f in findings if f["severity"] == s)

    counts = defaultdict(int)
    for f in findings:
        counts[f["asset_id"]] += 1
    asset_rows = [{
        "asset_id": a.id, "asset_name": a.asset_name, "asset_icon": a.resolved_icon, "ip_address": a.ip_address,
        "findings": counts[a.id],
        "products": [{"vendor": i.vendor, "product": i.product, "version": i.version, "label": i.label,
                      "source": i.source, "software_id": i.software_id} for i in per_asset[a.id]],
    } for a in assets]
    return {"summary": summary, "findings": findings, "assets": asset_rows}
