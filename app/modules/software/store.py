"""
Saving a collection: replace the asset's items of that collector, record
what changed, keep the change history to a year. Firmware versions also
update the asset's own OS version (the change is logged like a manual edit).
"""
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import Asset
from app.models.software import SoftwareChange, SoftwareCollection, SoftwareItem

logger = logging.getLogger(__name__)

CHANGE_RETENTION = timedelta(days=365)


def _keys(items: Iterable) -> Dict[Tuple, object]:
    """(kind, name, arch) per item; a second item with the same three (two
    versions of one Windows program) is told apart by its version."""
    out = {}
    for it in items:
        get = it.get if isinstance(it, dict) else (lambda f, _it=it: getattr(_it, f))
        key = (get("kind"), get("name"), get("arch") or "")
        if key in out:
            key = key + (get("version") or "",)
        out[key] = it
    return out


def save(db: Session, asset_id: int, collector: str, items: Optional[List[dict]], *, trigger: str = "audit",
         audit_session_id: Optional[int] = None, user_id: Optional[int] = None,
         error: Optional[str] = None) -> SoftwareCollection:
    now = datetime.utcnow()
    col = SoftwareCollection(asset_id=asset_id, collector=collector, trigger=trigger,
                             audit_session_id=audit_session_id, collected_by=user_id, collected_at=now)
    if error is not None or items is None:
        col.status, col.error = "failed", (error or "Nothing could be collected")[:2000]
        db.add(col)
        db.commit()
        return col

    had_before = db.query(SoftwareCollection.id).filter(
        SoftwareCollection.asset_id == asset_id, SoftwareCollection.collector == collector,
        SoftwareCollection.status == "ok").first() is not None
    db.add(col)
    db.flush()

    old = _keys(db.query(SoftwareItem).filter(SoftwareItem.asset_id == asset_id,
                                              SoftwareItem.collector == collector).all())
    new = _keys(items)
    changes: List[SoftwareChange] = []
    added = removed = updated = 0
    for key, it in new.items():
        row = old.get(key)
        if row is None:
            db.add(SoftwareItem(asset_id=asset_id, collector=collector, kind=it["kind"], name=it["name"][:300],
                                version=(it.get("version") or None) and it["version"][:160], arch=it.get("arch"),
                                source=it["source"], origin=(it.get("origin") or None) and it["origin"][:200],
                                publisher=(it.get("publisher") or None) and it["publisher"][:200],
                                source_package=it.get("source_package"), vkind=it.get("vkind"),
                                collection_id=col.id, first_seen=now, last_seen=now))
            added += 1
            changes.append(SoftwareChange(change="added", kind=it["kind"], name=it["name"][:300],
                                          new_version=it.get("version"), source=it["source"],
                                          origin=it.get("origin")))
            continue
        if (row.version or None) != (it.get("version") or None):
            updated += 1
            changes.append(SoftwareChange(change="updated", kind=it["kind"], name=row.name,
                                          old_version=row.version, new_version=it.get("version"),
                                          source=it["source"], origin=it.get("origin")))
        row.version = (it.get("version") or None) and it["version"][:160]
        row.source, row.origin = it["source"], (it.get("origin") or None) and it["origin"][:200]
        row.publisher = (it.get("publisher") or None) and it["publisher"][:200]
        row.source_package, row.vkind = it.get("source_package"), it.get("vkind")
        row.collection_id, row.last_seen = col.id, now
    for key, row in old.items():
        if key not in new:
            removed += 1
            changes.append(SoftwareChange(change="removed", kind=row.kind, name=row.name, old_version=row.version,
                                          source=row.source, origin=row.origin))
            db.delete(row)

    col.item_count = len(new)
    col.summary = {"by_source": dict(Counter(it["source"] for it in items if it["kind"] in ("package", "program"))),
                   "first": not had_before}
    os_item = next((it for it in items if it["kind"] == "os"), None)
    if os_item:
        col.summary["os"] = f"{os_item['name']} {os_item.get('version') or ''}".strip()
    if had_before:
        # The first collection lists everything once; changes start with the second.
        col.added, col.removed, col.updated = added, removed, updated
        for ch in changes:
            ch.asset_id, ch.collection_id, ch.at = asset_id, col.id, now
            db.add(ch)
    db.query(SoftwareChange).filter(SoftwareChange.asset_id == asset_id,
                                    SoftwareChange.at < now - CHANGE_RETENTION).delete(synchronize_session=False)
    db.commit()
    db.refresh(col)
    return col


def record_firmware(db: Session, asset_id: int, item: dict, user_id: Optional[int]) -> None:
    """Write a device's firmware version into the asset's OS version, logged
    in its change history like any edit."""
    asset = db.get(Asset, asset_id)
    if asset is None or not item.get("version"):
        return
    version = item["version"]
    if (asset.os_version or "").strip() == version:
        return
    old = asset.os_version
    asset.os_version = version
    if not (asset.os_name or "").strip():
        asset.os_name = item["name"]
    db.commit()
    try:
        from app.models.asset_log import log_asset_updated
        log_asset_updated(db, user_id, asset.id, asset.asset_name, changes=[{
            "field": "os_version", "label": "OS Version", "category": "network", "old": old or "", "new": version,
            "note": f"Read from the device by the {item['name']} audit"}], ip_address=None)
    except Exception:
        logger.exception("[software] could not log the firmware version change")
        db.rollback()
