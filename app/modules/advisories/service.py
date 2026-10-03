"""
What the pages show: the state of the advisory database, and one asset's
security updates (grouped by package, as an admin installs them).
"""
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import Asset
from app.models.advisory import AVAILABILITY_PRO, DistroFeed
from app.modules.advisories import match, releases, store
from app.modules.advisories.versions import compare


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def status(db: Session) -> Dict:
    use = store.in_use(db)
    extra = store.extra(db)
    feeds = {f.release: f for f in db.query(DistroFeed)}
    rows = []
    for r in sorted(set(use) | set(extra) | set(feeds)):
        f = feeds.get(r)
        rows.append({
            "release": r, "label": releases.label(r), "assets": len(use.get(r, [])),
            "requested": r in extra, "rows": f.rows if f else 0, "records": f.records if f else 0,
            "watermark": _iso(f.watermark) if f else None, "loaded_at": _iso(f.loaded_at) if f else None,
            "updated_at": _iso(f.updated_at) if f else None, "source": f.source if f else None,
            "last_changes": f.last_changes if f else None, "error": f.error if f else None,
            "state": "loaded" if f and f.watermark else "waiting",
        })
    names = {a.id: (a.asset_name, a.ip_address) for a in db.query(Asset.id, Asset.asset_name, Asset.ip_address)}
    uncovered = []
    for aid, platform in store.platforms(db).items():
        release, st = releases.from_platform(platform)
        if st != "ok":
            name, ip = names.get(aid, (None, None))
            uncovered.append({"asset_id": aid, "asset_name": name, "ip_address": ip, "reason": st,
                              "platform": releases.platform_label(platform)})
    uncovered.sort(key=lambda x: (x["asset_name"] or ""))
    return {
        "releases": rows, "uncovered": uncovered, "auto": store.auto_enabled(db), "extra": extra,
        "supported": [{"distro": k, "label": v["label"]} for k, v in releases.DISTROS.items()],
        "loaded": any(r["state"] == "loaded" for r in rows),
    }


def _group_command(family: str, groups: List[dict], reboot: bool) -> List[str]:
    std = [g for g in groups if g["availability"] != AVAILABILITY_PRO]
    lines = []
    plain = sorted({b for g in std if not g["kernel"] for b in g["binaries"]})
    kernel_new = any(g["kernel"] and not g["reboot"] for g in std)
    if family == "deb":
        if plain or kernel_new:
            lines.append("sudo apt-get update")
        if plain:
            lines.append("sudo apt-get install --only-upgrade " + " ".join(plain))
        if kernel_new:
            lines.append("sudo apt-get full-upgrade")
    else:
        names = sorted({b for g in std if not g["kernel"] for b in g["binaries"]})
        if names:
            lines.append("sudo dnf upgrade " + " ".join(names))
        if kernel_new:
            lines.append("sudo dnf upgrade kernel")
    if reboot or kernel_new:
        lines.append("sudo reboot")
    return lines


def security_updates(db: Session, asset_id: int) -> Dict:
    from app.modules.cve import findings as cve_findings
    res = match.analyse(db, [asset_id]).get(asset_id)
    if res is None:
        return {"status": "no_inventory"}
    out = {
        "status": res.status, "release": res.release, "label": res.label,
        "platform": res.platform.get("pretty") if res.platform else None,
        "running_kernel": res.running_kernel, "newest_kernel": res.newest_kernel,
        "reboot_required": res.reboot_required,
        "reboot_packages": (res.platform or {}).get("reboot_packages") or [],
        "feed": None, "summary": None, "updates": [], "unfixed": [], "commands": [],
    }
    if res.status != "ok":
        return out
    f = db.query(DistroFeed).filter(DistroFeed.release == res.release).first()
    out["feed"] = {"updated_at": _iso(f.updated_at), "watermark": _iso(f.watermark)} if f else None
    fam = releases.family(res.release)
    rows = [x for x in cve_findings.compute(db, asset_id)["findings"] if x["source"] == "advisory"]
    groups: Dict[str, dict] = {}
    for x in rows:
        g = groups.setdefault(x["package"], {
            "package": x["package"], "binaries": set(), "installed": x["installed"], "fixed_in": x["fixed_in"],
            "advisories": set(), "cves": [], "priority": x["priority"], "kev": False, "availability": set(),
            "kernel": False, "reboot": True, "severity": x["severity"],
        })
        g["binaries"].update(x["binaries"])
        if compare(fam, x["installed"], g["installed"]) < 0:
            g["installed"] = x["installed"]
        if x["fixed_in"] and compare(fam, x["fixed_in"], g["fixed_in"]) > 0:
            g["fixed_in"] = x["fixed_in"]
        g["advisories"].update(x["advisories"])
        g["cves"].append({"cve_id": x["cve_id"], "priority": x["priority"], "kev": x["kev"], "cvss": x["cvss"],
                          "epss": x["epss"], "severity": x["severity"]})
        if x["priority"] < g["priority"]:
            g["priority"], g["severity"] = x["priority"], x["severity"]
        g["kev"] = g["kev"] or x["kev"]
        g["availability"].add(x["availability"])
        g["kernel"] = g["kernel"] or x["package"].startswith(("linux", "kernel")) and any(
            b.startswith(("linux-image", "linux-modules", "kernel")) for b in x["binaries"])
        g["reboot"] = g["reboot"] and bool(x["reboot"])
    updates = []
    for g in groups.values():
        g["binaries"] = sorted(g["binaries"])
        g["advisories"] = sorted(g["advisories"])
        g["cves"].sort(key=lambda c: (c["priority"], -(c["cvss"] or 0), c["cve_id"]))
        g["availability"] = AVAILABILITY_PRO if g["availability"] == {AVAILABILITY_PRO} else "standard"
        g["reboot"] = g["reboot"] and g["kernel"]
        updates.append(g)
    updates.sort(key=lambda g: (g["priority"], not g["kev"], -len(g["cves"]), g["package"]))
    out["updates"] = updates
    out["unfixed"] = res.unfixed
    out["summary"] = {
        "packages": len(updates), "cves": len(rows), "kev": sum(1 for x in rows if x["kev"]),
        "unfixed": len({u["cve_id"] for u in res.unfixed}),
        "pro_only": sum(1 for g in updates if g["availability"] == AVAILABILITY_PRO),
        "worst": min((g["priority"] for g in updates), default=None),
    }
    out["commands"] = _group_command(fam, updates, res.reboot_required)
    return out


def set_settings(db: Session, auto: Optional[bool], extra: Optional[List[str]]) -> List[str]:
    from app.modules.cve import settings as cve_settings
    changes = []
    if auto is not None:
        cve_settings.put(db, store.AUTO, {"enabled": bool(auto)})
        changes.append(f"automatic advisory updates {'on' if auto else 'off'}")
    if extra is not None:
        bad = [r for r in extra if not releases.valid(r)]
        if bad:
            raise ValueError(f"Unknown release: {bad[0]}")
        keep = sorted(set(extra))
        cve_settings.put(db, store.EXTRA_RELEASES, keep)
        changes.append("releases kept besides those in use: " + (", ".join(keep) or "none"))
    db.commit()
    return changes


def remove_release(db: Session, release: str) -> bool:
    """Drop a release no asset runs any more (it is loaded again if one does)."""
    if release in store.in_use(db):
        return False
    store.clear(db, release)
    db.query(DistroFeed).filter(DistroFeed.release == release).delete()
    from app.modules.cve import settings as cve_settings
    cve_settings.put(db, store.EXTRA_RELEASES, [r for r in store.extra(db) if r != release])
    db.commit()
    return True
