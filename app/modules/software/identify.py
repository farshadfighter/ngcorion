"""
Turning inventory items into products: which NVD product an item is, the
upstream version to compare, and whether it is matched against NVD at all.

Resolution of one item:
  hotfix     a Windows update (KB...) - listed, never a product
  component  a library / -dev / -doc package with nothing known about it -
             listed under its asset, never in the fleet's product list
  internal   an admin marked it "internal, not in NVD"
  known      catalog or admin mapping gives its CPE(s)
  unknown    a product nobody has identified yet
  distro     a distribution package the catalog does not know - never asked
             about, its distribution's advisories cover it (phase 2)
A distribution package is resolved like any other (so its name and CPE show),
but is not matched against NVD in phase 1 (see app/models/software.py).
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.software import MAP_CPE, MAP_INTERNAL, NVD_SOURCES, SoftwareProductMap
from app.modules.software import catalog

_WINDOWS_SERVER = re.compile(r"windows server (20\d\d)", re.I)


@dataclass
class Resolved:
    status: str                         # known | unknown | internal | component | hotfix | os
    key: str                            # match key the status came from (or the group key)
    label: str
    cpes: List[Tuple[str, str]] = field(default_factory=list)
    version: Optional[str] = None       # upstream version for NVD
    nvd: bool = False                   # matched against NVD in phase 1
    mapped_by: Optional[str] = None     # catalog | admin


def load_maps(db: Session) -> Dict[str, SoftwareProductMap]:
    return {m.match_key: m for m in db.query(SoftwareProductMap).all()}


def keys_for(item) -> List[str]:
    get = item.get if isinstance(item, dict) else (lambda f, _i=item: getattr(_i, f))
    windows = get("vkind") == "win" or get("kind") in ("program", "hotfix", "os")
    keys = [catalog.match_key(get("name"), windows=windows)]
    src = get("source_package")
    if src:
        sk = catalog.match_key(src)
        if sk and sk not in keys:
            keys.append(sk)
    return keys


def resolve(item, maps: Dict[str, SoftwareProductMap]) -> Resolved:
    get = item.get if isinstance(item, dict) else (lambda f, _i=item: getattr(_i, f))
    kind, name, source = get("kind"), get("name"), get("source")
    version = catalog.upstream_version(get("version"), get("vkind") or "")
    keys = keys_for(item)
    if kind == "hotfix":
        return Resolved("hotfix", keys[0], name)
    if kind == "os":
        m = _WINDOWS_SERVER.search(name or "")
        if m:
            return Resolved("known", keys[0], f"Windows Server {m.group(1)}",
                            [("microsoft", f"windows_server_{m.group(1)}")], get("version"),
                            nvd=True, mapped_by="catalog")
        return Resolved("os", keys[0], name)
    nvd = source in NVD_SOURCES
    for key in keys:
        mp = maps.get(key)
        if mp is not None:
            if mp.status == MAP_INTERNAL:
                return Resolved("internal", key, mp.label or name)
            if mp.status == MAP_CPE and mp.vendor and mp.product:
                known = catalog.lookup(key)
                label = mp.label or (known[0] if known else name)
                return Resolved("known", key, label, [(mp.vendor, mp.product)], version, nvd, "admin")
    for key in keys:
        hit = catalog.lookup(key)
        if hit:
            return Resolved("known", key, hit[0], hit[1], version, nvd, "catalog")
    group = keys[-1] if len(keys) > 1 else keys[0]       # the source package groups its binaries
    if any(catalog.is_component(k) for k in keys) or source == "distro":
        # Distribution packages are not asked about: phase 2 covers them by
        # their advisories, whatever their CPE.
        return Resolved("component" if source != "distro" else "distro", group, name, version=version)
    return Resolved("unknown", group, name, version=version, nvd=nvd)


def nvd_identities(items: Iterable, maps: Dict[str, SoftwareProductMap]):
    """(vendor, product, version, label) for the items matched against NVD,
    without duplicates (docker-ce and docker-ce-cli are one product)."""
    seen, out = set(), []
    for it in items:
        r = resolve(it, maps)
        if r.status != "known" or not r.nvd:
            continue
        for vendor, product in r.cpes:
            key = (vendor, product, r.version)
            if key not in seen:
                seen.add(key)
                out.append((vendor, product, r.version, r.label))
    return out
