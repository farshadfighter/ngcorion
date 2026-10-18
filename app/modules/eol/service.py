"""
End of life of what runs on the assets: each operating system, firmware and server software the software
inventory found (SoftwareItem of kind os / firmware / service), the operating system typed on an asset
that has no inventory, and what was entered by hand (EolAssetEntry), matched to the catalog
(app/modules/eol/catalog.py, match.py) and given a status:

  unsupported  security support has ended (and paid extended support too, or there is none)
  extended     security support has ended; only paid extended support (Ubuntu Pro, RHEL ELS, Windows
               ESU ...) still brings fixes, if the organisation has it
  ending       security support ends within the warning period (default 180 days)
  supported    supported beyond that
  unknown      not in the catalog, or a release cycle the catalog does not know

Nothing is stored: the status is computed from the inventory when asked. The alerts, the remediation
tracker and the risk score read evaluate().
"""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.eol import EolAssetEntry
from app.models.system_config import SystemConfigSetting
from app.modules.eol import catalog as C
from app.modules.eol import match as M

SECTION = "eol"
DEFAULTS = {"warn_days": 180}
LIMITS = {"warn_days": (30, 730)}
KINDS = ("os", "firmware", "service")
ORDER = {"unsupported": 0, "extended": 1, "ending": 2, "supported": 3, "unknown": 4}


# ── settings ─────────────────────────────────────────────────────────────

def get_settings(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    out = {}
    for key, default in DEFAULTS.items():
        try:
            lo, hi = LIMITS[key]
            out[key] = max(lo, min(int(stored.get(key, default)), hi))
        except (TypeError, ValueError):
            out[key] = default
    return out


def save_settings(db: Session, values: Dict, user_id: Optional[int]) -> Dict:
    current = get_settings(db)
    current.update({k: v for k, v in values.items() if k in DEFAULTS and v is not None})
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = current
    row.updated_by = user_id
    db.commit()
    return get_settings(db)


# ── status ───────────────────────────────────────────────────────────────

def _date(v) -> Optional[date]:
    if isinstance(v, date):
        return v
    if isinstance(v, str) and len(v) >= 10:
        try:
            return date.fromisoformat(v[:10])
        except ValueError:
            return None
    return None


def status_of(cycle: Optional[dict], today: date, warn_days: int) -> Dict:
    """The status of a release cycle on a day, with the date it is about."""
    if not cycle:
        return {"status": "unknown", "until": None}
    sec, ext, active = cycle.get("security_until"), cycle.get("extended_until"), cycle.get("active_until")
    sec_d, ext_d, act_d = _date(sec), _date(ext), _date(active)
    security_only = (active is True) or (act_d is not None and act_d <= today)
    ended = sec is True or (sec_d is not None and sec_d <= today)
    if ended:
        if ext_d is not None and ext_d > today:
            return {"status": "extended", "until": ext_d.isoformat(), "ended_on": sec_d.isoformat() if sec_d else None}
        return {"status": "unsupported", "until": sec_d.isoformat() if sec_d else None}
    if sec_d is not None and sec_d <= today + timedelta(days=warn_days):
        return {"status": "ending", "until": sec_d.isoformat(), "security_only": security_only}
    return {"status": "supported", "until": sec_d.isoformat() if sec_d else None, "security_only": security_only}


@dataclass
class Component:
    asset_id: int
    name: str
    version: Optional[str]
    kind: str                       # os | firmware | service | manual
    origin: str                     # inventory | asset | manual
    product: Optional[str] = None
    product_name: Optional[str] = None
    cycle: Optional[str] = None
    cycle_label: Optional[str] = None
    status: str = "unknown"
    until: Optional[str] = None
    ended_on: Optional[str] = None
    security_only: bool = False
    extended_until: Optional[str] = None
    latest: Optional[str] = None
    entry_id: Optional[int] = None
    note: Optional[str] = None
    extra: Dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable per asset: the product and cycle, or the name."""
        return f"{self.product}:{self.cycle}" if self.product and self.cycle else f"name:{self.name.lower()}"

    @property
    def title(self) -> str:
        """How people name it: product and release cycle ("FortiOS 7.0"); a cycle label that already
        names the product stands alone ("Windows Server 2012 R2", not "Microsoft Windows Server
        Windows Server 2012 R2"). Unmatched: the name as found."""
        if not (self.product and self.cycle):
            return self.name
        label = self.cycle_label or self.cycle
        first = label.split()[0].lower()
        if first.isalpha() and first in (self.product_name or "").lower().split():
            return label
        return f"{self.product_name} {label}"

    def out(self) -> Dict:
        return {"asset_id": self.asset_id, "name": self.name, "version": self.version, "kind": self.kind,
                "origin": self.origin, "product": self.product, "product_name": self.product_name,
                "cycle": self.cycle, "cycle_label": self.cycle_label, "status": self.status, "until": self.until,
                "ended_on": self.ended_on, "security_only": self.security_only,
                "extended_until": self.extended_until, "latest": self.latest, "entry_id": self.entry_id,
                "note": self.note, "key": self.key, "title": self.title}


def components(db: Session, asset_ids: Optional[Iterable[int]] = None,
               today: Optional[date] = None) -> List[Component]:
    """Every component of the assets (all when None) with its end-of-life status."""
    from app.models.software import SoftwareItem
    today = today or datetime.utcnow().date()
    warn = get_settings(db)["warn_days"]
    products, custom = C.load(db)
    ids = None if asset_ids is None else list(asset_ids)

    q = db.query(SoftwareItem).filter(SoftwareItem.kind.in_(KINDS))
    if ids is not None:
        q = q.filter(SoftwareItem.asset_id.in_(ids or [-1]))
    out: List[Component] = []
    seen = set()
    with_os = set()
    for it in q.order_by(SoftwareItem.asset_id, SoftwareItem.kind, SoftwareItem.name):
        dedupe = (it.asset_id, it.name, it.version)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        if it.kind in ("os", "firmware"):
            with_os.add(it.asset_id)
        out.append(_matched(Component(it.asset_id, it.name, it.version, it.kind, "inventory"),
                            products, custom, today, warn))

    # The operating system typed on an asset the inventory has nothing for.
    aq = db.query(Asset.id, Asset.os_name, Asset.os_version).filter(Asset.os_name.isnot(None), Asset.os_name != "")
    if ids is not None:
        aq = aq.filter(Asset.id.in_(ids or [-1]))
    for aid, os_name, os_version in aq:
        if aid in with_os:
            continue
        name = os_name.strip()
        c = _matched(Component(aid, name, (os_version or "").strip() or None, "os", "asset"), products, custom,
                     today, warn)
        if c.product:          # an unrecognised free-text OS says nothing reliable
            out.append(c)

    eq = db.query(EolAssetEntry)
    if ids is not None:
        eq = eq.filter(EolAssetEntry.asset_id.in_(ids or [-1]))
    for e in eq:
        st = status_of({"security_until": e.support_until.isoformat()}, today, warn)
        out.append(Component(e.asset_id, e.name, e.version, "manual", "manual", status=st["status"],
                             until=st["until"], entry_id=e.id, note=e.note))
    return out


def _matched(c: Component, products: Dict[str, dict], custom: Dict[str, str], today: date,
             warn: int) -> Component:
    key, cycle_id = M.identify(c.name, c.version, products, custom)
    if key and key in products:
        c.product, c.product_name = key, products[key]["name"]
        cycle = next((x for x in products[key]["cycles"] if x["cycle"] == cycle_id), None) if cycle_id else None
        if cycle:
            c.cycle, c.cycle_label, c.latest = cycle["cycle"], cycle.get("label") or cycle["cycle"], cycle.get("latest")
            c.extended_until = cycle.get("extended_until") if isinstance(cycle.get("extended_until"), str) else None
            st = status_of(cycle, today, warn)
            c.status, c.until = st["status"], st["until"]
            c.ended_on, c.security_only = st.get("ended_on"), bool(st.get("security_only"))
    return c


def by_asset(comps: List[Component]) -> Dict[int, List[Component]]:
    out = defaultdict(list)
    for c in comps:
        out[c.asset_id].append(c)
    for v in out.values():
        v.sort(key=lambda c: (ORDER[c.status], c.name))
    return out


def worst(comps: List[Component]) -> Optional[str]:
    """The asset's worst status (unknown only when nothing is known)."""
    known = [c.status for c in comps if c.status != "unknown"]
    return min(known, key=ORDER.get) if known else ("unknown" if comps else None)


def summary(comps: List[Component]) -> Dict:
    assets = by_asset(comps)
    counts = defaultdict(int)
    for aid, cs in assets.items():
        counts[worst(cs)] += 1
    return {"assets": dict(counts), "components": dict(_count(c.status for c in comps)),
            "assets_with_data": len(assets)}


def _count(values) -> Dict[str, int]:
    out = defaultdict(int)
    for v in values:
        out[v] += 1
    return out


# Severity of a finding for the remediation tracker and the score the risk factor takes.
SEVERITY = {"unsupported": "high", "extended": "medium"}
RISK_SCORE = {"unsupported": 80.0, "extended": 40.0}
