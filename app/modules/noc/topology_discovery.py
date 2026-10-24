"""
The Topology map drawn from the devices themselves: every monitored router and switch reports, in its
LLDP and CDP neighbour tables, what is cabled to each of its ports (app/modules/noc/lldp.py). NOC
reads them (System Configuration section "noc_topology_discovery", every 60 minutes by default) and:

  * keeps each neighbour (TopologyNeighbor) and works out which asset it is: by the chassis id the
    neighbour itself reports when NOC reads it too, its MAC or management address, or its name;
  * turns each cable between two assets into one Topology link (origin "lldp" / "cdp"). The two
    devices usually report the same cable from both sides; both reports make one link. A link
    drawn by hand for the same ports (or with no ports filled in) is confirmed instead of doubled,
    and is never changed;
  * marks a found link "missing" when a device that reported it is read again and no longer does,
    raising the "Network link lost" alert; it is removed after FORGET_LINK_DAYS.

Removing a found link from the map suppresses the neighbour reports that made it, so the next read
does not draw it again; "Add to map" on the neighbour brings it back.
"""
import asyncio
import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from app.core.singleton import lock_key
from app.models.asset import Asset
from app.models.noc import (AssetSnmpCredential, AssetSnmpInterface, AssetSnmpStatus, NetworkEndpoint,
                            TopologyDiscoverySource, TopologyNeighbor)
from app.models.system_config import SystemConfigSetting
from app.models.topology import TopologyLink
from app.models.topology_log import TopologyLog
from app.modules.noc import lldp, oui

logger = logging.getLogger(__name__)

SECTION = "noc_topology_discovery"
DEFAULTS = {"enabled": True, "interval_minutes": 60, "auto_links": True}
LIMITS = {"interval_minutes": (5, 1440)}

MAX_CONCURRENT_READS = 5
FORGET_NEIGHBOR_DAYS = 30      # a neighbour report not seen again
FORGET_LINK_DAYS = 30          # a found link the devices stopped reporting
PORT_LEN = 100                 # TopologyLink.source_interface / destination_interface


# --------------------------------------------------------------------------- settings

def get_settings(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    out = {}
    for key, default in DEFAULTS.items():
        value = stored.get(key, default)
        try:
            if isinstance(default, bool):
                out[key] = bool(value)
            else:
                lo, hi = LIMITS[key]
                out[key] = max(lo, min(int(value), hi))
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


# --------------------------------------------------------------------------- ports and names

# Long interface names and the short forms devices also use for the same port (Cisco, Arista, NX-OS).
_PORT_PREFIXES = [
    ("hundredgigabitethernet", "hu"), ("hundredgige", "hu"), ("fortygigabitethernet", "fo"),
    ("twentyfivegigabitethernet", "twe"), ("twentyfivegige", "twe"), ("tengigabitethernet", "te"),
    ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("ethernet", "eth"), ("port-channel", "po"),
    ("management", "mgmt"),
]


def port_key(name: Optional[str]) -> Optional[str]:
    """One spelling per port: "GigabitEthernet1/0/24", "Gi1/0/24" and "gi 1/0/24" all -> "gi1/0/24"."""
    if not name:
        return None
    key = re.sub(r"\s+", "", name.lower())
    for long, short in _PORT_PREFIXES:
        if key.startswith(long):
            return short + key[len(long):]
    if key.startswith("et") and not key.startswith("eth") and key[2:3].isdigit():
        return "eth" + key[2:]
    return key


def name_key(name: Optional[str]) -> Optional[str]:
    """A device name for matching: lower case, without a CDP serial "(FOC123)" or a domain."""
    if not name:
        return None
    key = re.sub(r"\(.*\)$", "", name.strip().lower()).strip()
    return key.split(".")[0] or None


@dataclass
class _Ports:
    """One device's interfaces from the NOC poll, to name its ports the way its own pages do."""
    by_key: Dict[str, Tuple[int, str]]
    by_index: Dict[int, str]
    speed: Dict[int, int]

    def find(self, *names: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
        """The first of `names` that is one of the device's interfaces -> (its name, ifIndex)."""
        for n in names:
            hit = self.by_key.get(port_key(n)) if n else None
            if hit:
                return hit[1], hit[0]
        return None, None


def _ports(db: Session, asset_ids: Set[int]) -> Dict[int, _Ports]:
    out: Dict[int, _Ports] = defaultdict(lambda: _Ports({}, {}, {}))
    if not asset_ids:
        return out
    for r in db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id.in_(asset_ids)):
        p = out[r.asset_id]
        name = r.if_name or r.if_descr or f"ifIndex {r.if_index}"
        p.by_index[r.if_index] = name
        for n in (r.if_name, r.if_descr):
            if n:
                p.by_key.setdefault(port_key(n), (r.if_index, name))
        if r.if_speed:
            p.speed[r.if_index] = r.if_speed
    return out


# --------------------------------------------------------------------------- matching

@dataclass
class Directory:
    """How to tell which asset a neighbour is."""
    chassis: Dict[str, int]
    mac: Dict[str, int]
    ip: Dict[str, int]
    name: Dict[str, int]

    def match(self, row: TopologyNeighbor) -> Optional[int]:
        cid = row.chassis_id
        if cid:
            key = cid.lower()
            if key in self.chassis:
                return self.chassis[key]
            if row.chassis_kind == "mac" and key in self.mac:
                return self.mac[key]
            if row.chassis_kind == "ip" and key in self.ip:
                return self.ip[key]
        if row.remote_mgmt_ip and row.remote_mgmt_ip in self.ip:
            return self.ip[row.remote_mgmt_ip]
        key = name_key(row.remote_name)
        return self.name.get(key) if key else None


def directory(db: Session) -> Directory:
    chassis = {s.chassis_id.lower(): s.asset_id for s in db.query(TopologyDiscoverySource)
               if s.chassis_id}
    mac: Dict[str, int] = {}
    ip: Dict[str, int] = {}
    names: Dict[str, Optional[int]] = {}
    for aid, m, addr, name, host in db.query(Asset.id, Asset.mac_address, Asset.ip_address, Asset.asset_name,
                                              Asset.hostname):
        nm = oui.normalize_mac(m)
        if nm:
            mac.setdefault(nm, aid)
        if addr:
            ip.setdefault(addr.strip(), aid)
        for n in {name_key(name), name_key(host)} - {None}:
            names[n] = aid if names.get(n, aid) == aid else None      # ambiguous names match nothing
    for aid, sys_name in db.query(AssetSnmpStatus.asset_id, AssetSnmpStatus.sys_name):
        n = name_key(sys_name)
        if n:
            names[n] = aid if names.get(n, aid) == aid else None
    # A monitored device's own interface MACs (from the ARP / MAC table reads).
    for m, aid in db.query(NetworkEndpoint.mac, NetworkEndpoint.matched_asset_id).filter(
            NetworkEndpoint.matched_asset_id.isnot(None)):
        mac.setdefault(m, aid)
    return Directory(chassis, mac, ip, {k: v for k, v in names.items() if v is not None})


def _ident(n: lldp.Neighbor) -> str:
    raw = "|".join([n.protocol, n.local_port, n.chassis_id or n.remote_name or "", n.remote_port or ""])
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()


# --------------------------------------------------------------------------- reading

async def read_reports(db: Session) -> Tuple[Dict[int, lldp.NeighborReport], Dict[int, str]]:
    """Read the neighbour tables of every reachable device with an SNMP credential."""
    from puresnmp import Client, PyWrapper
    from app.modules.noc.snmp_client import _build_credentials

    reachable = {s.asset_id for s in db.query(AssetSnmpStatus).filter(AssetSnmpStatus.reachable.is_(True))}
    creds = [c for c in db.query(AssetSnmpCredential).options(joinedload(AssetSnmpCredential.asset))
             if c.asset and c.target and c.asset_id in reachable]
    interfaces: Dict[int, list] = defaultdict(list)
    if creds:
        for r in db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id.in_([c.asset_id for c in creds])):
            interfaces[r.asset_id].append((r.if_index, r.if_name, r.if_descr))
    reports: Dict[int, lldp.NeighborReport] = {}
    errors: Dict[int, str] = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_READS)

    async def read(c: AssetSnmpCredential):
        async with semaphore:
            try:
                client = PyWrapper(Client(c.target, _build_credentials(c), port=c.port))
                rep = await lldp.collect(client, interfaces.get(c.asset_id, []))
            except Exception as exc:  # noqa: BLE001 - one device must not stop the sweep
                errors[c.asset_id] = f"{type(exc).__name__}: {exc}"
                return
            reports[c.asset_id] = rep
            if rep.errors and not rep.neighbors:
                errors[c.asset_id] = "; ".join(rep.errors)

    await asyncio.gather(*(read(c) for c in creds))
    return reports, errors


# --------------------------------------------------------------------------- recording

def record(db: Session, reports: Dict[int, lldp.NeighborReport], errors: Dict[int, str],
           now: Optional[datetime] = None) -> Dict:
    """Write one sweep's result and bring the found links up to date. Serialised across workers by
    an advisory lock, so a manual read and the poller's cannot make the same link twice."""
    now = now or datetime.utcnow()
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key("noc-topology-sweep")})

    sources = {s.asset_id: s for s in db.query(TopologyDiscoverySource)}
    for aid in set(reports) | set(errors):
        src = sources.get(aid)
        if src is None:
            src = sources[aid] = TopologyDiscoverySource(asset_id=aid)
            db.add(src)
        rep = reports.get(aid)
        src.last_read_at, src.ok, src.error = now, aid not in errors, errors.get(aid)
        if rep is not None:
            src.lldp, src.cdp, src.neighbors = rep.lldp, rep.cdp, len(rep.neighbors)
            src.chassis_id = rep.local_chassis_id or src.chassis_id
    db.flush()

    existing = {(r.asset_id, r.ident): r for r in db.query(TopologyNeighbor)}
    added = 0
    for aid, rep in reports.items():
        for n in rep.neighbors:
            key = (aid, _ident(n))
            row = existing.get(key)
            if row is None:
                row = existing[key] = TopologyNeighbor(asset_id=aid, ident=key[1], first_seen_at=now,
                                                       suppressed=False)
                db.add(row)
                added += 1
            row.protocol, row.local_port, row.local_if_index = n.protocol, n.local_port[:255], n.local_if_index
            row.chassis_id, row.chassis_kind = (n.chassis_id or None), n.chassis_kind
            row.remote_name, row.remote_port, row.remote_port_desc = n.remote_name, n.remote_port, n.remote_port_desc
            row.remote_mgmt_ip, row.remote_description = n.remote_mgmt_ip, n.remote_description
            row.capabilities = n.capabilities or None
            row.last_seen_at = now
    db.flush()

    rematch(db, commit=False)
    read_ok = {aid for aid, src in sources.items() if src.last_read_at == now and src.ok and (src.lldp or src.cdp)}
    links = update_links(db, now, read_ok, get_settings(db)["auto_links"])
    forgotten = (db.query(TopologyNeighbor)
                 .filter(TopologyNeighbor.last_seen_at < now - timedelta(days=FORGET_NEIGHBOR_DAYS))
                 .delete(synchronize_session=False))
    db.commit()
    total = sum(len(r.neighbors) for r in reports.values())
    return {"devices_read": len(reports), "devices_failed": len(errors), "neighbors": total, "new": added,
            "forgotten": forgotten, **links}


def rematch(db: Session, commit: bool = True) -> None:
    """Work out (again) which asset every neighbour is; an asset added or edited since the last
    read is found without waiting for the next one. A neighbour added as an asset by hand keeps
    that asset when nothing else matches it (the asset is gone: the foreign key clears it)."""
    d = directory(db)
    for row in db.query(TopologyNeighbor):
        found = d.match(row)
        if found == row.asset_id:
            row.matched_asset_id = None
        elif found is not None:
            row.matched_asset_id = found
    if commit:
        db.commit()


def _pair_key(a: int, pa: Optional[str], b: int, pb: Optional[str]) -> frozenset:
    return frozenset({(a, port_key(pa)), (b, port_key(pb))})


def _link_key(link: TopologyLink) -> frozenset:
    return _pair_key(link.source_asset_id, link.source_interface, link.destination_asset_id,
                     link.destination_interface)


def _ends(row: TopologyNeighbor, ports: Dict[int, _Ports]) -> Tuple[str, Optional[int], Optional[str], Optional[int]]:
    """A neighbour report as two named ports: (local name, local ifIndex, remote name, remote ifIndex),
    named as each device's own interface list names them when it is known."""
    mine = ports[row.asset_id]
    local, local_idx = (mine.by_index.get(row.local_if_index), row.local_if_index) if row.local_if_index else (None, None)
    if not local:
        local, local_idx = mine.find(row.local_port)
    theirs = ports[row.matched_asset_id]
    remote, remote_idx = theirs.find(row.remote_port, row.remote_port_desc)
    return (local or row.local_port), local_idx, (remote or row.remote_port or row.remote_port_desc), remote_idx


def update_links(db: Session, now: datetime, read_ok: Set[int], auto_links: bool) -> Dict:
    """Confirm, create and mark missing the links the neighbour reports describe (see the module
    docstring). Every report that makes a link gets its link_id."""
    rows = [r for r in db.query(TopologyNeighbor).filter(TopologyNeighbor.last_seen_at == now,
                                                         TopologyNeighbor.matched_asset_id.isnot(None))]
    ports = _ports(db, {r.asset_id for r in rows} | {r.matched_asset_id for r in rows})
    groups: Dict[frozenset, List[Tuple[TopologyNeighbor, tuple]]] = defaultdict(list)
    for r in rows:
        ends = _ends(r, ports)
        groups[_pair_key(r.asset_id, ends[0], r.matched_asset_id, ends[2])].append((r, ends))

    links = db.query(TopologyLink).all()
    by_key: Dict[frozenset, TopologyLink] = {}
    blank: Dict[frozenset, List[TopologyLink]] = defaultdict(list)       # hand-drawn, no ports given
    for link in links:
        if link.status == "planned":
            continue
        if link.origin == "manual" and not link.source_interface and not link.destination_interface:
            blank[frozenset({link.source_asset_id, link.destination_asset_id})].append(link)
        else:
            by_key.setdefault(_link_key(link), link)

    created = confirmed = 0
    seen_links: Set[int] = set()
    for key, members in groups.items():
        if any(r.suppressed for r, _ in members):
            for r, _ in members:
                r.link_id = None
            continue
        r, (local, local_idx, remote, _) = members[0]
        link = by_key.get(key)
        if link is None:
            spare = blank.get(frozenset({r.asset_id, r.matched_asset_id}))
            link = spare.pop(0) if spare else None
        if link is None and auto_links:
            speed = ports[r.asset_id].speed.get(local_idx) if local_idx is not None else None
            link = TopologyLink(source_asset_id=r.asset_id, destination_asset_id=r.matched_asset_id,
                                source_interface=local[:PORT_LEN] if local else None,
                                destination_interface=remote[:PORT_LEN] if remote else None,
                                link_type="ethernet", speed_mbps=int(speed // 1_000_000) if speed else None,
                                status="active", origin=r.protocol, created_by=None)
            db.add(link)
            db.flush()
            by_key[key] = link
            db.add(TopologyLog(user_id=None, action="discovered", link_id=link.id, status="success",
                               details={"protocol": r.protocol, "source_asset_id": link.source_asset_id,
                                        "destination_asset_id": link.destination_asset_id}))
            created += 1
        elif link is not None:
            confirmed += 1
        if link is None:
            for m, _ in members:
                m.link_id = None
            continue
        link.last_seen_at, link.missing_since = now, None
        seen_links.add(link.id)
        for m, _ in members:
            m.link_id = link.id

    # Found links the devices no longer report, when a device at either end was read just now.
    missing = 0
    for link in links:
        if link.origin == "manual" or link.id in seen_links:
            continue
        if link.source_asset_id in read_ok or link.destination_asset_id in read_ok:
            if link.missing_since is None:
                link.missing_since = now
                missing += 1
    gone = [link for link in links if link.origin != "manual" and link.missing_since
            and link.missing_since < now - timedelta(days=FORGET_LINK_DAYS)]
    for link in gone:
        db.add(TopologyLog(user_id=None, action="expired", link_id=link.id, status="success",
                           details={"source_asset_id": link.source_asset_id,
                                    "destination_asset_id": link.destination_asset_id}))
        db.delete(link)
    return {"links_created": created, "links_confirmed": confirmed, "links_missing": missing,
            "links_removed": len(gone)}


def link_from_neighbor(db: Session, row: TopologyNeighbor, user_id: Optional[int]) -> TopologyLink:
    """"Add to map" on one neighbour: draw (or bring back) the link it describes now."""
    for m in db.query(TopologyNeighbor).filter(TopologyNeighbor.suppressed.is_(True),
                                               TopologyNeighbor.asset_id.in_([row.asset_id, row.matched_asset_id]),
                                               TopologyNeighbor.matched_asset_id.in_([row.asset_id,
                                                                                      row.matched_asset_id])):
        m.suppressed = False
    row.suppressed = False
    ports = _ports(db, {row.asset_id, row.matched_asset_id})
    local, local_idx, remote, _ = _ends(row, ports)
    key = _pair_key(row.asset_id, local, row.matched_asset_id, remote)
    link = next((lk for lk in db.query(TopologyLink).filter(
        TopologyLink.source_asset_id.in_([row.asset_id, row.matched_asset_id]),
        TopologyLink.destination_asset_id.in_([row.asset_id, row.matched_asset_id])) if _link_key(lk) == key), None)
    if link is None:
        speed = ports[row.asset_id].speed.get(local_idx) if local_idx is not None else None
        link = TopologyLink(source_asset_id=row.asset_id, destination_asset_id=row.matched_asset_id,
                            source_interface=local[:PORT_LEN] if local else None,
                            destination_interface=remote[:PORT_LEN] if remote else None,
                            link_type="ethernet", speed_mbps=int(speed // 1_000_000) if speed else None,
                            status="active", origin=row.protocol, created_by=user_id)
        db.add(link)
    link.last_seen_at, link.missing_since = row.last_seen_at, None
    db.flush()
    row.link_id = link.id
    db.commit()
    return link


def suppress_link(db: Session, link: TopologyLink) -> None:
    """A found link is being removed from the map: keep the reports that made it from drawing it
    again (called before the delete, which clears their link_id)."""
    if link.origin == "manual":
        return
    db.query(TopologyNeighbor).filter(TopologyNeighbor.link_id == link.id).update(
        {TopologyNeighbor.suppressed: True}, synchronize_session=False)


# --------------------------------------------------------------------------- sweep

async def sweep(db: Session) -> Dict:
    """Read every device and update neighbours and links (the poller and "Read now")."""
    reports, errors = await read_reports(db)
    return record(db, reports, errors)


_last_sweep: Optional[datetime] = None


async def run_if_due(db: Session) -> Optional[Dict]:
    """Called after every NOC poll sweep: sweep when turned on and the interval has passed."""
    global _last_sweep
    cfg = get_settings(db)
    if not cfg["enabled"]:
        return None
    now = datetime.utcnow()
    if _last_sweep is None:
        last = db.query(TopologyDiscoverySource.last_read_at).order_by(
            TopologyDiscoverySource.last_read_at.desc().nullslast()).first()
        _last_sweep = last[0] if last and last[0] else None
    if _last_sweep is not None and now - _last_sweep < timedelta(minutes=cfg["interval_minutes"]):
        return None
    _last_sweep = now
    result = await sweep(db)
    logger.info("[NOC] Topology discovery: %s", result)
    return result
