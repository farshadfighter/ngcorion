"""
Unknown devices on the network, found in the ARP and MAC tables of the monitored routers and
switches (no scanning: NOC only reads, over the SNMP access it already has).

Every NOC_DISCOVERY interval (System Configuration section "noc_endpoint_discovery", 15 minutes by
default) the poller calls `sweep`: it reads the tables of every reachable device with an SNMP
credential (app/modules/noc/neighbors.py), merges them by MAC address and records each address in
NetworkEndpoint. An address is known when it is an asset's MAC or IP, or a monitored device's own
interface; otherwise it stays on the Unknown devices page until someone adds it as an asset or
ignores it.

Where a device is: of all the ports its MAC is learned on, the one with the fewest MACs - an access
port rather than an uplink, which carries the MACs of everything behind it.

The first read of a device takes its whole table as found; addresses seen only in such a read are
marked baseline and raise no "new device" alert (otherwise turning NOC on would alert for every
device on the network).
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import or_, text
from sqlalchemy.orm import Session, joinedload

from app.core.singleton import lock_key
from app.models.asset import Asset
from app.models.noc import (AssetSnmpCredential, AssetSnmpInterface, AssetSnmpStatus, NetworkDiscoverySource,
                            NetworkEndpoint)
from app.models.system_config import SystemConfigSetting
from app.modules.noc import neighbors, oui

logger = logging.getLogger(__name__)

SECTION = "noc_endpoint_discovery"
DEFAULTS = {"enabled": True, "interval_minutes": 15}
LIMITS = {"interval_minutes": (5, 1440)}

MAX_CONCURRENT_READS = 5
MAX_OTHER_IPS = 8
# How long an address is kept after it was last seen.
FORGET_UNKNOWN_DAYS = 30
FORGET_PRIVATE_DAYS = 7        # randomized addresses change all the time
FORGET_KNOWN_DAYS = 90
FORGET_IGNORED_DAYS = 365


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


# --------------------------------------------------------------------------- merging

@dataclass
class Sighting:
    """Everything one sweep learned about one MAC address."""
    mac: str
    ips: List[str] = field(default_factory=list)
    arp_at: Optional[Tuple[int, Optional[int]]] = None            # (asset, ifIndex) of the ARP entry
    ports: List[Tuple[int, Optional[int], Optional[int]]] = field(default_factory=list)  # (asset, ifIndex, vlan)
    own_of: Optional[int] = None                                   # a monitored device's own interface

    @property
    def via(self) -> str:
        return "both" if self.ips and self.ports else ("mac" if self.ports else "arp")


def merge(tables: Dict[int, neighbors.NeighborTables]) -> Dict[str, Sighting]:
    """All devices' tables -> one Sighting per MAC, with the most specific port first."""
    out: Dict[str, Sighting] = {}
    port_load: Dict[Tuple[int, Optional[int]], int] = {}
    for asset_id, t in tables.items():
        for mac in t.own_macs:
            out.setdefault(mac, Sighting(mac)).own_of = asset_id
        for e in t.arp:
            s = out.setdefault(e.mac, Sighting(e.mac))
            if e.ip not in s.ips:
                s.ips.append(e.ip)
            s.arp_at = s.arp_at or (asset_id, e.if_index)
        for e in t.fdb:
            out.setdefault(e.mac, Sighting(e.mac)).ports.append((asset_id, e.if_index, e.vlan))
            port_load[(asset_id, e.if_index)] = port_load.get((asset_id, e.if_index), 0) + 1
    for s in out.values():
        s.ports.sort(key=lambda p: port_load.get((p[0], p[1]), 0))
    return out


def _port_names(db: Session, asset_ids: Set[int]) -> Dict[Tuple[int, int], str]:
    if not asset_ids:
        return {}
    rows = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id.in_(asset_ids)).all()
    return {(r.asset_id, r.if_index): (r.if_name or r.if_descr or f"ifIndex {r.if_index}")
            for r in rows}


def _asset_maps(db: Session) -> Tuple[Dict[str, int], Dict[str, int]]:
    by_mac, by_ip = {}, {}
    for aid, mac, ip in db.query(Asset.id, Asset.mac_address, Asset.ip_address).all():
        m = oui.normalize_mac(mac)
        if m:
            by_mac.setdefault(m, aid)
        if ip:
            by_ip.setdefault(ip.strip(), aid)
    return by_mac, by_ip


def match_asset(row: NetworkEndpoint, by_mac: Dict[str, int], by_ip: Dict[str, int],
                own_of: Optional[int] = None) -> Optional[int]:
    """The asset an address belongs to: its MAC, then any of its IPs, then the monitored device it
    is an interface of."""
    if row.mac in by_mac:
        return by_mac[row.mac]
    for ip in [row.ip, *(row.other_ips or [])]:
        if ip and ip in by_ip:
            return by_ip[ip]
    return own_of


# --------------------------------------------------------------------------- sweep

def vlan_client(c: AssetSnmpCredential, vlan: int):
    """A client for one VLAN's bridge table on Cisco IOS: community "<community>@<vlan>" on SNMP v2c,
    context "vlan-<vlan>" on SNMP v3 (the same user)."""
    from puresnmp import V2C, Client, PyWrapper
    from app.core.snmp_crypto import decrypt_secret
    from app.modules.noc.snmp_client import _build_credentials

    if c.version == "v3":
        return PyWrapper(Client(c.target, _build_credentials(c), port=c.port,
                                context_name=f"vlan-{vlan}".encode()))
    community = decrypt_secret(c.community_encrypted) if c.community_encrypted else "public"
    return PyWrapper(Client(c.target, V2C(f"{community}@{vlan}"), port=c.port))


async def read_tables(db: Session) -> Tuple[Dict[int, neighbors.NeighborTables], Dict[int, str]]:
    """Read the tables of every reachable device with an SNMP credential. Returns the tables of the
    devices that answered and the error of those that did not."""
    from puresnmp import Client, PyWrapper
    from app.modules.noc.snmp_client import _build_credentials

    reachable = {s.asset_id for s in db.query(AssetSnmpStatus).filter(AssetSnmpStatus.reachable.is_(True))}
    creds = [c for c in db.query(AssetSnmpCredential).options(joinedload(AssetSnmpCredential.asset))
             if c.asset and c.target and c.asset_id in reachable]
    tables: Dict[int, neighbors.NeighborTables] = {}
    errors: Dict[int, str] = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_READS)

    async def read(c: AssetSnmpCredential):
        async with semaphore:
            try:
                client = PyWrapper(Client(c.target, _build_credentials(c), port=c.port))
                t = await neighbors.collect(client, vlan_client=lambda vlan, c=c: vlan_client(c, vlan))
            except Exception as exc:  # noqa: BLE001 - one device must not stop the sweep
                errors[c.asset_id] = f"{type(exc).__name__}: {exc}"
                return
            tables[c.asset_id] = t
            if t.errors and not (t.arp or t.fdb):
                errors[c.asset_id] = "; ".join(t.errors)

    await asyncio.gather(*(read(c) for c in creds))
    return tables, errors


def record(db: Session, tables: Dict[int, neighbors.NeighborTables], errors: Dict[int, str],
           now: Optional[datetime] = None) -> Dict:
    """Write one sweep's result. Serialised across workers by an advisory lock, so a manual sweep
    and the poller's cannot insert the same MAC twice."""
    now = now or datetime.utcnow()
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key("noc-endpoint-sweep")})

    sources = {s.asset_id: s for s in db.query(NetworkDiscoverySource).all()}
    first_read: Set[int] = set()
    for aid in set(tables) | set(errors):
        src = sources.get(aid)
        if src is None:
            src = NetworkDiscoverySource(asset_id=aid)
            db.add(src)
            sources[aid] = src
        t = tables.get(aid)
        src.last_read_at = now
        src.ok = aid not in errors
        src.error = errors.get(aid)
        if t is not None:
            src.arp_entries, src.mac_entries = len(t.arp), len(t.fdb)
            if src.first_read_at is None and src.ok:
                src.first_read_at = now
                first_read.add(aid)

    sightings = merge(tables)
    names = _port_names(db, set(tables))
    existing = {r.mac: r for r in db.query(NetworkEndpoint).all()}
    by_mac, by_ip = _asset_maps(db)
    created = 0
    for mac, s in sightings.items():
        row = existing.get(mac)
        if row is None:
            row = NetworkEndpoint(mac=mac, first_seen_at=now, private_mac=oui.is_private(mac))
            row.vendor = oui.vendor_of(mac)
            row.guess_kind, row.guess_icon = oui.guess(mac, row.vendor)
            reporters = ({p[0] for p in s.ports} | ({s.arp_at[0]} if s.arp_at else set())
                         | ({s.own_of} if s.own_of else set()))
            row.baseline = bool(reporters) and reporters <= first_read
            db.add(row)
            existing[mac] = row
            created += 1
        row.last_seen_at = now
        if s.ips:
            row.ip = s.ips[0]
            others = [ip for ip in [*s.ips[1:], *(row.other_ips or [])] if ip != row.ip]
            row.other_ips = list(dict.fromkeys(others))[:MAX_OTHER_IPS] or None
        where = s.ports[0] if s.ports else ((*s.arp_at, None) if s.arp_at else None)
        if where:
            aid, if_index, vlan = where
            row.seen_by_asset_id, row.seen_if_index, row.seen_vlan = aid, if_index, vlan
            row.seen_port = names.get((aid, if_index)) if if_index is not None else None
        row.seen_via = s.via
        row.matched_asset_id = match_asset(row, by_mac, by_ip, s.own_of)

    # Addresses not seen this time may have become known meanwhile (an asset was added or edited).
    for mac, row in existing.items():
        if mac not in sightings and row.matched_asset_id is None:
            row.matched_asset_id = match_asset(row, by_mac, by_ip)
    forgotten = forget_old(db, now)
    db.commit()
    unknown = sum(1 for r in existing.values() if r.matched_asset_id is None and r.state == "open")
    return {"devices_read": len(tables), "devices_failed": len(errors), "addresses": len(sightings),
            "new": created, "unknown": unknown, "forgotten": forgotten}


def forget_old(db: Session, now: datetime) -> int:
    """Drop addresses not seen for a long time (shorter for unknown and randomized ones)."""
    q = db.query(NetworkEndpoint)
    cut = lambda days: now - timedelta(days=days)  # noqa: E731
    stale = q.filter(or_(
        (NetworkEndpoint.state == "ignored") & (NetworkEndpoint.last_seen_at < cut(FORGET_IGNORED_DAYS)),
        (NetworkEndpoint.state == "open") & NetworkEndpoint.matched_asset_id.isnot(None)
        & (NetworkEndpoint.last_seen_at < cut(FORGET_KNOWN_DAYS)),
        (NetworkEndpoint.state == "open") & NetworkEndpoint.matched_asset_id.is_(None)
        & NetworkEndpoint.private_mac.is_(True) & (NetworkEndpoint.last_seen_at < cut(FORGET_PRIVATE_DAYS)),
        (NetworkEndpoint.state == "open") & NetworkEndpoint.matched_asset_id.is_(None)
        & (NetworkEndpoint.last_seen_at < cut(FORGET_UNKNOWN_DAYS)),
    ))
    return stale.delete(synchronize_session=False)


async def sweep(db: Session) -> Dict:
    """Read every device and record what it sees (the poller and "Read now")."""
    tables, errors = await read_tables(db)
    return record(db, tables, errors)


_last_sweep: Optional[datetime] = None


async def run_if_due(db: Session) -> Optional[Dict]:
    """Called after every NOC poll sweep: sweep when turned on and the interval has passed."""
    global _last_sweep
    cfg = get_settings(db)
    if not cfg["enabled"]:
        return None
    now = datetime.utcnow()
    if _last_sweep is None:
        last = db.query(NetworkDiscoverySource.last_read_at).order_by(
            NetworkDiscoverySource.last_read_at.desc().nullslast()).first()
        _last_sweep = last[0] if last and last[0] else None
    if _last_sweep is not None and now - _last_sweep < timedelta(minutes=cfg["interval_minutes"]):
        return None
    _last_sweep = now
    result = await sweep(db)
    logger.info("[NOC] Network discovery: %s", result)
    return result


def rematch(db: Session) -> None:
    """Mark addresses known that an inventory change (an asset added from the Unknown devices page,
    or a MAC/IP filled in) now explains, without waiting for the next sweep."""
    by_mac, by_ip = _asset_maps(db)
    for row in db.query(NetworkEndpoint).filter(NetworkEndpoint.matched_asset_id.is_(None)).all():
        row.matched_asset_id = match_asset(row, by_mac, by_ip)
    db.commit()
