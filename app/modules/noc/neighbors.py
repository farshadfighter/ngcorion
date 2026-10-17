"""
Which addresses a monitored router or switch sees on the network, read over SNMP (read-only).

  ARP table   IP-MIB ipNetToMediaTable (RFC 1213), or the newer ipNetToPhysicalTable (RFC 4293)
              when a device only has that one: IPv4 address -> MAC, and the interface it is on.
  MAC table   Q-BRIDGE-MIB dot1qTpFdbTable (RFC 4363; per VLAN), or BRIDGE-MIB dot1dTpFdbTable
              (RFC 4188): MAC -> bridge port, which dot1dBasePortTable maps to an interface.
  Own MACs    IF-MIB ifPhysAddress: the device's own interface addresses, which then belong to
              the device itself rather than to an unknown neighbour.

Cisco IOS answers the MAC table per VLAN only with "community@vlan" indexing; without it the
VLAN-1 table (or nothing) comes back. The ARP table of the routers is then what finds devices.

Parsing is kept apart from the SNMP calls (parse_* take (oid, value) pairs) so it can be tested
without a device. Every table is capped and timed, so a core switch with a very large table
cannot stall the poller.
"""
import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple

from app.modules.noc.oui import is_unicast, normalize_mac

ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"          # ipNetToMediaPhysAddress.<ifIndex>.<a.b.c.d>
ARP_TYPE = "1.3.6.1.2.1.4.22.1.4"          # ipNetToMediaType: 1 other 2 invalid 3 dynamic 4 static
NET_PHYS = "1.3.6.1.2.1.4.35.1.4"          # ipNetToPhysicalPhysAddress.<ifIndex>.<type>.<len>.<addr>
NET_TYPE = "1.3.6.1.2.1.4.35.1.6"          # ipNetToPhysicalType: ... 5 local
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort.<fdbId>.<6 MAC octets>
QFDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"  # 1 other 2 invalid 3 learned 4 self 5 mgmt
DFDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort.<6 MAC octets>
DFDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex.<bridge port>
IF_PHYS = "1.3.6.1.2.1.2.2.1.6"             # ifPhysAddress.<ifIndex>

MAX_ROWS = 50_000          # per table
TABLE_TIMEOUT = 30.0       # seconds per table

_SKIP_ARP_TYPES = {2, 5}   # invalid, local
_SKIP_FDB_STATUS = {2, 4}  # invalid, self


@dataclass
class ArpEntry:
    ip: str
    mac: str
    if_index: Optional[int]


@dataclass
class FdbEntry:
    mac: str
    if_index: Optional[int]
    vlan: Optional[int]


@dataclass
class NeighborTables:
    """What one device reported. `errors` names the tables that failed (timeout, no access)."""
    arp: List[ArpEntry] = field(default_factory=list)
    fdb: List[FdbEntry] = field(default_factory=list)
    own_macs: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)


def _suffix(oid: str, base: str) -> Optional[List[int]]:
    oid = str(oid).lstrip(".")
    if not oid.startswith(base + "."):
        return None
    try:
        return [int(p) for p in oid[len(base) + 1:].split(".")]
    except ValueError:
        return None


def _as_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_arp(phys: Iterable[Tuple[str, object]], types: Iterable[Tuple[str, object]]) -> List[ArpEntry]:
    """ipNetToMediaTable rows -> entries, without invalid/local ones and non-unicast MACs."""
    kind = {tuple(s): _as_int(v) for oid, v in types if (s := _suffix(oid, ARP_TYPE)) and len(s) == 5}
    out = []
    for oid, value in phys:
        s = _suffix(oid, ARP_PHYS)
        if not s or len(s) != 5 or kind.get(tuple(s)) in _SKIP_ARP_TYPES:
            continue
        mac = normalize_mac(value)
        if mac and is_unicast(mac):
            out.append(ArpEntry(ip=".".join(str(o) for o in s[1:]), mac=mac, if_index=s[0]))
    return out


def parse_net_to_physical(phys, types) -> List[ArpEntry]:
    """ipNetToPhysicalTable rows (IPv4 only: address type 1, length 4) -> entries."""
    kind = {tuple(s): _as_int(v) for oid, v in types if (s := _suffix(oid, NET_TYPE))}
    out = []
    for oid, value in phys:
        s = _suffix(oid, NET_PHYS)
        if not s or len(s) != 7 or s[1] != 1 or s[2] != 4 or kind.get(tuple(s)) in _SKIP_ARP_TYPES:
            continue
        mac = normalize_mac(value)
        if mac and is_unicast(mac):
            out.append(ArpEntry(ip=".".join(str(o) for o in s[3:]), mac=mac, if_index=s[0]))
    return out


def _mac_from_octets(octets: List[int]) -> Optional[str]:
    if len(octets) != 6 or any(not 0 <= o <= 255 for o in octets):
        return None
    return ":".join(f"{o:02x}" for o in octets)


def parse_fdb(ports, statuses, port_ifindex: dict, qbridge: bool) -> List[FdbEntry]:
    """MAC table rows -> entries with the interface (via the bridge port map) and, for Q-BRIDGE, the
    VLAN (the filtering database id, which is the VLAN id on practically every switch)."""
    base_port, base_status, width = (QFDB_PORT, QFDB_STATUS, 7) if qbridge else (DFDB_PORT, DFDB_STATUS, 6)
    status = {tuple(s): _as_int(v) for oid, v in statuses if (s := _suffix(oid, base_status))}
    out = []
    for oid, value in ports:
        s = _suffix(oid, base_port)
        if not s or len(s) != width or status.get(tuple(s)) in _SKIP_FDB_STATUS:
            continue
        mac = _mac_from_octets(s[-6:])
        port = _as_int(value)
        if not mac or not is_unicast(mac) or not port:
            continue
        vlan = s[0] if qbridge and 1 <= s[0] <= 4094 else None
        out.append(FdbEntry(mac=mac, if_index=port_ifindex.get(port), vlan=vlan))
    return out


def parse_port_ifindex(rows) -> dict:
    return {s[0]: _as_int(v) for oid, v in rows if (s := _suffix(oid, BASE_PORT_IFINDEX)) and len(s) == 1}


def parse_own_macs(rows) -> Set[str]:
    out = set()
    for _, value in rows:
        mac = normalize_mac(value)
        if mac and is_unicast(mac):
            out.add(mac)
    return out


def valid_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr.is_loopback or ip.endswith(".255"))


async def _walk(client, base: str, timeout: float) -> List[Tuple[str, object]]:
    rows: List[Tuple[str, object]] = []

    async def run():
        async for vb in client.walk(base):
            rows.append((str(vb.oid), vb.value))
            if len(rows) >= MAX_ROWS:
                break

    await asyncio.wait_for(run(), timeout=timeout)
    return rows


async def collect(client, timeout: float = TABLE_TIMEOUT) -> NeighborTables:
    """Read the ARP and MAC tables of one device. Never raises: a table the device does not have
    is simply empty, one that fails is named in `errors`."""
    out = NeighborTables()

    async def table(name: str, base: str) -> List[Tuple[str, object]]:
        try:
            return await _walk(client, base, timeout)
        except Exception as exc:  # noqa: BLE001 - timeouts, no such object, access denied
            out.errors.append(f"{name}: {type(exc).__name__}")
            return []

    out.own_macs = parse_own_macs(await table("ifPhysAddress", IF_PHYS))

    arp = parse_arp(await table("ARP", ARP_PHYS), await table("ARP type", ARP_TYPE))
    if not arp:
        arp = parse_net_to_physical(await table("ipNetToPhysical", NET_PHYS),
                                    await table("ipNetToPhysical type", NET_TYPE))
    out.arp = [e for e in arp if valid_ipv4(e.ip)]

    port_map = parse_port_ifindex(await table("bridge ports", BASE_PORT_IFINDEX))
    fdb = parse_fdb(await table("Q-BRIDGE MAC table", QFDB_PORT),
                    await table("Q-BRIDGE status", QFDB_STATUS), port_map, qbridge=True)
    if not fdb:
        fdb = parse_fdb(await table("BRIDGE MAC table", DFDB_PORT),
                        await table("BRIDGE status", DFDB_STATUS), port_map, qbridge=False)
    out.fdb = fdb
    # A device without a bridge (a router, a server) has no MAC table; that is not an error.
    out.errors = [e for e in out.errors if "NoSuchOID" not in e and "EndOfMib" not in e]
    return out
