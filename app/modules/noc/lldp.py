"""
Who is cabled to whom, from the neighbour tables a router or switch keeps itself, read over SNMP
(read-only):

  LLDP   IEEE 802.1AB LLDP-MIB (every vendor): lldpRemTable, one row per neighbour heard on a local
         port - its chassis id, port id and description, system name and description, capabilities -
         plus lldpRemManAddrTable (its management address) and lldpLocPortTable (the local port's
         name) and lldpLocChassisId (this device's own chassis id, which its neighbours report).
  CDP    CISCO-CDP-MIB cdpCacheTable (Cisco, and some others): per local ifIndex, the neighbour's
         device id, port, platform, version, address and capabilities.

Parsing is kept apart from the SNMP calls (parse_* take (oid, value) pairs) so it can be tested
without a device; every walk is capped and timed like the ARP / MAC tables (neighbors.py).
"""
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.modules.noc.neighbors import _as_int, _suffix, _walk
from app.modules.noc.oui import normalize_mac

LLDP_LOC_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.3.1"   # .0
LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2"        # .0
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"            # lldpLocPortEntry: .2 id subtype .3 id .4 desc, index portNum
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"                 # lldpRemEntry, index timeMark.localPortNum.remIndex
LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1"        # lldpRemManAddrEntry, index ... .addrSubtype.len.addr
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"            # cdpCacheEntry, index ifIndex.deviceIndex

# lldpRemEntry columns
_REM_CHASSIS_SUBTYPE, _REM_CHASSIS_ID, _REM_PORT_SUBTYPE, _REM_PORT_ID = 4, 5, 6, 7
_REM_PORT_DESC, _REM_SYS_NAME, _REM_SYS_DESC, _REM_CAPS_ENABLED = 8, 9, 10, 12
# cdpCacheEntry columns
_CDP_ADDR_TYPE, _CDP_ADDR, _CDP_VERSION, _CDP_DEVICE_ID, _CDP_PORT, _CDP_PLATFORM, _CDP_CAPS = 3, 4, 5, 6, 7, 8, 9

# lldpSysCapEnabled is a BITS value: bit 0 is the high bit of the first octet.
_LLDP_CAPS = ["other", "repeater", "bridge", "wlan_ap", "router", "phone", "docsis", "station"]
# cdpCacheCapabilities: a 32-bit mask in four octets.
_CDP_CAP_BITS = [(0x01, "router"), (0x02, "bridge"), (0x04, "bridge"), (0x08, "bridge"), (0x10, "station"),
             (0x40, "repeater"), (0x80, "phone"), (0x200, "station")]

MAX_TEXT = 255


@dataclass
class Neighbor:
    """One neighbour as one device reported it."""
    protocol: str                       # lldp | cdp
    local_port: str                     # the reporting device's port, as it names it
    local_if_index: Optional[int]       # when known (CDP always; LLDP when the port maps to one)
    chassis_id: Optional[str]           # LLDP chassis id (a MAC when it is one), or CDP device id
    chassis_kind: str                   # mac | ip | name
    remote_port: Optional[str]
    remote_port_desc: Optional[str] = None
    remote_name: Optional[str] = None
    remote_mgmt_ip: Optional[str] = None
    remote_description: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)


@dataclass
class NeighborReport:
    """What one device reported. `errors` names the tables that failed (timeout, no access)."""
    neighbors: List[Neighbor] = field(default_factory=list)
    local_chassis_id: Optional[str] = None
    lldp: bool = False                  # the device answered the LLDP tables
    cdp: bool = False
    errors: List[str] = field(default_factory=list)


def _text(value) -> Optional[str]:
    """An SNMP string as text: printable bytes decoded, anything else as hex, trimmed and capped."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value).rstrip(b"\x00")
        try:
            out = raw.decode("utf-8")
        except UnicodeDecodeError:
            out = None
        if out is None or any(ord(c) < 32 and c not in "\t\r\n" for c in out):
            out = ":".join(f"{b:02x}" for b in raw)
    else:
        out = str(value)
    out = " ".join(out.split())
    return out[:MAX_TEXT] or None


def _ipv4(raw) -> Optional[str]:
    if isinstance(raw, (bytes, bytearray)) and len(raw) == 4:
        return str(ipaddress.IPv4Address(bytes(raw)))
    text = _text(raw)
    try:
        return str(ipaddress.IPv4Address(text)) if text else None
    except ValueError:
        return None


def chassis_value(subtype: Optional[int], raw) -> Tuple[Optional[str], str]:
    """LLDP chassis id -> (value, kind). Subtype 4 is a MAC, 5 a network address (first octet the
    address family, 1 = IPv4); everything else (interface name, local, ...) is text."""
    if subtype == 4:
        mac = normalize_mac(raw)
        if mac:
            return mac, "mac"
    if subtype == 5 and isinstance(raw, (bytes, bytearray)) and len(raw) == 5 and raw[0] == 1:
        return str(ipaddress.IPv4Address(bytes(raw[1:]))), "ip"
    return _text(raw), "name"


def port_value(subtype: Optional[int], raw) -> Optional[str]:
    """LLDP port id as a name: subtype 3 is a MAC, 4 a network address; others are text."""
    if subtype == 3:
        return normalize_mac(raw) or _text(raw)
    if subtype == 4 and isinstance(raw, (bytes, bytearray)) and len(raw) == 5 and raw[0] == 1:
        return str(ipaddress.IPv4Address(bytes(raw[1:])))
    return _text(raw)


def lldp_caps(raw) -> List[str]:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    out = []
    for bit, name in enumerate(_LLDP_CAPS):
        octet, mask = divmod(bit, 8)
        if octet < len(raw) and raw[octet] & (0x80 >> mask):
            out.append(name)
    return out


def cdp_caps(raw) -> List[str]:
    if isinstance(raw, (bytes, bytearray)):
        value = int.from_bytes(bytes(raw)[:4], "big") if raw else 0
    else:
        value = _as_int(raw) or 0
    out: List[str] = []
    for mask, name in _CDP_CAP_BITS:
        if value & mask and name not in out:
            out.append(name)
    return out


def _columns(rows, base: str, index_len: Optional[int] = None) -> Dict[Tuple[int, ...], Dict[int, object]]:
    """Walk rows of a table -> {index: {column: value}}."""
    out: Dict[Tuple[int, ...], Dict[int, object]] = {}
    for oid, value in rows:
        s = _suffix(oid, base)
        if not s or len(s) < 2 or (index_len is not None and len(s) != index_len + 1):
            continue
        out.setdefault(tuple(s[1:]), {})[s[0]] = value
    return out


def parse_local_ports(rows) -> Dict[int, Tuple[Optional[str], Optional[str]]]:
    """lldpLocPortTable -> {portNum: (port id as a name, port description)}."""
    out = {}
    for index, cols in _columns(rows, LLDP_LOC_PORT, 1).items():
        out[index[0]] = (port_value(_as_int(cols.get(2)), cols.get(3)), _text(cols.get(4)))
    return out


def parse_man_addrs(rows) -> Dict[Tuple[int, int, int], str]:
    """lldpRemManAddrTable -> {(timeMark, localPortNum, remIndex): IPv4 management address}. The
    address is in the row index (subtype 1 = IPv4, then its length 4, then the four octets)."""
    out: Dict[Tuple[int, int, int], str] = {}
    for oid, _ in rows:
        s = _suffix(oid, LLDP_REM_MAN_ADDR)
        if not s or len(s) != 1 + 3 + 1 + 1 + 4 or s[4] != 1 or s[5] != 4:
            continue
        key = (s[1], s[2], s[3])
        if key not in out and all(0 <= o <= 255 for o in s[6:]):
            out[key] = ".".join(str(o) for o in s[6:])
    return out


def parse_lldp(rem_rows, man_rows, local_ports: Dict[int, Tuple[Optional[str], Optional[str]]],
               if_names: Dict[str, int], by_index: Optional[Dict[int, str]] = None) -> List[Neighbor]:
    """lldpRemTable rows -> neighbours. The local port is named from lldpLocPortTable (its id when
    that is a name, else its description) and mapped to an ifIndex by name when the device's
    interfaces are known (`if_names`: name or description, lower case -> ifIndex). A device without
    lldpLocPortTable numbers its ports by ifIndex on practically every platform (`by_index`)."""
    man = parse_man_addrs(man_rows)
    out = []
    for index, cols in _columns(rem_rows, LLDP_REM, 3).items():
        _, port_num, _ = index
        chassis, kind = chassis_value(_as_int(cols.get(_REM_CHASSIS_SUBTYPE)), cols.get(_REM_CHASSIS_ID))
        local_id, local_desc = local_ports.get(port_num, (None, None))
        if_index = None
        if not (local_id or local_desc) and by_index and port_num in by_index:
            local_id, if_index = by_index[port_num], port_num
        for name in (local_id, local_desc):
            if name and name.lower() in if_names:
                if_index = if_names[name.lower()]
                break
        out.append(Neighbor(
            protocol="lldp",
            local_port=local_id or local_desc or f"port {port_num}",
            local_if_index=if_index,
            chassis_id=chassis, chassis_kind=kind,
            remote_port=port_value(_as_int(cols.get(_REM_PORT_SUBTYPE)), cols.get(_REM_PORT_ID)),
            remote_port_desc=_text(cols.get(_REM_PORT_DESC)),
            remote_name=_text(cols.get(_REM_SYS_NAME)),
            remote_mgmt_ip=man.get(index),
            remote_description=_text(cols.get(_REM_SYS_DESC)),
            capabilities=lldp_caps(cols.get(_REM_CAPS_ENABLED)),
        ))
    return out


def parse_cdp(rows, if_names_by_index: Dict[int, str]) -> List[Neighbor]:
    """cdpCacheTable rows -> neighbours (the local port is the row's ifIndex)."""
    out = []
    for index, cols in _columns(rows, CDP_CACHE, 2).items():
        if_index = index[0]
        device = _text(cols.get(_CDP_DEVICE_ID))
        platform, version = _text(cols.get(_CDP_PLATFORM)), _text(cols.get(_CDP_VERSION))
        description = " - ".join(p for p in (platform, version) if p) or None
        ip = _ipv4(cols.get(_CDP_ADDR)) if _as_int(cols.get(_CDP_ADDR_TYPE)) in (1, None) else None
        out.append(Neighbor(
            protocol="cdp",
            local_port=if_names_by_index.get(if_index) or f"ifIndex {if_index}",
            local_if_index=if_index,
            chassis_id=device, chassis_kind="name",
            remote_port=_text(cols.get(_CDP_PORT)),
            remote_name=device,
            remote_mgmt_ip=ip,
            remote_description=description[:MAX_TEXT] if description else None,
            capabilities=cdp_caps(cols.get(_CDP_CAPS)),
        ))
    return out


async def collect(client, interfaces: List[Tuple[int, Optional[str], Optional[str]]],
                  timeout: float = 30.0) -> NeighborReport:
    """Read the LLDP and CDP neighbour tables of one device. Never raises: a table the device does
    not have is empty, one that fails is named in `errors`. `interfaces` is the device's interfaces
    from the NOC poll, (ifIndex, ifName, ifDescr), to name and map local ports."""
    if_names_by_index = {i: (n or d) for i, n, d in interfaces if n or d}
    out = NeighborReport()

    async def table(name: str, base: str):
        try:
            return await _walk(client, base, timeout)
        except Exception as exc:  # noqa: BLE001 - timeouts, no such object, access denied
            out.errors.append(f"{name}: {type(exc).__name__}")
            return []

    loc = await table("LLDP local", LLDP_LOC_CHASSIS_SUBTYPE.rsplit(".", 1)[0])
    subtype = raw = None
    for oid, value in loc:
        if str(oid).lstrip(".") == LLDP_LOC_CHASSIS_SUBTYPE + ".0":
            subtype = _as_int(value)
        elif str(oid).lstrip(".") == LLDP_LOC_CHASSIS_ID + ".0":
            raw = value
    if raw is not None:
        out.local_chassis_id = chassis_value(subtype, raw)[0]
    local_ports = parse_local_ports([r for r in loc if str(r[0]).lstrip(".").startswith(LLDP_LOC_PORT + ".")])

    rem = await table("LLDP neighbours", LLDP_REM)
    man = await table("LLDP management addresses", LLDP_REM_MAN_ADDR) if rem else []
    names: Dict[str, int] = {}
    for idx, name, descr in interfaces:
        for n in (name, descr):
            if n:
                names.setdefault(n.lower(), idx)
    out.neighbors = parse_lldp(rem, man, local_ports, names, if_names_by_index)
    out.lldp = bool(loc or rem)

    cdp_rows = await table("CDP neighbours", CDP_CACHE)
    out.neighbors += parse_cdp(cdp_rows, if_names_by_index)
    out.cdp = bool(cdp_rows)
    # A device without LLDP or CDP (a server, an old router) has no such tables; that is not an error.
    out.errors = [e for e in out.errors if "NoSuchOID" not in e and "EndOfMib" not in e]
    return out
