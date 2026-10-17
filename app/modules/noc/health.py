"""
Device health over SNMP: CPU, memory, disk, temperature and the host's own uptime.

collect() walks a few read-only MIB subtrees after the system group (snmp_client.poll_asset), each
best effort with its own timeout: a device that does not implement a MIB simply has nothing there.
summarize() turns what came back into one value per measure, choosing the most specific source:

  CPU          FortiGate fgSysCpuUsage; Cisco cpmCPUTotal1minRev (average of the CPUs);
               HOST-RESOURCES hrProcessorLoad (average of the cores); UCD 100 - ssCpuIdle
  memory       FortiGate fgSysMemUsage; Cisco ciscoMemoryPool "Processor" (else cpmCPUMemoryUsed/Free);
               UCD total - available (memSysAvail, net-snmp 5.9+; else total - free - buffers - cache,
               which is what "free" calls used); HOST-RESOURCES hrStorageRam
  disk         FortiGate fgSysDiskUsage / Capacity; HOST-RESOURCES hrStorageFixedDisk (the fullest
               file system; /proc, /sys, /run, /dev and snap images left out)
  temperature  the hottest of: FortiGate hardware sensors named "...temp..."/"DTS..."; Cisco
               ciscoEnvMonTemperatureStatusValue; ENTITY-SENSOR-MIB sensors in celsius; UCD lm-sensors
  uptime       HOST-RESOURCES hrSystemUptime (the host's, not the SNMP agent's), else sysUpTime

Vendor subtrees are walked only when sysDescr names the vendor, so a Linux server is asked nothing
about Cisco. Nothing here writes to a device.
"""
import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

HR_SYSTEM_UPTIME = "1.3.6.1.2.1.25.1.1"
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"           # .2 type .3 descr .4 allocation units .5 size .6 used
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
UCD_MEMORY = "1.3.6.1.4.1.2021.4"              # .5 total .6 free .14 buffers .15 cached .27 available (kB)
UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11"
UCD_LM_TEMP = "1.3.6.1.4.1.2021.13.16.2.1"    # .2 name .3 value (millidegrees)
ENT_SENSOR = "1.3.6.1.2.1.99.1.1.1"            # .1 type .2 scale .3 precision .4 value
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
CISCO_CPU_1MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
CISCO_CPU_MEM_USED = "1.3.6.1.4.1.9.9.109.1.1.1.1.12"   # kB
CISCO_CPU_MEM_FREE = "1.3.6.1.4.1.9.9.109.1.1.1.1.13"   # kB
CISCO_MEMPOOL = "1.3.6.1.4.1.9.9.48.1.1.1"     # .2 name .5 used .6 free (bytes)
CISCO_TEMPERATURE = "1.3.6.1.4.1.9.9.13.1.3.1"  # .2 description .3 value (celsius)
FORTI_SYSTEM = "1.3.6.1.4.1.12356.101.4.1"     # .3 cpu % .4 memory % .5 memory kB .6 disk MB .7 disk capacity MB
FORTI_SENSOR = "1.3.6.1.4.1.12356.101.4.3.2.1"  # .2 name .3 value

GENERIC = [HR_SYSTEM_UPTIME, f"{HR_STORAGE}.2", f"{HR_STORAGE}.3", f"{HR_STORAGE}.4", f"{HR_STORAGE}.5",
           f"{HR_STORAGE}.6", HR_PROCESSOR_LOAD]
UCD = [UCD_MEMORY, UCD_CPU_IDLE, UCD_LM_TEMP]
ENTITY = [f"{ENT_SENSOR}.1", f"{ENT_SENSOR}.2", f"{ENT_SENSOR}.3", f"{ENT_SENSOR}.4"]
CISCO = [CISCO_CPU_1MIN, CISCO_CPU_MEM_USED, CISCO_CPU_MEM_FREE, f"{CISCO_MEMPOOL}.2", f"{CISCO_MEMPOOL}.5",
         f"{CISCO_MEMPOOL}.6", f"{CISCO_TEMPERATURE}.2", f"{CISCO_TEMPERATURE}.3"]
FORTI = [FORTI_SYSTEM, f"{FORTI_SENSOR}.2", f"{FORTI_SENSOR}.3"]

_SKIP_MOUNTS = ("/proc", "/sys", "/run", "/dev", "/snap")
MAX_FILESYSTEMS = 20
MAX_SENSORS = 20


@dataclass
class Health:
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    memory_total_bytes: Optional[int] = None
    disk_percent: Optional[float] = None
    temperature_c: Optional[float] = None
    uptime_ticks: Optional[int] = None               # hrSystemUptime, when the device has it
    source: Optional[str] = None
    filesystems: List[Dict] = field(default_factory=list)
    sensors: List[Dict] = field(default_factory=list)

    def detail(self) -> Optional[Dict]:
        if self.source is None and not self.filesystems and not self.sensors:
            return None
        return {"source": self.source, "filesystems": self.filesystems, "sensors": self.sensors}


def _text(value) -> Optional[str]:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00 ").strip()
    return None if value is None else str(value).strip()


def _num(value) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, timedelta):
        return value.total_seconds() * 100
    if isinstance(value, bytes):
        value = _text(value)
    try:
        return float(str(value).strip().split()[0])
    except (ValueError, IndexError):
        return None


def _column(values: Dict[str, Any], base: str) -> Dict[str, Any]:
    """{row index: value} of one table column ("base.<index>")."""
    prefix = base + "."
    return {oid[len(prefix):]: v for oid, v in values.items() if oid.startswith(prefix)}


def _pct(used, total) -> Optional[float]:
    if used is None or not total or total <= 0:
        return None
    return round(max(0.0, min(100.0, used / total * 100)), 1)


def _avg(numbers) -> Optional[float]:
    numbers = [n for n in numbers if n is not None]
    return round(sum(numbers) / len(numbers), 1) if numbers else None


def _cpu(values: Dict[str, Any]) -> tuple:
    forti = _num(values.get(f"{FORTI_SYSTEM}.3.0"))
    if forti is not None:
        return forti, "fortigate"
    cisco = _avg(_num(v) for v in _column(values, CISCO_CPU_1MIN).values())
    if cisco is not None:
        return cisco, "cisco"
    hr = _avg(_num(v) for v in _column(values, HR_PROCESSOR_LOAD).values())
    if hr is not None:
        return hr, "host-resources"
    idle = _num(values.get(f"{UCD_CPU_IDLE}.0"))
    if idle is not None:
        return round(100 - idle, 1), "ucd"
    return None, None


def _storage(values: Dict[str, Any]) -> List[Dict]:
    rows = []
    types = _column(values, f"{HR_STORAGE}.2")
    for idx, kind in types.items():
        units = _num(values.get(f"{HR_STORAGE}.4.{idx}")) or 1
        size = _num(values.get(f"{HR_STORAGE}.5.{idx}"))
        used = _num(values.get(f"{HR_STORAGE}.6.{idx}"))
        if size is None or used is None:
            continue
        rows.append({"type": str(kind).lstrip("."), "name": _text(values.get(f"{HR_STORAGE}.3.{idx}")) or idx,
                     "size": int(size * units), "used": int(used * units)})
    return rows


def _memory(values: Dict[str, Any], storage: List[Dict]) -> tuple:
    forti = _num(values.get(f"{FORTI_SYSTEM}.4.0"))
    if forti is not None:
        kb = _num(values.get(f"{FORTI_SYSTEM}.5.0"))
        return forti, int(kb * 1024) if kb else None, "fortigate"
    names = _column(values, f"{CISCO_MEMPOOL}.2")
    for idx, name in names.items():
        if "processor" in (_text(name) or "").lower():
            used, free = _num(values.get(f"{CISCO_MEMPOOL}.5.{idx}")), _num(values.get(f"{CISCO_MEMPOOL}.6.{idx}"))
            if used is not None and free is not None:
                return _pct(used, used + free), int(used + free), "cisco"
    used_kb = [_num(v) for v in _column(values, CISCO_CPU_MEM_USED).values()]
    free_kb = [_num(v) for v in _column(values, CISCO_CPU_MEM_FREE).values()]
    if used_kb and free_kb and None not in used_kb + free_kb:
        total = sum(used_kb) + sum(free_kb)
        return _pct(sum(used_kb), total), int(total * 1024), "cisco"
    total = _num(values.get(f"{UCD_MEMORY}.5.0"))
    available = _num(values.get(f"{UCD_MEMORY}.27.0"))
    free = _num(values.get(f"{UCD_MEMORY}.6.0"))
    if total and available is not None:
        return _pct(max(total - available, 0), total), int(total * 1024), "ucd"
    if total and free is not None:
        cached = (_num(values.get(f"{UCD_MEMORY}.14.0")) or 0) + (_num(values.get(f"{UCD_MEMORY}.15.0")) or 0)
        return _pct(max(total - free - cached, 0), total), int(total * 1024), "ucd"
    for row in storage:
        if row["type"] == HR_STORAGE_RAM and row["size"]:
            return _pct(row["used"], row["size"]), row["size"], "host-resources"
    return None, None, None


def _disks(values: Dict[str, Any], storage: List[Dict]) -> List[Dict]:
    out = []
    used_mb, cap_mb = _num(values.get(f"{FORTI_SYSTEM}.6.0")), _num(values.get(f"{FORTI_SYSTEM}.7.0"))
    if cap_mb:
        out.append({"name": "disk", "size": int(cap_mb * 2 ** 20), "used": int((used_mb or 0) * 2 ** 20),
                    "percent": _pct(used_mb or 0, cap_mb)})
    for row in storage:
        if row["type"] != HR_STORAGE_FIXED_DISK or not row["size"] or row["name"].startswith(_SKIP_MOUNTS):
            continue
        out.append({"name": row["name"][:120], "size": row["size"], "used": row["used"],
                    "percent": _pct(row["used"], row["size"])})
    out.sort(key=lambda d: d["percent"] or 0, reverse=True)
    return out[:MAX_FILESYSTEMS]


_ENT_SCALE = {i: 10 ** ((i - 9) * 3) for i in range(1, 18)}      # yocto(1) .. units(9) .. yotta(17)


def _sensors(values: Dict[str, Any]) -> List[Dict]:
    out = []
    forti_names = _column(values, f"{FORTI_SENSOR}.2")
    for idx, name in forti_names.items():
        label = _text(name) or idx
        if "temp" in label.lower() or label.upper().startswith("DTS"):
            out.append({"name": label, "celsius": _num(values.get(f"{FORTI_SENSOR}.3.{idx}"))})
    for idx, value in _column(values, f"{CISCO_TEMPERATURE}.3").items():
        out.append({"name": _text(values.get(f"{CISCO_TEMPERATURE}.2.{idx}")) or f"sensor {idx}", "celsius": _num(value)})
    for idx, kind in _column(values, f"{ENT_SENSOR}.1").items():
        if _num(kind) != 8:                                         # celsius(8)
            continue
        raw = _num(values.get(f"{ENT_SENSOR}.4.{idx}"))
        if raw is None:
            continue
        scale = _ENT_SCALE.get(int(_num(values.get(f"{ENT_SENSOR}.2.{idx}")) or 9), 1)
        precision = int(_num(values.get(f"{ENT_SENSOR}.3.{idx}")) or 0)
        name = _text(values.get(f"{ENT_PHYSICAL_NAME}.{idx}")) or f"sensor {idx}"
        out.append({"name": name, "celsius": round(raw * scale / 10 ** precision, 1)})
    for idx, value in _column(values, f"{UCD_LM_TEMP}.3").items():
        milli = _num(value)
        if milli is not None:
            out.append({"name": _text(values.get(f"{UCD_LM_TEMP}.2.{idx}")) or f"sensor {idx}",
                        "celsius": round(milli / 1000, 1)})
    # a sensor that is absent reads 0 or a huge sentinel on some devices
    out = [s for s in out if s["celsius"] is not None and -40 < s["celsius"] < 200 and s["celsius"] != 0]
    out.sort(key=lambda s: s["celsius"], reverse=True)
    return out[:MAX_SENSORS]


def summarize(values: Dict[str, Any]) -> Health:
    """One value per measure from the walked OIDs ({"1.3.6...": value}); see the module docstring."""
    h = Health()
    up = values.get(f"{HR_SYSTEM_UPTIME}.0")
    if up is not None and _num(up) is not None:
        h.uptime_ticks = int(_num(up))
    storage = _storage(values)
    h.cpu_percent, cpu_source = _cpu(values)
    h.memory_percent, h.memory_total_bytes, mem_source = _memory(values, storage)
    h.filesystems = _disks(values, storage)
    h.disk_percent = h.filesystems[0]["percent"] if h.filesystems else None
    h.sensors = _sensors(values)
    h.temperature_c = h.sensors[0]["celsius"] if h.sensors else None
    h.source = cpu_source or mem_source or ("host-resources" if h.filesystems else None)
    if h.cpu_percent is not None:
        h.cpu_percent = round(max(0.0, min(100.0, h.cpu_percent)), 1)
    return h


async def _walk(client, roots: List[str], timeout: float) -> Dict[str, Any]:
    async def go():
        return {str(vb.oid): vb.value async for vb in client.multiwalk(roots)}
    try:
        return await asyncio.wait_for(go(), timeout=timeout)
    except Exception:  # noqa: BLE001 - a MIB the device does not have, or a slow answer, leaves it out
        return {}


async def collect(client, sys_descr: Optional[str], timeout: float) -> Health:
    """Walk the health subtrees of one device (already known to answer) and summarize them."""
    descr = (sys_descr or "").lower()
    groups = [GENERIC, UCD, ENTITY]
    if "cisco" in descr:
        groups.append(CISCO)
    if "forti" in descr:
        groups.append(FORTI)
    values: Dict[str, Any] = {}
    for part in await asyncio.gather(*(_walk(client, g, timeout) for g in groups)):
        values.update(part)
    celsius = [idx for idx, kind in _column(values, f"{ENT_SENSOR}.1").items() if _num(kind) == 8]
    if celsius:
        values.update(await _walk(client, [ENT_PHYSICAL_NAME], timeout))
    return summarize(values)
