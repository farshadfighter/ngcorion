"""
Which product and release cycle of the end-of-life catalog a piece of software is.

The software inventory names what it found the way the device or its package manager does ("Ubuntu"
"22.04", "Windows Server 2019 Standard" "10.0.17763.5329", "Fortinet FortiOS" "7.0.12", "Microsoft SQL
Server 2016" "13.0.6300.2"); the catalog (endoflife.date) names release cycles ("22.04", "2019", "7.0",
"13.0-sp3"). The product is recognised from the name; the cycle from the version: major.minor when the
product has such a cycle, else major, with the exceptions below.

  Windows Server  the year (and R2) in the name, else the build (10.0.17763 is 2019)
  Windows         the build, then the edition: Enterprise and Education have their own, longer cycles
  SQL Server      major.minor, and the service pack from the build: the cycle whose latest build is the
                  first at or above this one (13.0.6300 is 13.0 SP3)
"""
import re
from typing import Dict, List, Optional, Tuple

# endoflife.date product -> how its name looks in the inventory (case-insensitive). Order matters: the
# first match wins (CentOS Stream before CentOS).
PRODUCT_NAMES: List[Tuple[str, str]] = [
    ("ubuntu", r"\bubuntu\b"),
    ("debian", r"\bdebian\b"),
    ("rhel", r"red hat enterprise linux|\brhel\b"),
    ("rocky-linux", r"\brocky\b"),
    ("almalinux", r"\balma ?linux\b"),
    ("centos-stream", r"centos stream"),
    ("centos", r"\bcentos\b"),
    ("oracle-linux", r"oracle linux"),
    ("amazon-linux", r"amazon linux"),
    ("sles", r"\bsles\b|suse linux enterprise server"),
    ("opensuse", r"opensuse leap"),
    ("windows-server", r"windows server"),
    ("windows", r"^(?:microsoft )?windows (?:7|8\.1|8|10|11)\b"),
    ("fortios", r"\bfortios\b"),
    ("cisco-ios-xe", r"\bios[ -]?xe\b"),
    ("vmware-esxi", r"\besxi\b"),
    ("mssqlserver", r"\bsql server\b"),
    ("mongodb", r"\bmongodb\b"),
    ("apache-http-server", r"apache http server|^apache httpd\b|^httpd$"),
    ("mysql", r"^mysql\b"),
    ("nginx", r"^nginx\b"),
    ("kubernetes", r"^kubernetes\b"),
    ("docker-engine", r"^docker(?: engine)?$"),
    ("postgresql", r"^postgresql\b"),
]
_PRODUCT_RX = [(k, re.compile(p, re.I)) for k, p in PRODUCT_NAMES]
_VERSION = re.compile(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")


def product_of(name: Optional[str]) -> Optional[str]:
    text = (name or "").strip()
    for key, rx in _PRODUCT_RX:
        if rx.search(text):
            return key
    return None


def numbers(version: Optional[str]) -> List[int]:
    """The leading numbers of a version, without zero padding ("17.03.04a" -> [17, 3, 4])."""
    m = _VERSION.search(version or "")
    return [int(g) for g in m.groups() if g is not None] if m else []


def generic_cycle(version: Optional[str], cycles: List[str]) -> Optional[str]:
    """major.minor when the product has that cycle, else major."""
    parts = numbers(version)
    if not parts:
        return None
    known = {_norm(c): c for c in cycles}
    if len(parts) > 1 and f"{parts[0]}.{parts[1]}" in known:
        return known[f"{parts[0]}.{parts[1]}"]
    return known.get(str(parts[0]))


def _norm(cycle: str) -> str:
    """'17.03' -> '17.3', '10.00' -> '10.0'; other cycle names unchanged."""
    if re.fullmatch(r"\d+(?:\.\d+)?", cycle):
        return ".".join(str(int(x)) for x in cycle.split("."))
    return cycle


def _build(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    p = numbers(version)
    return tuple(p[:3]) if len(p) >= 3 else None


def windows_server_cycle(name: str, version: Optional[str], cycles: List[dict]) -> Optional[str]:
    text = name.lower()
    m = re.search(r"\b(2025|2022|2019|2016|2012|2008|2003|2000)\b", text)
    if m:
        year, r2 = m.group(1), " r2" in text
        wanted = [f"{year}-r2", f"{year}-r2-sp1"] if r2 else [year, f"{year}-sp2", f"{year}-sp1"]
        ids = {c["cycle"] for c in cycles}
        for w in wanted:
            if w in ids:
                return w
    build = _build(version)
    if build:
        prefix = ".".join(map(str, build))
        hits = [c["cycle"] for c in cycles if (c.get("latest") or "").startswith(prefix)]
        lts = [h for h in hits if not h.endswith("-sac") and not h.endswith("-ac")]
        return (lts or hits or [None])[0]
    return None


def windows_cycle(name: str, version: Optional[str], cycles: List[dict]) -> Optional[str]:
    build = _build(version)
    if not build:
        return None
    prefix = ".".join(map(str, build))
    hits = [c["cycle"] for c in cycles if (c.get("latest") or "") == prefix]
    if not hits:
        return None
    text = name.lower()
    ltsc, iot = "ltsc" in text or "ltsb" in text, "iot" in text
    enterprise = "enterprise" in text or "education" in text
    plain = [h for h in hits if not h.endswith("-lts") and "-iot" not in h]
    if iot:
        pick = [h for h in hits if "-iot" in h]
    elif ltsc:
        pick = [h for h in hits if h.endswith("-e-lts")]
    else:
        pick = [h for h in plain if h.endswith("-e")] if enterprise else [h for h in plain if h.endswith("-w")]
        pick = pick or [h for h in plain if not re.search(r"-[ew]$", h)] or plain
    return (pick or hits)[0]


def mssql_cycle(version: Optional[str], cycles: List[dict]) -> Optional[str]:
    parts = numbers(version)
    if len(parts) < 3:
        return None
    base = f"{parts[0]}.{parts[1]}"
    mine = []
    for c in cycles:
        cid = c["cycle"]
        head = cid.split("-", 1)[0]
        if _norm(head) != base:
            continue
        latest = numbers(c.get("latest"))
        if len(latest) >= 3:
            mine.append((latest[2], cid))
    if not mine:
        return None
    above = sorted(b for b in mine if b[0] >= parts[2])
    return (above[0] if above else max(mine))[1]


def identify(name: Optional[str], version: Optional[str], catalog: Dict[str, dict],
             custom: Optional[Dict[str, str]] = None) -> Tuple[Optional[str], Optional[str]]:
    """(product key, cycle) of a piece of software, either None when unknown. `catalog` maps product key
    -> product (with "cycles"); `custom` maps a lower-cased software name -> the organisation's product."""
    text = (name or "").strip()
    key = (custom or {}).get(text.lower()) or product_of(text)
    if key is None or key not in catalog:
        return key, None
    cycles = catalog[key].get("cycles") or []
    if not version:
        # an OS typed by hand: "Ubuntu 22.04", "Windows Server 2016"
        version = " ".join(re.findall(r"\d+(?:\.\d+)*", text)) or None
    if key == "windows-server":
        return key, windows_server_cycle(text, version, cycles)
    if key == "windows":
        return key, windows_cycle(text, version, cycles)
    if key == "mssqlserver":
        return key, mssql_cycle(version, cycles) or _sql_year(text, cycles)
    return key, generic_cycle(version, [c["cycle"] for c in cycles])


_SQL_YEARS = {"2025": "17.0", "2022": "16.0", "2019": "15.0", "2017": "14.0", "2016": "13.0", "2014": "12.0",
              "2012": "11.0"}


def _sql_year(name: str, cycles: List[dict]) -> Optional[str]:
    m = re.search(r"\b(20\d\d)\b", name)
    base = _SQL_YEARS.get(m.group(1)) if m else None
    if not base:
        return None
    mine = [c["cycle"] for c in cycles if c["cycle"].split("-", 1)[0] == base and "acp" not in c["cycle"]]
    return mine[0] if mine else None
