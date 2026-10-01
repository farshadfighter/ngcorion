"""
What Auditing and Hardening can run against.

The single list behind the target picker in both forms. A new audit or
hardening module (Sophos, MySQL, Kubernetes...) registers itself here with
its category, icon, versions and how it connects, and appears in both
pickers without touching the frontend.

`device_type` values are the ones the audit/hardening endpoints already take
(see front/src/store/*Slice getDeviceApiPath): "cisco", "linux-ubuntu-22",
"mssql-2019"... A target with versions has one device_type per version; one
without has a single device_type.

`family` is the device family assets are classified into
(app/utils/device_classification.py) and is what inventory counts use.
"""
from dataclasses import dataclass, field
from typing import Optional, Tuple

# Display order of the picker's category rail.
CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("network", "Network & security"),
    ("servers", "Servers & OS"),
    ("platforms", "Containers & virtualisation"),
    ("databases", "Databases"),
    ("web", "Web & application servers"),
    ("services", "Directory & network services"),
)

MODES = ("audit", "hardening")


@dataclass(frozen=True)
class TargetVersion:
    device_type: str
    label: str                 # "22.04 LTS"
    group: Optional[str] = None  # "Ubuntu" - versions are grouped by it in the picker


@dataclass(frozen=True)
class Target:
    id: str
    label: str
    description: str
    category: str
    family: str
    icon: str                  # app.core.asset_icons key
    monogram: str              # two letters drawn on the icon
    connects_via: str
    device_type: Optional[str] = None
    versions: Tuple[TargetVersion, ...] = ()
    modes: Tuple[str, ...] = MODES
    keywords: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def device_types(self) -> Tuple[str, ...]:
        return tuple(v.device_type for v in self.versions) or (self.device_type,)


def _versions(group: Optional[str], *pairs) -> Tuple[TargetVersion, ...]:
    return tuple(TargetVersion(dt, label, group) for dt, label in pairs)


TARGETS: Tuple[Target, ...] = (
    Target("cisco", "Cisco IOS", "Routers & switches", "network", "cisco", "router", "CS", "SSH",
           device_type="cisco", keywords=("router", "switch", "ios", "ios-xe", "catalyst")),
    Target("fortinet", "FortiGate", "Firewall", "network", "fortinet", "firewall", "FG", "SSH",
           device_type="fortinet", keywords=("fortinet", "fortios", "firewall", "vdom")),
    Target("windows", "Windows Server", "Operating system", "servers", "windows", "windows", "WS", "WinRM",
           versions=_versions(None, ("windows-2016", "2016"), ("windows-2022", "2022"), ("windows-2025", "2025")),
           keywords=("microsoft", "os")),
    Target("linux", "Linux", "Ubuntu · Red Hat · Rocky", "servers", "linux", "linux", "LX", "SSH",
           versions=(
               _versions("Ubuntu", ("linux-ubuntu-24", "24.04 LTS"), ("linux-ubuntu-22", "22.04 LTS"),
                         ("linux-ubuntu-20", "20.04 LTS"))
               + _versions("Red Hat", ("linux-redhat-10", "10"), ("linux-redhat-9", "9"), ("linux-redhat-8", "8"))
               + _versions("Rocky Linux", ("linux-rocky-10", "10"), ("linux-rocky-9", "9"), ("linux-rocky-8", "8"))
           ),
           keywords=("ubuntu", "red hat", "rhel", "rocky", "os")),
    Target("mssql", "SQL Server", "Microsoft database", "databases", "mssql", "database", "MS", "SQL Server login",
           versions=_versions(None, ("mssql-2016", "2016"), ("mssql-2019", "2019"), ("mssql-2022", "2022")),
           keywords=("mssql", "microsoft", "sql")),
    Target("mongodb", "MongoDB", "Document database", "databases", "mongodb", "database", "MG",
           "SSH + MongoDB login", device_type="mongodb", keywords=("mongo", "nosql")),
    Target("apache", "Apache", "HTTP server", "web", "apache", "web", "AP", "SSH",
           device_type="apache", keywords=("httpd", "web server")),
)

ALL_DEVICE_TYPES = frozenset(dt for t in TARGETS for dt in t.device_types)


def targets_for(mode: str) -> Tuple[Target, ...]:
    return tuple(t for t in TARGETS if mode in t.modes)


def target_for_device_type(device_type: str) -> Optional[Target]:
    for t in TARGETS:
        if device_type in t.device_types:
            return t
    return None
