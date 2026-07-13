"""
Asset -> hardening/audit device-family classification.

Assets in `asset_inventory` do NOT store the hardening/audit `DeviceType`
directly. They carry free-text `manufacturer` / `os_name` / `model`, a generic
`asset_type` (Firewall, Router, Server, ...) and a name. The hardening & audit
flows, on the other hand, work with a device family (cisco, fortinet, apache,
mongodb, mssql, windows, linux) plus finer variants (mssql-2019, windows-2022,
linux-ubuntu-22, ...).

This module heuristically maps an asset onto a device *family* so the assets
list can be filtered by the selected service/vendor. It is intentionally
dependency-free (imports nothing from app.models) so it can be reused by the
model layer, routers and services without circular imports.

NOTE (data model): this is a best-effort heuristic over free-text fields. A
future improvement is to persist an explicit `device_type` column on the asset
(backfilled with this same heuristic) so the mapping becomes exact.
"""

from typing import Optional

# Canonical device families. These line up with the audit/hardening DeviceType
# enum (cisco/linux/windows/fortinet/apache/mongodb/mssql).
FAMILIES = ("fortinet", "cisco", "mongodb", "mssql", "apache", "windows", "linux")

# Families that are network/OS "hosts" a service can run on top of.
_HOST_FAMILIES = {"linux", "windows"}

# Service families that legitimately run on top of a host OS. When one of these
# is requested we also keep host-OS assets (they may run that service), rather
# than excluding them.
_SERVICE_FAMILIES = {"apache", "mongodb", "mssql"}

# Keyword signals per family, checked in priority order (most specific first so
# e.g. "MongoDB on Ubuntu" resolves to mongodb, not linux).
_FAMILY_KEYWORDS = [
    ("fortinet", ("fortinet", "fortigate", "fortios")),
    ("cisco", ("cisco", "catalyst", "nexus", "ios-xe", "ios xe", "nx-os")),
    ("mongodb", ("mongodb", "mongo")),
    ("mssql", ("mssql", "sql server", "sqlserver", "microsoft sql")),
    ("apache", ("apache", "httpd")),
    ("windows", ("windows",)),
    ("linux", ("linux", "ubuntu", "red hat", "redhat", "rhel", "rocky",
               "centos", "debian", "fedora", "suse", "almalinux")),
]


def normalize_device_type(device_type: Optional[str]) -> Optional[str]:
    """Collapse a granular device_type value to its family.

    e.g. "linux-ubuntu-22" -> "linux", "mssql-2019" -> "mssql",
         "windows-2022" -> "windows", "fortinet" -> "fortinet".
    """
    if not device_type:
        return None
    dt = device_type.strip().lower()
    if not dt:
        return None
    if dt.startswith("linux"):
        return "linux"
    if dt.startswith("windows"):
        return "windows"
    if dt.startswith("mssql"):
        return "mssql"
    # cisco, fortinet, apache, mongodb (and any already-normalized value)
    return dt


def _asset_text(asset) -> str:
    """Build a lowercase haystack from an asset's identifying free-text fields."""
    parts = [
        getattr(asset, "manufacturer", None),
        getattr(asset, "os_name", None),
        getattr(asset, "model", None),
        getattr(asset, "asset_name", None),
    ]
    # asset_type is a relationship; guard against it being unloaded/None.
    try:
        asset_type = getattr(asset, "asset_type", None)
        if asset_type is not None:
            parts.append(getattr(asset_type, "type_name", None))
    except Exception:
        pass
    return " ".join(p for p in parts if p).lower()


def infer_device_family(asset) -> Optional[str]:
    """Best-effort device family for an asset, or None if it can't be determined.

    Returns one of FAMILIES, or None when there's no confident signal (the caller
    treats None as "unknown" and surfaces it in an Other/Unknown group).
    """
    text = _asset_text(asset)
    if not text.strip():
        return None
    for family, keywords in _FAMILY_KEYWORDS:
        if any(kw in text for kw in keywords):
            return family
    return None


def family_matches(inferred: Optional[str], requested: Optional[str]) -> bool:
    """Whether an asset (with `inferred` family) should be listed for `requested`.

    - Unknown assets (inferred None) are always kept -> shown under Other/Unknown.
    - Exact family match is kept.
    - For service families (apache/mongodb/mssql) a host-OS asset (linux/windows)
      is kept, since the service may run on it.
    - Otherwise (a different known family, e.g. cisco when fortinet is requested)
      the asset is excluded.
    """
    if not requested:
        return True
    if inferred is None:
        return True
    if inferred == requested:
        return True
    if requested in _SERVICE_FAMILIES and inferred in _HOST_FAMILIES:
        return True
    return False
