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

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Canonical device families. These line up with the audit/hardening DeviceType
# enum (cisco/linux/windows/fortinet/apache/mongodb/mssql).
FAMILIES = ("fortinet", "cisco", "mongodb", "mssql", "apache", "active_directory", "dns_server", "windows", "linux")

# Windows Server roles audited as their own target. A host carrying one of
# these roles is still a Windows Server: it stays in the Windows target's
# asset list (and gets its Windows version), and Windows hosts stay in the
# role's list, since the role may run on any of them.
WINDOWS_ROLE_FAMILIES = {"active_directory", "dns_server"}

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
    ("active_directory", ("active directory", "activedirectory", "domain controller")),
    ("dns_server", ("dns server", "dns-server", "name server", "nameserver", "dns")),
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
    except Exception as e:
        logger.warning(f"[DeviceClassification] could not read asset_type for classification: {e}")
    return " ".join(p for p in parts if p).lower()


def infer_device_family(asset) -> Optional[str]:
    """Best-effort device family for an asset, or None if it can't be determined.

    Returns one of FAMILIES, or None when there's no confident signal (the caller
    treats None as "unknown" and surfaces it in an Other/Unknown group).
    """
    text = _asset_text(asset)
    if not text.strip():
        return None
    linux_keywords = dict(_FAMILY_KEYWORDS)["linux"]
    for family, keywords in _FAMILY_KEYWORDS:
        if any(kw in text for kw in keywords):
            # A Windows role only on a host that is not Linux: a BIND name
            # server or a Samba DC stays a Linux host.
            if family in WINDOWS_ROLE_FAMILIES and any(kw in text for kw in linux_keywords):
                continue
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
    if requested in WINDOWS_ROLE_FAMILIES and (inferred == "windows" or inferred in WINDOWS_ROLE_FAMILIES):
        return True
    if requested == "windows" and inferred in WINDOWS_ROLE_FAMILIES:
        return True
    return False


# ── Variant (version) detection ─────────────────────────────────────────────
# The audit/hardening forms also pick a version for some families
# (linux-ubuntu-22, windows-2022, mssql-2019). Detecting it from the asset lets
# the picker mark which assets match the chosen version. Like the family, this
# is a best-effort guess; None means "version not detected", never "wrong".

import re  # noqa: E402

_LINUX_DISTROS = (
    ("ubuntu", re.compile(r"ubuntu", re.I), re.compile(r"\b(20|22|24)\.04\b")),
    ("redhat", re.compile(r"red ?hat|rhel", re.I), re.compile(r"\b(8|9|10)(?:\.\d+)?\b")),
    ("rocky", re.compile(r"rocky", re.I), re.compile(r"\b(8|9|10)(?:\.\d+)?\b")),
)
_WINDOWS_YEAR = re.compile(r"windows(?:\s*server)?\s*(20\d\d)", re.I)
# Only a year written next to SQL Server counts - "SQL Server on Windows
# Server 2022" must not read as SQL Server 2022.
_MSSQL_YEAR = re.compile(r"(?:mssql|sql\s*server|sql)\s*(20\d\d)", re.I)


def infer_device_variant(asset) -> Optional[str]:
    """The granular device type for an asset (e.g. "linux-ubuntu-22"), or None
    when its family has no versions or the version cannot be read."""
    family = infer_device_family(asset)
    os_name = getattr(asset, "os_name", None) or ""
    os_version = getattr(asset, "os_version", None) or ""
    text = _asset_text(asset) + " " + os_version.lower()
    if family == "linux":
        for distro, name_re, version_re in _LINUX_DISTROS:
            if name_re.search(text):
                # The version field is the most reliable; the name is a fallback
                # ("Ubuntu 22.04 LTS" written into os_name).
                m = version_re.search(os_version) or version_re.search(os_name)
                return f"linux-{distro}-{m.group(1)}" if m else None
        return None
    if family == "windows" or family in WINDOWS_ROLE_FAMILIES:
        m = _WINDOWS_YEAR.search(f"{os_name} {os_version}") or _WINDOWS_YEAR.search(text)
        return f"windows-{m.group(1)}" if m else None
    if family == "mssql":
        m = _MSSQL_YEAR.search(text)
        return f"mssql-{m.group(1)}" if m else None
    return None
