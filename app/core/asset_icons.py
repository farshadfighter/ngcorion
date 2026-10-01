"""
Which icon an asset is drawn with.

One resolver for the whole product, so an asset looks the same in Design,
Topology, NOC, Asset Inventory and Backup. The frontend only maps the
returned key to a glyph (front/src/components/shared/assetIcons.js).

Order, first hit wins:
  1. the asset's own icon (an explicit per-asset override)
  2. the icon chosen on its Asset Type
  3. keywords in the asset type name and the asset role
  4. keywords in the operating system   (Ubuntu -> linux, FortiOS -> firewall)
  5. keywords in the manufacturer       (Fortinet -> firewall, Synology -> storage)
  6. "other"

Asset type names are free text, which is why 3-5 exist; an icon chosen on
the type makes it exact. ``suggest_icon`` is what the Asset Type form offers
as the default (the frontend mirrors the same table for live suggestions).
"""
import re
from typing import Optional, Sequence, Tuple

ICON_KEYS: Tuple[str, ...] = (
    "router", "switch", "wireless", "load_balancer", "firewall",
    "server", "hypervisor", "linux", "windows",
    "web", "database", "storage",
    "workstation", "iot", "internet", "other",
)

# Network-ish icons show the vendor as their badge; hosts show the OS.
_VENDOR_BADGE_ICONS = {"router", "switch", "wireless", "load_balancer", "firewall", "storage"}

# Function before platform: a "Linux Web Server" is a web server, a
# "Windows Database Server" a database. The generic "server" is last.
_NAME_RULES: Sequence[Tuple[re.Pattern, str]] = [
    (re.compile(r"firewall|fortigate|palo ?alto|\basa\b|\butm\b|check ?point|sophos", re.I), "firewall"),
    (re.compile(r"load ?balanc|\bf5\b|big-?ip|haproxy|\badc\b", re.I), "load_balancer"),
    (re.compile(r"router|gateway|\bisr\b|\basr\b", re.I), "router"),
    (re.compile(r"wireless|wi-?fi|access ?point|\bap\b|\bwlc\b", re.I), "wireless"),
    (re.compile(r"switch|catalyst|nexus", re.I), "switch"),
    (re.compile(r"hypervisor|esxi|vmware|hyper-?v|proxmox|virtual ?host|vcenter|\bxen", re.I), "hypervisor"),
    (re.compile(r"database|\bdb\b|mongo|mssql|sql ?server|mysql|postgres|oracle|mariadb|redis", re.I), "database"),
    (re.compile(r"\bweb|apache|nginx|\biis\b|tomcat", re.I), "web"),
    (re.compile(r"storage|\bnas\b|\bsan\b|netapp|synology", re.I), "storage"),
    (re.compile(r"windows|domain ?controller|active ?directory", re.I), "windows"),
    (re.compile(r"linux|ubuntu|debian|centos|rhel|red ?hat|rocky|alma|suse|fedora", re.I), "linux"),
    (re.compile(r"workstation|desktop|laptop|\bpc\b|endpoint", re.I), "workstation"),
    (re.compile(r"\biot\b|camera|cctv|printer|sensor|\bplc\b|scada|voip|ip ?phone", re.I), "iot"),
    (re.compile(r"internet|\bisp\b|\bwan\b|cloud", re.I), "internet"),
    (re.compile(r"server|bare ?metal", re.I), "server"),
]

_OS_RULES: Sequence[Tuple[re.Pattern, str]] = [
    (re.compile(r"fortios|pan-?os", re.I), "firewall"),
    (re.compile(r"esxi", re.I), "hypervisor"),
    (re.compile(r"windows", re.I), "windows"),
    (re.compile(r"linux|ubuntu|debian|centos|rhel|red ?hat|rocky|alma|suse|fedora", re.I), "linux"),
    (re.compile(r"nx-?os", re.I), "switch"),
    (re.compile(r"\bios\b|ios-?xe|ios-?xr", re.I), "router"),
    (re.compile(r"\bdsm\b|ontap", re.I), "storage"),
]

_VENDOR_RULES: Sequence[Tuple[re.Pattern, str]] = [
    (re.compile(r"fortinet|palo ?alto|check ?point|sophos|sonicwall", re.I), "firewall"),
    (re.compile(r"\bf5\b|citrix", re.I), "load_balancer"),
    (re.compile(r"aruba|ubiquiti|ruckus|meraki", re.I), "wireless"),
    (re.compile(r"synology|netapp|qnap", re.I), "storage"),
    (re.compile(r"vmware", re.I), "hypervisor"),
]


def _match(rules, *texts: Optional[str]) -> Optional[str]:
    text = " ".join(t for t in texts if t)
    if not text:
        return None
    for pattern, key in rules:
        if pattern.search(text):
            return key
    return None


def suggest_icon(type_name: Optional[str]) -> str:
    """The icon an Asset Type named ``type_name`` gets unless one is chosen."""
    return _match(_NAME_RULES, type_name) or "other"


def resolve_icon(asset, use_override: bool = True) -> str:
    """The icon key for an Asset row (see module docstring for the order).
    ``use_override=False`` gives what the asset would get without its own
    icon - the "Automatic" choice in the asset's icon picker."""
    if use_override and getattr(asset, "icon", None) in ICON_KEYS:
        return asset.icon
    asset_type = getattr(asset, "asset_type", None)
    if asset_type is not None and getattr(asset_type, "icon", None) in ICON_KEYS:
        return asset_type.icon
    type_name = asset_type.type_name if asset_type is not None else None
    return (
        _match(_NAME_RULES, type_name, getattr(asset, "asset_role", None))
        or _match(_OS_RULES, getattr(asset, "os_name", None))
        or _match(_VENDOR_RULES, getattr(asset, "manufacturer", None))
        or "other"
    )


def icon_badge(asset, icon: Optional[str] = None) -> Optional[str]:
    """Short vendor/OS label drawn under the icon: the vendor for network
    gear ("Fortinet"), the operating system for hosts ("Ubuntu 22.04")."""
    icon = icon or resolve_icon(asset)
    vendor = (getattr(asset, "manufacturer", None) or "").strip()
    os_name = (getattr(asset, "os_name", None) or "").strip()
    os_version = (getattr(asset, "os_version", None) or "").strip()
    os_label = f"{os_name} {os_version}".strip() if os_version and os_version not in os_name else os_name
    badge = (vendor or os_label) if icon in _VENDOR_BADGE_ICONS else (os_label or vendor)
    return badge[:28] or None
