"""
What a MAC address says about a device: its manufacturer and a guess at its kind.

The manufacturer comes from the IEEE OUI registry as nmap ships it (nmap-mac-prefixes, installed
with nmap in the backend image), so no download and no internet access is needed. Newer nmap
releases also list the 28- and 36-bit MA-M / MA-S blocks; the longest matching prefix wins.

A MAC with the "locally administered" bit set was not assigned by a manufacturer: phones and
laptops make one up per network (private / randomized address), so there is no maker to look up.

The kind is only a hint for the Unknown devices page (and the icon an asset made from it starts
with): a maker of cameras is very likely a camera, a VMware address a virtual machine. Makers that
build many kinds of device (HP, Cisco, Samsung) give a broader guess or none.
"""
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple

from app.core.asset_icons import _VENDOR_RULES, _match

PREFIX_FILES = ("/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes")

_HEX = re.compile(r"[0-9a-f]")


def normalize_mac(value) -> Optional[str]:
    """'aa:bb:cc:dd:ee:ff' from raw bytes or any common text form (AA-BB-.., aabb.ccdd.eeff,
    aabbccddeeff); None when it is not a 6-byte address."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 6:
            return None
        digits = value.hex()
    else:
        digits = "".join(_HEX.findall(str(value).lower()))
        if len(digits) != 12:
            return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_unicast(mac: str) -> bool:
    """A real device address: not multicast/broadcast (low bit of the first octet) and not zero."""
    return mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 1


def is_private(mac: str) -> bool:
    """Locally administered (second-lowest bit of the first octet): made up by the device, typically
    a phone or laptop hiding its real address on Wi-Fi."""
    return bool(int(mac[:2], 16) & 2)


@lru_cache(maxsize=1)
def _prefixes() -> Dict[str, str]:
    table: Dict[str, str] = {}
    for name in PREFIX_FILES:
        path = Path(name)
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            prefix, _, vendor = line.partition(" ")
            prefix = prefix.strip().lower()
            if vendor.strip() and all(c in "0123456789abcdef" for c in prefix):
                table[prefix] = vendor.strip()
        break
    return table


def vendor_of(mac: Optional[str]) -> Optional[str]:
    """The manufacturer registered for this address, or None (unknown, or a private address)."""
    if not mac or is_private(mac):
        return None
    digits = mac.replace(":", "")
    table = _prefixes()
    for length in (9, 7, 6):
        vendor = table.get(digits[:length])
        if vendor:
            return vendor
    return None


# Endpoint-only guesses, before the asset icon rules: a VMware *address* is a virtual machine, not a
# hypervisor; phone makers make phones. (kind, icon)
_ENDPOINT_RULES = [
    (re.compile(r"vmware|xensource|qemu|parallels|virtualbox|nutanix", re.I), ("virtual_machine", "server")),
    (re.compile(r"\bapple\b|samsung electronics|xiaomi|oneplus|huawei device|oppo|vivo mobile|"
                r"motorola mobility|honor device|realme", re.I), ("mobile", "laptop")),
    (re.compile(r"raspberry pi|espressif|tuya|shelly|sonoff|particle industries", re.I), (None, "iot")),
    (re.compile(r"intel corporate|realtek|dell\b|lenovo|asustek|micro-star|gigabyte|liteon|azurewave|"
                r"pegatron|quanta|wistron|compal", re.I), ("computer", "workstation")),
    (re.compile(r"cisco|juniper|mikrotik|routerboard|huawei technologies|tp-link|d-link|netgear|zyxel|"
                r"h3c|ruijie|extreme networks|arista|allied telesis", re.I), ("network", "switch")),
]


def guess(mac: Optional[str], vendor: Optional[str]) -> Tuple[Optional[str], str]:
    """(kind, icon) for an address: kind is one of virtual_machine | mobile | computer | network |
    private, or None when the icon says it all (camera, UPS ...); icon is an asset icon key."""
    if mac and is_private(mac):
        return "private", "laptop"
    if vendor:
        for pattern, result in _ENDPOINT_RULES:
            if pattern.search(vendor):
                return result
        icon = _match(_VENDOR_RULES, vendor)
        if icon:
            return None, icon
    return None, "other"
