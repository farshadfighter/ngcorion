"""
What the operator configures on the appliance, and the checks every value
passes before anything is written to the machine.

Every validator returns the value in canonical form or raises ValueError with
a message meant for the console.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def hostname(value: str) -> str:
    """A host name (RFC 1123): letters, digits and hyphens, labels of up to 63 characters."""
    value = (value or "").strip().lower().rstrip(".")
    if not value or len(value) > 253:
        raise ValueError("Enter a host name of 1 to 253 characters")
    for label in value.split("."):
        if not _HOST_LABEL.match(label):
            raise ValueError(f"'{label}' is not valid in a host name (letters, digits, hyphens; no hyphen at either end)")
    return value


def interface_address(value: str) -> ipaddress.IPv4Interface:
    """An IPv4 address with its prefix, e.g. 192.168.10.20/24 (a dotted netmask is accepted too)."""
    value = (value or "").strip()
    if "/" not in value:
        raise ValueError("Give the address with its prefix length, e.g. 192.168.10.20/24")
    try:
        iface = ipaddress.IPv4Interface(value)
    except ValueError:
        raise ValueError(f"'{value}' is not an IPv4 address with a prefix length")
    if iface.network.prefixlen > 30:
        raise ValueError("The prefix length must be /30 or shorter")
    if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
        raise ValueError("That is the network's own or its broadcast address, not a host address")
    if iface.ip.is_loopback or iface.ip.is_multicast or iface.ip.is_unspecified:
        raise ValueError("Use an ordinary unicast address")
    return iface


def ipv4(value: str) -> ipaddress.IPv4Address:
    """A single IPv4 address."""
    try:
        return ipaddress.IPv4Address((value or "").strip())
    except ValueError:
        raise ValueError(f"'{value}' is not an IPv4 address")


def gateway(value: str, address: ipaddress.IPv4Interface) -> ipaddress.IPv4Address:
    """The default gateway: an address inside the appliance's own network, not the appliance itself."""
    gw = ipv4(value)
    if gw not in address.network:
        raise ValueError(f"The gateway {gw} is not in the network {address.network}")
    if gw == address.ip:
        raise ValueError("The gateway cannot be the appliance's own address")
    return gw


def address_list(value: str, *, at_least: int = 1) -> List[str]:
    """Comma- or space-separated IPv4 addresses (DNS servers)."""
    items = [v for v in re.split(r"[,\s]+", value or "") if v]
    if len(items) < at_least:
        raise ValueError("Enter at least one address")
    return [str(ipv4(v)) for v in items]


def server_list(value: str) -> List[str]:
    """Comma- or space-separated NTP servers: host names or IPv4 addresses. May be empty."""
    items = [v for v in re.split(r"[,\s]+", value or "") if v]
    out = []
    for v in items:
        try:
            out.append(str(ipaddress.IPv4Address(v)))
        except ValueError:
            out.append(hostname(v))
    return out


# The special characters NGCorion's password policy counts
# (app/schemas/user.py, validate_password_strength).
_SPECIAL = r"[!@#$%^&*()_+=\-[\]{};':\"\\|,.<>/?]"


def admin_password(value: str) -> str:
    """The first administrator's web password. NGCorion's own policy
    (app/schemas/user.py validate_password_strength), so scripts/init_db.py
    accepts it, with 12 characters instead of 8 for this first account."""
    if len(value) < 12:
        raise ValueError("At least 12 characters")
    checks = [
        (r"[A-Z]", "an upper-case letter"),
        (r"[a-z]", "a lower-case letter"),
        (r"[0-9]", "a digit"),
        (_SPECIAL, "one of the special characters !@#$%^&*()_+-=[]{};':\"\\|,.<>/?"),
    ]
    missing = [name for pattern, name in checks if not re.search(pattern, value)]
    if missing:
        raise ValueError("The password needs " + ", ".join(missing))
    return value


@dataclass
class Network:
    """How the appliance's management interface is addressed."""
    interface: str
    dhcp: bool = True
    address: Optional[ipaddress.IPv4Interface] = None
    gateway: Optional[ipaddress.IPv4Address] = None
    dns: List[str] = field(default_factory=list)

    def check(self) -> "Network":
        if not self.dhcp:
            if self.address is None or self.gateway is None:
                raise ValueError("A static configuration needs an address and a gateway")
            if not self.dns:
                raise ValueError("A static configuration needs at least one DNS server")
            gateway(str(self.gateway), self.address)
        return self


@dataclass
class ApplianceSettings:
    """Everything the first-boot wizard (or the OVF properties) decides."""
    hostname: str
    network: Network
    ntp: List[str]
