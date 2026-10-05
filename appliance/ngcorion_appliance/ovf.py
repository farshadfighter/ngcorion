"""
OVF properties: the values an administrator fills in on vCenter's "Deploy OVF
Template" screen (declared in appliance/ovf/ngcorion.ovf.tmpl). VMware Tools
hands them to the guest as the XML document guestinfo.ovfEnv.

When the essential ones are set, the appliance configures itself on first
boot without asking anything on the console.
"""
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Tuple

from . import settings as S

OE = "{http://schemas.dmtf.org/ovf/environment/1}"

KEYS = (
    "ngcorion.hostname",
    "ngcorion.ip",            # address/prefix, empty for DHCP
    "ngcorion.gateway",
    "ngcorion.dns",
    "ngcorion.ntp",
    "ngcorion.admin_password",
)


def read_environment() -> Optional[str]:
    """The ovfEnv document from VMware Tools, or None outside vSphere / without properties."""
    try:
        out = subprocess.run(
            ["vmtoolsd", "--cmd", "info-get guestinfo.ovfEnv"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out.stdout.strip()
    return text if out.returncode == 0 and text.startswith("<") else None


def parse(document: str) -> Dict[str, str]:
    """The ngcorion.* properties of an ovfEnv document (unset ones omitted)."""
    root = ET.fromstring(document)
    props = {}
    for prop in root.iter(f"{OE}Property"):
        key = prop.get(f"{OE}key", "")
        value = (prop.get(f"{OE}value") or "").strip()
        if key in KEYS and value:
            props[key] = value
    return props


def complete(props: Dict[str, str]) -> bool:
    """Enough to configure the appliance unattended."""
    return all(k in props for k in ("ngcorion.hostname", "ngcorion.admin_password"))


def to_settings(props: Dict[str, str], interface: str) -> Tuple[S.ApplianceSettings, str]:
    """The appliance settings and the admin password the properties describe.
    Raises ValueError naming the first property that is wrong."""
    def field(key, check, *args):
        try:
            return check(props.get(key, ""), *args)
        except ValueError as exc:
            raise ValueError(f"OVF property {key}: {exc}")

    network = S.Network(interface=interface, dhcp=True)
    if props.get("ngcorion.ip"):
        address = field("ngcorion.ip", S.interface_address)
        network = S.Network(
            interface=interface, dhcp=False, address=address,
            gateway=field("ngcorion.gateway", S.gateway, address),
            dns=field("ngcorion.dns", S.address_list),
        )
    settings = S.ApplianceSettings(
        hostname=field("ngcorion.hostname", S.hostname),
        network=network,
        ntp=field("ngcorion.ntp", S.server_list),
    )
    return settings, field("ngcorion.admin_password", S.admin_password)
