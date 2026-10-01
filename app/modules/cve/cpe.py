"""
Which products (as CPE vendor/product/version) an asset runs.

Two sources:
  * inferred from the asset's own fields - the operating system / firmware
    named in os_name + os_version, and the product when manufacturer or model
    names one (rules below);
  * AssetSoftware rows added by hand, for software the inventory does not
    describe (Apache 2.4.52 on a Linux host, OpenSSH, ...).

CPE vendor/product names are NVD's own (e.g. "fortinet:fortios",
"cisco:ios_xe", "canonical:ubuntu_linux"). A rule only claims what the
fields actually say; a guessed product would produce findings nobody can
trust, so an asset with nothing recognisable simply has no inferred identity.
"""
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Identity:
    vendor: str
    product: str
    version: Optional[str]
    source: str          # inferred | manual
    label: str           # human name, e.g. "Fortinet FortiOS"
    software_id: Optional[int] = None


# 7.2.5, 17.9.4a, 10.0.20348.2527, and Cisco IOS trains such as 15.2(4)M3
_VERSION = re.compile(r"\d+(?:[.\-_(]\w+\)?\w*)*")


def _version_from(*texts: Optional[str]) -> Optional[str]:
    for t in texts:
        if t:
            m = _VERSION.search(t)
            if m:
                return m.group(0)
    return None


def parse_cpe23(criteria: str) -> Optional[dict]:
    """cpe:2.3:part:vendor:product:version:update:... -> its parts (escaped
    characters such as "\\:" kept as written by NVD)."""
    if not criteria or not criteria.startswith("cpe:2.3:"):
        return None
    parts = re.split(r"(?<!\\):", criteria)
    if len(parts) < 6:
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5],
            "update": parts[6] if len(parts) > 6 else "*"}


# (pattern over "<os_name> <model> <manufacturer> <type>", vendor, product, label, version source)
# version source: "os" = os_version, then a version inside os_name
_RULES = [
    (re.compile(r"fortios|fortigate", re.I), "fortinet", "fortios", "Fortinet FortiOS"),
    (re.compile(r"ios[ -]?xe", re.I), "cisco", "ios_xe", "Cisco IOS XE"),
    (re.compile(r"nx-?os", re.I), "cisco", "nx-os", "Cisco NX-OS"),
    (re.compile(r"\basa\b|adaptive security", re.I), "cisco", "adaptive_security_appliance_software", "Cisco ASA"),
    (re.compile(r"\bios\b", re.I), "cisco", "ios", "Cisco IOS"),
    (re.compile(r"junos", re.I), "juniper", "junos", "Juniper Junos"),
    (re.compile(r"pan-?os", re.I), "paloaltonetworks", "pan-os", "Palo Alto PAN-OS"),
    (re.compile(r"esxi", re.I), "vmware", "esxi", "VMware ESXi"),
    (re.compile(r"ubuntu", re.I), "canonical", "ubuntu_linux", "Ubuntu"),
    (re.compile(r"red ?hat|rhel", re.I), "redhat", "enterprise_linux", "Red Hat Enterprise Linux"),
    (re.compile(r"debian", re.I), "debian", "debian_linux", "Debian"),
]
_WINDOWS_SERVER = re.compile(r"windows\s*server\s*(20\d\d)", re.I)
_WINDOWS_BUILD = re.compile(r"\b10\.0\.\d{5}(?:\.\d+)?\b")
# Applications named with their version in os_name/model (an Application asset
# hosted on a server - see app/modules/assets/hosting.py).
_APPS = [
    (re.compile(r"apache\s*(?:http(?:d| server)?)?", re.I), "apache", "http_server", "Apache HTTP Server"),
    (re.compile(r"mongo", re.I), "mongodb", "mongodb", "MongoDB"),
    (re.compile(r"nginx", re.I), "f5", "nginx", "nginx"),
    (re.compile(r"openssh", re.I), "openbsd", "openssh", "OpenSSH"),
    (re.compile(r"mysql", re.I), "oracle", "mysql", "MySQL"),
    (re.compile(r"postgres", re.I), "postgresql", "postgresql", "PostgreSQL"),
]


_LABELS = {(v, p): label for _, v, p, label in _RULES + _APPS}


def label_for(vendor: str, product: str) -> str:
    """A readable name for a CPE product: "Apache HTTP Server", else
    "Openbsd openssh"-style from the CPE names."""
    known = _LABELS.get((vendor, product))
    if known:
        return known
    return f"{vendor.replace('_', ' ').title()} {product.replace('_', ' ')}"


def infer_identities(asset) -> List[Identity]:
    os_name = (getattr(asset, "os_name", None) or "").strip()
    os_version = (getattr(asset, "os_version", None) or "").strip()
    model = (getattr(asset, "model", None) or "").strip()
    found: List[Identity] = []

    m = _WINDOWS_SERVER.search(f"{os_name} {os_version}")
    if m:
        build = _WINDOWS_BUILD.search(f"{os_version} {os_name}")
        found.append(Identity("microsoft", f"windows_server_{m.group(1)}", build.group(0) if build else None,
                              "inferred", f"Windows Server {m.group(1)}"))
        return found

    haystack = f"{os_name} {model}".strip()
    for pattern, vendor, product, label in _RULES:
        if pattern.search(haystack):
            version = _version_from(os_version, os_name)
            if product == "ubuntu_linux" and version:
                vm = re.search(r"\d{2}\.\d{2}", f"{os_version} {os_name}")
                version = vm.group(0) if vm else version
            if product == "enterprise_linux" and version:
                # NVD lists RHEL CVEs against the major release ("9.0").
                version = version.split(".")[0] + ".0"
            found.append(Identity(vendor, product, version, "inferred", label))
            break

    for pattern, vendor, product, label in _APPS:
        if pattern.search(os_name) and not found:
            found.append(Identity(vendor, product, _version_from(os_version, os_name), "inferred", label))
            break
        if pattern.search(model):
            found.append(Identity(vendor, product, _version_from(model), "inferred", label))
            break
    return found


def identities_for(asset, software_rows) -> List[Identity]:
    """Inferred + hand-added, without duplicates."""
    ids = infer_identities(asset)
    seen = {(i.vendor, i.product, i.version) for i in ids}
    for s in software_rows:
        key = (s.vendor, s.product, s.version)
        if key not in seen:
            seen.add(key)
            ids.append(Identity(s.vendor, s.product, s.version, "manual", label_for(s.vendor, s.product),
                                software_id=s.id))
    return ids
