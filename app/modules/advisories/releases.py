"""
Releases: which distribution and version an asset runs, and how each
distribution names it in OSV.

A release key is "<distro>:<version>": ubuntu:22.04, debian:12, rhel:9,
rocky:9, alma:9. Ubuntu and Debian advisories are per release; RHEL, Rocky
and Alma per major version (9.4 takes the fixes of 9).
"""
import re
from typing import List, Optional, Tuple

DISTROS = {
    "ubuntu": {"label": "Ubuntu", "family": "deb", "osv": "Ubuntu"},
    "debian": {"label": "Debian", "family": "deb", "osv": "Debian"},
    "rhel": {"label": "Red Hat Enterprise Linux", "family": "rpm", "osv": "Red Hat"},
    "rocky": {"label": "Rocky Linux", "family": "rpm", "osv": "Rocky Linux"},
    "alma": {"label": "AlmaLinux", "family": "rpm", "osv": "AlmaLinux"},
}
# /etc/os-release ID -> distro
_OS_IDS = {"ubuntu": "ubuntu", "debian": "debian", "rhel": "rhel", "rocky": "rocky", "almalinux": "alma"}
# Linux distributions OSV has no advisories for (named so the page can say so)
UNSUPPORTED = {"centos": "CentOS", "ol": "Oracle Linux", "amzn": "Amazon Linux", "fedora": "Fedora",
               "sles": "SUSE Linux Enterprise", "opensuse-leap": "openSUSE Leap", "linuxmint": "Linux Mint",
               "kali": "Kali Linux", "pop": "Pop!_OS", "alpine": "Alpine Linux", "arch": "Arch Linux"}

_ECOSYSTEMS = [
    (re.compile(r"^Ubuntu:(Pro:)?(\d{2}\.\d{2})(?::LTS)?$"), "ubuntu"),
    (re.compile(r"^Debian:(\d+)$"), "debian"),
    (re.compile(r"^Red Hat:enterprise_linux:(\d+)::[\w.-]+$"), "rhel"),
    (re.compile(r"^Rocky Linux:(\d+)$"), "rocky"),
    (re.compile(r"^AlmaLinux:(\d+)$"), "alma"),
]


def split(release: str) -> Tuple[str, str]:
    distro, _, version = (release or "").partition(":")
    return distro, version


def family(release: str) -> Optional[str]:
    d = DISTROS.get(split(release)[0])
    return d["family"] if d else None


def osv_top(release: str) -> str:
    return DISTROS[split(release)[0]]["osv"]


def is_lts(version: str) -> bool:
    m = re.match(r"^(\d{2})\.04$", version or "")
    return bool(m) and int(m.group(1)) % 2 == 0


def label(release: str) -> str:
    distro, version = split(release)
    d = DISTROS.get(distro)
    if d is None:
        return release
    return f"{d['label']} {version}" + (" LTS" if distro == "ubuntu" and is_lts(version) else "")


def valid(release: str) -> bool:
    distro, version = split(release)
    if distro == "ubuntu":
        return bool(re.match(r"^\d{2}\.\d{2}$", version))
    return distro in DISTROS and version.isdigit()


def bundles(release: str) -> List[str]:
    """OSV paths that hold everything about one release (all.zip under each).

    The distribution-wide archive, filtered: OSV also publishes one archive
    per release (Ubuntu:22.04:LTS, Debian:12), but those stopped being
    updated in October 2024 while the distribution-wide ones are current."""
    return [DISTROS[split(release)[0]]["osv"]]


def from_ecosystem(ecosystem: str) -> Optional[Tuple[str, bool]]:
    """("ubuntu:22.04", pro) for an OSV ecosystem we load, else None."""
    for rx, distro in _ECOSYSTEMS:
        m = rx.match(ecosystem or "")
        if m:
            if distro == "ubuntu":
                return f"ubuntu:{m.group(2)}", bool(m.group(1))
            return f"{distro}:{m.group(1)}", False
    return None


def from_platform(platform: Optional[dict]) -> Tuple[Optional[str], str]:
    """(release, status) for a collected platform. status: ok | unknown |
    unsupported."""
    if not platform or not platform.get("id"):
        return None, "unknown"
    os_id = platform["id"].lower()
    distro = _OS_IDS.get(os_id)
    version = (platform.get("version_id") or "").strip()
    if distro is None:
        return None, "unsupported"
    if distro == "ubuntu":
        return (f"ubuntu:{version}", "ok") if re.match(r"^\d{2}\.\d{2}$", version) else (None, "unknown")
    major = version.split(".")[0]
    return (f"{distro}:{major}", "ok") if major.isdigit() else (None, "unknown")


def platform_label(platform: Optional[dict]) -> Optional[str]:
    if not platform:
        return None
    return platform.get("pretty") or UNSUPPORTED.get((platform.get("id") or "").lower()) or platform.get("id")
