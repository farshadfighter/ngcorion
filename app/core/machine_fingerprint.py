"""
Fingerprint of the machine NGCorion runs on.

A license is bound to the first fingerprint it is activated with, so the
fingerprint must (1) be computed here, on the licensed machine - earlier
releases asked the license server, which answered with its OWN fingerprint, so
every installation looked identical - and (2) stay the same across container
rebuilds and restarts, so it must not use anything the container invents
(container id, its MAC, its hostname).

Sources, strongest first; every one that is readable contributes:

* the hardware/VM UUID (DMI product_uuid). Root-only under /sys, so
  entrypoint.sh copies it, as root, to HW_UUID_FILE before dropping
  privileges;
* the host's /etc/machine-id, bind-mounted read-only by docker-compose at
  HOST_MACHINE_ID_FILE.

When neither is available (a development machine, a stripped-down container)
it falls back to this OS's own /etc/machine-id, and last to a random install id
kept in the license storage directory, with a warning: such a fingerprint is
only as stable as that file.

The sources and the hash are versioned ("ngcorion-machine:v1"). Changing what
goes in changes every fingerprint, which releases every installation from its
license - do that only with a migration plan.
"""
import hashlib
import logging
import secrets
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

HW_UUID_FILE = Path("/run/ngcorion/hw/product_uuid")
DMI_UUID_FILE = Path("/sys/class/dmi/id/product_uuid")
HOST_MACHINE_ID_FILE = Path("/host/machine-id")
LOCAL_MACHINE_ID_FILE = Path("/etc/machine-id")
INSTALL_ID_NAME = ".install-id"

# Values some firmware reports instead of a real UUID.
_PLACEHOLDER_UUIDS = {
    "", "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}


def _read(path: Path) -> Optional[str]:
    try:
        value = path.read_text(encoding="ascii", errors="ignore").strip()
    except OSError:
        return None
    return value or None


def _hardware_uuid() -> Optional[str]:
    for path in (HW_UUID_FILE, DMI_UUID_FILE):
        value = (_read(path) or "").lower()
        if value and value not in _PLACEHOLDER_UUIDS:
            return value
    return None


def _install_id(storage_dir: Path) -> str:
    path = storage_dir / INSTALL_ID_NAME
    value = _read(path)
    if value:
        return value
    value = secrets.token_hex(16)
    storage_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)
    return value


def machine_sources(storage_dir: Path) -> List[Tuple[str, str]]:
    """The (name, value) pairs the fingerprint is computed from, strongest first."""
    sources: List[Tuple[str, str]] = []
    hw = _hardware_uuid()
    if hw:
        sources.append(("hw", hw))
    host_id = _read(HOST_MACHINE_ID_FILE)
    if host_id:
        sources.append(("host", host_id.lower()))
    if sources:
        return sources

    local_id = _read(LOCAL_MACHINE_ID_FILE)
    if local_id:
        logger.warning(
            "[License] No hardware UUID or host machine-id is visible; the machine fingerprint uses "
            "this OS's /etc/machine-id. In Docker, mount the host's /etc/machine-id at %s.",
            HOST_MACHINE_ID_FILE,
        )
        return [("os", local_id.lower())]

    logger.warning(
        "[License] No machine identifier is visible; the machine fingerprint uses a random install "
        "id stored in %s. Losing that file means re-activating the license.", storage_dir,
    )
    return [("install", _install_id(storage_dir))]


def compute_fingerprint(storage_dir) -> str:
    """The fingerprint this installation sends to the license server (64 hex characters)."""
    sources = machine_sources(Path(storage_dir).expanduser())
    material = "ngcorion-machine:v1|" + "|".join(f"{name}={value}" for name, value in sources)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
