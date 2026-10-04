"""The Sophos Firewall module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .api import sfos_version
from .hardening import TEMPLATES

# What a hardening run can change, read back before it runs.
BACKUP_ENTITIES = ("AdminSettings", "Zone", "Hotfix", "PatternDownload", "SyslogServers", "FirewallRule", "ATP")


def _backup(conn) -> str:
    parts = [bundle_header("sophos", getattr(conn, "ip", None))]
    for entity in BACKUP_ENTITIES:
        parts.append(f"##### {entity} before hardening (XML API Get) #####\n{conn.run(C.COMMANDS[entity])}\n")
    return C.redact("".join(parts))


def collect_software(conn) -> Optional[dict]:
    """The SFOS firmware version as a software item for the inventory, or None."""
    m = re.search(r"APIVersion=(\S+)", conn.run(C.COMMANDS[C.VERSION]))
    if not m or sfos_version(m.group(1)) == "unknown":
        return None
    return {"name": "Sophos Firewall OS", "version": sfos_version(m.group(1)), "arch": None, "source": "firmware",
            "origin": None, "publisher": "Sophos", "kind": "firmware", "source_package": None, "vkind": "fw"}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "sophos", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="sophos",
    label="Sophos Firewall",
    device_type=DeviceType.SOPHOS,
    log_module="sophos_firewall",
    connector="sophos_api",
    benchmark="Sophos Firewall hardening guidance",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    redact=C.redact,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="sophos",
    tags_audit=["Audit - Sophos Firewall"],
    tags_hardening=["Hardening - Sophos Firewall"],
)
