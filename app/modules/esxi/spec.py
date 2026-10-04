"""The VMware ESXi module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES

# What a hardening run can change: advanced settings, services, firewall,
# NTP/syslog/SNMP, boot and FIPS settings, vSwitch policies, and root's
# authorized_keys (public keys only), so they can be put back by hand.
BACKUP_SECTIONS = ("ADVANCED", "SERVICES", "NTP", "SYSLOG", "FIREWALL", "SNMP", "ACCEPTANCE", "ENCRYPTION", "FIPS",
                   "VSWITCH")
AUTHORIZED_KEYS = "cat /etc/ssh/keys-root/authorized_keys 2>/dev/null || true"

_COMMUNITIES = re.compile(r"^(\s*Communities:)[ \t]*(\S.*)$", re.M)


def redact(dump: str) -> str:
    """SNMP v1/v2c community strings are passwords; keep how many there are."""
    return _COMMUNITIES.sub(lambda m: f"{m.group(1)} *** ({len([c for c in m.group(2).split(',') if c.strip()])})",
                            dump)


def _backup(conn) -> str:
    parts = [bundle_header("esxi", getattr(conn, "ip", None))]
    for name in BACKUP_SECTIONS:
        parts.append(f"##### {name} before hardening #####\n{redact(conn.run(C.COMMANDS[name]))}\n")
    parts.append("##### /etc/ssh/keys-root/authorized_keys before hardening #####\n" + conn.run(AUTHORIZED_KEYS) + "\n")
    return "".join(parts)


def collect_software(conn) -> Optional[dict]:
    """The ESXi version and build as a firmware item for the inventory, or None."""
    m = re.search(r"VMware ESXi (\d+\.\d+\.\d+)(?: build-(\d+))?", conn.run("vmware -v"))
    if not m:
        return None
    return {"name": "VMware ESXi", "version": m.group(1), "arch": None, "source": "firmware", "origin": None,
            "publisher": "VMware by Broadcom", "kind": "firmware", "source_package": None, "vkind": "fw",
            "build": m.group(2)}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "esxi", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="esxi",
    label="VMware ESXi",
    device_type=DeviceType.ESXI,
    log_module="esxi_cis",
    connector="ssh_esxi",
    benchmark="CIS VMware ESXi 7/8 Benchmark",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    redact=redact,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="esxi",
    tags_audit=["Audit - VMware ESXi"],
    tags_hardening=["Hardening - VMware ESXi"],
)
