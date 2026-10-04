"""The Active Directory module's declaration for the benchmark engine."""

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.software.hooks import collect_windows, save_windows
from app.modules.windows.audit.winrm_client import redact_sensitive_windows_data

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES


def _backup(conn) -> str:
    """The Windows security snapshot (secedit + auditpol) plus the directory
    settings the AD fixes change, as they were before."""
    snapshot = conn._ex.backup_config()
    directory = conn.run(C.guarded(C.AD_DOMAIN))
    registry = conn.run(C.registry_script(C.AD_REGISTRY_PROPS))
    return (snapshot
            + "\n##### BEGIN SECTION: Active Directory settings #####\n" + directory
            + "\n##### END SECTION: Active Directory settings #####\n"
            + "\n##### BEGIN SECTION: Domain controller registry #####\n" + registry
            + "\n##### END SECTION: Domain controller registry #####\n")


SPEC = ModuleSpec(
    key="active_directory",
    label="Active Directory",
    device_type=DeviceType.ACTIVE_DIRECTORY,
    log_module="active_directory_cis",
    connector="winrm",
    benchmark="CIS Microsoft Windows Server (domain controller profile) + domain checks",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    json_sections=R.JSON_SECTIONS,
    redact=redact_sensitive_windows_data,
    describe=R.describe,
    collect_software=collect_windows,
    save_software=save_windows,
    backup=_backup,
    backup_device_type="windows",
    tags_audit=["Audit - Active Directory"],
    tags_hardening=["Hardening - Active Directory"],
)
