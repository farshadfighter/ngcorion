"""The IIS 10 module's declaration for the benchmark engine."""

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.software.hooks import collect_windows, save_windows
from app.modules.windows.audit.winrm_client import redact_sensitive_windows_data

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES


def _backup(conn) -> str:
    """An IIS configuration backup (appcmd add backup: applicationHost.config
    and the related files, restorable with appcmd restore backup), plus the
    SCHANNEL settings the TLS fixes change."""
    backup = conn.run(C.guarded(
        "$n = 'ngcorion-' + (Get-Date -Format yyyyMMddHHmmss); "
        "& \"$env:SystemRoot\\System32\\inetsrv\\appcmd.exe\" add backup $n | Out-Null; "
        "\"IIS configuration backup '$n' created (restore: appcmd restore backup $n)\""))
    schannel = conn.run(C.guarded(C.SCHANNEL))
    return ("#### IIS configuration snapshot ####\n" + backup + "\n"
            "##### BEGIN SECTION: SCHANNEL #####\n" + schannel + "\n##### END SECTION #####\n")


SPEC = ModuleSpec(
    key="iis",
    label="IIS 10",
    device_type=DeviceType.IIS,
    log_module="iis_cis",
    connector="winrm",
    benchmark="CIS Microsoft IIS 10 Benchmark",
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
    tags_audit=["Audit - IIS 10"],
    tags_hardening=["Hardening - IIS 10"],
)
