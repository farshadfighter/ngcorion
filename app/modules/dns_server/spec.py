"""The Windows DNS Server module's declaration for the benchmark engine."""

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.software.hooks import collect_windows, save_windows
from app.modules.windows.audit.winrm_client import redact_sensitive_windows_data

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES


def _backup(conn) -> str:
    """Server settings and zone properties as they were, plus a dnscmd export
    of every file-backed zone (AD-integrated zones live in the directory)."""
    settings = conn.run(C.guarded(C.DNS_SETTINGS))
    zones = conn.run(C.guarded(C.DNS_ZONES))
    exports = conn.run(C.guarded(
        "Import-Module DnsServer; Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' -and "
        "-not $_.IsDsIntegrated -and -not $_.IsAutoCreated } | ForEach-Object { "
        "$f = 'backup-' + $_.ZoneName + '-' + (Get-Date -Format yyyyMMddHHmmss) + '.dns'; "
        "Export-DnsServerZone -Name $_.ZoneName -FileName $f; \"$($_.ZoneName) -> %SystemRoot%\\System32\\dns\\$f\" }"))
    return ("#### Windows DNS Server configuration snapshot ####\n"
            "##### BEGIN SECTION: server settings #####\n" + settings + "\n##### END SECTION #####\n"
            "##### BEGIN SECTION: zones #####\n" + zones + "\n##### END SECTION #####\n"
            "##### BEGIN SECTION: zone file exports on the server #####\n" + exports + "\n##### END SECTION #####\n")


SPEC = ModuleSpec(
    key="dns_server",
    label="Windows DNS Server",
    device_type=DeviceType.DNS_SERVER,
    log_module="dns_server_stig",
    connector="winrm",
    benchmark="DISA STIG for Windows Server DNS (+ Microsoft DNS guidance)",
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
    tags_audit=["Audit - Windows DNS Server"],
    tags_hardening=["Hardening - Windows DNS Server"],
)
