"""The Windows DHCP Server module's declaration for the benchmark engine."""

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.software.hooks import collect_windows, save_windows
from app.modules.windows.audit.winrm_client import redact_sensitive_windows_data

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES


def _backup(conn) -> str:
    """Server settings as they were, plus a full Export-DhcpServer of the
    configuration (scopes, options, failover) to a file on the server."""
    settings = conn.run(C.guarded(C.DHCP_SETTINGS))
    export = conn.run(C.guarded(
        "Import-Module DhcpServer; $f = Join-Path $env:SystemRoot ('System32\\dhcp\\backup-config-' + "
        "(Get-Date -Format yyyyMMddHHmmss) + '.xml'); Export-DhcpServer -File $f -Force; \"exported to $f\""))
    return ("#### Windows DHCP Server configuration snapshot ####\n"
            "##### BEGIN SECTION: server settings and scopes #####\n" + settings + "\n##### END SECTION #####\n"
            "##### BEGIN SECTION: Export-DhcpServer on the server #####\n" + export + "\n##### END SECTION #####\n")


SPEC = ModuleSpec(
    key="dhcp_server",
    label="Windows DHCP Server",
    device_type=DeviceType.DHCP_SERVER,
    log_module="dhcp_server_audit",
    connector="winrm",
    benchmark="Microsoft DHCP Server security and deployment guidance",
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
    tags_audit=["Audit - Windows DHCP Server"],
    tags_hardening=["Hardening - Windows DHCP Server"],
)
