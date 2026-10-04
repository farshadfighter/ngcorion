"""
Windows DHCP Server remediation. Server and scope settings are changed with
the DhcpServer cmdlets and read back. Authorising the server in AD starts it
leasing to the domain, so it needs a confirmation. Fixes that need a secret
or a design decision (DNS update account, failover partner and shared
secret, scope sizes, group membership) stay manual.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))

_I = "Import-Module DhcpServer; "


def _ok(cond: str) -> str:
    return _I + f"if ({cond}) {{ 'PASS' }} else {{ 'FAIL' }}"


def _add(rid, description, statement, verify, warning=None, confirm=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"DHCP-{rid}", description=description, statements=[_I + statement],
        verify_statements=[_ok(verify)], parameters=["CONFIRM"] if confirm else [], warning=warning))


_add("AU-1", "Authorise this DHCP server in Active Directory", "Add-DhcpServerInDC",
     "(Get-DhcpServerSetting).IsAuthorized",
     warning="The server starts leasing addresses on every network it is bound to. Needs Enterprise Admin rights.",
     confirm=True)
_add("DN-2", "Enable DNS name protection on the server", "Set-DhcpServerv4DnsSetting -NameProtection $true",
     "(Get-DhcpServerv4DnsSetting).NameProtection",
     warning="A client can no longer register a name another client already holds in DNS.")
_add("DN-3", "Enable DNS name protection on every scope",
     "Get-DhcpServerv4Scope | ForEach-Object { Set-DhcpServerv4DnsSetting -ScopeId $_.ScopeId -NameProtection $true }",
     "-not @(Get-DhcpServerv4Scope | Where-Object { -not (Get-DhcpServerv4DnsSetting -ScopeId $_.ScopeId).NameProtection })",
     warning="A client can no longer register a name another client already holds in DNS.")
_add("DN-4", "Remove DNS records when leases expire", "Set-DhcpServerv4DnsSetting -DeleteDnsRRonLeaseExpiry $true",
     "(Get-DhcpServerv4DnsSetting).DeleteDnsRROnLeaseExpiry")
_add("LG-1", "Enable DHCP audit logging", "Set-DhcpServerAuditLog -Enable $true", "(Get-DhcpServerAuditLog).Enable")
_add("LG-2", "Back up the DHCP database every 60 minutes", "Set-DhcpServerDatabase -BackupInterval 60",
     "$b = (Get-DhcpServerDatabase).BackupInterval; $m = if ($b -is [TimeSpan]) { $b.TotalMinutes } else { $b }; $m -gt 0 -and $m -le 60")
_add("AV-5", "Enable conflict detection (one ping before leasing)", "Set-DhcpServerSetting -ConflictDetectionAttempts 1",
     "(Get-DhcpServerSetting).ConflictDetectionAttempts -ge 1",
     warning="Each new lease waits for one ping (about half a second).")
TEMPLATES.add(HardeningTemplate(
    check_id="DHCP-AV-6", description="Start the DHCP Server service and set it to start automatically",
    statements=["Set-Service -Name DHCPServer -StartupType Automatic; Start-Service -Name DHCPServer"],
    verify_statements=["$s = Get-Service DHCPServer; if ($s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic') { 'PASS' } else { 'FAIL' }"]))

for _rid, _desc in {
    "DN-1": "Set-DhcpServerDnsCredential -Credential (Get-Credential) with a dedicated, unprivileged domain account.",
    "AV-1": "Add the scopes to a failover relationship with a second DHCP server.",
    "AV-2": "Set a shared secret on each failover relationship (Set-DhcpServerv4Failover -SharedSecret).",
    "AV-3": "Enlarge the nearly exhausted scopes or shorten their leases.",
    "AV-4": "Shorten long leases (Set-DhcpServerv4Scope -LeaseDuration 8.00:00:00).",
    "AC-1": "Remove broad groups from DHCP Administrators.",
    "AC-2": "Remove broad groups from DHCP Users.",
    "AC-3": "Move the DHCP role off the domain controller.",
    "AC-4": "Move the DHCP role to Windows Server 2016 or later.",
}.items():
    TEMPLATES.manual(f"DHCP-{_rid}", _desc)
for _n in range(1, 6):
    TEMPLATES.manual(f"DHCP-PR-{_n}", "Procedural requirement: verify and document it; nothing to change on the server.")
