"""
Read-only collection for a Windows DHCP Server audit, over WinRM.

Uses the DhcpServer PowerShell module (Windows Server 2012 and later).
Leases, reservations and client identities are never read - only server
settings, scope properties and utilisation figures. The DNS dynamic-update
credential is reported by account name only.
"""

from typing import Dict

from app.modules.benchmark.rules import assemble
from app.modules.benchmark.winps import guarded
from app.modules.windows.audit.audit_commands import get_windows_audit_commands

DHCP_SETTINGS = (
    "Import-Module DhcpServer; "
    "$s = Get-DhcpServerSetting; $a = Get-DhcpServerAuditLog; $db = Get-DhcpServerDatabase; "
    "$dns = Get-DhcpServerv4DnsSetting; $cred = Get-DhcpServerDnsCredential; "
    "$bi = $db.BackupInterval; $bi = if ($bi -is [TimeSpan]) { [int]$bi.TotalMinutes } else { [int]$bi }; "
    "$scopes = @(Get-DhcpServerv4Scope | ForEach-Object { "
    "  $st = Get-DhcpServerv4ScopeStatistics -ScopeId $_.ScopeId; $sd = Get-DhcpServerv4DnsSetting -ScopeId $_.ScopeId; "
    "  [pscustomobject]@{ ScopeId = $_.ScopeId.IPAddressToString; Name = $_.Name; State = [string]$_.State; "
    "    LeaseDays = [math]::Round($_.LeaseDuration.TotalDays, 2); InUsePercent = [math]::Round($st.PercentageInUse, 1); "
    "    NameProtection = $sd.NameProtection } }); "
    "$fo = @(Get-DhcpServerv4Failover -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ "
    "  Name = $_.Name; Mode = [string]$_.Mode; EnableAuth = $_.EnableAuth; "
    "  Scopes = @($_.ScopeId | ForEach-Object { $_.IPAddressToString }) } }); "
    "[pscustomobject]@{ IsDomainJoined = $s.IsDomainJoined; IsAuthorized = $s.IsAuthorized; "
    "  ConflictDetectionAttempts = $s.ConflictDetectionAttempts; AuditEnabled = $a.Enable; AuditPath = $a.Path; "
    "  BackupIntervalMinutes = $bi; BackupPath = $db.BackupPath; NameProtection = $dns.NameProtection; "
    "  DeleteOnExpiry = $dns.DeleteDnsRROnLeaseExpiry; DynamicUpdates = [string]$dns.DynamicUpdates; "
    "  DnsCredentialUser = if ($cred.UserName) { \"$($cred.DomainName)\\$($cred.UserName)\" } else { $null }; "
    "  Scopes = $scopes; Failover = $fo } | ConvertTo-Json -Depth 5 -Compress"
)

# Members of the two delegation groups the role creates. On a DC they are
# domain local groups, which Get-LocalGroupMember cannot read.
DHCP_HOST = (
    "function Members($g) { try { @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } "
    "  catch { try { Import-Module ActiveDirectory -ErrorAction Stop; @(Get-ADGroupMember -Identity $g | ForEach-Object { "
    "    [string]$_.SamAccountName }) } catch { ,@('ERROR: ' + $_.Exception.Message) } } }; "
    "$svc = Get-Service -Name DHCPServer; "
    "[pscustomobject]@{ ServiceStatus = [string]$svc.Status; ServiceStartType = [string]$svc.StartType; "
    "  DhcpAdministrators = Members 'DHCP Administrators'; DhcpUsers = Members 'DHCP Users' } | ConvertTo-Json -Depth 4 -Compress"
)

HOST_SECTIONS = ("OS_VERSION", "DOMAIN_ROLE")


def dhcp_commands() -> Dict[str, str]:
    win = get_windows_audit_commands()
    cmds = {name: win[name] for name in HOST_SECTIONS}
    cmds.update({"DHCP_SETTINGS": guarded(DHCP_SETTINGS), "DHCP_HOST": guarded(DHCP_HOST)})
    return cmds


def collect(conn) -> str:
    return assemble({name: conn.run(script) for name, script in dhcp_commands().items()})
