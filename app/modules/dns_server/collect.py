"""
Read-only collection for a Windows DNS Server audit, over WinRM.

Uses the DnsServer PowerShell module (Windows Server 2012 R2 and later).
Zone contents are never read - only zone properties and the DNSSEC signing
key metadata (algorithm, length, rollover), never key material.
"""

from typing import Dict

from app.modules.benchmark.rules import assemble
from app.modules.benchmark.winps import guarded, registry_script
from app.modules.windows.audit.audit_commands import get_windows_audit_commands

DNS_PARAMS = r"HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
DNS_REGISTRY_PROPS = {DNS_PARAMS: ["SocketPoolSize", "EnableDnsSec"]}

_IMPORT = "Import-Module DnsServer; "

DNS_SETTINGS = _IMPORT + (
    "$s = Get-DnsServerSetting -All; $r = Get-DnsServerRecursion; $c = Get-DnsServerCache; "
    "$f = Get-DnsServerForwarder; $d = Get-DnsServerDiagnostics; "
    "$g = try { Get-DnsServerGlobalQueryBlockList -ErrorAction Stop } catch { $null }; "
    "$rrl = try { Get-DnsServerResponseRateLimiting -ErrorAction Stop } catch { $null }; "
    "$rh = @(Get-DnsServerRootHint -ErrorAction SilentlyContinue).Count; "
    "[pscustomobject]@{ "
    "  Version = \"$($s.MajorVersion).$($s.MinorVersion).$($s.BuildNumber)\"; EnableDnsSec = $s.EnableDnsSec; "
    "  ListeningIPAddress = @($s.ListeningIPAddress | ForEach-Object { $_.IPAddressToString }); "
    "  Recursion = [pscustomobject]@{ Enable = $r.Enable; SecureResponse = $r.SecureResponse }; "
    "  Cache = [pscustomobject]@{ EnablePollutionProtection = $c.EnablePollutionProtection; LockingPercent = $c.LockingPercent; "
    "    MaxTtlSeconds = [int]$c.MaxTtl.TotalSeconds; MaxNegativeTtlSeconds = [int]$c.MaxNegativeTtl.TotalSeconds }; "
    "  Forwarders = @($f.IPAddress | Where-Object { $_ } | ForEach-Object { $_.IPAddressToString }); "
    "  UseRootHint = $f.UseRootHint; RootHints = $rh; "
    "  BlockList = if ($g) { [pscustomobject]@{ Enable = $g.Enable; List = @($g.List) } } else { $null }; "
    "  Rrl = if ($rrl) { [string]$rrl.Mode } else { 'NotSupported' }; "
    "  Diagnostics = [pscustomobject]@{ EventLogLevel = $d.EventLogLevel; EnableLoggingToFile = $d.EnableLoggingToFile } "
    "} | ConvertTo-Json -Depth 4 -Compress"
)

DNS_ZONES = _IMPORT + (
    "$z = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object { "
    "  $sec = $null; "
    "  if ($_.IsSigned) { try { "
    "    $ds = Get-DnsServerDnsSecZoneSetting -ZoneName $_.ZoneName; "
    "    $keys = @(Get-DnsServerSigningKey -ZoneName $_.ZoneName | ForEach-Object { [pscustomobject]@{ "
    "      Type = [string]$_.KeyType; Algorithm = [string]$_.CryptoAlgorithm; Length = $_.KeyLength; "
    "      Rollover = [bool]$_.IsRolloverEnabled } }); "
    "    $sec = [pscustomobject]@{ DenialOfExistence = [string]$ds.DenialOfExistence; Keys = $keys } "
    "  } catch { $sec = [pscustomobject]@{ Error = $_.Exception.Message } } }; "
    "  [pscustomobject]@{ Name = $_.ZoneName; Type = [string]$_.ZoneType; DsIntegrated = $_.IsDsIntegrated; "
    "    Reverse = $_.IsReverseLookupZone; DynamicUpdate = [string]$_.DynamicUpdate; "
    "    SecureSecondaries = [string]$_.SecureSecondaries; Signed = [bool]$_.IsSigned; Dnssec = $sec } }); "
    "ConvertTo-Json -InputObject $z -Depth 5 -Compress"
)

DNS_HOST = (
    "$ifs = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.ConnectionState -eq 'Connected' "
    "  -and $_.InterfaceAlias -notlike 'Loopback*' } | ForEach-Object { [pscustomobject]@{ Alias = $_.InterfaceAlias; "
    "  Dhcp = [string]$_.Dhcp } }); "
    "$acl = @((Get-Acl \"$env:SystemRoot\\System32\\dns\").Access | ForEach-Object { [pscustomobject]@{ "
    "  Identity = [string]$_.IdentityReference; Rights = [string]$_.FileSystemRights; Type = [string]$_.AccessControlType } }); "
    "$audit = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Audit' -ErrorAction SilentlyContinue; "
    "$log = Get-WinEvent -ListLog 'DNS Server' -ErrorAction SilentlyContinue; "
    "$svc = Get-Service -Name DNS; "
    "$roles = @(Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { $_.Name }); "
    "[pscustomobject]@{ Interfaces = $ifs; DnsFolderAcl = $acl; AuditLogEnabled = [bool]$audit.IsEnabled; "
    "  DnsLogMaxBytes = $log.MaximumSizeInBytes; ServiceStatus = [string]$svc.Status; "
    "  ServiceStartType = [string]$svc.StartType; Roles = $roles } | ConvertTo-Json -Depth 4 -Compress"
)

HOST_SECTIONS = ("OS_VERSION", "DOMAIN_ROLE")
DNS_SECTIONS = ("DNS_SETTINGS", "DNS_ZONES", "DNS_HOST", "DNS_REGISTRY")


def dns_commands() -> Dict[str, str]:
    win = get_windows_audit_commands()
    cmds = {name: win[name] for name in HOST_SECTIONS}
    cmds.update({
        "DNS_SETTINGS": guarded(DNS_SETTINGS),
        "DNS_ZONES": guarded(DNS_ZONES),
        "DNS_HOST": guarded(DNS_HOST),
        "DNS_REGISTRY": registry_script(DNS_REGISTRY_PROPS),
    })
    return cmds


def collect(conn) -> str:
    return assemble({name: conn.run(script) for name, script in dns_commands().items()})
