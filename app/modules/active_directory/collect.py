"""
Read-only collection for an Active Directory audit, run on a domain
controller over WinRM.

The host sections are the Windows module's own commands (secedit, auditpol,
registry, firewall), so the CIS rules read exactly what they read on a
Windows Server audit. The AD_* sections query the directory with the
ActiveDirectory PowerShell module that every domain controller has. Nothing
here writes to the directory or the host. Account lists are capped at 50
names per category; counts are always exact. Secret values (GPP cpassword,
LAPS passwords) are never read - only whether they exist.
"""

from typing import Dict

from app.modules.benchmark.winps import guarded, registry_script  # noqa: F401 (re-exported)
from app.modules.windows.audit.audit_commands import get_windows_audit_commands

LSA = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
NETLOGON = r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
KDC = r"HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
SRV = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
NTDS = r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

AD_REGISTRY_PROPS = {
    LSA: ["DsrmAdminLogonBehavior", "SubmitControl"],
    NETLOGON: ["FullSecureChannelProtection", "VulnerableChannelAllowList"],
    KDC: ["StrongCertificateBindingEnforcement"],
    SRV: ["NullSessionPipes"],
    NTDS: ["LdapEnforceChannelBinding", "LDAPServerIntegrity"],
}

# Host sections reused from the Windows module (LOCAL_USERS is skipped: a
# domain controller has no local accounts).
HOST_SECTIONS = ("OS_VERSION", "DOMAIN_ROLE", "SECURITY_POLICY", "USER_RIGHTS",
                 "AUDIT_POLICY", "REGISTRY", "FIREWALL_PROFILES")

_IMPORT = "Import-Module ActiveDirectory; "

# FILETIME / generalized-time thresholds, and a helper turning a FILETIME
# attribute into "days ago" (null when never set).
_TIME = (
    "$now = (Get-Date).ToUniversalTime(); "
    "function Days($ft) { if ($ft -and [int64]$ft -gt 0 -and [int64]$ft -lt [int64]::MaxValue) "
    "{ [int]($now - [DateTime]::FromFileTimeUtc([int64]$ft)).TotalDays } else { $null } }; "
)

AD_DOMAIN = _IMPORT + (
    "$d = Get-ADDomain; $f = Get-ADForest; $root = Get-ADRootDSE; "
    "$cfg = $root.configurationNamingContext; $schema = $root.schemaNamingContext; "
    "$ds = Get-ADObject ('CN=Directory Service,CN=Windows NT,CN=Services,' + $cfg) "
    "  -Properties tombstoneLifetime, dsHeuristics; "
    "$rb = Get-ADOptionalFeature -Filter \"Name -eq 'Recycle Bin Feature'\"; "
    "$maq = (Get-ADObject $d.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'; "
    "$lapsLegacy = @(Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)').Count -gt 0; "
    "$lapsWin = @(Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)').Count -gt 0; "
    "$dcs = @(Get-ADDomainController -Filter * | ForEach-Object { [pscustomobject]@{ "
    "  Name = $_.Name; HostName = $_.HostName; OperatingSystem = $_.OperatingSystem; "
    "  OperatingSystemVersion = $_.OperatingSystemVersion; IsGlobalCatalog = $_.IsGlobalCatalog; IsReadOnly = $_.IsReadOnly } }); "
    "$fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue).Count; "
    "[pscustomobject]@{ DNSRoot = $d.DNSRoot; NetBIOSName = $d.NetBIOSName; DomainSID = $d.DomainSID.Value; "
    "  DistinguishedName = $d.DistinguishedName; DomainMode = [string]$d.DomainMode; ForestMode = [string]$f.ForestMode; "
    "  ForestRoot = $f.RootDomain; IsForestRoot = ($f.RootDomain -eq $d.DNSRoot); DomainControllers = $dcs; "
    "  TombstoneLifetime = $ds.tombstoneLifetime; DsHeuristics = $ds.dsHeuristics; "
    "  RecycleBinEnabled = [bool]($rb -and @($rb.EnabledScopes).Count -gt 0); MachineAccountQuota = $maq; "
    "  LapsLegacySchema = $lapsLegacy; LapsWindowsSchema = $lapsWin; FineGrainedPolicies = $fgpp "
    "} | ConvertTo-Json -Depth 4 -Compress"
)

# Members are resolved with LDAP_MATCHING_RULE_IN_CHAIN, which follows nested
# groups without failing on foreign security principals the way
# Get-ADGroupMember -Recursive does.
AD_PRIVILEGED = _IMPORT + _TIME + (
    "$d = Get-ADDomain; $f = Get-ADForest; $sid = $d.DomainSID.Value; "
    "$rootServer = $null; $rootSid = $sid; "
    "if ($f.RootDomain -ne $d.DNSRoot) { $rootServer = $f.RootDomain; "
    "  try { $rootSid = (Get-ADDomain -Identity $f.RootDomain -Server $f.RootDomain).DomainSID.Value } catch { $rootSid = $null } }; "
    "$groups = [ordered]@{ "
    "  'Domain Admins' = @(\"$sid-512\", $null); 'Schema Admins' = @(\"$rootSid-518\", $rootServer); "
    "  'Enterprise Admins' = @(\"$rootSid-519\", $rootServer); 'Administrators' = @('S-1-5-32-544', $null); "
    "  'Account Operators' = @('S-1-5-32-548', $null); 'Server Operators' = @('S-1-5-32-549', $null); "
    "  'Print Operators' = @('S-1-5-32-550', $null); 'Backup Operators' = @('S-1-5-32-551', $null); "
    "  'Group Policy Creator Owners' = @(\"$sid-520\", $null); 'Key Admins' = @(\"$sid-526\", $null); "
    "  'Enterprise Key Admins' = @(\"$rootSid-527\", $rootServer); 'Protected Users' = @(\"$sid-525\", $null); "
    "  'DnsAdmins' = @('DnsAdmins', $null) }; "
    "$out = [ordered]@{}; "
    "foreach ($name in $groups.Keys) { $id = $groups[$name][0]; $srv = $groups[$name][1]; "
    "  $e = [ordered]@{ Identity = $id; Exists = $false; Members = @(); Error = $null }; "
    "  try { "
    "    $p = @{ Identity = $id; ErrorAction = 'Stop' }; if ($srv) { $p.Server = $srv }; $g = Get-ADGroup @p; $e.Exists = $true; "
    "    $q = @{ LDAPFilter = \"(&(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName))(!(objectClass=group)))\"; "
    "      Properties = @('sAMAccountName','objectSid','userAccountControl','pwdLastSet','lastLogonTimestamp','adminCount','servicePrincipalName'); "
    "      ResultSetSize = 500; ErrorAction = 'Stop' }; if ($srv) { $q.Server = $srv }; "
    "    $e.Members = @(Get-ADObject @q | ForEach-Object { $uac = [int]$_.userAccountControl; [pscustomobject]@{ "
    "      Sam = $_.sAMAccountName; Class = $_.ObjectClass; Sid = if ($_.objectSid) { $_.objectSid.Value } else { $_.Name }; "
    "      Enabled = -not ($uac -band 2); PwdNeverExpires = [bool]($uac -band 65536); NotDelegated = [bool]($uac -band 1048576); "
    "      PwdLastSetDays = Days $_.pwdLastSet; LastLogonDays = Days $_.lastLogonTimestamp; "
    "      Spn = @($_.servicePrincipalName).Count; AdminCount = $_.adminCount } }) "
    "  } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $e.Exists = $false "
    "  } catch { $e.Error = $_.Exception.Message }; $out[$name] = $e }; "
    "$pre = Get-ADGroup -Identity 'S-1-5-32-554' -Properties member; "
    "$out['Pre-Windows 2000 Compatible Access'] = [ordered]@{ Identity = 'S-1-5-32-554'; Exists = $true; "
    "  Members = @($pre.member | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }); Error = $null }; "
    "$out | ConvertTo-Json -Depth 5 -Compress"
)

_U = "(objectCategory=person)(objectClass=user)"
_EN = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"


def _bit(n: int) -> str:
    return f"(userAccountControl:1.2.840.113556.1.4.803:={n})"


_DC = "(|" + _bit(8192) + _bit(67108864) + ")"          # DC / RODC computer accounts
_OLD_OS = ("(|(operatingSystem=Windows XP*)(operatingSystem=Windows Vista*)(operatingSystem=Windows 7*)"
           "(operatingSystem=Windows 8*)(operatingSystem=Windows 10*)(operatingSystem=Windows 2000*)"
           "(operatingSystem=Windows Server 2003*)(operatingSystem=Windows Server 2008*)"
           "(operatingSystem=Windows Server 2012*))")

ACCOUNT_QUERIES = {
    "UsersEnabled": f"(&{_U}{_EN})",
    "PwdNotRequired": f"(&{_U}{_EN}{_bit(32)})",
    "ReversibleEncryption": f"(&{_U}{_bit(128)})",
    "PwdNeverExpires": f"(&{_U}{_EN}{_bit(65536)})",
    "DesOnly": f"(&{_U}{_bit(2097152)})",
    "NoPreAuth": f"(&{_U}{_EN}{_bit(4194304)})",
    "UserSpn": f"(&{_U}{_EN}(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
    "UnconstrainedUsers": f"(&{_U}{_EN}{_bit(524288)})",
    "UnconstrainedComputers": f"(&(objectCategory=computer){_EN}{_bit(524288)}(!{_DC}))",
    "ProtocolTransition": f"(&{_EN}{_bit(16777216)})",
    "ConstrainedDelegation": f"(&{_EN}(msDS-AllowedToDelegateTo=*))",
    "StaleUsers": f"(&{_U}{_EN}(|(lastLogonTimestamp<={{FT}})(&(!(lastLogonTimestamp=*))(whenCreated<={{GT}}))))",
    "StaleComputers": f"(&(objectCategory=computer){_EN}(!{_DC})(|(lastLogonTimestamp<={{FT}})(&(!(lastLogonTimestamp=*))(whenCreated<={{GT}}))))",
    "UnsupportedOs": f"(&(objectCategory=computer){_EN}{_OLD_OS}(!(operatingSystem=*LTSC*))(!(operatingSystem=*LTSB*)))",
    "WindowsComputers": f"(&(objectCategory=computer){_EN}(!{_DC})(operatingSystem=Windows*))",
}
LAPS_QUERIES = {
    "LapsLegacyManaged": f"(&(objectCategory=computer){_EN}(!{_DC})(operatingSystem=Windows*)(ms-Mcs-AdmPwdExpirationTime=*))",
    "LapsWindowsManaged": f"(&(objectCategory=computer){_EN}(!{_DC})(operatingSystem=Windows*)(msLAPS-PasswordExpirationTime=*))",
}
STALE_DAYS = 90


def _ps_hashtable(queries: Dict[str, str]) -> str:
    return "[ordered]@{ " + "; ".join(f"'{k}' = '{v}'" for k, v in queries.items()) + " }"


AD_ACCOUNTS = _IMPORT + _TIME + (
    f"$ft = $now.AddDays(-{STALE_DAYS}).ToFileTimeUtc(); "
    f"$gt = $now.AddDays(-{STALE_DAYS}).ToString('yyyyMMddHHmmss') + '.0Z'; "
    "function Q($filter) { $r = @(Get-ADObject -LDAPFilter $filter -Properties sAMAccountName -ResultSetSize $null); "
    "  [pscustomobject]@{ Count = $r.Count; Sample = @($r | Select-Object -First 50 | ForEach-Object { $_.sAMAccountName }) } }; "
    "$out = [ordered]@{}; "
    f"$queries = {_ps_hashtable(ACCOUNT_QUERIES)}; "
    "foreach ($k in $queries.Keys) { $out[$k] = Q ($queries[$k].Replace('{FT}', [string]$ft).Replace('{GT}', $gt)) }; "
    f"$laps = {_ps_hashtable(LAPS_QUERIES)}; "
    "foreach ($k in $laps.Keys) { try { $out[$k] = Q $laps[$k] } catch { $out[$k] = $null } }; "
    "$sid = (Get-ADDomain).DomainSID.Value; "
    "$k = Get-ADUser -Identity krbtgt -Properties pwdLastSet; "
    "$a = Get-ADUser -Identity \"$sid-500\" -Properties pwdLastSet, lastLogonTimestamp, userAccountControl; "
    "$gu = Get-ADUser -Identity \"$sid-501\" -Properties userAccountControl; "
    "$out['Krbtgt'] = [pscustomobject]@{ PwdLastSetDays = Days $k.pwdLastSet }; "
    "$out['BuiltinAdmin'] = [pscustomobject]@{ Sam = $a.SamAccountName; Enabled = $a.Enabled; "
    "  NotDelegated = [bool]([int]$a.userAccountControl -band 1048576); PwdLastSetDays = Days $a.pwdLastSet; "
    "  LastLogonDays = Days $a.lastLogonTimestamp }; "
    "$out['Guest'] = [pscustomobject]@{ Sam = $gu.SamAccountName; Enabled = $gu.Enabled }; "
    f"$out['StaleDays'] = {STALE_DAYS}; "
    "$out | ConvertTo-Json -Depth 4 -Compress"
)

AD_TRUSTS = _IMPORT + (
    "$t = @(Get-ADTrust -Filter * | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Direction = [string]$_.Direction; "
    "  TrustType = [string]$_.TrustType; ForestTransitive = $_.ForestTransitive; IntraForest = $_.IntraForest; "
    "  SIDFilteringQuarantined = $_.SIDFilteringQuarantined; SIDFilteringForestAware = $_.SIDFilteringForestAware; "
    "  SelectiveAuthentication = $_.SelectiveAuthentication; TGTDelegation = $_.TGTDelegation } }); "
    "ConvertTo-Json -InputObject $t -Depth 3 -Compress"
)

# Only the file names that contain a cpassword attribute are reported, never
# the value (it decrypts with a published key).
AD_GPP = _IMPORT + (
    "$dom = (Get-ADDomain).DNSRoot; $base = Join-Path (Get-SmbShare -Name SYSVOL).Path ($dom + '\\Policies'); "
    "$hits = @(Get-ChildItem -Path $base -Recurse -File -ErrorAction SilentlyContinue "
    "  -Include Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Printers.xml, Drives.xml | "
    "  Select-String -Pattern 'cpassword=\"[^\"]+\"' -List | ForEach-Object { $_.Path.Substring($base.Length) }); "
    "[pscustomobject]@{ Scanned = $base; Files = $hits } | ConvertTo-Json -Depth 3 -Compress"
)

AD_DC_CONFIG = (
    "$smb = Get-SmbServerConfiguration; $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue; "
    "[pscustomobject]@{ EnableSMB1Protocol = $smb.EnableSMB1Protocol; RequireSecuritySignature = $smb.RequireSecuritySignature; "
    "  SpoolerStatus = if ($sp) { [string]$sp.Status } else { 'NotInstalled' }; "
    "  SpoolerStartType = if ($sp) { [string]$sp.StartType } else { 'NotInstalled' } } | ConvertTo-Json -Compress"
)

AD_SECTIONS = ("AD_DOMAIN", "AD_PRIVILEGED", "AD_ACCOUNTS", "AD_TRUSTS", "AD_GPP", "AD_DC_CONFIG", "AD_REGISTRY")


def ad_commands() -> Dict[str, str]:
    win = get_windows_audit_commands()
    cmds: Dict[str, str] = {name: win[name] for name in HOST_SECTIONS}
    cmds.update({
        "AD_DOMAIN": guarded(AD_DOMAIN),
        "AD_PRIVILEGED": guarded(AD_PRIVILEGED),
        "AD_ACCOUNTS": guarded(AD_ACCOUNTS),
        "AD_TRUSTS": guarded(AD_TRUSTS),
        "AD_GPP": guarded(AD_GPP),
        "AD_DC_CONFIG": guarded(AD_DC_CONFIG),
        "AD_REGISTRY": registry_script(AD_REGISTRY_PROPS),
    })
    return cmds


def collect(conn) -> str:
    from app.modules.benchmark.rules import assemble
    return assemble({name: conn.run(script) for name, script in ad_commands().items()})
