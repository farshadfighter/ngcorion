"""
Active Directory remediation.

AD-CIS-* fixes reuse the Windows module's templates for the same control, so
an AD fix writes exactly what a Windows fix writes and what the audit reads.
Two kinds of CIS control are left manual on a DC:

* account policy (1.x): on a domain controller the Default Domain Policy GPO
  owns these, and writes made with `net accounts` are put back at the next
  policy refresh. The fix is a change to that GPO.
* the account-rename controls: Rename-LocalUser has no local account to act
  on on a DC.

AD-DOM-* fixes change the directory. Those with side effects an operator must
accept (a forest-wide change that cannot be undone, a credential reset,
legacy applications losing anonymous access) need an explicit confirmation
parameter, so Harden All never runs them on defaults alone. Fixes that need a
decision about specific accounts (who belongs in Domain Admins, which stale
account to disable) stay manual.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet
from app.modules.windows.hardening.command_templates import WINDOWS_HARDENING_TEMPLATES
from app.modules.windows.hardening.parameter_metadata import (
    WINDOWS_CHECK_PARAMETER_MAP,
    WINDOWS_PARAMETER_REGISTRY,
)

from .collect import KDC, LSA, NETLOGON, SRV
from .rules import cis_rules

TEMPLATES = TemplateSet()

_CONFIRM = "CONFIRM"
TEMPLATES.param(ParamMeta(
    name=_CONFIRM, input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))

for _name, _p in WINDOWS_PARAMETER_REGISTRY.items():
    TEMPLATES.param(ParamMeta(
        name=_p.name, input_type=_p.input_type, label=_p.label, description=_p.description,
        required=_p.required, default=_p.default, placeholder=_p.placeholder, validation=_p.validation,
        options=_p.options, min_value=_p.min_value, max_value=_p.max_value))

_GPO_ACCOUNT_POLICY = (
    "Edit the Default Domain Policy: Computer Configuration > Policies > Windows Settings > "
    "Security Settings > Account Policies. On a domain controller this GPO owns the setting.")
_MANUAL_ON_DC = {"2.3.1.3", "2.3.1.4"}


def _guard(stmt: str) -> str:
    return "Import-Module ActiveDirectory; " + stmt


def _ok(cond: str) -> str:
    return _guard(f"if ({cond}) {{ 'PASS' }} else {{ 'FAIL' }}")


def _reg_set(path: str, name: str, value, kind: str = "DWord") -> str:
    v = value if kind == "DWord" else value
    return (f"if (-not (Test-Path -LiteralPath '{path}')) {{ New-Item -Path '{path}' -Force | Out-Null }}; "
            f"Set-ItemProperty -LiteralPath '{path}' -Name '{name}' -Value {v} -Type {kind} -Force")


def _reg_ok(path: str, name: str, value) -> str:
    return (f"if ((Get-ItemProperty -LiteralPath '{path}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}' "
            f"-eq {value}) {{ 'PASS' }} else {{ 'FAIL' }}")


# ── CIS (DC profile) ───────────────────────────────────────────────────────

for _rule in cis_rules():
    _sec = _rule.section
    _cid = f"AD-CIS-{_sec}"
    if _sec.startswith("1."):
        TEMPLATES.manual(_cid, _GPO_ACCOUNT_POLICY)
        continue
    if _sec in _MANUAL_ON_DC:
        TEMPLATES.manual(_cid, "Rename the account in Active Directory Users and Computers (no local account on a DC).")
        continue
    _w = WINDOWS_HARDENING_TEMPLATES.get(f"WIN-2025-{_sec}")
    if _w is None:
        continue
    TEMPLATES.add(HardeningTemplate(
        check_id=_cid, description=_w.description, statements=list(_w.statements),
        verify_statements=list(_w.verify_statements), requires_restart=_w.requires_restart,
        manual_only=_w.manual_only, parameters=list(WINDOWS_CHECK_PARAMETER_MAP.get(f"WIN-2025-{_sec}", [])),
        warning=("A setting the Default Domain Controllers Policy also defines is put back at the next "
                 "policy refresh; change it in that GPO instead.")))

TEMPLATES.manual("AD-CIS-2.2.5", "Default Domain Controllers Policy > User Rights Assignment > "
                                 "Add workstations to domain: Administrators.")
TEMPLATES.add(HardeningTemplate(
    check_id="AD-CIS-2.3.5.1", description="Disable 'Allow server operators to schedule tasks'",
    statements=[_reg_set(LSA, "SubmitControl", 0)], verify_statements=[_reg_ok(LSA, "SubmitControl", 0)]))
TEMPLATES.add(HardeningTemplate(
    check_id="AD-CIS-2.3.10.6", description="Limit anonymous named pipes to LSARPC, NETLOGON, SAMR",
    statements=[f"Set-ItemProperty -LiteralPath '{SRV}' -Name 'NullSessionPipes' "
                "-Value @('LSARPC','NETLOGON','SAMR') -Type MultiString -Force"],
    verify_statements=[f"$p = @((Get-ItemProperty -LiteralPath '{SRV}' -Name NullSessionPipes).NullSessionPipes | "
                       "Where-Object { $_ }); if (-not ($p | Where-Object { $_ -notin 'LSARPC','NETLOGON','SAMR','BROWSER' })) "
                       "{ 'PASS' } else { 'FAIL' }"]))
TEMPLATES.add(HardeningTemplate(
    check_id="AD-CIS-5.1", description="Stop and disable the Print Spooler on the domain controller",
    statements=["Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue; "
                "Set-Service -Name Spooler -StartupType Disabled"],
    verify_statements=["if ((Get-Service -Name Spooler).StartType -eq 'Disabled') { 'PASS' } else { 'FAIL' }"],
    warning="Printing from this domain controller stops."))


# ── Beyond CIS ─────────────────────────────────────────────────────────────

_SID = "(Get-ADDomain).DomainSID.Value"
_PRIV_USERS = ("Get-ADUser -LDAPFilter '(&(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
               "(!(sAMAccountName=krbtgt)))' -Properties AccountNotDelegated")


def _add(n, description, statements, verify, warning=None, confirm=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"AD-DOM-{n}", description=description,
        statements=[_guard(s) for s in statements], verify_statements=verify,
        parameters=[_CONFIRM] if confirm else [], warning=warning))


_add("1.9", "Mark every privileged user account 'sensitive and cannot be delegated'",
     [f"{_PRIV_USERS} | Where-Object {{ -not $_.AccountNotDelegated }} | Set-ADUser -AccountNotDelegated $true"],
     [_ok(f"-not @({_PRIV_USERS} | Where-Object {{ -not $_.AccountNotDelegated }})")],
     warning="Services that impersonate these accounts through delegation stop working for them.", confirm=True)
_add("1.11", "Mark the built-in Administrator 'sensitive and cannot be delegated'",
     [f"Set-ADUser -Identity ({_SID} + '-500') -AccountNotDelegated $true"],
     [_ok(f"(Get-ADUser -Identity ({_SID} + '-500') -Properties AccountNotDelegated).AccountNotDelegated")])
_add("1.13", "Remove Everyone and Anonymous Logon from Pre-Windows 2000 Compatible Access",
     ["$dn = (Get-ADDomain).DistinguishedName; $g = Get-ADGroup -Identity 'S-1-5-32-554' -Properties member; "
      "foreach ($s in 'S-1-1-0','S-1-5-7') { $m = \"CN=$s,CN=ForeignSecurityPrincipals,$dn\"; "
      "if ($g.member -contains $m) { Set-ADGroup -Identity 'S-1-5-32-554' -Remove @{member = $m} } }"],
     [_ok("-not (@((Get-ADGroup -Identity 'S-1-5-32-554' -Properties member).member) -match '^CN=S-1-(1-0|5-7),')")],
     warning="Legacy applications and NT4-era trusts that read the directory anonymously lose that access.",
     confirm=True)
_add("2.1", "Reset the krbtgt password once",
     ["$b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); "
      "$p = ConvertTo-SecureString ([Convert]::ToBase64String($b) + 'aA1!') -AsPlainText -Force; "
      "Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $p"],
     [_ok("((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet).TotalDays -lt 1")],
     warning=("Make sure replication is healthy first. Reset once, wait for replication and at least the "
              "maximum ticket lifetime (10 hours by default) before a second reset; resetting twice in a row "
              "invalidates every Kerberos ticket in the domain."), confirm=True)
_add("2.2", "Require Kerberos pre-authentication on every account",
     ["Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Set-ADAccountControl -DoesNotRequirePreAuth $false"],
     [_ok("-not @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true')")],
     warning="Clients that cannot pre-authenticate (rare legacy UNIX Kerberos) stop authenticating.")
_add("2.3", "Clear 'Store password using reversible encryption' on every account",
     ["Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' | Set-ADUser -AllowReversiblePasswordEncryption $false"],
     [_ok("-not @(Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true')")],
     warning="The stored reversible copy goes away only when each user next changes the password.")
_add("2.4", "Clear 'Use only Kerberos DES encryption types' on every account",
     ["Get-ADUser -Filter 'UseDESKeyOnly -eq $true' | Set-ADAccountControl -UseDESKeyOnly $false"],
     [_ok("-not @(Get-ADUser -Filter 'UseDESKeyOnly -eq $true')")])
_add("2.5", "Clear 'Password not required' on every enabled account",
     ["Get-ADUser -Filter 'PasswordNotRequired -eq $true -and Enabled -eq $true' | Set-ADUser -PasswordNotRequired $false"],
     [_ok("-not @(Get-ADUser -Filter 'PasswordNotRequired -eq $true -and Enabled -eq $true')")],
     warning="An account that has an empty password keeps it until it is changed; set real passwords too.")
_add("2.7", "Disable the domain Guest account",
     [f"Disable-ADAccount -Identity ({_SID} + '-501')"],
     [_ok(f"-not (Get-ADUser -Identity ({_SID} + '-501')).Enabled")])
_add("3.4", "Set ms-DS-MachineAccountQuota to 0",
     ["Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota' = '0'}"],
     [_ok("(Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' -eq 0")],
     warning="Ordinary users can no longer join computers; delegate joins to a group first.", confirm=True)
_add("4.4", "Enable the Active Directory Recycle Bin",
     ["Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet "
      "-Target (Get-ADForest).Name -Confirm:$false"],
     [_ok("@((Get-ADOptionalFeature -Filter \"Name -eq 'Recycle Bin Feature'\").EnabledScopes).Count -gt 0")],
     warning="Forest-wide and permanent: the Recycle Bin cannot be disabled again. Needs Enterprise Admin rights.",
     confirm=True)
_add("4.5", "Set the tombstone lifetime to 180 days",
     ["Set-ADObject ('CN=Directory Service,CN=Windows NT,CN=Services,' + (Get-ADRootDSE).configurationNamingContext) "
      "-Replace @{tombstoneLifetime = 180}"],
     [_ok("(Get-ADObject ('CN=Directory Service,CN=Windows NT,CN=Services,' + (Get-ADRootDSE).configurationNamingContext) "
          "-Properties tombstoneLifetime).tombstoneLifetime -ge 180")],
     warning="Forest-wide. Needs Enterprise Admin rights.", confirm=True)

TEMPLATES.add(HardeningTemplate(
    check_id="AD-DOM-5.1", description="Disable SMBv1 on the domain controller",
    statements=["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
    verify_statements=["if ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false) { 'PASS' } else { 'FAIL' }"],
    warning="Clients that only speak SMBv1 (Windows XP / Server 2003, old NAS and printers) lose access."))
TEMPLATES.add(HardeningTemplate(
    check_id="AD-DOM-5.2", description="Enforce Netlogon secure channel protection",
    statements=[_reg_set(NETLOGON, "FullSecureChannelProtection", 1)],
    verify_statements=[_reg_ok(NETLOGON, "FullSecureChannelProtection", 1)]))
TEMPLATES.add(HardeningTemplate(
    check_id="AD-DOM-5.3", description="Enforce strong certificate binding on the KDC",
    statements=[_reg_set(KDC, "StrongCertificateBindingEnforcement", 2)],
    verify_statements=[_reg_ok(KDC, "StrongCertificateBindingEnforcement", 2)],
    warning="Certificate logons whose certificates are not strongly mapped to an account start failing.",
    parameters=[_CONFIRM]))
TEMPLATES.add(HardeningTemplate(
    check_id="AD-DOM-5.4", description="Prevent the DSRM administrator from logging on while AD DS runs",
    statements=[_reg_set(LSA, "DsrmAdminLogonBehavior", 0)],
    verify_statements=[_reg_ok(LSA, "DsrmAdminLogonBehavior", 0)]))

_MANUAL = {
    "1.1": "Remove standing members from Schema Admins.",
    "1.2": "Remove standing members from Enterprise Admins.",
    "1.3": "Reduce Domain Admins to the accounts that administer domain controllers.",
    "1.4": "Empty the Account, Server, Print and Backup Operators groups.",
    "1.5": "Remove members from DnsAdmins.",
    "1.6": "Remove disabled and unused accounts from privileged groups.",
    "1.7": "Clear 'Password never expires' on privileged accounts and rotate their passwords.",
    "1.8": "Change privileged account passwords.",
    "1.10": "Add privileged user accounts to Protected Users after testing their logons.",
    "1.12": "Move SPNs off privileged accounts onto gMSAs.",
    "2.6": "Move services to group Managed Service Accounts.",
    "2.8": "Review accounts with non-expiring passwords; move services to gMSAs.",
    "2.9": "Disable the inactive user accounts after confirming with their owners.",
    "2.10": "Disable the inactive computer accounts.",
    "2.11": "Upgrade or retire computers on unsupported Windows.",
    "3.1": "Switch these computers to constrained or resource-based constrained delegation.",
    "3.2": "Clear unconstrained delegation on these user accounts.",
    "3.3": "Review constrained delegation with protocol transition.",
    "4.1": "Raise the domain functional level (Active Directory Domains and Trusts).",
    "4.2": "Raise the forest functional level.",
    "4.3": "Replace domain controllers older than Windows Server 2016.",
    "4.6": "Set the 7th character of dSHeuristics to 0 (ADSI Edit, CN=Directory Service).",
    "4.7": "Run Update-LapsADSchema and deploy Windows LAPS.",
    "4.8": "Apply the Windows LAPS policy to every computer OU.",
    "4.9": "Delete the Group Policy Preferences items that store passwords, then change those passwords.",
    "4.10": "Enable SID filtering: netdom trust ... /quarantine:yes",
    "4.11": "Disable TGT delegation: netdom trust ... /EnableTGTDelegation:No",
}
for _n, _desc in _MANUAL.items():
    TEMPLATES.manual(f"AD-DOM-{_n}", _desc)
