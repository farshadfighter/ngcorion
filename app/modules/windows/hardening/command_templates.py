"""
Windows Server Hardening Command Templates (PowerShell)

Remediation PowerShell for each CIS Windows Server 2025 check. Unlike the
SSH-based modules, Windows hardening runs PowerShell directly on the server via
WinRM.

Check IDs match the audit rule IDs 1:1 (``WIN-2025-<section>``). The large
Section 2.3 / Section 18 registry set is *generated* from the same
``REGISTRY_CHECKS`` table the audit engine uses, so a fix always writes exactly
the value the audit later verifies — no audit↔hardening drift. Account-policy,
firewall, audit-policy and account-rename fixes are declared explicitly.

Each template:
- statements:        PowerShell run in order ({PARAM} placeholders substituted)
- verify_statements: PowerShell that prints 'PASS' or 'FAIL'
- requires_restart:  True when a reboot is needed for the change to take effect
- manual_only:       True when automated remediation is not feasible (GPO/HKU)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..audit.rules import REGISTRY_CHECKS


@dataclass
class WindowsHardeningTemplate:
    """Template for hardening a specific CIS Windows Server check."""
    check_id: str
    description: str
    statements: List[str]
    verify_statements: List[str] = field(default_factory=list)
    requires_restart: bool = False
    manual_only: bool = False


WINDOWS_HARDENING_TEMPLATES: Dict[str, WindowsHardeningTemplate] = {}


def _register(t: WindowsHardeningTemplate) -> None:
    WINDOWS_HARDENING_TEMPLATES[t.check_id] = t


# ===================================================================
# GENERATED: Registry checks (Section 2.3 / 18) from REGISTRY_CHECKS
# ===================================================================

def _reg_set_statement(path: str, prop: str, set_value, rtype: str) -> str:
    if rtype == "string":
        value_expr = "'" + str(set_value).replace("'", "''") + "'"
        type_expr = "String"
    else:
        value_expr = str(int(set_value))
        type_expr = "DWord"
    return (
        f"if (-not (Test-Path -LiteralPath '{path}')) "
        f"{{ New-Item -Path '{path}' -Force | Out-Null }}; "
        f"Set-ItemProperty -LiteralPath '{path}' -Name '{prop}' "
        f"-Value {value_expr} -Type {type_expr} -Force"
    )


def _reg_verify_statement(path: str, prop: str, set_value, rtype: str) -> str:
    if rtype == "string":
        cmp_expr = f"-eq '{str(set_value)}'"
    else:
        cmp_expr = f"-eq {int(set_value)}"
    return (
        f"if ((Get-ItemProperty -LiteralPath '{path}' -Name '{prop}' "
        f"-ErrorAction SilentlyContinue).'{prop}' {cmp_expr}) "
        f"{{ 'PASS' }} else {{ 'FAIL' }}"
    )


for _c in REGISTRY_CHECKS:
    if not _c.get("fixable"):
        continue
    _cid = f"WIN-2025-{_c['section']}"
    _register(WindowsHardeningTemplate(
        check_id=_cid,
        description=f"Set {_c['title']}",
        statements=[_reg_set_statement(_c["path"], _c["prop"], _c["set"], _c["rtype"])],
        verify_statements=[_reg_verify_statement(_c["path"], _c["prop"], _c["set"], _c["rtype"])],
        requires_restart=_c.get("restart", False),
    ))


# ===================================================================
# Account Policy (net accounts) — Section 1
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.1.1",
    description="Set 'Enforce password history' to 24 passwords",
    statements=["net accounts /uniquepw:24"],
    verify_statements=[
        "net accounts | Select-String 'password history' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 24) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.1.2",
    description="Set 'Maximum password age' to {MAX_PASSWORD_AGE} days",
    statements=["net accounts /maxpwage:{MAX_PASSWORD_AGE}"],
    verify_statements=[
        "net accounts | Select-String 'Maximum password age' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -le 365 -and [int]$Matches[1] -gt 0) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.1.3",
    description="Set 'Minimum password age' to 1 day",
    statements=["net accounts /minpwage:1"],
    verify_statements=[
        "net accounts | Select-String 'Minimum password age' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 1) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.1.4",
    description="Set 'Minimum password length' to 14 characters",
    statements=["net accounts /minpwlen:14"],
    verify_statements=[
        "net accounts | Select-String 'Minimum password length' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 14) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.2.1",
    description="Set 'Account lockout duration' to {LOCKOUT_DURATION} minutes",
    statements=["net accounts /lockoutduration:{LOCKOUT_DURATION}"],
    verify_statements=[
        "net accounts | Select-String 'Lockout duration' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 15) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.2.2",
    description="Set 'Account lockout threshold' to {LOCKOUT_THRESHOLD} attempts",
    statements=["net accounts /lockoutthreshold:{LOCKOUT_THRESHOLD}"],
    verify_statements=[
        "net accounts | Select-String 'Lockout threshold' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -le 5 -and [int]$Matches[1] -gt 0) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-1.2.4",
    description="Set 'Reset account lockout counter after' to {LOCKOUT_WINDOW} minutes",
    statements=["net accounts /lockoutwindow:{LOCKOUT_WINDOW}"],
    verify_statements=[
        "net accounts | Select-String 'Lockout observation' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 15) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

# ===================================================================
# Accounts (2.3.1) — disable Guest + rename admin/guest
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-2.3.1.1",
    description="Disable the built-in Guest account",
    statements=["Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue"],
    verify_statements=[
        "if ((Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled -eq $false) { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-2.3.1.3",
    description="Rename built-in Administrator account to {NEW_ADMIN_NAME}",
    statements=[
        "Rename-LocalUser -Name (Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name "
        "-NewName '{NEW_ADMIN_NAME}' -ErrorAction Stop",
    ],
    verify_statements=[
        "if ((Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name -ne 'Administrator') { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-2025-2.3.1.4",
    description="Rename built-in Guest account to {NEW_GUEST_NAME}",
    statements=[
        "Rename-LocalUser -Name (Get-LocalUser | Where-Object { $_.SID -like '*-501' }).Name "
        "-NewName '{NEW_GUEST_NAME}' -ErrorAction Stop",
    ],
    verify_statements=[
        "if ((Get-LocalUser | Where-Object { $_.SID -like '*-501' }).Name -ne 'Guest') { 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# GENERATED: Windows Defender Firewall — Section 9
# ===================================================================

_FW_PROFILES = {"Domain": ("9.1", "domainfw.log"),
                "Private": ("9.2", "privatefw.log"),
                "Public": ("9.3", "publicfw.log")}


def _fw(section, profile, description, set_stmt, verify_expr):
    _register(WindowsHardeningTemplate(
        check_id=f"WIN-2025-{section}",
        description=description,
        statements=[f"Set-NetFirewallProfile -Profile {profile} {set_stmt}"],
        verify_statements=[
            f"if ({verify_expr}) {{ 'PASS' }} else {{ 'FAIL' }}"
        ],
    ))


for _prof, (_base, _logfile) in _FW_PROFILES.items():
    _fw(f"{_base}.1", _prof, f"Turn Windows Firewall On for {_prof} profile",
        "-Enabled True", f"(Get-NetFirewallProfile -Profile {_prof}).Enabled")
    _fw(f"{_base}.2", _prof, f"Block inbound connections by default ({_prof})",
        "-DefaultInboundAction Block",
        f"(Get-NetFirewallProfile -Profile {_prof}).DefaultInboundAction -eq 'Block'")
    _fw(f"{_base}.3", _prof, f"Disable notifications ({_prof})",
        "-NotifyOnListen False",
        f"(Get-NetFirewallProfile -Profile {_prof}).NotifyOnListen -eq $false")
    if _prof == "Public":
        _fw("9.3.4", _prof, "Do not apply local firewall rules (Public)",
            "-AllowLocalFirewallRules False",
            "(Get-NetFirewallProfile -Profile Public).AllowLocalFirewallRules -eq $false")
        _fw("9.3.5", _prof, "Do not apply local connection security rules (Public)",
            "-AllowLocalIPsecRules False",
            "(Get-NetFirewallProfile -Profile Public).AllowLocalIPsecRules -eq $false")
        _ln, _sz, _dr, _sc = "9.3.6", "9.3.7", "9.3.8", "9.3.9"
    else:
        _ln, _sz, _dr, _sc = f"{_base}.4", f"{_base}.5", f"{_base}.6", f"{_base}.7"
    _fw(_ln, _prof, f"Set firewall log file name ({_prof})",
        f"-LogFileName '%systemroot%\\system32\\logfiles\\firewall\\{_logfile}'",
        f"(Get-NetFirewallProfile -Profile {_prof}).LogFileName -like '*{_logfile}'")
    _fw(_sz, _prof, f"Set firewall log size limit to 16384 KB ({_prof})",
        "-LogMaxSizeKilobytes 16384",
        f"(Get-NetFirewallProfile -Profile {_prof}).LogMaxSizeKilobytes -ge 16384")
    _fw(_dr, _prof, f"Log dropped packets ({_prof})",
        "-LogBlocked True",
        f"(Get-NetFirewallProfile -Profile {_prof}).LogBlocked -eq $true")
    _fw(_sc, _prof, f"Log successful connections ({_prof})",
        "-LogAllowed True",
        f"(Get-NetFirewallProfile -Profile {_prof}).LogAllowed -eq $true")

# ===================================================================
# GENERATED: Advanced Audit Policy — Section 17 (auditpol)
# ===================================================================

# (section, subcategory, flag) — flag in {'both','success','failure'}
_AUDIT_FIXES = [
    ("17.1.1", "Credential Validation", "both"),
    ("17.1.2", "Kerberos Authentication Service", "both"),
    ("17.1.3", "Kerberos Service Ticket Operations", "both"),
    ("17.2.1", "Application Group Management", "both"),
    ("17.2.2", "Computer Account Management", "success"),
    ("17.2.3", "Distribution Group Management", "success"),
    ("17.2.4", "Other Account Management Events", "success"),
    ("17.2.5", "Security Group Management", "success"),
    ("17.2.6", "User Account Management", "both"),
    ("17.3.1", "Plug and Play Events", "success"),
    ("17.3.2", "Process Creation", "success"),
    ("17.4.1", "Directory Service Access", "failure"),
    ("17.4.2", "Directory Service Changes", "success"),
    ("17.5.1", "Account Lockout", "failure"),
    ("17.5.2", "Group Membership", "success"),
    ("17.5.3", "Logoff", "success"),
    ("17.5.4", "Logon", "both"),
    ("17.5.5", "Other Logon/Logoff Events", "both"),
    ("17.5.6", "Special Logon", "success"),
    ("17.6.1", "Detailed File Share", "failure"),
    ("17.6.2", "File Share", "both"),
    ("17.6.3", "Other Object Access Events", "both"),
    ("17.6.4", "Removable Storage", "both"),
    ("17.7.1", "Audit Policy Change", "success"),
    ("17.7.2", "Authentication Policy Change", "success"),
    ("17.7.3", "Authorization Policy Change", "success"),
    ("17.7.4", "MPSSVC Rule-Level Policy Change", "both"),
    ("17.7.5", "Other Policy Change Events", "failure"),
    ("17.8.1", "Sensitive Privilege Use", "both"),
    ("17.9.1", "IPsec Driver", "both"),
    ("17.9.2", "Other System Events", "both"),
    ("17.9.3", "Security State Change", "success"),
    ("17.9.4", "Security System Extension", "success"),
    ("17.9.5", "System Integrity", "both"),
]

for _sec, _subcat, _flag in _AUDIT_FIXES:
    if _flag == "both":
        _set = f"auditpol /set /subcategory:\"{_subcat}\" /success:enable /failure:enable"
        _need_s, _need_f = True, True
    elif _flag == "success":
        _set = f"auditpol /set /subcategory:\"{_subcat}\" /success:enable /failure:disable"
        _need_s, _need_f = True, False
    else:
        _set = f"auditpol /set /subcategory:\"{_subcat}\" /success:disable /failure:enable"
        _need_s, _need_f = False, True
    if _need_s and _need_f:
        _vcond = "$s -match 'Success' -and $s -match 'Failure'"
    elif _need_s:
        _vcond = "$s -match 'Success'"
    else:
        _vcond = "$s -match 'Failure'"
    _register(WindowsHardeningTemplate(
        check_id=f"WIN-2025-{_sec}",
        description=f"Set audit policy '{_subcat}' ({_flag})",
        statements=[_set],
        verify_statements=[
            f"$r = auditpol /get /subcategory:\"{_subcat}\" /r | ConvertFrom-Csv; "
            f"$s = $r.'Inclusion Setting'; if ({_vcond}) {{ 'PASS' }} else {{ 'FAIL' }}"
        ],
    ))

# ===================================================================
# MANUAL ONLY — GPO / secedit-template / patch / HKU controls
# ===================================================================

_MANUAL_CHECKS = [
    ("WIN-2025-1.1.5", "Password must meet complexity requirements — requires secedit template / GPO"),
    ("WIN-2025-1.1.7", "Disable reversible encryption — requires secedit template / GPO"),
    ("WIN-2025-1.2.3", "Allow Administrator account lockout — requires secpol / GPO"),
    ("WIN-2025-2.3.7.4", "Interactive logon message text — configure via GPO"),
    ("WIN-2025-2.3.7.5", "Interactive logon message title — configure via GPO"),
    ("WIN-2025-2.3.10.7", "Named pipes accessible anonymously — clear multi-string value manually"),
    ("WIN-2025-2.3.10.12", "Anonymous shares — clear multi-string value manually"),
]

for _mid, _desc in _MANUAL_CHECKS:
    _register(WindowsHardeningTemplate(
        check_id=_mid, description=_desc, statements=[], manual_only=True,
    ))


# ===================================================================
# Helper functions
# ===================================================================

def get_windows_hardening_template(check_id: str) -> Optional[WindowsHardeningTemplate]:
    """Return the hardening template for the given check ID, or None."""
    return WINDOWS_HARDENING_TEMPLATES.get(check_id)


def get_all_supported_checks() -> Set[str]:
    """Return the set of all check IDs that have a hardening template."""
    return set(WINDOWS_HARDENING_TEMPLATES.keys())


def get_windows_template_statements(
    check_id: str, parameters: Dict[str, str] = None
) -> List[str]:
    """Return PowerShell statements with {PARAM} placeholders substituted."""
    template = get_windows_hardening_template(check_id)
    if not template:
        return []
    parameters = parameters or {}
    result = []
    for stmt in template.statements:
        for name, value in parameters.items():
            stmt = stmt.replace(f"{{{name}}}", str(value))
        result.append(stmt)
    return result


def get_windows_verify_statements(
    check_id: str, parameters: Dict[str, str] = None
) -> List[str]:
    """Return verification PowerShell statements with placeholders substituted."""
    template = get_windows_hardening_template(check_id)
    if not template:
        return []
    parameters = parameters or {}
    result = []
    for stmt in template.verify_statements:
        for name, value in parameters.items():
            stmt = stmt.replace(f"{{{name}}}", str(value))
        result.append(stmt)
    return result
