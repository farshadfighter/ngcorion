"""
Windows Server Hardening Command Templates (PowerShell)

Remediation PowerShell commands for each CIS Windows Server check. Unlike
SSH-based modules, Windows hardening executes PowerShell directly against the
server via WinRM.

Each template contains:
- statements:        PowerShell commands executed in order (placeholders substituted)
- verify_statements: PowerShell returning 'PASS' or 'FAIL' as output
- requires_restart:  True when the server must restart for the change
- manual_only:       True when automated remediation is not feasible
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class WindowsHardeningTemplate:
    """Template for hardening a specific CIS Windows Server check."""
    check_id: str
    description: str
    statements: List[str]
    verify_statements: List[str] = field(default_factory=list)
    requires_restart: bool = False
    manual_only: bool = False


# Registry: check_id → WindowsHardeningTemplate
WINDOWS_HARDENING_TEMPLATES: Dict[str, WindowsHardeningTemplate] = {}


def _register(t: WindowsHardeningTemplate) -> None:
    WINDOWS_HARDENING_TEMPLATES[t.check_id] = t


# ===================================================================
# AUTO-FIXABLE: Security Policy (secedit-based — uses registry directly)
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-001",
    description="Set 'Enforce password history' to 24 passwords",
    statements=[
        "net accounts /uniquepw:24",
    ],
    verify_statements=[
        "net accounts | Select-String 'Length of password history' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 24) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-002",
    description="Set 'Maximum password age' to 365 days",
    statements=[
        "net accounts /maxpwage:{MAX_PASSWORD_AGE}",
    ],
    verify_statements=[
        "net accounts | Select-String 'Maximum password age' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -le 365 -and [int]$Matches[1] -gt 0) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-003",
    description="Set 'Minimum password age' to 1 day",
    statements=[
        "net accounts /minpwage:1",
    ],
    verify_statements=[
        "net accounts | Select-String 'Minimum password age' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 1) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-004",
    description="Set 'Minimum password length' to 14 characters",
    statements=[
        "net accounts /minpwlen:14",
    ],
    verify_statements=[
        "net accounts | Select-String 'Minimum password length' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 14) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: Account Lockout Policy
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-008",
    description="Set 'Account lockout duration' to 15 minutes",
    statements=[
        "net accounts /lockoutduration:{LOCKOUT_DURATION}",
    ],
    verify_statements=[
        "net accounts | Select-String 'Lockout duration' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 15) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-009",
    description="Set 'Account lockout threshold' to 5 attempts",
    statements=[
        "net accounts /lockoutthreshold:{LOCKOUT_THRESHOLD}",
    ],
    verify_statements=[
        "net accounts | Select-String 'Lockout threshold' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -le 5 -and [int]$Matches[1] -gt 0) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-011",
    description="Set 'Reset account lockout counter after' to 15 minutes",
    statements=[
        "net accounts /lockoutwindow:{LOCKOUT_WINDOW}",
    ],
    verify_statements=[
        "net accounts | Select-String 'Lockout observation' | "
        "ForEach-Object { if ($_ -match '(\\d+)') { if ([int]$Matches[1] -ge 15) { 'PASS' } else { 'FAIL' } } else { 'FAIL' } }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: Firewall Profiles
# ===================================================================

for _profile in ["Domain", "Private", "Public"]:
    _offset = {"Domain": 58, "Private": 61, "Public": 64}[_profile]

    _register(WindowsHardeningTemplate(
        check_id=f"WIN-L1-{_offset:03d}",
        description=f"Enable Windows Firewall for {_profile} profile",
        statements=[
            f"Set-NetFirewallProfile -Profile {_profile} -Enabled True",
        ],
        verify_statements=[
            f"if ((Get-NetFirewallProfile -Profile {_profile}).Enabled) {{ 'PASS' }} else {{ 'FAIL' }}",
        ],
    ))

    _register(WindowsHardeningTemplate(
        check_id=f"WIN-L1-{_offset + 1:03d}",
        description=f"Set default inbound action to Block for {_profile} profile",
        statements=[
            f"Set-NetFirewallProfile -Profile {_profile} -DefaultInboundAction Block",
        ],
        verify_statements=[
            f"if ((Get-NetFirewallProfile -Profile {_profile}).DefaultInboundAction -eq 'Block') {{ 'PASS' }} else {{ 'FAIL' }}",
        ],
    ))

    _register(WindowsHardeningTemplate(
        check_id=f"WIN-L1-{_offset + 2:03d}",
        description=f"Enable dropped packet logging for {_profile} profile",
        statements=[
            f"Set-NetFirewallProfile -Profile {_profile} -LogBlocked True",
        ],
        verify_statements=[
            f"if ((Get-NetFirewallProfile -Profile {_profile}).LogBlocked) {{ 'PASS' }} else {{ 'FAIL' }}",
        ],
    ))

# ===================================================================
# AUTO-FIXABLE: Registry-based Security Options
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-026",
    description="Disable the Guest account",
    statements=[
        "Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue",
    ],
    verify_statements=[
        "if ((Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled -eq $false) { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-029",
    description="Enable 'Audit: Force audit policy subcategory settings' (SCENoApplyLegacyAuditPolicy)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-030",
    description="Enable 'Do not display last user name'",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'DontDisplayLastUserName' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'DontDisplayLastUserName' -ErrorAction SilentlyContinue).DontDisplayLastUserName -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-031",
    description="Set 'Machine inactivity limit' to {INACTIVITY_TIMEOUT} seconds",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'InactivityTimeoutSecs' -Value {INACTIVITY_TIMEOUT} -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'InactivityTimeoutSecs' -ErrorAction SilentlyContinue).InactivityTimeoutSecs -le 900 -and "
        "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'InactivityTimeoutSecs' -ErrorAction SilentlyContinue).InactivityTimeoutSecs -gt 0) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-034",
    description="Enable 'Do not allow anonymous enumeration of SAM accounts' (RestrictAnonymousSAM = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RestrictAnonymousSAM' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue).RestrictAnonymousSAM -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-035",
    description="Enable 'Do not allow anonymous enumeration of SAM accounts and shares' (RestrictAnonymous = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RestrictAnonymous' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RestrictAnonymous' -ErrorAction SilentlyContinue).RestrictAnonymous -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-036",
    description="Disable 'Let Everyone permissions apply to anonymous users'",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'EveryoneIncludesAnonymous' -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous -eq 0) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-038",
    description="Set LAN Manager authentication level to NTLMv2 only (LmCompatibilityLevel = 5)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel -eq 5) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-039",
    description="Disable LAN Manager hash storage (NoLMHash = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'NoLMHash' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'NoLMHash' -ErrorAction SilentlyContinue).NoLMHash -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: UAC Settings
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-040",
    description="Enable UAC Admin Approval Mode for Built-in Administrator (FilterAdministratorToken = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'FilterAdministratorToken' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'FilterAdministratorToken' -ErrorAction SilentlyContinue).FilterAdministratorToken -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-045",
    description="Enable UAC (EnableLUA = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'EnableLUA' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
    requires_restart=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-046",
    description="Enable UAC secure desktop (PromptOnSecureDesktop = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'PromptOnSecureDesktop' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'PromptOnSecureDesktop' -ErrorAction SilentlyContinue).PromptOnSecureDesktop -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: Services
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-048",
    description="Disable Print Spooler service",
    statements=[
        "Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue",
        "Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue",
    ],
    verify_statements=[
        "if ((Get-Service -Name Spooler -ErrorAction SilentlyContinue).StartType -eq 'Disabled') { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-051",
    description="Disable SSDP Discovery service",
    statements=[
        "Set-Service -Name SSDPSRV -StartupType Disabled -ErrorAction SilentlyContinue",
        "Stop-Service -Name SSDPSRV -Force -ErrorAction SilentlyContinue",
    ],
    verify_statements=[
        "if ((Get-Service -Name SSDPSRV -ErrorAction SilentlyContinue).StartType -eq 'Disabled') { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-052",
    description="Disable UPnP Device Host service",
    statements=[
        "Set-Service -Name upnphost -StartupType Disabled -ErrorAction SilentlyContinue",
        "Stop-Service -Name upnphost -Force -ErrorAction SilentlyContinue",
    ],
    verify_statements=[
        "if ((Get-Service -Name upnphost -ErrorAction SilentlyContinue).StartType -eq 'Disabled') { 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: SMBv1 and critical registry
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-095",
    description="Disable SMBv1 protocol",
    statements=[
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
    ],
    verify_statements=[
        "if ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $false) { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-097",
    description="Enable LSA Protection (RunAsPPL = 1)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RunAsPPL' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
    requires_restart=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-098",
    description="Disable WDigest authentication (UseLogonCredential = 0)",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name 'UseLogonCredential' -Value 0 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential -eq 0) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-101",
    description="Enable Network Level Authentication for Remote Desktop",
    statements=[
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name 'UserAuthentication' -Value 1 -Type DWord -Force",
    ],
    verify_statements=[
        "if ((Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1) "
        "{ 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-103",
    description="Disable PowerShell v2",
    statements=[
        "try { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction Stop } "
        "catch { try { Uninstall-WindowsFeature PowerShell-V2 -ErrorAction Stop } catch { Write-Output 'FEATURE_REMOVE_FAILED' } }",
    ],
    verify_statements=[
        "try { $s = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State; "
        "if ($s -eq 'Disabled' -or $s -eq 'DisabledWithPayloadRemoved') { 'PASS' } else { 'FAIL' } } "
        "catch { try { if ((Get-WindowsFeature PowerShell-V2 -ErrorAction Stop).Installed -eq $false) { 'PASS' } else { 'FAIL' } } "
        "catch { 'PASS' } }",
    ],
    requires_restart=True,
))

# ===================================================================
# PARAMETERIZED: Account renames
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-027",
    description="Rename built-in Administrator account to {NEW_ADMIN_NAME}",
    statements=[
        "Rename-LocalUser -Name Administrator -NewName '{NEW_ADMIN_NAME}' -ErrorAction Stop",
    ],
    verify_statements=[
        "if ((Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name -ne 'Administrator') { 'PASS' } else { 'FAIL' }",
    ],
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-028",
    description="Rename built-in Guest account to {NEW_GUEST_NAME}",
    statements=[
        "Rename-LocalUser -Name Guest -NewName '{NEW_GUEST_NAME}' -ErrorAction Stop",
    ],
    verify_statements=[
        "if ((Get-LocalUser | Where-Object { $_.SID -like '*-501' }).Name -ne 'Guest') { 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# PARAMETERIZED: Disable custom service
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-048-CUSTOM",
    description="Disable service {SERVICE_NAME}",
    statements=[
        "Set-Service -Name '{SERVICE_NAME}' -StartupType Disabled -ErrorAction SilentlyContinue",
        "Stop-Service -Name '{SERVICE_NAME}' -Force -ErrorAction SilentlyContinue",
    ],
    verify_statements=[
        "if ((Get-Service -Name '{SERVICE_NAME}' -ErrorAction SilentlyContinue).StartType -eq 'Disabled') { 'PASS' } else { 'FAIL' }",
    ],
))

# ===================================================================
# AUTO-FIXABLE: Audit Policy (auditpol)
# ===================================================================

_audit_policy_fixes = [
    ("WIN-L1-067", "Credential Validation", "Success and Failure", "success,failure"),
    ("WIN-L1-068", "Application Group Management", "Success and Failure", "success,failure"),
    ("WIN-L1-069", "Computer Account Management", "Success", "success"),
    ("WIN-L1-071", "Security Group Management", "Success", "success"),
    ("WIN-L1-072", "User Account Management", "Success and Failure", "success,failure"),
    ("WIN-L1-075", "Account Lockout", "Failure", "failure"),
    ("WIN-L1-078", "Logon", "Success and Failure", "success,failure"),
    ("WIN-L1-085", "Audit Policy Change", "Success", "success"),
    ("WIN-L1-089", "Sensitive Privilege Use", "Success and Failure", "success,failure"),
    ("WIN-L1-092", "Security State Change", "Success", "success"),
    ("WIN-L1-093", "Security System Extension", "Success", "success"),
    ("WIN-L1-094", "System Integrity", "Success and Failure", "success,failure"),
]

for _cid, _subcat, _desc_val, _auditpol_val in _audit_policy_fixes:
    _register(WindowsHardeningTemplate(
        check_id=_cid,
        description=f"Set audit policy '{_subcat}' to '{_desc_val}'",
        statements=[
            f"auditpol /set /subcategory:\"{_subcat}\" /success:enable /failure:enable"
            if _auditpol_val == "success,failure" else
            f"auditpol /set /subcategory:\"{_subcat}\" /success:enable"
            if _auditpol_val == "success" else
            f"auditpol /set /subcategory:\"{_subcat}\" /failure:enable"
        ],
        verify_statements=[
            f"$r = auditpol /get /subcategory:\"{_subcat}\" /r | ConvertFrom-Csv; "
            f"if ($r.'Inclusion Setting' -like '*{_desc_val}*') {{ 'PASS' }} else {{ 'FAIL' }}"
        ],
    ))

# ===================================================================
# MANUAL ONLY: Require GUI / restart / domain changes
# ===================================================================

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-107",
    description="Apply latest Windows Server patches – manual via WSUS / Windows Update",
    statements=[],
    manual_only=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L2-108",
    description="Enable Credential Guard – requires UEFI/Hyper-V; manual configuration",
    statements=[],
    manual_only=True,
    requires_restart=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-005",
    description="Password complexity – requires secedit template or GPO; manual configuration",
    statements=[],
    manual_only=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-007",
    description="Disable reversible encryption – requires secedit template or GPO; manual configuration",
    statements=[],
    manual_only=True,
))

_register(WindowsHardeningTemplate(
    check_id="WIN-L1-025",
    description="Block Microsoft accounts – requires Group Policy; manual configuration",
    statements=[],
    manual_only=True,
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
    check_id: str,
    parameters: Dict[str, str] = None,
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
    check_id: str,
    parameters: Dict[str, str] = None,
) -> List[str]:
    """Return verification PowerShell statements with {PARAM} placeholders substituted."""
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
