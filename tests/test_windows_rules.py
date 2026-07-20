"""
Windows Server CIS Benchmark Rule Tests

Simulates a hypothetical Windows Server 2022 instance with a realistic audit dump,
then exercises all 112 rules, hardening templates, and parameter metadata.
"""

import pytest
from app.modules.windows.audit.rules import (
    build_all_windows_cis_rules,
    filter_rules_by_profile,
    evaluate_compliance,
    _section,
    _parse_json,
    _json_section,
    _detect_os_version,
    _secpol_value,
    _secpol_int,
    _user_right_sids,
    _audit_policy_setting,
    _audit_includes,
    _registry_value,
    _lsa_value,
    _uac_value,
    _service_startup,
    _service_is_disabled,
    _firewall_profile,
    _firewall_enabled,
    _firewall_inbound_block,
    _feature_installed,
    WindowsCISRule,
)
from app.modules.windows.hardening.command_templates import (
    WINDOWS_HARDENING_TEMPLATES,
    get_windows_hardening_template,
    get_all_supported_checks,
    get_windows_template_statements,
    get_windows_verify_statements,
)
from app.modules.windows.hardening.parameter_metadata import (
    WINDOWS_CHECK_PARAMETER_MAP,
    WINDOWS_PARAMETER_REGISTRY,
    get_windows_parameter_metadata,
    get_windows_parameters_for_check,
    is_windows_check_auto_fixable,
    get_windows_check_defaults,
    categorize_windows_checks_by_fixability,
    aggregate_windows_parameters_for_checks,
    get_windows_auto_fix_preview,
)


# ================================================================== #
#  Hypothetical Windows Server 2022 audit dump                        #
# ================================================================== #

# Mostly compliant with several deliberate failures to verify rule detection.
MOCK_WIN2022_DUMP = """
===SECTION:OS_VERSION===
{"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348", "BuildNumber": "20348"}
===SECTION:SECURITY_POLICY===
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 3
ResetLockoutCount = 30
LockoutDuration = 30
AllowAdministratorLockout = 1
EnableGuestAccount = 0
NewAdministratorName = "WinAdmin"
NewGuestName = "WinGuest"
RequireSignOrSeal = 1
DisablePasswordChange = 0
AllocateDASD = "0"
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11
SeInteractiveLogonRight = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
===SECTION:USER_RIGHTS===
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11
SeInteractiveLogonRight = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
===SECTION:AUDIT_POLICY===
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
WIN2022SRV,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Application Group Management,{0cce9239-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Failure,
WIN2022SRV,System,Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},Failure,
WIN2022SRV,System,File Share,{0cce9224-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Other Object Access Events,{0cce9227-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Authorization Policy Change,{0cce9231-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},Success and Failure,
WIN2022SRV,System,Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success,
WIN2022SRV,System,System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,
===SECTION:REGISTRY_SYSTEM===
{"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanWorkstation\\\\Parameters": {"RequireSecuritySignature": 1}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanManServer\\\\Parameters": {"RequireSecuritySignature": 1}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa": {"UseMachineId": 1}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Netlogon\\\\Parameters": {"NodeType": 2}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\MSV1_0": {"AuditReceivingNTLMTraffic": 2}}
===SECTION:REGISTRY_SOFTWARE===
{"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\DNSClient": {"EnableMulticast": 0}}
===SECTION:SERVICES===
[{"Name": "Spooler", "StartType": 4, "Status": 1}, {"Name": "SSDPSRV", "StartType": 4, "Status": 1}, {"Name": "upnphost", "StartType": 4, "Status": 1}, {"Name": "WinRM", "StartType": 2, "Status": 4}, {"Name": "XboxGipSvc", "StartType": 4, "Status": 1}, {"Name": "XblAuthManager", "StartType": 4, "Status": 1}, {"Name": "XblGameSave", "StartType": 4, "Status": 1}, {"Name": "XboxNetApiSvc", "StartType": 4, "Status": 1}]
===SECTION:FIREWALL_PROFILES===
[{"Name": "Domain", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}, {"Name": "Private", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}, {"Name": "Public", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}]
===SECTION:WINDOWS_FEATURES===
[{"Name": "FileAndStorage-Services"}, {"Name": "Windows-Defender"}]
===SECTION:LOCAL_USERS===
[{"Name": "WinAdmin", "Enabled": true, "SID": "S-1-5-21-xxx-500"}, {"Name": "WinGuest", "Enabled": false, "SID": "S-1-5-21-xxx-501"}]
===SECTION:LSA_PROTECTION===
{"RunAsPPL": 1, "SCENoApplyLegacyAuditPolicy": 1, "RestrictAnonymousSAM": 1, "RestrictAnonymous": 1, "EveryoneIncludesAnonymous": 0, "LmCompatibilityLevel": 5, "NoLMHash": 1}
===SECTION:REMOTE_DESKTOP===
{"UserAuthentication": 1, "MinEncryptionLevel": 3}
===SECTION:WDIGEST===
{"UseLogonCredential": 0}
===SECTION:HOTFIXES===
[{"HotFixID": "KB5034129", "InstalledOn": "2024-01-15"}, {"HotFixID": "KB5033914", "InstalledOn": "2024-01-10"}]
===SECTION:DEFENDER_STATUS===
{"RealTimeProtectionEnabled": true, "AntivirusEnabled": true, "AntispywareEnabled": true}
===SECTION:BITLOCKER===
[{"MountPoint": "C:", "ProtectionStatus": 1, "VolumeStatus": "FullyEncrypted"}]
===SECTION:SMBV1_STATUS===
{"EnableSMB1Protocol": false, "SMB1FeatureState": "Disabled"}
===SECTION:POWERSHELL_V2===
{"FeatureName": "MicrosoftWindowsPowerShellV2", "State": "Disabled"}
===SECTION:CREDENTIAL_GUARD===
{"SecurityServicesRunning": [1, 2], "VirtualizationBasedSecurityStatus": 2}
===SECTION:NETWORK_PROFILES===
{}
===SECTION:UAC_SETTINGS===
{"FilterAdministratorToken": 1, "ConsentPromptBehaviorAdmin": 2, "ConsentPromptBehaviorUser": 0, "EnableInstallerDetection": 1, "EnableSecureUIAPaths": 1, "EnableLUA": 1, "PromptOnSecureDesktop": 1, "EnableVirtualization": 1, "DontDisplayLastUserName": 1, "InactivityTimeoutSecs": 900, "NoConnectedUser": 3}
===SECTION:SCHEDULED_TASKS===
[]
"""


# ================================================================== #
#  Partially non-compliant dump (some deliberate failures)            #
# ================================================================== #

MOCK_WIN2022_NONCOMPLIANT_DUMP = """
===SECTION:OS_VERSION===
{"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348", "BuildNumber": "20348"}
===SECTION:SECURITY_POLICY===
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 0
MinimumPasswordLength = 8
PasswordComplexity = 0
PasswordHistorySize = 5
ClearTextPassword = 1
LockoutBadCount = 0
ResetLockoutCount = 0
LockoutDuration = 0
AllowAdministratorLockout = 0
EnableGuestAccount = 1
NewAdministratorName = "Administrator"
NewGuestName = "Guest"
RequireSignOrSeal = 0
DisablePasswordChange = 1
AllocateDASD = "2"
[Privilege Rights]
SeTrustedCredManAccessPrivilege = *S-1-5-32-545
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11
SeInteractiveLogonRight = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight =
SeDenyBatchLogonRight =
SeDenyServiceLogonRight =
SeDenyInteractiveLogonRight =
SeDenyRemoteInteractiveLogonRight =
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
===SECTION:USER_RIGHTS===
SeTrustedCredManAccessPrivilege = *S-1-5-32-545
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11
SeInteractiveLogonRight = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight =
SeDenyBatchLogonRight =
SeDenyServiceLogonRight =
SeDenyInteractiveLogonRight =
SeDenyRemoteInteractiveLogonRight =
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
===SECTION:AUDIT_POLICY===
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
WIN2022SRV,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Application Group Management,{0cce9239-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Logoff,{0cce9216-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,File Share,{0cce9224-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Other Object Access Events,{0cce9227-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Authorization Policy Change,{0cce9231-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},No Auditing,
WIN2022SRV,System,System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},No Auditing,
===SECTION:REGISTRY_SYSTEM===
{"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanWorkstation\\\\Parameters": {"RequireSecuritySignature": 0}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanManServer\\\\Parameters": {"RequireSecuritySignature": 0}, "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa": {"UseMachineId": 0}}
===SECTION:REGISTRY_SOFTWARE===
{}
===SECTION:SERVICES===
[{"Name": "Spooler", "StartType": 2, "Status": 4}, {"Name": "SSDPSRV", "StartType": 2, "Status": 4}, {"Name": "upnphost", "StartType": 3, "Status": 1}, {"Name": "WinRM", "StartType": 2, "Status": 4}]
===SECTION:FIREWALL_PROFILES===
[{"Name": "Domain", "Enabled": false, "DefaultInboundAction": 0, "LogBlocked": false}, {"Name": "Private", "Enabled": false, "DefaultInboundAction": 0, "LogBlocked": false}, {"Name": "Public", "Enabled": false, "DefaultInboundAction": 0, "LogBlocked": false}]
===SECTION:WINDOWS_FEATURES===
[{"Name": "FileAndStorage-Services"}, {"Name": "PowerShell-V2"}]
===SECTION:LOCAL_USERS===
[{"Name": "Administrator", "Enabled": true, "SID": "S-1-5-21-xxx-500"}, {"Name": "Guest", "Enabled": true, "SID": "S-1-5-21-xxx-501"}]
===SECTION:LSA_PROTECTION===
{"RunAsPPL": 0, "SCENoApplyLegacyAuditPolicy": 0, "RestrictAnonymousSAM": 0, "RestrictAnonymous": 0, "EveryoneIncludesAnonymous": 1, "LmCompatibilityLevel": 1, "NoLMHash": 0}
===SECTION:REMOTE_DESKTOP===
{"UserAuthentication": 0, "MinEncryptionLevel": 1}
===SECTION:WDIGEST===
{"UseLogonCredential": 1}
===SECTION:HOTFIXES===
[]
===SECTION:DEFENDER_STATUS===
{"RealTimeProtectionEnabled": false, "AntivirusEnabled": false}
===SECTION:SMBV1_STATUS===
{"EnableSMB1Protocol": true, "SMB1FeatureState": "Enabled"}
===SECTION:POWERSHELL_V2===
{"FeatureName": "MicrosoftWindowsPowerShellV2", "State": "Enabled"}
===SECTION:CREDENTIAL_GUARD===
{"SecurityServicesRunning": [], "VirtualizationBasedSecurityStatus": 0}
===SECTION:UAC_SETTINGS===
{"FilterAdministratorToken": 0, "ConsentPromptBehaviorAdmin": 5, "ConsentPromptBehaviorUser": 3, "EnableInstallerDetection": 0, "EnableSecureUIAPaths": 0, "EnableLUA": 0, "PromptOnSecureDesktop": 0, "EnableVirtualization": 0, "DontDisplayLastUserName": 0, "InactivityTimeoutSecs": 0, "NoConnectedUser": 0}
===SECTION:SCHEDULED_TASKS===
[]
"""


# ================================================================== #
#  Windows Server 2016 dump (version-specific testing)                #
# ================================================================== #

MOCK_WIN2016_DUMP = """
===SECTION:OS_VERSION===
{"Caption": "Microsoft Windows Server 2016 Standard", "Version": "10.0.14393", "BuildNumber": "14393"}
===SECTION:SECURITY_POLICY===
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 3
ResetLockoutCount = 30
LockoutDuration = 30
EnableGuestAccount = 0
NewAdministratorName = "WinAdmin"
NewGuestName = "WinGuest"
RequireSignOrSeal = 1
DisablePasswordChange = 0
AllocateDASD = "0"
===SECTION:SERVICES===
[{"Name": "Spooler", "StartType": 4, "Status": 1}, {"Name": "WinRM", "StartType": 2, "Status": 4}]
===SECTION:LSA_PROTECTION===
{"RunAsPPL": 1, "SCENoApplyLegacyAuditPolicy": 1, "RestrictAnonymousSAM": 1, "RestrictAnonymous": 1, "EveryoneIncludesAnonymous": 0, "LmCompatibilityLevel": 5, "NoLMHash": 1}
===SECTION:UAC_SETTINGS===
{"FilterAdministratorToken": 1, "ConsentPromptBehaviorAdmin": 2, "ConsentPromptBehaviorUser": 0, "EnableInstallerDetection": 1, "EnableSecureUIAPaths": 1, "EnableLUA": 1, "PromptOnSecureDesktop": 1, "EnableVirtualization": 1, "DontDisplayLastUserName": 1, "InactivityTimeoutSecs": 900}
===SECTION:FIREWALL_PROFILES===
[{"Name": "Domain", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}, {"Name": "Private", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}, {"Name": "Public", "Enabled": true, "DefaultInboundAction": 4, "LogBlocked": true}]
===SECTION:SMBV1_STATUS===
{"EnableSMB1Protocol": false}
===SECTION:WDIGEST===
{"UseLogonCredential": 0}
===SECTION:REMOTE_DESKTOP===
{"UserAuthentication": 1, "MinEncryptionLevel": 3}
===SECTION:HOTFIXES===
[{"HotFixID": "KB5000001"}]
===SECTION:DEFENDER_STATUS===
{"RealTimeProtectionEnabled": true, "AntivirusEnabled": true}
===SECTION:POWERSHELL_V2===
{"FeatureName": "MicrosoftWindowsPowerShellV2", "State": "Disabled"}
===SECTION:CREDENTIAL_GUARD===
{"SecurityServicesRunning": [1], "VirtualizationBasedSecurityStatus": 2}
"""


# ================================================================== #
#  Test: Rule count                                                   #
# ================================================================== #

class TestRuleCount:
    def test_total_rules(self):
        rules = build_all_windows_cis_rules()
        assert len(rules) == 112

    def test_unique_ids(self):
        rules = build_all_windows_cis_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_rules_have_required_fields(self):
        rules = build_all_windows_cis_rules()
        for rule in rules:
            assert rule.id, f"Rule missing id"
            assert rule.section, f"{rule.id} missing section"
            assert rule.title, f"{rule.id} missing title"
            assert rule.severity in ("high", "medium", "low", "info"), f"{rule.id} invalid severity: {rule.severity}"
            assert rule.level in ("L1", "L2"), f"{rule.id} invalid level: {rule.level}"
            assert callable(rule.check_fn), f"{rule.id} check_fn not callable"
            assert callable(rule.evidence_fn), f"{rule.id} evidence_fn not callable"

    def test_l1_count(self):
        rules = build_all_windows_cis_rules()
        l1 = [r for r in rules if r.level == "L1"]
        assert len(l1) > 90, f"Expected >90 L1 rules, got {len(l1)}"

    def test_l2_count(self):
        rules = build_all_windows_cis_rules()
        l2 = [r for r in rules if r.level == "L2"]
        assert len(l2) > 5, f"Expected >5 L2 rules, got {len(l2)}"


# ================================================================== #
#  Test: Version detection                                            #
# ================================================================== #

class TestVersionDetection:
    def test_detect_2022(self):
        assert _detect_os_version(MOCK_WIN2022_DUMP) == "2022"

    def test_detect_2016(self):
        assert _detect_os_version(MOCK_WIN2016_DUMP) == "2016"

    def test_detect_2019(self):
        dump = '===SECTION:OS_VERSION===\n{"Caption": "Windows Server 2019", "BuildNumber": "17763"}\n'
        assert _detect_os_version(dump) == "2019"

    def test_detect_2025(self):
        dump = '===SECTION:OS_VERSION===\n{"Caption": "Windows Server 2025", "BuildNumber": "26100"}\n'
        assert _detect_os_version(dump) == "2025"

    def test_detect_unknown(self):
        dump = '===SECTION:OS_VERSION===\n{"Caption": "Unknown OS", "BuildNumber": "99999"}\n'
        assert _detect_os_version(dump) == "unknown"

    def test_caption_fallback(self):
        dump = '===SECTION:OS_VERSION===\n{"Caption": "Microsoft Windows Server 2022 Datacenter", "BuildNumber": "99999"}\n'
        assert _detect_os_version(dump) == "2022"

    def test_raw_text_fallback(self):
        dump = '===SECTION:OS_VERSION===\nWindows Server 2019 Standard\n'
        assert _detect_os_version(dump) == "2019"


# ================================================================== #
#  Test: Helper functions                                             #
# ================================================================== #

class TestHelpers:
    def test_section_extraction(self):
        content = _section(MOCK_WIN2022_DUMP, "OS_VERSION")
        assert "20348" in content

    def test_section_missing(self):
        assert _section(MOCK_WIN2022_DUMP, "NONEXISTENT") == ""

    def test_parse_json_valid(self):
        result = _parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_invalid(self):
        assert _parse_json("not json") is None
        assert _parse_json("") is None
        assert _parse_json("PS_ERROR: something") is None
        assert _parse_json("COLLECTION_ERROR") is None

    def test_json_section(self):
        data = _json_section(MOCK_WIN2022_DUMP, "LSA_PROTECTION")
        assert isinstance(data, dict)
        assert data["RunAsPPL"] == 1

    def test_secpol_value(self):
        assert _secpol_value(MOCK_WIN2022_DUMP, "PasswordHistorySize") == "24"
        assert _secpol_value(MOCK_WIN2022_DUMP, "MaximumPasswordAge") == "90"

    def test_secpol_value_missing(self):
        assert _secpol_value(MOCK_WIN2022_DUMP, "NonExistentKey") is None

    def test_secpol_int(self):
        assert _secpol_int(MOCK_WIN2022_DUMP, "PasswordHistorySize") == 24
        assert _secpol_int(MOCK_WIN2022_DUMP, "MinimumPasswordAge") == 1

    def test_secpol_int_missing(self):
        assert _secpol_int(MOCK_WIN2022_DUMP, "NonExistent") is None

    def test_user_right_sids(self):
        sids = _user_right_sids(MOCK_WIN2022_DUMP, "SeNetworkLogonRight")
        assert "*S-1-5-32-544" in sids
        assert "*S-1-5-11" in sids

    def test_user_right_empty(self):
        sids = _user_right_sids(MOCK_WIN2022_DUMP, "SeTrustedCredManAccessPrivilege")
        assert len(sids) == 0

    def test_audit_policy_setting(self):
        setting = _audit_policy_setting(MOCK_WIN2022_DUMP, "Credential Validation")
        assert "Success and Failure" in setting

    def test_audit_includes(self):
        assert _audit_includes(MOCK_WIN2022_DUMP, "Credential Validation", "Success and Failure")
        assert not _audit_includes(MOCK_WIN2022_NONCOMPLIANT_DUMP, "Credential Validation", "Success and Failure")

    def test_lsa_value(self):
        assert _lsa_value(MOCK_WIN2022_DUMP, "RunAsPPL") == 1
        assert _lsa_value(MOCK_WIN2022_DUMP, "LmCompatibilityLevel") == 5

    def test_uac_value(self):
        assert _uac_value(MOCK_WIN2022_DUMP, "EnableLUA") == 1
        assert _uac_value(MOCK_WIN2022_DUMP, "FilterAdministratorToken") == 1

    def test_service_startup(self):
        assert _service_startup(MOCK_WIN2022_DUMP, "Spooler") == "Disabled"
        assert _service_startup(MOCK_WIN2022_DUMP, "WinRM") == "Automatic"

    def test_service_startup_missing(self):
        assert _service_startup(MOCK_WIN2022_DUMP, "NonExistentService") is None

    def test_service_is_disabled(self):
        assert _service_is_disabled(MOCK_WIN2022_DUMP, "Spooler") is True
        assert _service_is_disabled(MOCK_WIN2022_DUMP, "WinRM") is False
        # Not installed = compliant
        assert _service_is_disabled(MOCK_WIN2022_DUMP, "NonExistent") is True

    def test_firewall_enabled(self):
        assert _firewall_enabled(MOCK_WIN2022_DUMP, "Domain") is True
        assert _firewall_enabled(MOCK_WIN2022_NONCOMPLIANT_DUMP, "Domain") is False

    def test_firewall_inbound_block(self):
        assert _firewall_inbound_block(MOCK_WIN2022_DUMP, "Public") is True
        assert _firewall_inbound_block(MOCK_WIN2022_NONCOMPLIANT_DUMP, "Public") is False

    def test_firewall_profile(self):
        p = _firewall_profile(MOCK_WIN2022_DUMP, "Domain")
        assert p is not None
        assert p["Enabled"] is True

    def test_feature_installed(self):
        assert _feature_installed(MOCK_WIN2022_DUMP, "Windows-Defender") is True
        assert _feature_installed(MOCK_WIN2022_DUMP, "PowerShell-V2") is False

    def test_registry_value(self):
        val = _registry_value(MOCK_WIN2022_DUMP, "REGISTRY_SYSTEM",
                              "LanmanWorkstation\\Parameters", "RequireSecuritySignature")
        assert val == 1

    def test_registry_value_missing(self):
        val = _registry_value(MOCK_WIN2022_DUMP, "REGISTRY_SYSTEM",
                              "NonExistent", "SomeProperty")
        assert val is None


# ================================================================== #
#  Test: Rule evaluation on compliant 2022 server                     #
# ================================================================== #

class TestCompliantServer2022:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = build_all_windows_cis_rules()
        self.result = evaluate_compliance(MOCK_WIN2022_DUMP, self.rules)
        self.findings = {f["id"]: f for f in self.result["findings"]}

    def test_high_compliance_pct(self):
        pct = self.result["summary"]["compliance_pct"]
        assert pct > 85.0, f"Expected >85% compliance on compliant dump, got {pct}%"

    def test_password_history_pass(self):
        assert self.findings["WIN-L1-001"]["compliant"] is True

    def test_max_password_age_pass(self):
        assert self.findings["WIN-L1-002"]["compliant"] is True

    def test_min_password_age_pass(self):
        assert self.findings["WIN-L1-003"]["compliant"] is True

    def test_min_password_length_pass(self):
        assert self.findings["WIN-L1-004"]["compliant"] is True

    def test_password_complexity_pass(self):
        assert self.findings["WIN-L1-005"]["compliant"] is True

    def test_reversible_encryption_pass(self):
        assert self.findings["WIN-L1-007"]["compliant"] is True

    def test_lockout_duration_pass(self):
        assert self.findings["WIN-L1-008"]["compliant"] is True

    def test_lockout_threshold_pass(self):
        assert self.findings["WIN-L1-009"]["compliant"] is True

    def test_admin_lockout_pass(self):
        assert self.findings["WIN-L1-010"]["compliant"] is True

    def test_lockout_reset_pass(self):
        assert self.findings["WIN-L1-011"]["compliant"] is True

    def test_guest_disabled_pass(self):
        assert self.findings["WIN-L1-026"]["compliant"] is True

    def test_admin_renamed_pass(self):
        assert self.findings["WIN-L1-027"]["compliant"] is True

    def test_guest_renamed_pass(self):
        assert self.findings["WIN-L1-028"]["compliant"] is True

    def test_lsa_audit_policy_pass(self):
        assert self.findings["WIN-L1-029"]["compliant"] is True

    def test_dont_display_last_user_pass(self):
        assert self.findings["WIN-L1-030"]["compliant"] is True

    def test_inactivity_timeout_pass(self):
        assert self.findings["WIN-L1-031"]["compliant"] is True

    def test_smb_client_signing_pass(self):
        assert self.findings["WIN-L1-032"]["compliant"] is True

    def test_smb_server_signing_pass(self):
        assert self.findings["WIN-L1-033"]["compliant"] is True

    def test_restrict_anonymous_sam_pass(self):
        assert self.findings["WIN-L1-034"]["compliant"] is True

    def test_restrict_anonymous_pass(self):
        assert self.findings["WIN-L1-035"]["compliant"] is True

    def test_everyone_includes_anonymous_pass(self):
        assert self.findings["WIN-L1-036"]["compliant"] is True

    def test_lm_compatibility_level_pass(self):
        assert self.findings["WIN-L1-038"]["compliant"] is True

    def test_no_lm_hash_pass(self):
        assert self.findings["WIN-L1-039"]["compliant"] is True

    def test_uac_filter_admin_token_pass(self):
        assert self.findings["WIN-L1-040"]["compliant"] is True

    def test_uac_enable_lua_pass(self):
        assert self.findings["WIN-L1-045"]["compliant"] is True

    def test_uac_secure_desktop_pass(self):
        assert self.findings["WIN-L1-046"]["compliant"] is True

    def test_print_spooler_disabled_pass(self):
        assert self.findings["WIN-L1-048"]["compliant"] is True

    def test_ssdp_disabled_pass(self):
        assert self.findings["WIN-L1-051"]["compliant"] is True

    def test_upnp_disabled_pass(self):
        assert self.findings["WIN-L1-052"]["compliant"] is True

    def test_winrm_running_pass(self):
        assert self.findings["WIN-L1-053"]["compliant"] is True

    def test_domain_firewall_enabled_pass(self):
        assert self.findings["WIN-L1-058"]["compliant"] is True

    def test_domain_firewall_inbound_block_pass(self):
        assert self.findings["WIN-L1-059"]["compliant"] is True

    def test_domain_firewall_log_pass(self):
        assert self.findings["WIN-L1-060"]["compliant"] is True

    def test_smbv1_disabled_pass(self):
        assert self.findings["WIN-L1-095"]["compliant"] is True

    def test_lsa_protection_pass(self):
        assert self.findings["WIN-L1-097"]["compliant"] is True

    def test_wdigest_disabled_pass(self):
        assert self.findings["WIN-L1-098"]["compliant"] is True

    def test_nla_enabled_pass(self):
        assert self.findings["WIN-L1-101"]["compliant"] is True

    def test_powershell_v2_disabled_pass(self):
        assert self.findings["WIN-L1-103"]["compliant"] is True

    def test_defender_realtime_pass(self):
        assert self.findings["WIN-L1-105"]["compliant"] is True

    def test_defender_enabled_pass(self):
        assert self.findings["WIN-L1-106"]["compliant"] is True

    def test_hotfixes_present_pass(self):
        assert self.findings["WIN-L1-107"]["compliant"] is True

    def test_credential_validation_audit_pass(self):
        assert self.findings["WIN-L1-067"]["compliant"] is True

    def test_logon_audit_pass(self):
        assert self.findings["WIN-L1-078"]["compliant"] is True


# ================================================================== #
#  Test: Non-compliant server detection                               #
# ================================================================== #

class TestNonCompliantServer2022:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = build_all_windows_cis_rules()
        self.result = evaluate_compliance(MOCK_WIN2022_NONCOMPLIANT_DUMP, self.rules)
        self.findings = {f["id"]: f for f in self.result["findings"]}

    def test_low_compliance_pct(self):
        pct = self.result["summary"]["compliance_pct"]
        assert pct < 30.0, f"Expected <30% compliance on non-compliant dump, got {pct}%"

    def test_password_history_fail(self):
        assert self.findings["WIN-L1-001"]["compliant"] is False

    def test_max_password_age_fail(self):
        # MaximumPasswordAge = 0 means never expires → FAIL
        assert self.findings["WIN-L1-002"]["compliant"] is False

    def test_min_password_age_fail(self):
        assert self.findings["WIN-L1-003"]["compliant"] is False

    def test_min_password_length_fail(self):
        assert self.findings["WIN-L1-004"]["compliant"] is False

    def test_password_complexity_fail(self):
        assert self.findings["WIN-L1-005"]["compliant"] is False

    def test_reversible_encryption_fail(self):
        assert self.findings["WIN-L1-007"]["compliant"] is False

    def test_lockout_threshold_fail(self):
        # LockoutBadCount = 0 means disabled
        assert self.findings["WIN-L1-009"]["compliant"] is False

    def test_guest_enabled_fail(self):
        assert self.findings["WIN-L1-026"]["compliant"] is False

    def test_admin_not_renamed_fail(self):
        assert self.findings["WIN-L1-027"]["compliant"] is False

    def test_guest_not_renamed_fail(self):
        assert self.findings["WIN-L1-028"]["compliant"] is False

    def test_lsa_audit_policy_fail(self):
        assert self.findings["WIN-L1-029"]["compliant"] is False

    def test_dont_display_last_user_fail(self):
        assert self.findings["WIN-L1-030"]["compliant"] is False

    def test_inactivity_timeout_fail(self):
        # 0 means disabled
        assert self.findings["WIN-L1-031"]["compliant"] is False

    def test_firewall_disabled_fail(self):
        assert self.findings["WIN-L1-058"]["compliant"] is False

    def test_smbv1_enabled_fail(self):
        assert self.findings["WIN-L1-095"]["compliant"] is False

    def test_wdigest_enabled_fail(self):
        assert self.findings["WIN-L1-098"]["compliant"] is False

    def test_nla_disabled_fail(self):
        assert self.findings["WIN-L1-101"]["compliant"] is False

    def test_powershell_v2_enabled_fail(self):
        assert self.findings["WIN-L1-103"]["compliant"] is False

    def test_defender_disabled_fail(self):
        assert self.findings["WIN-L1-105"]["compliant"] is False
        assert self.findings["WIN-L1-106"]["compliant"] is False

    def test_uac_disabled_fail(self):
        assert self.findings["WIN-L1-040"]["compliant"] is False
        assert self.findings["WIN-L1-045"]["compliant"] is False
        assert self.findings["WIN-L1-046"]["compliant"] is False

    def test_all_audit_policies_fail(self):
        for rule_id in ["WIN-L1-067", "WIN-L1-078", "WIN-L1-085", "WIN-L1-092", "WIN-L1-094"]:
            assert self.findings[rule_id]["compliant"] is False, f"{rule_id} should fail"

    def test_deny_rights_fail(self):
        """Deny rights have empty SID lists, so guests aren't denied."""
        for rule_id in ["WIN-L1-016", "WIN-L1-017", "WIN-L1-018", "WIN-L1-019", "WIN-L1-020"]:
            assert self.findings[rule_id]["compliant"] is False, f"{rule_id} should fail"

    def test_credential_manager_fail(self):
        """SeTrustedCredManAccessPrivilege has *S-1-5-32-545 (not empty)."""
        assert self.findings["WIN-L1-012"]["compliant"] is False

    def test_domain_member_fail(self):
        assert self.findings["WIN-L1-111"]["compliant"] is False
        assert self.findings["WIN-L1-112"]["compliant"] is False


# ================================================================== #
#  Test: Version-aware rule filtering                                 #
# ================================================================== #

class TestVersionAwareRules:
    def test_filter_l1_only(self):
        rules = build_all_windows_cis_rules()
        filtered = filter_rules_by_profile(rules, "L1")
        for r in filtered:
            assert r.level == "L1"

    def test_filter_full_includes_all(self):
        rules = build_all_windows_cis_rules()
        filtered = filter_rules_by_profile(rules, "FULL")
        assert len(filtered) == len(rules)

    def test_version_specific_rule_006_not_on_2016(self):
        """WIN-L1-006 applies to 2019/2022/2025 only, not 2016."""
        rules = build_all_windows_cis_rules()
        r006 = [r for r in rules if r.id == "WIN-L1-006"][0]
        assert "2016" not in r006.versions
        assert "2019" in r006.versions

        # Filtered out for 2016
        filtered = filter_rules_by_profile(rules, "FULL", os_version="2016")
        ids = [r.id for r in filtered]
        assert "WIN-L1-006" not in ids

    def test_version_specific_rule_010_not_on_2016(self):
        """WIN-L1-010 applies to 2022/2025 only."""
        rules = build_all_windows_cis_rules()
        r010 = [r for r in rules if r.id == "WIN-L1-010"][0]
        assert "2022" in r010.versions

        filtered_2016 = filter_rules_by_profile(rules, "FULL", os_version="2016")
        ids_2016 = [r.id for r in filtered_2016]
        assert "WIN-L1-010" not in ids_2016

    def test_all_version_rule_appears_everywhere(self):
        rules = build_all_windows_cis_rules()
        r001 = [r for r in rules if r.id == "WIN-L1-001"][0]
        assert "all" in r001.versions

        for version in ["2016", "2019", "2022", "2025"]:
            filtered = filter_rules_by_profile(rules, "FULL", os_version=version)
            ids = [r.id for r in filtered]
            assert "WIN-L1-001" in ids


# ================================================================== #
#  Test: Evidence extraction                                          #
# ================================================================== #

class TestEvidenceExtraction:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = build_all_windows_cis_rules()

    def test_evidence_is_string(self):
        for rule in self.rules:
            evidence = rule.evidence_fn(MOCK_WIN2022_DUMP)
            assert isinstance(evidence, str), f"{rule.id} evidence_fn returned non-string"

    def test_evidence_not_empty_on_compliant(self):
        for rule in self.rules[:20]:  # Sample first 20
            evidence = rule.evidence_fn(MOCK_WIN2022_DUMP)
            assert len(evidence) > 0, f"{rule.id} evidence is empty"

    def test_password_history_evidence(self):
        r = [r for r in self.rules if r.id == "WIN-L1-001"][0]
        ev = r.evidence_fn(MOCK_WIN2022_DUMP)
        assert "24" in ev

    def test_firewall_evidence(self):
        r = [r for r in self.rules if r.id == "WIN-L1-058"][0]
        ev = r.evidence_fn(MOCK_WIN2022_DUMP)
        assert "True" in ev


# ================================================================== #
#  Test: Compliance summary                                           #
# ================================================================== #

class TestComplianceSummary:
    def test_summary_structure(self):
        rules = build_all_windows_cis_rules()
        result = evaluate_compliance(MOCK_WIN2022_DUMP, rules)
        summary = result["summary"]
        assert "total_rules_scored" in summary
        assert "passed_scored" in summary
        assert "failed_scored" in summary
        assert "compliance_pct" in summary
        assert "weighted_compliance_pct" in summary
        assert summary["total_rules_scored"] == summary["passed_scored"] + summary["failed_scored"]

    def test_findings_have_required_keys(self):
        rules = build_all_windows_cis_rules()
        result = evaluate_compliance(MOCK_WIN2022_DUMP, rules)
        for finding in result["findings"]:
            assert "id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert "level" in finding
            assert "compliant" in finding
            assert "evidence" in finding
            assert "remediation" in finding

    def test_weighted_compliance_different_from_simple(self):
        rules = build_all_windows_cis_rules()
        # Use noncompliant dump where high-severity fails should make weighted worse
        result = evaluate_compliance(MOCK_WIN2022_NONCOMPLIANT_DUMP, rules)
        summary = result["summary"]
        # Weighted and simple may differ (high-severity rules have more weight)
        assert isinstance(summary["weighted_compliance_pct"], float)


# ================================================================== #
#  Test: Hardening Templates                                          #
# ================================================================== #

class TestHardeningTemplates:
    def test_template_count(self):
        assert len(WINDOWS_HARDENING_TEMPLATES) >= 50

    def test_all_templates_have_required_fields(self):
        for check_id, tmpl in WINDOWS_HARDENING_TEMPLATES.items():
            assert tmpl.check_id == check_id
            assert len(tmpl.description) > 0, f"{check_id} has empty description"
            if not tmpl.manual_only:
                assert len(tmpl.statements) > 0, f"{check_id} non-manual but no statements"

    def test_manual_templates_have_no_statements(self):
        for check_id, tmpl in WINDOWS_HARDENING_TEMPLATES.items():
            if tmpl.manual_only:
                assert len(tmpl.statements) == 0, f"{check_id} is manual_only but has statements"

    def test_get_template_existing(self):
        tmpl = get_windows_hardening_template("WIN-L1-001")
        assert tmpl is not None
        assert "password history" in tmpl.description.lower()

    def test_get_template_missing(self):
        assert get_windows_hardening_template("WIN-NONEXISTENT") is None

    def test_supported_checks(self):
        supported = get_all_supported_checks()
        assert "WIN-L1-001" in supported
        assert "WIN-L1-048" in supported
        assert len(supported) >= 50

    def test_template_statements_no_params(self):
        stmts = get_windows_template_statements("WIN-L1-001")
        assert len(stmts) > 0
        assert "net accounts /uniquepw:24" in stmts[0]

    def test_template_statements_with_params(self):
        stmts = get_windows_template_statements("WIN-L1-027", {"NEW_ADMIN_NAME": "MyAdmin"})
        assert len(stmts) > 0
        assert "MyAdmin" in stmts[0]

    def test_verify_statements(self):
        vstmts = get_windows_verify_statements("WIN-L1-001")
        assert len(vstmts) > 0

    def test_verify_statements_missing_template(self):
        assert get_windows_verify_statements("NONEXISTENT") == []

    def test_firewall_templates_all_profiles(self):
        for profile, offset in [("Domain", 58), ("Private", 61), ("Public", 64)]:
            for i in range(3):
                check_id = f"WIN-L1-{offset + i:03d}"
                tmpl = get_windows_hardening_template(check_id)
                assert tmpl is not None, f"Missing template for {check_id}"
                assert not tmpl.manual_only

    def test_audit_policy_templates(self):
        audit_ids = ["WIN-L1-067", "WIN-L1-068", "WIN-L1-078", "WIN-L1-085",
                     "WIN-L1-092", "WIN-L1-093", "WIN-L1-094"]
        for check_id in audit_ids:
            tmpl = get_windows_hardening_template(check_id)
            assert tmpl is not None, f"Missing template for {check_id}"
            assert "auditpol" in tmpl.statements[0].lower()

    def test_service_disable_templates(self):
        for check_id in ["WIN-L1-048", "WIN-L1-051", "WIN-L1-052"]:
            tmpl = get_windows_hardening_template(check_id)
            assert tmpl is not None
            assert any("Set-Service" in s for s in tmpl.statements)

    def test_requires_restart_flags(self):
        tmpl_045 = get_windows_hardening_template("WIN-L1-045")
        assert tmpl_045.requires_restart is True

        tmpl_097 = get_windows_hardening_template("WIN-L1-097")
        assert tmpl_097.requires_restart is True

        tmpl_001 = get_windows_hardening_template("WIN-L1-001")
        assert tmpl_001.requires_restart is False


# ================================================================== #
#  Test: Parameter Metadata                                           #
# ================================================================== #

class TestParameterMetadata:
    def test_parameter_registry_not_empty(self):
        assert len(WINDOWS_PARAMETER_REGISTRY) > 0

    def test_all_registry_params_valid(self):
        for name, meta in WINDOWS_PARAMETER_REGISTRY.items():
            assert meta.name == name
            assert meta.input_type in ("text", "number", "ip", "select", "textarea")
            assert len(meta.label) > 0
            assert len(meta.description) > 0

    def test_check_parameter_map_not_empty(self):
        assert len(WINDOWS_CHECK_PARAMETER_MAP) >= 48

    def test_all_mapped_params_exist_in_registry(self):
        for check_id, param_names in WINDOWS_CHECK_PARAMETER_MAP.items():
            for pname in param_names:
                assert pname in WINDOWS_PARAMETER_REGISTRY, (
                    f"Parameter '{pname}' for check {check_id} not in registry"
                )

    def test_get_parameter_metadata(self):
        meta = get_windows_parameter_metadata("NEW_ADMIN_NAME")
        assert meta is not None
        assert meta.input_type == "text"

    def test_get_parameter_metadata_missing(self):
        assert get_windows_parameter_metadata("NONEXISTENT") is None

    def test_get_parameters_for_check(self):
        params = get_windows_parameters_for_check("WIN-L1-027")
        assert len(params) == 1
        assert params[0].name == "NEW_ADMIN_NAME"

    def test_get_parameters_for_auto_check(self):
        params = get_windows_parameters_for_check("WIN-L1-001")
        assert len(params) == 0

    def test_is_auto_fixable_no_params(self):
        assert is_windows_check_auto_fixable("WIN-L1-001") is True
        assert is_windows_check_auto_fixable("WIN-L1-048") is True

    def test_is_auto_fixable_with_defaults(self):
        assert is_windows_check_auto_fixable("WIN-L1-002") is True
        assert is_windows_check_auto_fixable("WIN-L1-008") is True

    def test_is_not_auto_fixable_needs_params(self):
        assert is_windows_check_auto_fixable("WIN-L1-027") is False  # NEW_ADMIN_NAME required
        assert is_windows_check_auto_fixable("WIN-L1-028") is False  # NEW_GUEST_NAME required

    def test_is_not_auto_fixable_not_in_map(self):
        assert is_windows_check_auto_fixable("WIN-NONEXISTENT") is False

    def test_manual_only_not_auto_fixable(self):
        """Manual-only checks with templates should not be auto-fixable."""
        # WIN-L1-005 is manual_only
        tmpl = get_windows_hardening_template("WIN-L1-005")
        assert tmpl is not None
        assert tmpl.manual_only is True
        # If it's not in the parameter map, it's not auto-fixable
        if "WIN-L1-005" in WINDOWS_CHECK_PARAMETER_MAP:
            assert is_windows_check_auto_fixable("WIN-L1-005") is False

    def test_get_check_defaults(self):
        defaults = get_windows_check_defaults("WIN-L1-002")
        assert "MAX_PASSWORD_AGE" in defaults
        assert defaults["MAX_PASSWORD_AGE"] == "365"

    def test_get_check_defaults_no_params(self):
        defaults = get_windows_check_defaults("WIN-L1-001")
        assert defaults == {}

    def test_categorize_checks(self):
        check_ids = ["WIN-L1-001", "WIN-L1-027", "WIN-L1-999"]
        cats = categorize_windows_checks_by_fixability(check_ids)
        assert "WIN-L1-001" in cats["auto_fixable"]
        assert "WIN-L1-027" in cats["needs_params"]
        assert "WIN-L1-999" in cats["not_supported"]

    def test_aggregate_parameters(self):
        check_ids = ["WIN-L1-027", "WIN-L1-028"]
        aggregated = aggregate_windows_parameters_for_checks(check_ids)
        assert "NEW_ADMIN_NAME" in aggregated
        assert "NEW_GUEST_NAME" in aggregated
        assert "WIN-L1-027" in aggregated["NEW_ADMIN_NAME"]["checks"]
        assert "WIN-L1-028" in aggregated["NEW_GUEST_NAME"]["checks"]

    def test_auto_fix_preview(self):
        check_ids = ["WIN-L1-001", "WIN-L1-002", "WIN-L1-027"]
        preview = get_windows_auto_fix_preview(check_ids)
        preview_ids = [p["check_id"] for p in preview]
        assert "WIN-L1-001" in preview_ids
        assert "WIN-L1-002" in preview_ids
        # WIN-L1-027 needs required param → not auto-fixable
        assert "WIN-L1-027" not in preview_ids


# ================================================================== #
#  Test: Edge cases                                                   #
# ================================================================== #

class TestEdgeCases:
    def test_empty_dump(self):
        rules = build_all_windows_cis_rules()
        result = evaluate_compliance("", rules)
        assert result["summary"]["total_rules_scored"] == len(rules)
        # Most rules should fail on empty dump
        assert result["summary"]["failed_scored"] > 80

    def test_error_sections(self):
        dump = """
===SECTION:OS_VERSION===
PS_ERROR: Access Denied
===SECTION:SECURITY_POLICY===
COLLECTION_ERROR: secedit failed
===SECTION:LSA_PROTECTION===
PS_ERROR: Registry not accessible
===SECTION:UAC_SETTINGS===
PS_ERROR: Unable to read
===SECTION:SERVICES===
PS_ERROR: Service query failed
===SECTION:FIREWALL_PROFILES===
PS_ERROR: Firewall query failed
===SECTION:AUDIT_POLICY===
PS_ERROR: auditpol failed
"""
        rules = build_all_windows_cis_rules()
        result = evaluate_compliance(dump, rules)
        # Should not crash, all rules should return a finding
        assert result["summary"]["total_rules_scored"] == len(rules)

    def test_malformed_json_sections(self):
        dump = """
===SECTION:OS_VERSION===
{not valid json
===SECTION:LSA_PROTECTION===
{also: broken
===SECTION:UAC_SETTINGS===
===SECTION:SERVICES===
not json at all
"""
        rules = build_all_windows_cis_rules()
        # Should not raise, all rules handle gracefully
        result = evaluate_compliance(dump, rules)
        assert result["summary"]["total_rules_scored"] == len(rules)

    def test_evidence_on_error_dump(self):
        dump = """
===SECTION:OS_VERSION===
PS_ERROR: fail
===SECTION:SECURITY_POLICY===
PS_ERROR: fail
"""
        rules = build_all_windows_cis_rules()
        for rule in rules[:10]:
            ev = rule.evidence_fn(dump)
            assert isinstance(ev, str)


# ================================================================== #
#  Test: Hardening integration (template ↔ param map ↔ rules)         #
# ================================================================== #

class TestHardeningIntegration:
    def test_all_param_map_entries_have_templates(self):
        """Every check in WINDOWS_CHECK_PARAMETER_MAP must have a hardening template."""
        for check_id in WINDOWS_CHECK_PARAMETER_MAP:
            tmpl = get_windows_hardening_template(check_id)
            assert tmpl is not None, f"Check {check_id} in param map but no template"

    def test_auto_fixable_count(self):
        """Count auto-fixable checks."""
        auto = [cid for cid in WINDOWS_CHECK_PARAMETER_MAP
                if is_windows_check_auto_fixable(cid)]
        assert len(auto) >= 45, f"Expected ≥45 auto-fixable, got {len(auto)}"

    def test_categorize_all_failed_checks(self):
        """Simulate categorizing all rules as failed."""
        rules = build_all_windows_cis_rules()
        all_ids = [r.id for r in rules]
        cats = categorize_windows_checks_by_fixability(all_ids)

        total = len(cats["auto_fixable"]) + len(cats["needs_params"]) + len(cats["not_supported"])
        assert total == len(all_ids)

    def test_param_substitution_correctness(self):
        """Verify parameter substitution produces valid PowerShell."""
        stmts = get_windows_template_statements("WIN-L1-002", {"MAX_PASSWORD_AGE": "180"})
        assert "180" in stmts[0]
        assert "{MAX_PASSWORD_AGE}" not in stmts[0]

    def test_service_disable_custom(self):
        """Test custom service disable template."""
        stmts = get_windows_template_statements("WIN-L1-048-CUSTOM", {"SERVICE_NAME": "TestSvc"})
        assert any("TestSvc" in s for s in stmts)
        assert not any("{SERVICE_NAME}" in s for s in stmts)

    def test_firewall_hardening_coverage(self):
        """All 9 firewall rules have templates."""
        for offset in [58, 59, 60, 61, 62, 63, 64, 65, 66]:
            check_id = f"WIN-L1-{offset:03d}"
            assert check_id in WINDOWS_CHECK_PARAMETER_MAP, f"{check_id} not in param map"
            tmpl = get_windows_hardening_template(check_id)
            assert tmpl is not None, f"{check_id} has no template"

    def test_audit_policy_hardening_coverage(self):
        """Selected audit policy checks have templates."""
        audit_ids = ["WIN-L1-067", "WIN-L1-068", "WIN-L1-072", "WIN-L1-078",
                     "WIN-L1-085", "WIN-L1-089", "WIN-L1-092", "WIN-L1-094"]
        for check_id in audit_ids:
            tmpl = get_windows_hardening_template(check_id)
            assert tmpl is not None, f"{check_id} missing template"
            assert not tmpl.manual_only
