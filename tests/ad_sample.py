"""
Sample collector output of a Windows Server 2022 domain controller
(corp.example.com), in the exact shape the Active Directory collection
scripts print: ConvertTo-Json -Compress for the AD_* sections, the secedit /
auditpol / registry formats of the Windows module for the host sections.

It is built here rather than captured from a real DC, and describes a
typical, lightly managed domain: default domain policy, a few stale and
over-privileged accounts, no LAPS, SMBv1 off. Tests copy and modify it.
"""
import copy
import json

from app.modules.windows.audit.rules import REGISTRY_CHECKS

DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"


def sid(rid):
    return f"{DOMAIN_SID}-{rid}"


SECURITY_POLICY = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
NewAdministratorName = "Administrator"
NewGuestName = "Guest"
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableAdminAccount = 1
EnableGuestAccount = 0
[Version]
signature="$CHICAGO$"
Revision=1"""

USER_RIGHTS = """SeNetworkLogonRight = *S-1-1-0,*S-1-5-11,*S-1-5-32-544,*S-1-5-32-554,*S-1-5-9
SeMachineAccountPrivilege = *S-1-5-11
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-32-548,*S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544,*S-1-5-9
SeBackupPrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-32-549,*S-1-5-19,*S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-549,*S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeEnableDelegationPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-550,*S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-11,*S-1-5-32-554
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-549
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544"""

_AUDIT = [
    ("Account Logon", "Credential Validation", "Success"),
    ("Account Logon", "Kerberos Authentication Service", "Success and Failure"),
    ("Account Logon", "Kerberos Service Ticket Operations", "Success and Failure"),
    ("Account Management", "Application Group Management", "No Auditing"),
    ("Account Management", "Computer Account Management", "Success"),
    ("Account Management", "Distribution Group Management", "No Auditing"),
    ("Account Management", "Other Account Management Events", "No Auditing"),
    ("Account Management", "Security Group Management", "Success"),
    ("Account Management", "User Account Management", "Success"),
    ("Detailed Tracking", "Plug and Play Events", "No Auditing"),
    ("Detailed Tracking", "Process Creation", "No Auditing"),
    ("DS Access", "Directory Service Access", "Success"),
    ("DS Access", "Directory Service Changes", "No Auditing"),
    ("Logon/Logoff", "Account Lockout", "Success"),
    ("Logon/Logoff", "Group Membership", "No Auditing"),
    ("Logon/Logoff", "Logoff", "Success"),
    ("Logon/Logoff", "Logon", "Success and Failure"),
    ("Logon/Logoff", "Other Logon/Logoff Events", "No Auditing"),
    ("Logon/Logoff", "Special Logon", "Success"),
    ("Object Access", "Detailed File Share", "No Auditing"),
    ("Object Access", "File Share", "No Auditing"),
    ("Object Access", "Other Object Access Events", "No Auditing"),
    ("Object Access", "Removable Storage", "No Auditing"),
    ("Policy Change", "Audit Policy Change", "Success"),
    ("Policy Change", "Authentication Policy Change", "Success"),
    ("Policy Change", "Authorization Policy Change", "No Auditing"),
    ("Policy Change", "MPSSVC Rule-Level Policy Change", "No Auditing"),
    ("Policy Change", "Other Policy Change Events", "No Auditing"),
    ("Privilege Use", "Sensitive Privilege Use", "No Auditing"),
    ("System", "IPsec Driver", "No Auditing"),
    ("System", "Other System Events", "Success and Failure"),
    ("System", "Security State Change", "Success"),
    ("System", "Security System Extension", "No Auditing"),
    ("System", "System Integrity", "Success and Failure"),
]
AUDIT_POLICY = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n" + "\n".join(
    f"DC01,System,{sub},{{0CCE92{i:02X}-69AE-11D9-BED3-505054503030}},{inc}," for i, (_, sub, inc) in enumerate(_AUDIT))


def _registry():
    """Every registry value the Windows rules read, about two thirds of them
    at the CIS value (deterministic by position), the rest left at the
    Windows default (absent)."""
    out = {}
    for i, c in enumerate(REGISTRY_CHECKS):
        if i % 3 == 2 or c.get("set") is None:
            continue
        out.setdefault(c["path"], {})[c["prop"]] = c["set"]
    return {path: json.dumps(props, separators=(",", ":")) for path, props in out.items()}


FIREWALL = [
    {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured", "DefaultOutboundAction": "NotConfigured",
     "NotifyOnListen": "False", "AllowLocalFirewallRules": "NotConfigured", "AllowLocalIPsecRules": "NotConfigured",
     "LogAllowed": "False", "LogBlocked": "False", "LogMaxSizeKilobytes": "4096",
     "LogFileName": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"},
    {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured", "DefaultOutboundAction": "NotConfigured",
     "NotifyOnListen": "False", "AllowLocalFirewallRules": "NotConfigured", "AllowLocalIPsecRules": "NotConfigured",
     "LogAllowed": "False", "LogBlocked": "False", "LogMaxSizeKilobytes": "4096",
     "LogFileName": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"},
    {"Name": "Public", "Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "NotConfigured",
     "NotifyOnListen": "False", "AllowLocalFirewallRules": "NotConfigured", "AllowLocalIPsecRules": "NotConfigured",
     "LogAllowed": "False", "LogBlocked": "True", "LogMaxSizeKilobytes": "16384",
     "LogFileName": "%systemroot%\\system32\\logfiles\\firewall\\publicfw.log"},
]


def _member(sam, rid=None, cls="user", enabled=True, never=False, nodeleg=False, pwd=120, last=2, spn=0, admin=1, sid_=None):
    return {"Sam": sam, "Class": cls, "Sid": sid_ or sid(rid), "Enabled": enabled, "PwdNeverExpires": never,
            "NotDelegated": nodeleg, "PwdLastSetDays": pwd, "LastLogonDays": last, "Spn": spn, "AdminCount": admin}


ADMIN = _member("Administrator", 500, never=True, pwd=812, last=1)
DA = [ADMIN, _member("adm.sara", 1105, pwd=64, last=0), _member("adm.reza", 1106, pwd=401, last=3),
      _member("svc_backup", 1120, never=True, pwd=1460, last=0, spn=1), _member("adm.old", 1131, enabled=False, pwd=900, last=None)]


def _group(identity, members=(), exists=True, error=None):
    return {"Identity": identity, "Exists": exists, "Members": list(members), "Error": error}


AD = {
    "AD_DOMAIN": {
        "DNSRoot": "corp.example.com", "NetBIOSName": "CORP", "DomainSID": DOMAIN_SID,
        "DistinguishedName": "DC=corp,DC=example,DC=com", "DomainMode": "Windows2012R2Domain",
        "ForestMode": "Windows2012R2Forest", "ForestRoot": "corp.example.com", "IsForestRoot": True,
        "DomainControllers": [
            {"Name": "DC01", "HostName": "dc01.corp.example.com", "OperatingSystem": "Windows Server 2022 Standard",
             "OperatingSystemVersion": "10.0 (20348)", "IsGlobalCatalog": True, "IsReadOnly": False},
            {"Name": "DC02", "HostName": "dc02.corp.example.com", "OperatingSystem": "Windows Server 2012 R2 Standard",
             "OperatingSystemVersion": "6.3 (9600)", "IsGlobalCatalog": True, "IsReadOnly": False},
        ],
        "TombstoneLifetime": 180, "DsHeuristics": None, "RecycleBinEnabled": False, "MachineAccountQuota": 10,
        "LapsLegacySchema": False, "LapsWindowsSchema": True, "FineGrainedPolicies": 0,
    },
    "AD_PRIVILEGED": {
        "Domain Admins": _group(sid(512), DA),
        "Schema Admins": _group(sid(518), [ADMIN]),
        "Enterprise Admins": _group(sid(519), [ADMIN, DA[1]]),
        "Administrators": _group("S-1-5-32-544", DA),
        "Account Operators": _group("S-1-5-32-548", [_member("helpdesk1", 1140, pwd=30, last=1, admin=1)]),
        "Server Operators": _group("S-1-5-32-549"),
        "Print Operators": _group("S-1-5-32-550"),
        "Backup Operators": _group("S-1-5-32-551", [DA[3]]),
        "Group Policy Creator Owners": _group(sid(520), [ADMIN]),
        "Key Admins": _group(sid(526)),
        "Enterprise Key Admins": _group(sid(527)),
        "Protected Users": _group(sid(525), [DA[1]]),
        "DnsAdmins": _group("DnsAdmins", [_member("svc_dnsmgmt", 1150, never=True, pwd=700, last=12, admin=None)]),
        "Pre-Windows 2000 Compatible Access": _group("S-1-5-32-554", ["S-1-5-11"]),
    },
    "AD_ACCOUNTS": {
        "UsersEnabled": {"Count": 412, "Sample": []},
        "PwdNotRequired": {"Count": 2, "Sample": ["scanner", "kiosk01"]},
        "ReversibleEncryption": {"Count": 0, "Sample": []},
        "PwdNeverExpires": {"Count": 37, "Sample": ["Administrator", "svc_backup", "svc_sql", "svc_dnsmgmt", "scanner"]},
        "DesOnly": {"Count": 0, "Sample": []},
        "NoPreAuth": {"Count": 1, "Sample": ["legacy.unix"]},
        "UserSpn": {"Count": 3, "Sample": ["svc_backup", "svc_sql", "svc_web"]},
        "UnconstrainedUsers": {"Count": 0, "Sample": []},
        "UnconstrainedComputers": {"Count": 1, "Sample": ["APP-OLD01$"]},
        "ProtocolTransition": {"Count": 0, "Sample": []},
        "ConstrainedDelegation": {"Count": 1, "Sample": ["WEB01$"]},
        "StaleUsers": {"Count": 58, "Sample": ["m.ahmadi", "t.karimi", "intern2023"]},
        "StaleComputers": {"Count": 23, "Sample": ["PC-0412$", "PC-0198$"]},
        "UnsupportedOs": {"Count": 4, "Sample": ["PC-0007$", "SRV-LEGACY$"]},
        "WindowsComputers": {"Count": 318, "Sample": []},
        "LapsLegacyManaged": None,
        "LapsWindowsManaged": {"Count": 141, "Sample": []},
        "Krbtgt": {"PwdLastSetDays": 1283},
        "BuiltinAdmin": {"Sam": "Administrator", "Enabled": True, "NotDelegated": False, "PwdLastSetDays": 812, "LastLogonDays": 1},
        "Guest": {"Sam": "Guest", "Enabled": False},
        "StaleDays": 90,
    },
    "AD_TRUSTS": [
        {"Name": "partner.example.net", "Direction": "Outbound", "TrustType": "Uplevel", "ForestTransitive": False,
         "IntraForest": False, "SIDFilteringQuarantined": False, "SIDFilteringForestAware": False,
         "SelectiveAuthentication": False, "TGTDelegation": False},
    ],
    "AD_GPP": {"Scanned": "C:\\Windows\\SYSVOL\\sysvol\\corp.example.com\\Policies",
               "Files": ["\\{6AC1786C-016F-11D2-945F-00C04fB984F9}\\Machine\\Preferences\\Groups\\Groups.xml"]},
    "AD_DC_CONFIG": {"EnableSMB1Protocol": False, "RequireSecuritySignature": True,
                     "SpoolerStatus": "Running", "SpoolerStartType": "Automatic"},
    "AD_REGISTRY": {
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa": '{"DsrmAdminLogonBehavior":2}',
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters":
            '{"NullSessionPipes":["LSARPC","NETLOGON","SAMR","BROWSER"]}',
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters": '{"LDAPServerIntegrity":1}',
    },
}

HOST = {
    "OS_VERSION": {"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348",
                   "BuildNumber": "20348", "OSArchitecture": "64-bit"},
    "DOMAIN_ROLE": {"DomainRole": 5, "Domain": "corp.example.com", "PartOfDomain": True},
}


def sections():
    """section name -> collector output text, in collection order."""
    s = copy.deepcopy(AD)
    out = {
        "OS_VERSION": json.dumps(HOST["OS_VERSION"], separators=(",", ":")),
        "DOMAIN_ROLE": json.dumps(HOST["DOMAIN_ROLE"], separators=(",", ":")),
        "SECURITY_POLICY": SECURITY_POLICY,
        "USER_RIGHTS": USER_RIGHTS,
        "AUDIT_POLICY": AUDIT_POLICY,
        "REGISTRY": json.dumps(_registry(), indent=2),
        "FIREWALL_PROFILES": json.dumps(FIREWALL, separators=(",", ":")),
    }
    for name, value in s.items():
        out[name] = json.dumps(value, separators=(",", ":"))
    return out


def dump(overrides=None):
    """The assembled dump, with section texts replaced by `overrides`."""
    from app.modules.benchmark.rules import assemble
    data = sections()
    data.update(overrides or {})
    return assemble(data)


def with_ad(path, value):
    """A copy of one AD_* section with data[path...] = value, as JSON text."""
    section, *keys = path.split(".")
    data = copy.deepcopy(AD[section])
    cur = data
    for k in keys[:-1]:
        cur = cur[k]
    cur[keys[-1]] = value
    return {section: json.dumps(data, separators=(",", ":"))}
