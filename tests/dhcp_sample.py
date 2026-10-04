"""
Sample collector output of a Windows Server 2022 DHCP server (DHCP01, a
domain member), in the shape the DHCP collection scripts print. Built here,
not captured: authorised, no DNS update account, name protection off on one
scope, one scope without failover and nearly full, a failover relationship
without a shared secret, Authenticated Users in DHCP Users.
"""
import copy
import json

DATA = {
    "OS_VERSION": {"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348",
                   "BuildNumber": "20348", "OSArchitecture": "64-bit"},
    "DOMAIN_ROLE": {"DomainRole": 3, "Domain": "corp.example.com", "PartOfDomain": True},
    "DHCP_SETTINGS": {
        "IsDomainJoined": True, "IsAuthorized": True, "ConflictDetectionAttempts": 0,
        "AuditEnabled": True, "AuditPath": "C:\\Windows\\system32\\dhcp",
        "BackupIntervalMinutes": 60, "BackupPath": "C:\\Windows\\system32\\dhcp\\backup",
        "NameProtection": False, "DeleteOnExpiry": True, "DynamicUpdates": "OnClientRequest",
        "DnsCredentialUser": None,
        "Scopes": [
            {"ScopeId": "10.20.0.0", "Name": "HQ users", "State": "Active", "LeaseDays": 8,
             "InUsePercent": 71.4, "NameProtection": True},
            {"ScopeId": "10.20.8.0", "Name": "HQ voice", "State": "Active", "LeaseDays": 8,
             "InUsePercent": 34.0, "NameProtection": True},
            {"ScopeId": "10.30.0.0", "Name": "Branch Tabriz", "State": "Active", "LeaseDays": 30,
             "InUsePercent": 96.5, "NameProtection": False},
            {"ScopeId": "10.40.0.0", "Name": "Old lab", "State": "Inactive", "LeaseDays": 1,
             "InUsePercent": 0.0, "NameProtection": True},
        ],
        "Failover": [{"Name": "dhcp01-dhcp02", "Mode": "LoadBalance", "EnableAuth": False,
                      "Scopes": ["10.20.0.0", "10.20.8.0"]}],
    },
    "DHCP_HOST": {"ServiceStatus": "Running", "ServiceStartType": "Automatic",
                  "DhcpAdministrators": ["CORP\\net-admins"],
                  "DhcpUsers": ["CORP\\helpdesk", "NT AUTHORITY\\Authenticated Users"]},
}


def sections(**changes):
    data = copy.deepcopy(DATA)
    data.update(changes)
    return {k: json.dumps(v, separators=(",", ":")) for k, v in data.items()}


def dump(**changes):
    from app.modules.benchmark.rules import assemble
    return assemble(sections(**changes))


def with_(section, **fields):
    data = copy.deepcopy(DATA[section])
    data.update(fields)
    return data
