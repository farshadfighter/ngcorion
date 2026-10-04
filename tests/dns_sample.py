"""
Sample collector output of a Windows Server 2022 DNS server (DNS01, a
domain member serving corp.example.com), in the shape the DNS collection
scripts print. Built here, not captured from a real server: one signed
AD-integrated zone, a file-backed zone open to any secondary, an
AD-integrated lab zone with non-secure updates, root hints still used
next to forwarders, rate limiting off, an extra Print role.
"""
import copy
import json

KEY_SET = [{"Type": "KeySigningKey", "Algorithm": "RsaSha256", "Length": 2048, "Rollover": True},
           {"Type": "ZoneSigningKey", "Algorithm": "RsaSha256", "Length": 1024, "Rollover": True}]

DATA = {
    "OS_VERSION": {"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348",
                   "BuildNumber": "20348", "OSArchitecture": "64-bit"},
    "DOMAIN_ROLE": {"DomainRole": 3, "Domain": "corp.example.com", "PartOfDomain": True},
    "DNS_SETTINGS": {
        "Version": "10.0.20348", "EnableDnsSec": True, "ListeningIPAddress": ["10.10.0.53"],
        "Recursion": {"Enable": True, "SecureResponse": True},
        "Cache": {"EnablePollutionProtection": True, "LockingPercent": 100, "MaxTtlSeconds": 86400,
                  "MaxNegativeTtlSeconds": 900},
        "Forwarders": ["10.0.0.53", "10.0.1.53"], "UseRootHint": True, "RootHints": 13,
        "BlockList": {"Enable": True, "List": ["wpad", "isatap"]},
        "Rrl": "Disable",
        "Diagnostics": {"EventLogLevel": 2, "EnableLoggingToFile": False},
    },
    "DNS_ZONES": [
        {"Name": "corp.example.com", "Type": "Primary", "DsIntegrated": True, "Reverse": False,
         "DynamicUpdate": "Secure", "SecureSecondaries": "NoTransfer", "Signed": True,
         "Dnssec": {"DenialOfExistence": "NSec3", "Keys": KEY_SET}},
        {"Name": "lab.example.com", "Type": "Primary", "DsIntegrated": True, "Reverse": False,
         "DynamicUpdate": "NonsecureAndSecure", "SecureSecondaries": "NoTransfer", "Signed": False, "Dnssec": None},
        {"Name": "example.net", "Type": "Primary", "DsIntegrated": False, "Reverse": False,
         "DynamicUpdate": "None", "SecureSecondaries": "TransferAnyServer", "Signed": False, "Dnssec": None},
        {"Name": "10.in-addr.arpa", "Type": "Primary", "DsIntegrated": True, "Reverse": True,
         "DynamicUpdate": "Secure", "SecureSecondaries": "NoTransfer", "Signed": False, "Dnssec": None},
        {"Name": "partner.example.org", "Type": "Secondary", "DsIntegrated": False, "Reverse": False,
         "DynamicUpdate": "", "SecureSecondaries": "", "Signed": False, "Dnssec": None},
    ],
    "DNS_HOST": {
        "Interfaces": [{"Alias": "Ethernet0", "Dhcp": "Disabled"}],
        "DnsFolderAcl": [
            {"Identity": "NT AUTHORITY\\SYSTEM", "Rights": "FullControl", "Type": "Allow"},
            {"Identity": "BUILTIN\\Administrators", "Rights": "FullControl", "Type": "Allow"},
            {"Identity": "CREATOR OWNER", "Rights": "268435456", "Type": "Allow"},
            {"Identity": "CORP\\DnsAdmins", "Rights": "Modify, Synchronize", "Type": "Allow"},
            {"Identity": "BUILTIN\\Users", "Rights": "ReadAndExecute, Synchronize", "Type": "Allow"},
        ],
        "AuditLogEnabled": True, "DnsLogMaxBytes": 20971520,
        "ServiceStatus": "Running", "ServiceStartType": "Automatic",
        "Roles": ["DNS", "FileAndStorage-Services", "Print-Services"],
    },
    "DNS_REGISTRY": {},
}


def sections(**changes):
    data = copy.deepcopy(DATA)
    for k, v in changes.items():
        data[k] = v
    return {k: json.dumps(v, separators=(",", ":")) for k, v in data.items()}


def dump(**changes):
    from app.modules.benchmark.rules import assemble
    return assemble(sections(**changes))


def with_(section, **fields):
    data = copy.deepcopy(DATA[section])
    data.update(fields)
    return data
