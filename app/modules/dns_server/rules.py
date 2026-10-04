"""
Windows DNS Server rules.

After the DISA STIG for Microsoft Windows Server DNS, grouped by its
families: AC (access control), AU (audit), CM (configuration), SC (system and
communications protection - DNSSEC) and PR (the STIG's procedural
requirements, which need a person to verify and are reported as manual).
Where Microsoft's DNS hardening guidance covers what the STIG does not
(cache locking, socket pool, global query block list, response rate
limiting) the control is labelled "Microsoft".

IDs are this product's (DNS-<family>-<n>); the STIG's own vulnerability
numbers are not reproduced.
"""

from typing import Any, Dict, List, Optional

from app.modules.benchmark.rules import BenchmarkRule, as_list, json_section
from app.modules.benchmark.winps import registry_value
from app.modules.windows.audit import rules as W

from .collect import DNS_PARAMS

JSON_SECTIONS = frozenset({"OS_VERSION", "DOMAIN_ROLE", "DNS_SETTINGS", "DNS_ZONES", "DNS_HOST", "DNS_REGISTRY"})

STRONG_ALGORITHMS = ("RsaSha256", "RsaSha512", "ECDsaP256Sha256", "ECDsaP384Sha384")
# Folder ACL entries allowed to change %SystemRoot%\System32\dns.
_ALLOWED_WRITERS = ("NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller",
                    "CREATOR OWNER", "NT SERVICE\\DNS")
_WRITE_RIGHTS = ("FullControl", "Modify", "Write", "CreateFiles", "AppendData", "WriteData",
                 "ChangePermissions", "TakeOwnership", "Delete", "268435456", "1073741824")
# Roles that may share a DNS server (AD-integrated DNS lives on DCs).
ALLOWED_ROLES = ("DNS", "AD-Domain-Services", "FileAndStorage-Services")


def settings(d: str) -> Dict[str, Any]:
    v = json_section(d, "DNS_SETTINGS")
    return v if isinstance(v, dict) else {}


def zones(d: str) -> List[Dict[str, Any]]:
    return [z for z in as_list(json_section(d, "DNS_ZONES")) if isinstance(z, dict)]


def host(d: str) -> Dict[str, Any]:
    v = json_section(d, "DNS_HOST")
    return v if isinstance(v, dict) else {}


def primary_zones(d: str) -> List[Dict[str, Any]]:
    return [z for z in zones(d) if z.get("Type") == "Primary"]


def signable_zones(d: str) -> List[Dict[str, Any]]:
    """Primary forward zones (reverse zones are not required to be signed here)."""
    return [z for z in primary_zones(d) if not z.get("Reverse")]


def socket_pool(d: str) -> int:
    v = registry_value(json_section(d, "DNS_REGISTRY"), DNS_PARAMS, "SocketPoolSize")
    try:
        return int(v)
    except (TypeError, ValueError):
        return 2500          # Windows default when the value is not set


def _names(items, limit=20) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _zone_ev(pred, label):
    return lambda d: f"{label}: " + _names(z["Name"] for z in primary_zones(d) if pred(z))


def _keys(d):
    for z in signable_zones(d):
        sec = z.get("Dnssec") or {}
        for k in as_list(sec.get("Keys")):
            if isinstance(k, dict):
                yield z["Name"], k


def _key_ok(k) -> bool:
    if k.get("Algorithm") not in STRONG_ALGORITHMS:
        return False
    if str(k.get("Algorithm", "")).startswith("Rsa"):
        need = 2048 if k.get("Type") == "KeySigningKey" else 1024
        return (k.get("Length") or 0) >= need
    return True


def _acl_writers(d) -> List[str]:
    out = []
    for a in as_list(host(d).get("DnsFolderAcl")):
        if not isinstance(a, dict) or a.get("Type") != "Allow":
            continue
        ident = str(a.get("Identity") or "")
        if ident in _ALLOWED_WRITERS or ident.lower().endswith("\\dnsadmins"):
            continue
        rights = str(a.get("Rights") or "")
        if any(r in rights for r in _WRITE_RIGHTS):
            out.append(f"{ident} ({rights})")
    return out


def _supported_os(d) -> bool:
    return W._detect_version(d) in ("2016", "2019", "2022", "2025")


def _rule(rules, rid, title, severity, check, evidence, remediation, sections, source="DISA STIG",
          level="L1", manual=False, unavailable=None):
    family, _, n = rid.partition("-")
    rules.append(BenchmarkRule(
        id=f"DNS-{rid}", section=rid, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source=source, unavailable_fn=unavailable))


def _manual(rules, rid, title, severity, guidance):
    _rule(rules, rid, title, severity, lambda d: False, lambda d: f"Manual verification: {guidance}",
          guidance, [], manual=True)


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    S, Z, H = ["DNS_SETTINGS"], ["DNS_ZONES"], ["DNS_HOST"]

    # ── AC: access control ────────────────────────────────────────────────
    _rule(r, "AC-1", "Ensure zone transfers are not allowed to any server", "high",
          lambda d: not [z for z in primary_zones(d) if z.get("SecureSecondaries") == "TransferAnyServer"],
          _zone_ev(lambda z: z.get("SecureSecondaries") == "TransferAnyServer", "Zones transferring to any server"),
          "Allow zone transfers only to the zone's name servers or listed secondaries; none for AD-integrated zones.", Z)
    _rule(r, "AC-2", "Ensure no zone accepts non-secure dynamic updates", "high",
          lambda d: not [z for z in primary_zones(d) if z.get("DynamicUpdate") == "NonsecureAndSecure"],
          _zone_ev(lambda z: z.get("DynamicUpdate") == "NonsecureAndSecure", "Zones with non-secure updates"),
          "Set dynamic updates to 'Secure only' on AD-integrated zones and 'None' on file-backed zones.", Z)
    _rule(r, "AC-3", "Ensure only administrators can modify the DNS server files", "medium",
          lambda d: not _acl_writers(d),
          lambda d: "Other principals with write access to %SystemRoot%\\System32\\dns: " + _names(_acl_writers(d)),
          "Remove write permissions on %SystemRoot%\\System32\\dns from everyone but SYSTEM, Administrators and DnsAdmins.", H)

    # ── AU: audit ─────────────────────────────────────────────────────────
    _rule(r, "AU-1", "Ensure the DNS Server audit event log is enabled", "medium",
          lambda d: host(d).get("AuditLogEnabled") is True,
          lambda d: f"Microsoft-Windows-DNSServer/Audit enabled = {host(d).get('AuditLogEnabled')}",
          "wevtutil sl Microsoft-Windows-DNSServer/Audit /e:true", H)
    _rule(r, "AU-2", "Ensure the DNS Server event log is at least 32 MB", "low",
          lambda d: (host(d).get("DnsLogMaxBytes") or 0) >= 32 * 1024 * 1024,
          lambda d: f"DNS Server log maximum size = {host(d).get('DnsLogMaxBytes')} bytes",
          "wevtutil sl \"DNS Server\" /ms:33554432", H)
    _rule(r, "AU-3", "Ensure the DNS server logs errors, warnings and informational events", "low",
          lambda d: (settings(d).get("Diagnostics") or {}).get("EventLogLevel") == 4,
          lambda d: f"EventLogLevel = {(settings(d).get('Diagnostics') or {}).get('EventLogLevel')} (4 = all events)",
          "Set-DnsServerDiagnostics -EventLogLevel 4", S)

    # ── CM: configuration ─────────────────────────────────────────────────
    _rule(r, "CM-1", "Ensure the DNS server has a statically assigned IP address", "high",
          lambda d: bool(as_list(host(d).get("Interfaces"))) and all(
              i.get("Dhcp") == "Disabled" for i in as_list(host(d).get("Interfaces"))),
          lambda d: "Interfaces: " + _names(f"{i.get('Alias')} (DHCP {i.get('Dhcp')})" for i in as_list(host(d).get("Interfaces"))),
          "Assign static addresses to every connected interface of the DNS server.", H)
    _rule(r, "CM-2", "Ensure root hints are not used when the server forwards to internal resolvers", "medium",
          lambda d: not settings(d).get("Forwarders") or settings(d).get("UseRootHint") is False,
          lambda d: f"Forwarders = {_names(settings(d).get('Forwarders') or [])}, UseRootHint = {settings(d).get('UseRootHint')}",
          "Set-DnsServerForwarder -UseRootHint $false", S)
    _rule(r, "CM-3", "Ensure at least two forwarders are configured when forwarding is used", "low",
          lambda d: not settings(d).get("Forwarders") or len(settings(d).get("Forwarders")) >= 2,
          lambda d: f"Forwarders = {_names(settings(d).get('Forwarders') or [])}",
          "Configure a second forwarder so resolution survives one resolver failing.", S)
    _rule(r, "CM-4", "Ensure the DNS socket pool holds at least 2500 ports", "medium",
          lambda d: socket_pool(d) >= 2500,
          lambda d: f"SocketPoolSize = {socket_pool(d)} (unset = 2500)",
          "dnscmd /config /socketpoolsize 10000, then restart the DNS service.", ["DNS_REGISTRY"], source="Microsoft")
    _rule(r, "CM-5", "Ensure DNS cache locking is 100%", "medium",
          lambda d: (settings(d).get("Cache") or {}).get("LockingPercent") == 100,
          lambda d: f"Cache LockingPercent = {(settings(d).get('Cache') or {}).get('LockingPercent')}",
          "Set-DnsServerCache -LockingPercent 100", S, source="Microsoft")
    _rule(r, "CM-6", "Ensure cache pollution protection is enabled", "high",
          lambda d: (settings(d).get("Cache") or {}).get("EnablePollutionProtection") is True,
          lambda d: f"EnablePollutionProtection = {(settings(d).get('Cache') or {}).get('EnablePollutionProtection')}",
          "Set-DnsServerCache -EnablePollutionProtection $true", S)
    _rule(r, "CM-7", "Ensure the global query block list is enabled and blocks wpad and isatap", "medium",
          lambda d: bool((settings(d).get("BlockList") or {}).get("Enable")) and {"wpad", "isatap"} <= {
              str(x).lower() for x in as_list((settings(d).get("BlockList") or {}).get("List"))},
          lambda d: f"Global query block list: {settings(d).get('BlockList')}",
          "Set-DnsServerGlobalQueryBlockList -Enable $true -List wpad,isatap", S, source="Microsoft")
    _rule(r, "CM-8", "Ensure response rate limiting is enabled", "medium",
          lambda d: settings(d).get("Rrl") == "Enable",
          lambda d: f"Response rate limiting mode = {settings(d).get('Rrl')}",
          "Set-DnsServerResponseRateLimiting -Mode Enable", S, source="Microsoft",
          unavailable=lambda d: ("response rate limiting needs Windows Server 2016 or later"
                                 if settings(d).get("Rrl") == "NotSupported" else None))
    _rule(r, "CM-9", "Ensure recursion only returns secure responses", "medium",
          lambda d: (settings(d).get("Recursion") or {}).get("SecureResponse") is True,
          lambda d: f"Recursion: {settings(d).get('Recursion')}",
          "Set-DnsServerRecursion -SecureResponse $true", S)
    _rule(r, "CM-10", "Ensure cached records live no longer than one day", "low",
          lambda d: 0 < ((settings(d).get("Cache") or {}).get("MaxTtlSeconds") or 0) <= 86400,
          lambda d: f"Cache MaxTtl = {(settings(d).get('Cache') or {}).get('MaxTtlSeconds')} s",
          "Set-DnsServerCache -MaxTtl 1.00:00:00", S)
    _rule(r, "CM-11", "Ensure the DNS server runs a supported Windows Server version", "high",
          _supported_os, lambda d: f"Windows Server {W._detect_version(d)}",
          "Move the DNS role to Windows Server 2016 or later.", ["OS_VERSION"])
    _rule(r, "CM-12", "Ensure the DNS server hosts no roles beyond DNS and Active Directory", "medium",
          lambda d: not [x for x in as_list(host(d).get("Roles")) if x not in ALLOWED_ROLES],
          lambda d: "Other roles: " + _names(x for x in as_list(host(d).get("Roles")) if x not in ALLOWED_ROLES),
          "Move unrelated roles off the DNS server.", H)
    _rule(r, "CM-13", "Ensure the DNS Server service is running and starts automatically", "medium",
          lambda d: host(d).get("ServiceStatus") == "Running" and host(d).get("ServiceStartType") == "Automatic",
          lambda d: f"DNS service: {host(d).get('ServiceStatus')}, {host(d).get('ServiceStartType')}",
          "Set-Service DNS -StartupType Automatic; Start-Service DNS", H)

    # ── SC: DNSSEC ────────────────────────────────────────────────────────
    _rule(r, "SC-1", "Ensure every primary forward zone is signed with DNSSEC", "high",
          lambda d: not [z for z in signable_zones(d) if not z.get("Signed")],
          lambda d: "Unsigned zones: " + _names(z["Name"] for z in signable_zones(d) if not z.get("Signed")),
          "Sign the zones (DNSSEC > Sign the Zone, or Invoke-DnsServerZoneSign) and publish DS records in the parent.", Z)
    _rule(r, "SC-2", "Ensure signed zones use NSEC3 for authenticated denial of existence", "medium",
          lambda d: all((z.get("Dnssec") or {}).get("DenialOfExistence") == "NSec3"
                        for z in signable_zones(d) if z.get("Signed")),
          lambda d: "Signed zones: " + _names(f"{z['Name']} ({(z.get('Dnssec') or {}).get('DenialOfExistence')})"
                                             for z in signable_zones(d) if z.get("Signed")),
          "Re-sign with NSEC3 (Unsign, then sign with the default parameters).", Z)
    _rule(r, "SC-3", "Ensure DNSSEC keys use SHA-256 or stronger and adequate key lengths", "high",
          lambda d: all(_key_ok(k) for _, k in _keys(d)),
          lambda d: "Weak keys: " + _names(f"{z}: {k.get('Type')} {k.get('Algorithm')} {k.get('Length')}"
                                           for z, k in _keys(d) if not _key_ok(k)),
          "Use RSA/SHA-256 with a 2048-bit KSK and at least 1024-bit ZSK (or ECDSA P-256/P-384).", Z)
    _rule(r, "SC-4", "Ensure automatic key rollover is enabled for DNSSEC keys", "low",
          lambda d: all(k.get("Rollover") for _, k in _keys(d)),
          lambda d: "Keys without rollover: " + _names(f"{z}: {k.get('Type')}" for z, k in _keys(d) if not k.get("Rollover")),
          "Enable automated rollover on every signing key (DNSSEC properties > KSK/ZSK > Enable automatic rollover).", Z)
    _rule(r, "SC-5", "Ensure the DNS server returns DNSSEC records (EnableDnsSec)", "medium",
          lambda d: settings(d).get("EnableDnsSec") in (True, 1),
          lambda d: f"EnableDnsSec = {settings(d).get('EnableDnsSec')}",
          "dnscmd /config /enablednssec 1", S)

    # ── PR: procedural STIG requirements ──────────────────────────────────
    _manual(r, "PR-1", "Ensure the DNS architecture (primary, secondaries, hidden primary, forwarders) is documented",
            "medium", "Keep a current diagram and inventory of every DNS server, its role and the zones it serves.")
    _manual(r, "PR-2", "Ensure authoritative primary and secondary servers are on separate network segments and sites",
            "medium", "Place secondaries in another subnet and, where possible, another site.")
    _manual(r, "PR-3", "Ensure internal and external zones are served by separate DNS servers",
            "high", "Split-horizon DNS must not host the internal and external views on the same server.")
    _manual(r, "PR-4", "Ensure servers authoritative for external zones do not offer recursion to the internet",
            "high", "Disable recursion on internet-facing authoritative servers (Set-DnsServerRecursion -Enable $false).")
    _manual(r, "PR-5", "Ensure the DNSSEC key-signing key private material is protected and its handling documented",
            "high", "Restrict the key master, back up keys securely and record who may handle them.")
    _manual(r, "PR-6", "Ensure zone records are reviewed for stale, unauthorised or out-of-zone records",
            "medium", "Review zones periodically; enable aging/scavenging where dynamic records are used.")
    _manual(r, "PR-7", "Ensure DNS administrators are a documented, minimal group and their changes are reviewed",
            "medium", "Keep DnsAdmins minimal and review the DNS audit log.")
    _manual(r, "PR-8", "Ensure the DNS server's availability is monitored and alerts reach the administrators",
            "low", "Monitor the DNS service and resolution from clients.")
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    from app.modules.benchmark.rules import section
    raw = section(dump, "DNS_SETTINGS")
    if raw.startswith("PS_ERROR") and ("DnsServer" in raw or "Get-DnsServer" in raw):
        raise ValueError("The DNS Server role is not installed on this host "
                         "(the DnsServer PowerShell module is missing).")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    return (f"Windows Server {W._detect_version(dump)}, DNS {settings(dump).get('Version')}, "
            f"{len(zones(dump))} zones")
