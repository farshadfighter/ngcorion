"""
Windows DHCP Server rules, after Microsoft's DHCP security and deployment
guidance (authorisation, DNS dynamic-update credentials and name
protection, audit logging, failover, database backup, delegation groups).

IDs are this product's: DHCP-<area>-<n> with areas AU (authorisation), DN
(DNS integration), LG (logging and backup), AV (availability), AC (access)
and PR (procedural, verified by a person).
"""

from typing import Any, Dict, List

from app.modules.benchmark.rules import BenchmarkRule, as_list, json_section, section
from app.modules.windows.audit import rules as W

JSON_SECTIONS = frozenset({"OS_VERSION", "DOMAIN_ROLE", "DHCP_SETTINGS", "DHCP_HOST"})
BROAD_PRINCIPALS = ("everyone", "authenticated users", "domain users", "users", "interactive")
UTILISATION_LIMIT = 90.0
MAX_LEASE_DAYS = 8


def settings(d: str) -> Dict[str, Any]:
    v = json_section(d, "DHCP_SETTINGS")
    return v if isinstance(v, dict) else {}


def host(d: str) -> Dict[str, Any]:
    v = json_section(d, "DHCP_HOST")
    return v if isinstance(v, dict) else {}


def scopes(d: str) -> List[Dict[str, Any]]:
    return [s for s in as_list(settings(d).get("Scopes")) if isinstance(s, dict)]


def active_scopes(d: str) -> List[Dict[str, Any]]:
    return [s for s in scopes(d) if s.get("State") == "Active"]


def failover_scopes(d: str) -> set:
    return {sid for f in as_list(settings(d).get("Failover")) if isinstance(f, dict)
            for sid in as_list(f.get("Scopes"))}


def is_dc(d: str) -> bool:
    return W.is_domain_controller(d)


def _names(items, limit=20) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _group_error(name):
    def fn(d):
        members = as_list(host(d).get(name))
        bad = [m for m in members if str(m).startswith("ERROR:")]
        return f"{name} could not be read: {bad[0][7:]}" if bad else None
    return fn


def _broad(name):
    return lambda d: [m for m in as_list(host(d).get(name))
                      if str(m).split("\\")[-1].lower() in BROAD_PRINCIPALS]


def _rule(rules, rid, title, severity, check, evidence, remediation, sections, level="L1",
          manual=False, unavailable=None):
    rules.append(BenchmarkRule(
        id=f"DHCP-{rid}", section=rid, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="Microsoft", unavailable_fn=unavailable))


def _manual(rules, rid, title, severity, guidance):
    _rule(rules, rid, title, severity, lambda d: False, lambda d: f"Manual verification: {guidance}",
          guidance, [], manual=True)


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    S, H = ["DHCP_SETTINGS"], ["DHCP_HOST"]

    _rule(r, "AU-1", "Ensure the DHCP server is authorised in Active Directory", "high",
          lambda d: not settings(d).get("IsDomainJoined") or settings(d).get("IsAuthorized") is True,
          lambda d: f"Domain joined = {settings(d).get('IsDomainJoined')}, authorised = {settings(d).get('IsAuthorized')}",
          "Authorise the server (Add-DhcpServerInDC) so domain members can tell it from a rogue DHCP server.", S)

    _rule(r, "DN-1", "Ensure DHCP registers DNS records with a dedicated account", "high",
          lambda d: bool(settings(d).get("DnsCredentialUser")),
          lambda d: f"DNS dynamic update credential = {settings(d).get('DnsCredentialUser') or 'not set (computer account)'}",
          "Set-DhcpServerDnsCredential with a dedicated, unprivileged domain account. Without it records are "
          "registered with the server's computer account (and with full rights over them on a DC).", S)
    _rule(r, "DN-2", "Ensure DNS name protection is enabled on the server", "medium",
          lambda d: settings(d).get("NameProtection") is True,
          lambda d: f"Server NameProtection = {settings(d).get('NameProtection')}",
          "Set-DhcpServerv4DnsSetting -NameProtection $true", S)
    _rule(r, "DN-3", "Ensure DNS name protection is enabled on every scope", "medium",
          lambda d: all(s.get("NameProtection") is True for s in scopes(d)),
          lambda d: "Scopes without name protection: " + _names(
              f"{s['ScopeId']} ({s.get('Name')})" for s in scopes(d) if s.get("NameProtection") is not True),
          "Set-DhcpServerv4DnsSetting -ScopeId <scope> -NameProtection $true", S)
    _rule(r, "DN-4", "Ensure DNS records are removed when leases expire", "low",
          lambda d: settings(d).get("DeleteOnExpiry") is True,
          lambda d: f"DeleteDnsRROnLeaseExpiry = {settings(d).get('DeleteOnExpiry')}",
          "Set-DhcpServerv4DnsSetting -DeleteDnsRRonLeaseExpiry $true", S)

    _rule(r, "LG-1", "Ensure DHCP audit logging is enabled", "medium",
          lambda d: settings(d).get("AuditEnabled") is True,
          lambda d: f"Audit log enabled = {settings(d).get('AuditEnabled')}, path = {settings(d).get('AuditPath')}",
          "Set-DhcpServerAuditLog -Enable $true", S)
    _rule(r, "LG-2", "Ensure the DHCP database is backed up at least every 60 minutes", "low",
          lambda d: 0 < (settings(d).get("BackupIntervalMinutes") or 0) <= 60,
          lambda d: f"BackupInterval = {settings(d).get('BackupIntervalMinutes')} min, path = {settings(d).get('BackupPath')}",
          "Set-DhcpServerDatabase -BackupInterval 60", S)

    _rule(r, "AV-1", "Ensure every active scope is protected by DHCP failover", "medium",
          lambda d: all(s["ScopeId"] in failover_scopes(d) for s in active_scopes(d)),
          lambda d: "Active scopes without failover: " + _names(
              f"{s['ScopeId']} ({s.get('Name')})" for s in active_scopes(d) if s["ScopeId"] not in failover_scopes(d)),
          "Add the scopes to a failover relationship with a second DHCP server (Add-DhcpServerv4Failover).", S)
    _rule(r, "AV-2", "Ensure failover relationships authenticate their messages", "high",
          lambda d: all(f.get("EnableAuth") is True for f in as_list(settings(d).get("Failover")) if isinstance(f, dict)),
          lambda d: "Failover relationships without a shared secret: " + _names(
              f.get("Name") for f in as_list(settings(d).get("Failover")) if isinstance(f, dict) and f.get("EnableAuth") is not True),
          "Set-DhcpServerv4Failover -Name <relationship> -SharedSecret <secret>", S)
    _rule(r, "AV-3", f"Ensure no active scope is more than {UTILISATION_LIMIT:.0f}% in use", "medium",
          lambda d: all((s.get("InUsePercent") or 0) <= UTILISATION_LIMIT for s in active_scopes(d)),
          lambda d: "Nearly exhausted scopes: " + _names(
              f"{s['ScopeId']} {s.get('InUsePercent')}%" for s in active_scopes(d) if (s.get("InUsePercent") or 0) > UTILISATION_LIMIT),
          "Enlarge the scope or shorten its lease before clients start failing to get addresses.", S)
    _rule(r, "AV-4", f"Ensure scope leases last no longer than {MAX_LEASE_DAYS} days", "low",
          lambda d: all((s.get("LeaseDays") or 0) <= MAX_LEASE_DAYS for s in scopes(d)),
          lambda d: "Scopes with long leases: " + _names(
              f"{s['ScopeId']} {s.get('LeaseDays')} days" for s in scopes(d) if (s.get("LeaseDays") or 0) > MAX_LEASE_DAYS),
          "Shorten the lease (Set-DhcpServerv4Scope -LeaseDuration) so addresses of departed devices return to the pool.", S)
    _rule(r, "AV-5", "Ensure conflict detection is enabled", "low",
          lambda d: (settings(d).get("ConflictDetectionAttempts") or 0) >= 1,
          lambda d: f"ConflictDetectionAttempts = {settings(d).get('ConflictDetectionAttempts')}",
          "Set-DhcpServerSetting -ConflictDetectionAttempts 1", S)
    _rule(r, "AV-6", "Ensure the DHCP Server service is running and starts automatically", "medium",
          lambda d: host(d).get("ServiceStatus") == "Running" and host(d).get("ServiceStartType") == "Automatic",
          lambda d: f"DHCPServer service: {host(d).get('ServiceStatus')}, {host(d).get('ServiceStartType')}",
          "Set-Service DHCPServer -StartupType Automatic; Start-Service DHCPServer", H)

    _rule(r, "AC-1", "Ensure 'DHCP Administrators' does not include broad groups", "high",
          lambda d: not _broad("DhcpAdministrators")(d),
          lambda d: "DHCP Administrators: " + _names(as_list(host(d).get("DhcpAdministrators"))),
          "Keep only the people and groups that administer DHCP in DHCP Administrators.", H,
          unavailable=_group_error("DhcpAdministrators"))
    _rule(r, "AC-2", "Ensure 'DHCP Users' (read-only) does not include broad groups", "medium",
          lambda d: not _broad("DhcpUsers")(d),
          lambda d: "DHCP Users: " + _names(as_list(host(d).get("DhcpUsers"))),
          "Grant read access to DHCP only to the people who need it.", H,
          unavailable=_group_error("DhcpUsers"))
    _rule(r, "AC-3", "Ensure the DHCP role does not run on a domain controller", "low",
          lambda d: not is_dc(d),
          lambda d: f"Domain controller = {is_dc(d)}",
          "Move DHCP off the domain controller; if it must stay, configure the DNS update credential (DHCP-DN-1).",
          ["DOMAIN_ROLE"])
    _rule(r, "AC-4", "Ensure the DHCP server runs a supported Windows Server version", "high",
          lambda d: W._detect_version(d) in ("2016", "2019", "2022", "2025"),
          lambda d: f"Windows Server {W._detect_version(d)}",
          "Move the DHCP role to Windows Server 2016 or later.", ["OS_VERSION"])

    _manual(r, "PR-1", "Ensure the DHCP server is bound only to the interfaces of the networks it serves", "medium",
            "Check Get-DhcpServerv4Binding and unbind management or storage interfaces.")
    _manual(r, "PR-2", "Ensure switches block DHCP offers from unauthorised servers (DHCP snooping)", "high",
            "Enable DHCP snooping on access switches; Windows authorisation alone only stops Windows DHCP servers.")
    _manual(r, "PR-3", "Ensure scope options (DNS servers, router, domain) point only to authorised infrastructure", "medium",
            "Review options 3, 6 and 15 in every scope and in server options.")
    _manual(r, "PR-4", "Ensure DHCP configuration is exported and kept off the server", "low",
            "Export-DhcpServer -File <path> -Leases on a schedule and store the file elsewhere.")
    _manual(r, "PR-5", "Ensure the DHCP audit logs are collected centrally and reviewed", "low",
            "Forward %SystemRoot%\\System32\\dhcp\\DhcpSrvLog-*.log to the SIEM.")
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    raw = section(dump, "DHCP_SETTINGS")
    if raw.startswith("PS_ERROR") and ("DhcpServer" in raw or "Get-DhcpServer" in raw):
        raise ValueError("The DHCP Server role is not installed on this host "
                         "(the DhcpServer PowerShell module is missing).")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    return f"Windows Server {W._detect_version(dump)}, {len(scopes(dump))} IPv4 scopes"
