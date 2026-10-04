"""
Sophos Firewall (SFOS 19+) rules after Sophos's hardening guidance for the
firewall itself ("Sophos Firewall: best practices for securing" and the
admin guide's device access, administration, update and logging
recommendations): 1 administrative access, 2 updates, 3 logging and
monitoring, 4 network protection, 5 backup.

There is no CIS benchmark for Sophos Firewall; the controls are the vendor's
and reported with source "Sophos". Data comes from the XML API's Get answers.
"""

import re
from functools import lru_cache
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from app.modules.benchmark.rules import BenchmarkRule, section

from .api import sfos_version

ON = ("enable", "enabled", "on", "1", "yes", "true")
EXPOSED_ON_WAN = {"HTTPS": "web admin (HTTPS)", "SSH": "SSH", "UserPortal": "user portal",
                  "SNMP": "SNMP", "DNS": "DNS", "WebProxy": "web proxy", "DynamicRouting": "dynamic routing",
                  "SMTPRelay": "SMTP relay", "CaptivePortal": "captive portal"}
FAST_PATTERN = ("every 15 minutes", "every 30 minutes", "every hour")


# ── data access ──────────────────────────────────────────────────────────

@lru_cache(maxsize=64)
def _parse(text: str) -> ET.Element:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD in stored data")
    return ET.fromstring(f"<Root>{text}</Root>")


def items(d, entity) -> List[ET.Element]:
    text = section(d, entity)
    if not text or not text.lstrip().startswith("<"):
        return []
    return [el for el in _parse(text) if el.tag == entity]


def one(d, entity) -> Optional[ET.Element]:
    found = items(d, entity)
    return found[0] if found else None


def val(el: Optional[ET.Element], path: str, default: str = "") -> str:
    if el is None:
        return default
    v = el.findtext(path)
    return v.strip() if v is not None else default


def on(value: str) -> bool:
    return value.strip().lower() in ON


def api_version(d) -> str:
    m = re.search(r"APIVersion=(\S+)", section(d, "VERSION"))
    return m.group(1) if m else ""


def _names(seq, limit=12) -> str:
    seq = list(seq)
    if not seq:
        return "none"
    return ", ".join(str(s) for s in seq[:limit]) + (f" (+{len(seq) - limit} more)" if len(seq) > limit else "")


def wan_zones(d) -> List[ET.Element]:
    return [z for z in items(d, "Zone") if val(z, "Type").upper() == "WAN" or val(z, "Name").upper() == "WAN"]


def wan_services(d) -> Dict[str, List[str]]:
    """{service tag: [WAN zones where it is enabled]}"""
    out: Dict[str, List[str]] = {}
    for z in wan_zones(d):
        access = z.find("ApplianceAccess")
        if access is None:
            continue
        for node in access.iter():
            if node.tag in EXPOSED_ON_WAN and on(node.text or ""):
                out.setdefault(node.tag, []).append(val(z, "Name"))
    return out


def rules_list(d) -> List[ET.Element]:
    return items(d, "FirewallRule")


def policy(rule: ET.Element) -> Optional[ET.Element]:
    for tag in ("NetworkPolicy", "UserPolicy"):
        if rule.find(tag) is not None:
            return rule.find(tag)
    return None


def allows(rule: ET.Element) -> bool:
    p = policy(rule)
    return on(val(rule, "Status", "Enable")) and p is not None and val(p, "Action").lower() == "accept"


def listed(p: ET.Element, group: str, child: str) -> List[str]:
    node = p.find(group)
    return [c.text.strip() for c in node.findall(child) if c.text] if node is not None else []


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1", manual=False):
    rules.append(BenchmarkRule(
        id=f"SOPHOS-{sec}", section=sec, title=title, severity=severity, level=level, check_fn=check,
        evidence_fn=evidence, remediation=remediation, description=title, manual=manual,
        data_sections=list(sections), source="Sophos"))


def _manual(rules, sec, title, severity, guidance, evidence, sections, level="L1"):
    _rule(rules, sec, title, severity, lambda d: False, evidence, guidance, sections, level=level, manual=True)


def _wan_service_rule(rules, sec, title, severity, tags, remediation, level="L1"):
    def exposed(d):
        svc = wan_services(d)
        return [f"{EXPOSED_ON_WAN[t]} on {', '.join(svc[t])}" for t in tags if t in svc]
    _rule(rules, sec, title, severity, lambda d: bool(wan_zones(d)) and not exposed(d),
          lambda d: ("enabled on WAN zones: " + _names(exposed(d))) if wan_zones(d) else "no WAN zone returned",
          remediation, ["Zone"], level=level)


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    A = ["AdminSettings"]

    # 1 Administrative access ─────────────────────────────────────────────
    _wan_service_rule(r, "1.1", "Ensure web admin (HTTPS) and SSH are not reachable from the WAN zone", "high",
                      ("HTTPS", "SSH"),
                      "Administration > Device access: clear HTTPS and SSH for the WAN zone; manage remotely through "
                      "Sophos Central or a VPN.")
    _wan_service_rule(r, "1.2", "Ensure the user portal is not reachable from the WAN zone", "high", ("UserPortal",),
                      "Administration > Device access: clear User portal for the WAN zone.")
    _wan_service_rule(r, "1.3", "Ensure SNMP, DNS, web proxy, routing and SMTP relay are not offered on the WAN zone",
                      "medium", ("SNMP", "DNS", "WebProxy", "DynamicRouting", "SMTPRelay", "CaptivePortal"),
                      "Administration > Device access: clear the services the WAN zone does not need.")

    def acl_exceptions(d):
        out = []
        for acl in items(d, "LocalServiceACL"):
            services = [s.text for s in acl.iter("Service") if s.text]
            hosts = [h.text for h in acl.iter("Host") if h.text]
            if val(acl, "SourceZone").upper() == "WAN" and val(acl, "Action").lower() == "accept" \
                    and any(s.upper() in ("HTTPS", "SSH") for s in services):
                out.append(f"{val(acl, 'RuleName')} ({', '.join(services)} from {', '.join(hosts) or 'any host'})")
        return out
    _rule(r, "1.4", "Ensure local service ACL exceptions do not open administration to the WAN", "high",
          lambda d: not acl_exceptions(d), lambda d: "WAN exceptions for HTTPS/SSH: " + _names(acl_exceptions(d)),
          "Remove device access exceptions that allow HTTPS or SSH from the WAN zone (or limit them to fixed hosts "
          "of the management network).", ["LocalServiceACL"])

    def logout(d):
        return val(one(d, "AdminSettings"), "LoginSecurity/LogoutSession")
    _rule(r, "1.5", "Ensure idle administrator sessions are logged out after 10 minutes or less", "medium",
          lambda d: logout(d).isdigit() and 0 < int(logout(d)) <= 10,
          lambda d: f"LogoutSession = {logout(d) or 'not set'}",
          "Administration > Admin and user settings > Login security: log out admin session after 10 minutes.", A)

    def lockout(d):
        ls = one(d, "AdminSettings")
        attempts = val(ls, "LoginSecurity/BlockLoginSettings/UnsucccessfulAttempt")
        return val(ls, "LoginSecurity/BlockLogin"), attempts, val(ls, "LoginSecurity/BlockLoginSettings/ForMinutes")
    _rule(r, "1.6", "Ensure administrator login is blocked after repeated failures", "high",
          lambda d: on(lockout(d)[0]) and lockout(d)[1].isdigit() and int(lockout(d)[1]) <= 5,
          lambda d: "BlockLogin = {}, failed attempts allowed = {}, blocked for {} minutes".format(
              *(v or "not set" for v in lockout(d))),
          "Login security: block login after 5 unsuccessful attempts.", A)

    def complexity(d):
        pc = one(d, "AdminSettings")
        base = "PasswordComplexitySettings/PasswordComplexity/"
        length = val(pc, base + "MinimumPasswordLengthValue")
        problems = []
        if not on(val(pc, "PasswordComplexitySettings/PasswordComplexityCheck")):
            problems.append("complexity check off")
        if not on(val(pc, base + "MinimumPasswordLength")) or not length.isdigit() or int(length) < 12:
            problems.append(f"minimum length {length or 'not enforced'}")
        for tag, label in (("IncludeAlphabeticCharacters", "letters"), ("IncludeNumericCharacter", "digits"),
                           ("IncludeSpecialCharacter", "special characters")):
            if not on(val(pc, base + tag)):
                problems.append(f"{label} not required")
        return problems
    _rule(r, "1.7", "Ensure administrator passwords must be complex (12+ characters)", "high",
          lambda d: not complexity(d), lambda d: "; ".join(complexity(d)) or "complexity enforced, 12+ characters",
          "Admin and user settings > Administrator password complexity settings.", A)
    _rule(r, "1.8", "Ensure a login disclaimer is shown", "low",
          lambda d: on(val(one(d, "AdminSettings"), "LoginDisclaimer")),
          lambda d: f"LoginDisclaimer = {val(one(d, 'AdminSettings'), 'LoginDisclaimer') or 'not set'}",
          "Admin and user settings: enable the login disclaimer.", A)

    def otp(d):
        o = one(d, "OTPSettings")
        return val(o, "otp"), val(o, "otpWebAdmin")
    _rule(r, "1.9", "Ensure multi-factor authentication (OTP) is required for web admin", "high",
          lambda d: on(otp(d)[0]) and on(otp(d)[1]),
          lambda d: f"OTP = {otp(d)[0] or 'not set'}, OTP for web admin = {otp(d)[1] or 'not set'}",
          "Authentication > One-time password: enable OTP and require it for the web admin console (give every "
          "administrator a token first).", ["OTPSettings"])
    _manual(r, "1.10", "Ensure the web admin console does not use the default port", "low",
            "Admin and user settings > Admin console HTTPS port: use a non-default port (update this audit's port "
            "and the API allowed list accordingly).",
            lambda d: "web admin HTTPS port: " + (val(one(d, "AdminSettings"), "WebAdminSettings/HTTPSport") or "?"),
            A, level="L2")
    _manual(r, "1.11", "Ensure the web admin console uses a trusted certificate", "medium",
            "Admin and user settings: select a certificate issued by your CA instead of the appliance certificate.",
            lambda d: "certificate: " + (val(one(d, "AdminSettings"), "WebAdminSettings/Certificate") or "?"), A)

    def admins(d):
        return [f"{val(u, 'Username')} ({val(u, 'Profile') or 'profile ?'}, {val(u, 'Status') or 'status ?'})"
                for u in items(d, "User") if val(u, "UserType").lower() == "administrator"]
    _manual(r, "1.12", "Ensure administrator accounts are individual and reviewed", "medium",
            "Use named administrator accounts with the least-privilege profile; disable unused ones.",
            lambda d: "administrators: " + _names(admins(d)), ["User"])

    # 2 Updates ───────────────────────────────────────────────────────────
    _rule(r, "2.1", "Ensure hotfixes are installed automatically", "high",
          lambda d: on(val(one(d, "Hotfix"), "AllowAutoInstallOfHotFixes")),
          lambda d: f"AllowAutoInstallOfHotFixes = {val(one(d, 'Hotfix'), 'AllowAutoInstallOfHotFixes') or 'not set'}",
          "Backup & firmware > Hotfix: allow automatic installation of hotfixes.", ["Hotfix"])

    def pattern(d):
        p = one(d, "PatternDownload")
        return val(p, "AutoUpdate"), val(p, "Interval")
    _rule(r, "2.2", "Ensure protection patterns update automatically at least hourly", "high",
          lambda d: on(pattern(d)[0]) and pattern(d)[1].lower() in FAST_PATTERN,
          lambda d: f"AutoUpdate = {pattern(d)[0] or 'not set'}, interval = {pattern(d)[1] or 'not set'}",
          "Backup & firmware > Pattern updates: automatic, every 15 minutes.", ["PatternDownload"])
    _manual(r, "2.3", "Ensure the firewall runs a supported, current SFOS release", "high",
            "Install the current maintenance release of a supported SFOS version.",
            lambda d: f"API version {api_version(d)} (SFOS {sfos_version(api_version(d))})", ["VERSION"])

    # 3 Logging and monitoring ────────────────────────────────────────────
    def syslog(d):
        return [(val(s, "Name"), val(s, "ServerAddress") or val(s, "IPAddress"), val(s, "EnableSecureConnection"))
                for s in items(d, "SyslogServers")]
    _rule(r, "3.1", "Ensure logs are sent to a remote syslog server", "high", lambda d: bool(syslog(d)),
          lambda d: "syslog servers: " + _names(f"{n} ({a})" for n, a, _s in syslog(d)),
          "System services > Log settings: add a syslog server.", ["SyslogServers"])
    _rule(r, "3.2", "Ensure syslog is sent over an encrypted (TLS) connection", "medium",
          lambda d: bool(syslog(d)) and all(on(s) for _n, _a, s in syslog(d)),
          lambda d: "without TLS: " + _names(n for n, _a, s in syslog(d) if not on(s))
          + ("" if syslog(d) else " (no syslog server)"),
          "Log settings: enable secure connection (TLS) on each syslog server.", ["SyslogServers"], level="L2")

    def notification(d):
        n = one(d, "Notification")
        if n is None:
            return ""
        return " ".join(t.strip() for t in n.itertext() if t.strip() and "@" in t)
    _manual(r, "3.3", "Ensure email notifications for system events reach the administrators", "medium",
            "Administration > Notification settings: configure the mail server and administrator address.",
            lambda d: "notification recipients: " + (notification(d) or "none"), ["Notification"])

    def unlogged(d):
        return [val(x, "Name") for x in rules_list(d) if allows(x) and not on(val(policy(x), "LogTraffic"))]
    _rule(r, "3.4", "Ensure firewall rules that allow traffic log it", "medium", lambda d: not unlogged(d),
          lambda d: f"{len([x for x in rules_list(d) if allows(x)])} allow rules; not logging: {_names(unlogged(d))}",
          "Rules and policies: enable Log firewall traffic on every allow rule.", ["FirewallRule"])

    def ntp(d):
        t = one(d, "Time")
        if t is None:
            return ""
        return " ".join(f"{c.tag}={(c.text or '').strip()}" for c in t.iter() if "ntp" in c.tag.lower())
    _manual(r, "3.5", "Ensure the clock is synchronised with NTP", "medium",
            "Administration > Time: synchronise with NTP servers.",
            lambda d: "time settings: " + (ntp(d) or "not returned"), ["Time"])

    # 4 Network protection ────────────────────────────────────────────────
    def any_any(d):
        out = []
        for x in rules_list(d):
            p = policy(x)
            if allows(x) and not any(listed(p, g, c) for g, c in (
                    ("SourceZones", "Zone"), ("DestinationZones", "Zone"), ("SourceNetworks", "Network"),
                    ("DestinationNetworks", "Network"), ("Services", "Service"))):
                out.append(val(x, "Name"))
        return out
    _rule(r, "4.1", "Ensure no enabled rule allows any source, destination and service", "high",
          lambda d: not any_any(d), lambda d: "any-to-any allow rules: " + _names(any_any(d)),
          "Narrow or remove allow rules without zones, networks and services.", ["FirewallRule"])

    def inbound_without_ips(d):
        out = []
        for x in rules_list(d):
            p = policy(x)
            if allows(x) and "WAN" in [z.upper() for z in listed(p, "SourceZones", "Zone")] \
                    and val(p, "IntrusionPrevention", "None").lower() in ("", "none"):
                out.append(val(x, "Name"))
        return out
    _rule(r, "4.2", "Ensure rules allowing traffic from the WAN apply intrusion prevention", "high",
          lambda d: not inbound_without_ips(d), lambda d: "WAN allow rules without IPS: " + _names(inbound_without_ips(d)),
          "Select an IPS policy (for example WAN to DMZ) on every rule that allows traffic from the WAN.",
          ["FirewallRule"])
    _rule(r, "4.3", "Ensure Advanced Threat Protection is on", "high",
          lambda d: on(val(one(d, "ATP"), "ThreatProtectionStatus")),
          lambda d: f"ThreatProtectionStatus = {val(one(d, 'ATP'), 'ThreatProtectionStatus') or 'not set'}",
          "Active threat response / ATP: turn threat protection on.", ["ATP"])
    _manual(r, "4.4", "Ensure Advanced Threat Protection drops threats, not only logs them", "high",
            "Set the ATP policy to log and drop.",
            lambda d: f"ATP policy = {val(one(d, 'ATP'), 'Policy') or 'not set'}", ["ATP"])

    def snmp(d):
        agent = on(val(one(d, "SNMPAgentConfiguration"), "EnableAgent"))
        communities = [val(c, "Name") for c in items(d, "SNMPCommunity")]
        return agent, communities, [val(u, "Username") for u in items(d, "SNMPv3User")]
    _rule(r, "4.5", "Ensure SNMP uses v3 only (no v1/v2c communities)", "medium",
          lambda d: not snmp(d)[0] or not snmp(d)[1],
          lambda d: f"agent {'on' if snmp(d)[0] else 'off'}; v1/v2c communities: {_names(snmp(d)[1])}; "
                    f"v3 users: {_names(snmp(d)[2])}",
          "Administration > SNMP: delete v1/v2c communities and use SNMPv3 users (or turn the agent off).",
          ["SNMPAgentConfiguration", "SNMPCommunity", "SNMPv3User"])

    # 5 Backup ────────────────────────────────────────────────────────────
    def backup(d):
        b = one(d, "BackupRestore")
        return val(b, "ScheduleBackup/BackupFrequency"), val(b, "ScheduleBackup/BackupMode")
    _rule(r, "5.1", "Ensure configuration backups are scheduled", "medium",
          lambda d: backup(d)[0].lower() not in ("", "never"),
          lambda d: f"frequency = {backup(d)[0] or 'not set'}, destination = {backup(d)[1] or 'not set'}",
          "Backup & firmware > Backup and restore: schedule daily or weekly backups with an encryption password.",
          ["BackupRestore"])
    _rule(r, "5.2", "Ensure backups are stored off the firewall", "medium",
          lambda d: backup(d)[1].lower() in ("ftp", "email", "mail"),
          lambda d: f"backup destination = {backup(d)[1] or 'not set'}",
          "Send scheduled backups to FTP or email rather than keeping them only on the appliance.",
          ["BackupRestore"], level="L2")

    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    v = section(dump, "VERSION")
    if not v.startswith("APIVersion="):
        raise ValueError(f"The Sophos Firewall API did not answer: {v[:200] or 'no answer'}")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    return (f"SFOS {sfos_version(api_version(dump))} (API {api_version(dump)}), {len(items(dump, 'Zone'))} zones, "
            f"{len(rules_list(dump))} firewall rules")
