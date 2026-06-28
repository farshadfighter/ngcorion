"""
FortiGate CIS Benchmark control catalog.

Exactly the 53 recommendations of the CIS FortiGate Benchmark
(``docs/forti_cis_benchmark.docx`` — 8 sections, 28 Automated / 25 Manual).

Each control declares a ``scope`` that tells the SSH engine where to read it:
  - "global"     — ``config global`` (or flat top-level on single-VDOM devices)
  - "vdom"       — inside each ``config vdom`` / ``edit <name>`` (evaluated per VDOM)
  - "vdom_root"  — the management VDOM ("root") only (device-wide per-VDOM settings)

Evaluation respects FortiOS "show omits values at their default":
  - a secure setting that is default-ON  -> check the *absence* of "set X disable"
  - a secure setting that is default-OFF -> check the *presence* of "set X enable"
  - numeric defaults -> compare against ``FortiGateRule.default`` when the line is omitted

"Manual" recommendations cannot be reliably verified from config alone; they are
evidence-only (``is_manual``) and excluded from the compliance score by the service.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ssh_client import SCOPE_GLOBAL, SCOPE_VDOM, SCOPE_VDOM_ROOT


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FortiGateRule:
    """A single evaluation rule against the output of ``cmd``."""
    type: str  # set_bool, set_int_le, set_int_ge, set_eq, regex_present, regex_absent
    cmd: str
    key: Optional[str] = None
    expected: Any = None
    pattern: Optional[str] = None
    default: Optional[int] = None  # assumed value when a numeric line is omitted


@dataclass
class FortiGateControl:
    """A CIS FortiGate Benchmark recommendation."""
    id: str
    title: str
    cis_id: str             # benchmark section, e.g. "2.1.7"
    cis_section: str        # benchmark area name, e.g. "System Settings"
    cis_type: str           # "Automated" | "Manual"
    scope: str              # "global" | "vdom" | "vdom_root"
    severity: str
    level: str
    rules: List[FortiGateRule]
    remediation: str
    tags: List[str] = field(default_factory=list)

    @property
    def is_manual(self) -> bool:
        """Manual controls are evidence-only and excluded from the compliance score."""
        return self.cis_type == "Manual"


# Benchmark area names keyed by top-level section number.
_CIS_SECTION_NAMES: Dict[str, str] = {
    "1": "Network Settings",
    "2": "System Settings",
    "3": "Policy and Objects",
    "4": "Security Profiles",
    "5": "Security Fabric",
    "6": "VPN",
    "7": "Users and Authentication",
    "8": "Logs and Reports",
}


# ---------------------------------------------------------------------------
# Control builders (one rule each, except where noted)
# ---------------------------------------------------------------------------
def _section_name(cis_id: str) -> str:
    return _CIS_SECTION_NAMES.get(cis_id.split(".")[0], "")


def _ctl(id, title, cis_id, cis_type, scope, severity, level, rules, remediation) -> FortiGateControl:
    return FortiGateControl(
        id=id, title=title, cis_id=cis_id, cis_section=_section_name(cis_id),
        cis_type=cis_type, scope=scope, severity=severity, level=level,
        rules=rules, remediation=remediation,
    )


def _present(id, title, cis_id, scope, severity, cmd, pattern, remediation, level="L1"):
    """Automated control that passes when ``pattern`` is present (default-OFF setting)."""
    return _ctl(id, title, cis_id, "Automated", scope, severity, level,
                [FortiGateRule(type="regex_present", cmd=cmd, pattern=pattern)], remediation)


def _absent(id, title, cis_id, scope, severity, cmd, pattern, remediation, level="L1"):
    """Automated control that passes when ``pattern`` is absent (default-ON setting)."""
    return _ctl(id, title, cis_id, "Automated", scope, severity, level,
                [FortiGateRule(type="regex_absent", cmd=cmd, pattern=pattern)], remediation)


def _int_le(id, title, cis_id, scope, severity, cmd, key, expected, remediation, default=None, level="L1"):
    return _ctl(id, title, cis_id, "Automated", scope, severity, level,
                [FortiGateRule(type="set_int_le", cmd=cmd, key=key, expected=expected, default=default)],
                remediation)


def _manual(id, title, cis_id, scope, severity, cmd, pattern, remediation, level="L1"):
    """Manual (non-scoring) control. Runs ``cmd`` and captures evidence only."""
    return _ctl(id, title, cis_id, "Manual", scope, severity, level,
                [FortiGateRule(type="regex_present", cmd=cmd, pattern=pattern)], remediation)


# Command shortcuts (the show/get each control reads, in its own scope).
SG = "show system global"
DNS = "show system dns"
NTP = "show system ntp"
AUTOINST = "show system auto-install"
PWPOL = "show system password-policy"
SNMPC = "show system snmp community"
SNMPU = "show system snmp user"
ADMIN = "show system admin"
HA = "show system ha"
ZONE = "show system zone"
IFACE = "show system interface"
LOCALIN = "show firewall local-in-policy"
POL = "show firewall policy"
PUSHUPD = "show system autoupdate push-update"
AVPROF = "show antivirus profile"
AVSET = "show antivirus settings"
DNSF = "show dnsfilter profile"
APPL = "show application list"
STITCH = "show system automation-stitch"
CSF = "show system csf"
SSLVPN = "show vpn ssl settings"
USRSET = "show user setting"
EVENTF = "show log eventfilter"
FAZ = "show log fortianalyzer setting"
STATUS = "get system status"


def get_fortinet_controls() -> List[FortiGateControl]:
    """Return all 53 CIS FortiGate Benchmark controls."""
    controls: List[FortiGateControl] = [
        # ===== 1 Network Settings =====
        _present("FG-BL-043", "DNS server is configured", "1.1", SCOPE_GLOBAL, "Medium",
                 DNS, r"set\s+primary\s+\d+\.\d+\.\d+\.\d+",
                 "config system dns\n set primary <dns-ip>\n set secondary <dns-ip>\nend"),
        _manual("FG-NET-001", "Intra-zone traffic is not always allowed", "1.2", SCOPE_VDOM, "Medium",
                ZONE, r"set\s+intrazone\s+\w+",
                "config system zone\n edit <zone>\n set intrazone deny\nend"),
        _manual("FG-NET-002", "Management services disabled on WAN interface", "1.3", SCOPE_GLOBAL, "High",
                IFACE, r"set\s+allowaccess\s+.+",
                "Remove http/https/ssh/telnet/snmp from WAN interface allowaccess; use a dedicated "
                "management interface and local-in policies."),

        # ===== 2.1 General Settings =====
        _present("FG-BL-092", "Pre-Login Banner is set", "2.1.1", SCOPE_GLOBAL, "Low",
                 SG, r"set\s+pre-login-banner\s+enable",
                 "config system global\n set pre-login-banner enable\nend"),
        _present("FG-SYS-001", "Post-Login Banner is set", "2.1.2", SCOPE_GLOBAL, "Low",
                 SG, r"set\s+post-login-banner\s+enable",
                 "config system global\n set post-login-banner enable\nend"),
        _manual("FG-SYS-002", "Timezone is properly configured", "2.1.3", SCOPE_GLOBAL, "Low",
                SG, r"set\s+timezone\s+\S+",
                "config system global\n set timezone <id>\nend"),
        _absent("FG-BL-040", "System time configured through NTP", "2.1.4", SCOPE_GLOBAL, "Medium",
                NTP, r"set\s+ntpsync\s+disable",
                "config system ntp\n set ntpsync enable\n set type custom\n config ntpserver\n "
                "edit 1\n set server <ntp-ip>\n next\n end\nend"),
        _present("FG-SYS-003", "Hostname is set", "2.1.5", SCOPE_GLOBAL, "Low",
                 SG, r"set\s+hostname\s+\S+",
                 "config system global\n set hostname <name>\nend"),
        _manual("FG-SYS-004", "Latest firmware is installed", "2.1.6", SCOPE_GLOBAL, "Medium",
                STATUS, r"Version:\s*.+",
                "Review FortiGuard for the latest recommended release and upgrade."),
        _absent("FG-SYS-005", "USB firmware/configuration installation disabled", "2.1.7", SCOPE_GLOBAL, "High",
                AUTOINST, r"set\s+auto-install-(config|image)\s+enable",
                "config system auto-install\n set auto-install-config disable\n "
                "set auto-install-image disable\nend"),
        _absent("FG-SYS-006", "Static keys for TLS disabled", "2.1.8", SCOPE_GLOBAL, "High",
                SG, r"set\s+ssl-static-key-ciphers\s+enable",
                "config system global\n set ssl-static-key-ciphers disable\nend"),
        _present("FG-BL-090", "Global Strong Encryption enabled", "2.1.9", SCOPE_GLOBAL, "High",
                 SG, r"set\s+strong-crypto\s+enable",
                 "config system global\n set strong-crypto enable\nend"),
        _manual("FG-BL-005", "Management GUI listens on secure TLS version", "2.1.10", SCOPE_GLOBAL, "High",
                SG, r"set\s+admin-https-ssl-versions\s+.+",
                "config system global\n set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend"),

        # ===== 2.2 Password Policy =====
        _present("FG-BL-030", "Password Policy is enabled", "2.2.1", SCOPE_VDOM_ROOT, "High",
                 PWPOL, r"set\s+status\s+enable",
                 "config system password-policy\n set status enable\n set minimum-length 8\nend"),
        _absent("FG-PW-001", "Admin password retries and lockout configured", "2.2.2", SCOPE_GLOBAL, "Medium",
                SG, r"set\s+admin-lockout-threshold\s+0\b",
                "config system global\n set admin-lockout-threshold 3\n set admin-lockout-duration 60\nend"),

        # ===== 2.3 SNMP =====
        _absent("FG-BL-050", "Only SNMPv3 is enabled", "2.3.1", SCOPE_GLOBAL, "High",
                SNMPC, r"^\s*edit\s+\S+",
                "Delete SNMP v1/v2c communities (config system snmp community) and use SNMPv3 "
                "users with auth-priv only."),
        _manual("FG-SNMP-001", "Only trusted hosts allowed in SNMPv3", "2.3.2", SCOPE_GLOBAL, "Medium",
                SNMPU, r"set\s+(notify-hosts|hosts)\s+\S+",
                "config system snmp user\n edit <name>\n set notify-hosts <trusted-ip>\nend"),

        # ===== 2.4 Administrators and Admin Profiles =====
        _manual("FG-BL-021", "Default 'admin' password is changed", "2.4.1", SCOPE_GLOBAL, "High",
                ADMIN, r'edit\s+"?admin"?',
                "Set a strong password for the built-in admin account (or disable it and use named "
                "accounts)."),
        _manual("FG-BL-020", "Login accounts have specific trusted hosts", "2.4.2", SCOPE_GLOBAL, "High",
                ADMIN, r"set\s+trusthost\d?\s+\S+",
                "config system admin\n edit <admin>\n set trusthost1 <mgmt-subnet> <mask>\nend"),
        _manual("FG-ADM-001", "Admin accounts have correct profiles assigned", "2.4.3", SCOPE_GLOBAL, "Medium",
                ADMIN, r"set\s+accprofile\s+\S+",
                "config system admin\n edit <admin>\n set accprofile <least-privilege-profile>\nend"),
        _int_le("FG-BL-004", "Idle timeout is configured", "2.4.4", SCOPE_GLOBAL, "Medium",
                SG, "admintimeout", 10,
                "config system global\n set admintimeout 10\nend", default=5),
        _ctl("FG-BL-002", "Only encrypted access channels are enabled", "2.4.5", "Automated",
             SCOPE_GLOBAL, "Critical", "L1",
             [FortiGateRule(type="regex_absent", cmd=SG, pattern=r"set\s+admin-telnet\s+enable"),
              FortiGateRule(type="regex_absent", cmd=SG, pattern=r"set\s+admin-http\s+enable")],
             "config system global\n set admin-telnet disable\n set admin-http disable\nend"),
        _manual("FG-LIP-001", "Local-in policies applied", "2.4.6", SCOPE_VDOM, "Medium",
                LOCALIN, r"^\s*edit\s+\d+",
                "config firewall local-in-policy\n edit <id>\n ... restrict management access\nend"),
        _manual("FG-BL-007", "Default admin ports are changed", "2.4.7", SCOPE_GLOBAL, "Medium",
                SG, r"set\s+admin-(sport|ssh-port|port)\s+\d+",
                "config system global\n set admin-sport 10443\n set admin-ssh-port 2222\nend"),

        # ===== 2.5 High Availability =====
        _present("FG-HA-004", "High Availability configuration is enabled", "2.5.1", SCOPE_GLOBAL, "Medium",
                 HA, r"set\s+mode\s+(a-p|a-a|active-passive|active-active)",
                 "config system ha\n set mode a-p\n set group-name <name>\n set hbdev <port> 50\nend"),
        _present("FG-HA-005", "Monitor Interfaces for HA is enabled", "2.5.2", SCOPE_GLOBAL, "Medium",
                 HA, r"set\s+monitor\s+\S+",
                 "config system ha\n set monitor <port1> <port2>\nend"),
        _manual("FG-HA-006", "HA Reserved Management Interface configured", "2.5.3", SCOPE_GLOBAL, "Low",
                HA, r"set\s+ha-mgmt-(status|interface)\b",
                "config system ha\n set ha-mgmt-status enable\n config ha-mgmt-interfaces\n ...\nend"),

        # ===== 3 Policy and Objects =====
        _manual("FG-POL-001", "Unused policies are reviewed regularly", "3.1", SCOPE_VDOM, "Low",
                POL, r"edit\s+\d+",
                "Review policy hit counts and remove/disable unused firewall policies."),
        _absent("FG-BL-080", "Policies do not use 'ALL' as Service", "3.2", SCOPE_VDOM, "High",
                POL, r'set\s+service\s+"?ALL"?',
                "Replace 'ALL' service in firewall policies with specific service objects."),
        _manual("FG-POL-002", "Deny traffic to/from Tor, malicious or scanner IPs (ISDB)", "3.3", SCOPE_VDOM, "Medium",
                POL, r"set\s+internet-service\S*\s+\S+",
                "Create deny policies using Internet Service DB objects (Tor/Botnet/Scanner)."),
        _manual("FG-BL-082", "Logging enabled on all firewall policies", "3.4", SCOPE_VDOM, "Medium",
                POL, r"set\s+logtraffic\s+\w+",
                "On each policy: set logtraffic all (or utm)."),

        # ===== 4.1 Intrusion Prevention System =====
        _manual("FG-IPS-001", "Detect Botnet connections", "4.1.1", SCOPE_VDOM, "Medium",
                POL, r"set\s+scan-botnet-connections\s+\w+",
                "On each policy: set scan-botnet-connections block."),
        _manual("FG-UTM-003", "Apply IPS Security Profile to policies", "4.1.2", SCOPE_VDOM, "Medium",
                POL, r"set\s+ips-sensor\s+\S+",
                "Apply an IPS sensor to relevant firewall policies: set ips-sensor <sensor>."),

        # ===== 4.2 Antivirus =====
        _present("FG-AV-001", "Antivirus Definition Push Updates configured", "4.2.1", SCOPE_GLOBAL, "Medium",
                 PUSHUPD, r"set\s+status\s+enable",
                 "config system autoupdate push-update\n set status enable\nend"),
        _manual("FG-UTM-002", "Apply Antivirus Security Profile to policies", "4.2.2", SCOPE_VDOM, "Medium",
                POL, r"set\s+av-profile\s+\S+",
                "Apply an AV profile to relevant firewall policies: set av-profile <profile>."),
        _present("FG-AV-002", "Outbreak Prevention Database enabled", "4.2.3", SCOPE_VDOM, "Medium",
                 AVPROF, r"outbreak-prevention\s+(block|monitor|enable)",
                 "config antivirus profile\n edit <profile>\n config http\n set outbreak-prevention block\nend"),
        _absent("FG-AV-003", "AI/heuristic based malware detection enabled", "4.2.4", SCOPE_VDOM, "Medium",
                AVSET, r"set\s+machine-learning-detection\s+disable",
                "config antivirus settings\n set machine-learning-detection enable\nend"),
        _absent("FG-AV-004", "Grayware detection enabled", "4.2.5", SCOPE_VDOM, "Low",
                AVSET, r"set\s+grayware\s+disable",
                "config antivirus settings\n set grayware enable\nend"),

        # ===== 4.3 DNS Filter =====
        _present("FG-DNS-001", "Botnet C&C Domain Blocking enabled in DNS Filter", "4.3.1", SCOPE_VDOM, "High",
                 DNSF, r"set\s+block-botnet\s+enable",
                 "config dnsfilter profile\n edit <profile>\n set block-botnet enable\nend"),
        _manual("FG-DNS-002", "DNS Filter logs all DNS queries and responses", "4.3.2", SCOPE_VDOM, "Low",
                DNSF, r"set\s+log-all-domain\s+\w+",
                "config dnsfilter profile\n edit <profile>\n set log-all-domain enable\nend"),
        _manual("FG-DNS-003", "Apply DNS Filter Security Profile to policies", "4.3.3", SCOPE_VDOM, "Medium",
                POL, r"set\s+dnsfilter-profile\s+\S+",
                "Apply a DNS filter profile to relevant firewall policies."),

        # ===== 4.4 Application Control =====
        _manual("FG-APP-001", "Block high risk categories on Application Control", "4.4.1", SCOPE_VDOM, "Medium",
                APPL, r"set\s+(category|risk|application)\s+\S+",
                "config application list\n edit <list>\n config entries\n ... set action block (high risk)\nend"),
        _present("FG-APP-002", "Block applications running on non-default ports", "4.4.2", SCOPE_VDOM, "Medium",
                 APPL, r"set\s+enforce-default-app-port\s+enable",
                 "config application list\n edit <list>\n set enforce-default-app-port enable\nend"),
        _manual("FG-APP-003", "Application Control related traffic is logged", "4.4.3", SCOPE_VDOM, "Low",
                APPL, r"set\s+(other-application-log|unknown-application-log|log)\s+\w+",
                "config application list\n edit <list>\n set other-application-log enable\nend"),
        _manual("FG-APP-004", "Apply Application Control Security Profile to policies", "4.4.4", SCOPE_VDOM, "Medium",
                POL, r"set\s+application-list\s+\S+",
                "Apply an application-list profile to relevant firewall policies."),

        # ===== 5 Security Fabric =====
        _present("FG-FAB-001", "Compromised Host Quarantine enabled", "5.1.1", SCOPE_GLOBAL, "Medium",
                 STITCH, r"quarantine",
                 "Create an automation stitch with a quarantine action (e.g. Quarantine FortiClient via EMS)."),
        _present("FG-FAB-002", "Security Fabric is Configured", "5.2.1.1", SCOPE_GLOBAL, "Medium",
                 CSF, r"set\s+status\s+enable",
                 "config system csf\n set status enable\n set group-name <name>\nend"),

        # ===== 6 VPN =====
        _manual("FG-VPN-SSL-003", "Trusted signed certificate applied for SSL-VPN portal", "6.1.1", SCOPE_VDOM, "High",
                SSLVPN, r"set\s+servercert\s+\S+",
                "config vpn ssl settings\n set servercert <trusted-cert>\nend"),
        _manual("FG-VPN-SSL-001", "Limited TLS versions enabled for SSL VPN", "6.1.2", SCOPE_VDOM, "High",
                SSLVPN, r"set\s+ssl-min-proto-version\s+\S+",
                "config vpn ssl settings\n set ssl-min-proto-version tlsv1-2\nend"),

        # ===== 7 Users and Authentication =====
        _absent("FG-USER-001", "Maximum login attempts and lockout period configured", "7.1", SCOPE_VDOM, "Medium",
                USRSET, r"set\s+auth-lockout-threshold\s+0\b",
                "config user setting\n set auth-lockout-threshold 3\n set auth-lockout-duration 60\nend"),

        # ===== 8 Logs and Reports =====
        _absent("FG-LOG-001", "Event Logging enabled", "8.1.1", SCOPE_VDOM, "Medium",
                EVENTF, r"set\s+event\s+disable",
                "config log eventfilter\n set event enable\nend"),
        _present("FG-LOG-002", "Log transmission to FortiAnalyzer/FortiManager encrypted", "8.2.1", SCOPE_GLOBAL, "Medium",
                 FAZ, r"set\s+(reliable\s+enable|enc-algorithm\s+(high|default))",
                 "config log fortianalyzer setting\n set reliable enable\n set enc-algorithm high\nend"),
        _present("FG-FAZ-001", "Centralized Logging and Reporting configured", "8.3.1", SCOPE_GLOBAL, "Medium",
                 FAZ, r"set\s+status\s+enable",
                 "config log fortianalyzer setting\n set status enable\n set server <faz-ip>\nend"),
    ]
    return controls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_controls_by_level(level: str) -> List[FortiGateControl]:
    """Filter controls by CIS level (L1 or L2)."""
    return [c for c in get_fortinet_controls() if c.level == level]


def get_unique_commands(controls: List[FortiGateControl]) -> List[tuple]:
    """
    Return the unique (command, scope) pairs needed to evaluate ``controls``.
    Scope matters: the same command in different scopes is read separately.
    """
    seen = set()
    pairs: List[tuple] = []
    for control in controls:
        for rule in control.rules:
            key = (rule.cmd, control.scope)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs
