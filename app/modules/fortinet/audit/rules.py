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


# Rule types that only test for the presence/absence of a config line — a coarse
# heuristic, not a definitive parse of the actual setting. Used to decide which
# verdicts are ambiguous (see FortiGateControl.needs_review).
_HEURISTIC_RULE_TYPES = frozenset({"regex_present", "regex_absent"})


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
    # Force the "manual review" flag even when a dedicated parser is used — for
    # best-effort checks whose CLI output can't fully prove the control (e.g.
    # "profile applied to the right policies", "latest firmware", admin password).
    review_required: bool = False
    tags: List[str] = field(default_factory=list)

    @property
    def is_manual(self) -> bool:
        """Whether this is a CIS 'Manual' recommendation — one the benchmark says
        cannot be fully verified from configuration alone. (All controls are still
        scored; this only classifies the recommendation.)"""
        return self.cis_type == "Manual"

    @property
    def needs_review(self) -> bool:
        """True when the PASS/FAIL is *not definitive* and must be confirmed by a
        human: either explicitly marked ``review_required`` (best-effort parse), or
        a Manual recommendation evaluated only by presence/absence heuristics.
        Controls backed by a dedicated parser are definitive and not flagged."""
        if self.review_required:
            return True
        return self.is_manual and all(r.type in _HEURISTIC_RULE_TYPES for r in self.rules)


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


def _ctl(id, title, cis_id, cis_type, scope, severity, level, rules, remediation,
         review_required=False) -> FortiGateControl:
    return FortiGateControl(
        id=id, title=title, cis_id=cis_id, cis_section=_section_name(cis_id),
        cis_type=cis_type, scope=scope, severity=severity, level=level,
        rules=rules, remediation=remediation, review_required=review_required,
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
GG = "get system global"   # human-readable field view (e.g. "timezone : (GMT+3:30) Tehran")
DNS = "show system dns"
NTP = "show system ntp"
NTPSTAT = "diagnose sys ntp status"   # runtime sync state + active NTP servers
AUTOINST = "show system auto-install"
PWPOL = "show system password-policy"
SNMPC = "show system snmp community"
SNMPU = "show system snmp user"
SNMPINFO = "get system snmp sysinfo"   # SNMP master status (enable/disable)
SNMPUSERG = "get system snmp user"     # configured SNMPv3 users
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

# `get`-form commands — return the resolved value of every field (including
# defaults), so detection parses live values instead of presence/absence of a
# `show` line. Verified against FortiOS 7.0.x.
GDNS = "get system dns"
GPWPOL = "get system password-policy"
GAUTOINST = "get system auto-install"
GHA = "get system ha"
GCSF = "get system csf"
GSSLVPN = "get vpn ssl settings"
GUSRSET = "get user setting"
GEVENTF = "get log eventfilter"
GFAZ = "get log fortianalyzer setting"
GAVSET = "get antivirus settings"
GPUSHUPD = "get system autoupdate push-update"


def get_fortinet_controls() -> List[FortiGateControl]:
    """Return all 53 CIS FortiGate Benchmark controls."""
    controls: List[FortiGateControl] = [
        # ===== 1 Network Settings =====
        # `get system dns` → primary must be a real (non-zero) IPv4 address.
        _ctl("FG-BL-043", "DNS server is configured", "1.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_matches", cmd=GDNS, key="primary",
                            pattern=r"^(?!0\.0\.0\.0)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")],
             "config system dns\n set primary <dns-ip>\n set secondary <dns-ip>\nend"),
        # `show system zone` → every zone must have `set intrazone deny`.
        _ctl("FG-NET-001", "Intra-zone traffic is not always allowed", "1.2", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_all_match", cmd=ZONE, key="intrazone deny",
                            pattern=r"set\s+intrazone\s+deny")],
             "config system zone\n edit <zone>\n set intrazone deny\nend"),
        # Parsed per-interface: NON-COMPLIANT if any role=wan interface exposes a
        # management service in allowaccess (see service._wan_mgmt_violations).
        _ctl("FG-NET-002", "Management services disabled on WAN interface", "1.3", "Manual",
             SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="wan_mgmt_exposed", cmd=IFACE,
                            expected=["ping", "http", "https", "ssh", "telnet", "snmp", "radius-acct"])],
             "On every WAN-role interface remove management services from allowaccess "
             "(config system interface / edit <wan-iface> / set allowaccess to a minimal set, "
             "e.g. unset it); use a dedicated management interface and local-in policies."),

        # ===== 2.1 General Settings =====
        # `get system global` → pre/post-login-banner fields must read enable.
        _ctl("FG-BL-092", "Pre-Login Banner is set", "2.1.1", "Automated", SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GG, key="pre-login-banner", expected="enable")],
             "config system global\n set pre-login-banner enable\nend"),
        _ctl("FG-SYS-001", "Post-Login Banner is set", "2.1.2", "Automated", SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GG, key="post-login-banner", expected="enable")],
             "config system global\n set post-login-banner enable\nend"),
        # Parsed from `get system global`: NON-COMPLIANT unless the timezone
        # field equals the expected value (see service._get_field_value).
        _ctl("FG-SYS-002", "Timezone is properly configured", "2.1.3", "Manual",
             SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GG, key="timezone",
                            expected="(GMT+3:30) Tehran")],
             "config system global\n set timezone 41\nend"),
        # Parsed from `diagnose sys ntp status`: COMPLIANT only when synchronized,
        # ntpsync + server-mode (custom) enabled, and no *.fortiguard.com server
        # (see service._parse_ntp_status / _ntp_status_failures).
        _ctl("FG-BL-040", "System time configured through NTP", "2.1.4", "Automated",
             SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="ntp_status_ok", cmd=NTPSTAT)],
             "config system ntp\n set type custom\n config ntpserver\n edit 1\n "
             "set server pool.ntp.org\n next\n edit 2\n set server 1.1.1.1\n end\nend"),
        # Parsed from `get system global`: NON-COMPLIANT when hostname still
        # matches the default FGT<model><serial> pattern (see service evidence).
        _ctl("FG-SYS-003", "Hostname is set", "2.1.5", "Automated",
             SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_not_match", cmd=GG, key="hostname",
                            pattern=r"^FGT[A-Z0-9]+$")],
             'config system global\n set hostname "NEW-HOSTNAME"\nend'),
        # `get system status` → report running firmware; "latest" can't be known
        # from the device, so best-effort + keep the manual-review flag.
        _ctl("FG-SYS-004", "Latest firmware is installed", "2.1.6", "Manual", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_matches", cmd=STATUS, key="Version", pattern=r"v?\d+\.\d+")],
             "Review FortiGuard for the latest recommended release and upgrade.",
             review_required=True),
        # `get system auto-install` → both auto-install fields must be disable.
        _ctl("FG-SYS-005", "USB firmware/configuration installation disabled", "2.1.7", "Automated",
             SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GAUTOINST, key="auto-install-config", expected="disable"),
              FortiGateRule(type="get_field_eq", cmd=GAUTOINST, key="auto-install-image", expected="disable")],
             "config system auto-install\n set auto-install-config disable\n "
             "set auto-install-image disable\nend"),
        _ctl("FG-SYS-006", "Static keys for TLS disabled", "2.1.8", "Automated", SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GG, key="ssl-static-key-ciphers", expected="disable")],
             "config system global\n set ssl-static-key-ciphers disable\nend"),
        _ctl("FG-BL-090", "Global Strong Encryption enabled", "2.1.9", "Automated", SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GG, key="strong-crypto", expected="enable")],
             "config system global\n set strong-crypto enable\nend"),
        # Parsed from `get system global`: NON-COMPLIANT if admin-https-ssl-versions
        # contains tlsv1-0/tlsv1-1, or is absent (default includes weak versions).
        _ctl("FG-BL-005", "Management GUI listens on secure TLS version", "2.1.10", "Manual",
             SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="get_field_excludes", cmd=GG, key="admin-https-ssl-versions",
                            expected=["tlsv1-0", "tlsv1-1"])],
             "config system global\n set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend"),

        # ===== 2.2 Password Policy =====
        # `get system password-policy` → status must read enable.
        _ctl("FG-BL-030", "Password Policy is enabled", "2.2.1", "Automated", SCOPE_VDOM_ROOT, "High", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GPWPOL, key="status", expected="enable")],
             "config system password-policy\n set status enable\n set minimum-length 8\nend"),
        # `get system global` → admin-lockout-threshold must be >= 1 (not disabled).
        _ctl("FG-PW-001", "Admin password retries and lockout configured", "2.2.2", "Automated",
             SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_int_ge", cmd=GG, key="admin-lockout-threshold",
                            expected=1, default=3)],
             "config system global\n set admin-lockout-threshold 3\n set admin-lockout-duration 60\nend"),

        # ===== 2.3 SNMP =====
        # Two-step parse: (1) `get system snmp sysinfo` status must be enable,
        # then (2) `get system snmp user` must list at least one SNMPv3 user
        # (see service._snmp_evidence). Both rules must pass to be COMPLIANT.
        _ctl("FG-BL-050", "Only SNMPv3 is enabled", "2.3.1", "Automated",
             SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="snmp_status_enabled", cmd=SNMPINFO),
              FortiGateRule(type="snmp_user_exists", cmd=SNMPUSERG)],
             "config system snmp sysinfo\n set status enable\nend\n"
             "config system snmp user\n edit <name>\n set security-level auth-priv\n "
             "set auth-proto sha256\n set priv-proto aes256\n next\nend\n"
             "(and delete any SNMP v1/v2c communities under config system snmp community)"),
        # `show system snmp user` → best-effort: report users that restrict
        # notify-hosts; "trusted" is site-specific, so keep the review flag.
        _ctl("FG-SNMP-001", "Only trusted hosts allowed in SNMPv3", "2.3.2", "Manual", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=SNMPU, key="notify-hosts",
                            pattern=r"set\s+notify-hosts\s+\S")],
             "config system snmp user\n edit <name>\n set notify-hosts <trusted-ip>\nend",
             review_required=True),

        # ===== 2.4 Administrators and Admin Profiles =====
        # `show system admin` → passwords are never shown over CLI, so this is
        # best-effort (enumerate admin accounts) and stays review-flagged.
        _ctl("FG-BL-021", "Default 'admin' password is changed", "2.4.1", "Manual", SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="table_any_match", cmd=ADMIN, key="admin accounts (verify password)",
                            pattern=r"\S")],
             "Set a strong password for the built-in admin account (or disable it and use named accounts).",
             review_required=True),
        # `show system admin` → every admin must have a trusthost, and none may
        # use 0.0.0.0/0 (any). Both conditions parsed across all entries.
        _ctl("FG-BL-020", "Login accounts have specific trusted hosts", "2.4.2", "Manual", SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="table_all_match", cmd=ADMIN, key="trusthost set",
                            pattern=r"set\s+trusthost\d*\s+\S"),
              FortiGateRule(type="table_none_match", cmd=ADMIN, key="trusthost = any (0.0.0.0)",
                            pattern=r"set\s+trusthost\d*\s+0\.0\.0\.0\s+0\.0\.0\.0")],
             "config system admin\n edit <admin>\n set trusthost1 <mgmt-subnet> <mask>\nend"),
        # `show system admin` → best-effort: report each admin's accprofile;
        # "correct/least-privilege" is site-specific, so keep the review flag.
        _ctl("FG-ADM-001", "Admin accounts have correct profiles assigned", "2.4.3", "Manual", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=ADMIN, key="accprofile",
                            pattern=r"set\s+accprofile\s+\S")],
             "config system admin\n edit <admin>\n set accprofile <least-privilege-profile>\nend",
             review_required=True),
        # `get system global` → admintimeout must be <= 10 minutes (default 5).
        _ctl("FG-BL-004", "Idle timeout is configured", "2.4.4", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_int_le", cmd=GG, key="admintimeout", expected=10, default=5)],
             "config system global\n set admintimeout 10\nend"),
        # `show system interface` → no interface may expose telnet/http (cleartext).
        _ctl("FG-BL-002", "Only encrypted access channels are enabled", "2.4.5", "Automated",
             SCOPE_GLOBAL, "Critical", "L1",
             [FortiGateRule(type="iface_allowaccess_excludes", cmd=IFACE, key=None,
                            expected=["telnet", "http"])],
             "On each interface: config system interface / edit <if> / set allowaccess "
             "to HTTPS/SSH only (remove telnet and http)."),
        # `show firewall local-in-policy` → best-effort: report whether any
        # local-in policy restricts management access (keep review flag).
        _ctl("FG-LIP-001", "Local-in policies applied", "2.4.6", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=LOCALIN, key="local-in policy", pattern=r"set\s+\S")],
             "config firewall local-in-policy\n edit <id>\n ... restrict management access\nend",
             review_required=True),
        # `get system global` → admin HTTPS/SSH ports must be changed from defaults.
        _ctl("FG-BL-007", "Default admin ports are changed", "2.4.7", "Manual", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GG, key="admin-sport", expected="443"),
              FortiGateRule(type="get_field_ne", cmd=GG, key="admin-ssh-port", expected="22")],
             "config system global\n set admin-sport 10443\n set admin-ssh-port 2222\nend"),

        # ===== 2.5 High Availability =====
        # `get system ha` → mode != standalone, monitor set, ha-mgmt-status enable.
        _ctl("FG-HA-004", "High Availability configuration is enabled", "2.5.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GHA, key="mode", expected="standalone")],
             "config system ha\n set mode a-p\n set group-name <name>\n set hbdev <port> 50\nend"),
        _ctl("FG-HA-005", "Monitor Interfaces for HA is enabled", "2.5.2", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_matches", cmd=GHA, key="monitor", pattern=r"\S")],
             "config system ha\n set monitor <port1> <port2>\nend"),
        _ctl("FG-HA-006", "HA Reserved Management Interface configured", "2.5.3", "Manual", SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GHA, key="ha-mgmt-status", expected="enable")],
             "config system ha\n set ha-mgmt-status enable\n config ha-mgmt-interfaces\n ...\nend"),

        # ===== 3 Policy and Objects =====
        # `show firewall policy` → best-effort: report policy count; "reviewed
        # regularly" is a process, not a config state (keep review flag).
        _ctl("FG-POL-001", "Unused policies are reviewed regularly", "3.1", "Manual", SCOPE_VDOM, "Low", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="firewall policy", pattern=r"set\s+\S")],
             "Review policy hit counts and remove/disable unused firewall policies.",
             review_required=True),
        # `show firewall policy` → no policy may use service "ALL" (parsed per entry).
        _ctl("FG-BL-080", "Policies do not use 'ALL' as Service", "3.2", "Automated", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="table_none_match", cmd=POL, key="service ALL",
                            pattern=r'set\s+service\s+"?ALL"?')],
             "Replace 'ALL' service in firewall policies with specific service objects."),
        # `show firewall policy` → best-effort: report policies that use ISDB
        # deny objects; which destinations should be denied is site-specific.
        _ctl("FG-POL-002", "Deny traffic to/from Tor, malicious or scanner IPs (ISDB)", "3.3", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="internet-service (ISDB)",
                            pattern=r"set\s+internet-service\S*\s+\S")],
             "Create deny policies using Internet Service DB objects (Tor/Botnet/Scanner).",
             review_required=True),
        # `show firewall policy` → no policy may have logtraffic explicitly disabled.
        _ctl("FG-BL-082", "Logging enabled on all firewall policies", "3.4", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_none_match", cmd=POL, key="logtraffic disable",
                            pattern=r"set\s+logtraffic\s+disable")],
             "On each policy: set logtraffic all (or utm)."),

        # ===== 4.1 Intrusion Prevention System =====
        # `show firewall policy` → best-effort: report policies that block botnet /
        # apply an IPS sensor; which policies should is site-specific (review flag).
        _ctl("FG-IPS-001", "Detect Botnet connections", "4.1.1", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="scan-botnet-connections",
                            pattern=r"set\s+scan-botnet-connections\s+(block|monitor)")],
             "On each policy: set scan-botnet-connections block.",
             review_required=True),
        _ctl("FG-UTM-003", "Apply IPS Security Profile to policies", "4.1.2", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="ips-sensor",
                            pattern=r"set\s+ips-sensor\s+\S")],
             "Apply an IPS sensor to relevant firewall policies: set ips-sensor <sensor>.",
             review_required=True),

        # ===== 4.2 Antivirus =====
        # `get system autoupdate push-update` → status must read enable.
        _ctl("FG-AV-001", "Antivirus Definition Push Updates configured", "4.2.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GPUSHUPD, key="status", expected="enable")],
             "config system autoupdate push-update\n set status enable\nend"),
        # `show firewall policy` → best-effort: report policies applying an AV profile.
        _ctl("FG-UTM-002", "Apply Antivirus Security Profile to policies", "4.2.2", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="av-profile",
                            pattern=r"set\s+av-profile\s+\S")],
             "Apply an AV profile to relevant firewall policies: set av-profile <profile>.",
             review_required=True),
        # `show antivirus profile` → best-effort: report profiles with outbreak
        # prevention; only matters once the profile is applied (keep review flag).
        _ctl("FG-AV-002", "Outbreak Prevention Database enabled", "4.2.3", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=AVPROF, key="outbreak-prevention",
                            pattern=r"outbreak-prevention\s+(block|monitor|enable)")],
             "config antivirus profile\n edit <profile>\n config http\n set outbreak-prevention block\nend",
             review_required=True),
        # `get antivirus settings` → ML detection enabled, grayware enabled.
        _ctl("FG-AV-003", "AI/heuristic based malware detection enabled", "4.2.4", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GAVSET, key="machine-learning-detection", expected="disable")],
             "config antivirus settings\n set machine-learning-detection enable\nend"),
        _ctl("FG-AV-004", "Grayware detection enabled", "4.2.5", "Automated", SCOPE_VDOM, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GAVSET, key="grayware", expected="enable")],
             "config antivirus settings\n set grayware enable\nend"),

        # ===== 4.3 DNS Filter =====  (profiles only matter once applied → review)
        _ctl("FG-DNS-001", "Botnet C&C Domain Blocking enabled in DNS Filter", "4.3.1", "Automated", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="table_any_match", cmd=DNSF, key="block-botnet",
                            pattern=r"set\s+block-botnet\s+(enable|block)")],
             "config dnsfilter profile\n edit <profile>\n set block-botnet enable\nend",
             review_required=True),
        _ctl("FG-DNS-002", "DNS Filter logs all DNS queries and responses", "4.3.2", "Manual", SCOPE_VDOM, "Low", "L1",
             [FortiGateRule(type="table_any_match", cmd=DNSF, key="log-all-domain",
                            pattern=r"set\s+log-all-domain\s+enable")],
             "config dnsfilter profile\n edit <profile>\n set log-all-domain enable\nend",
             review_required=True),
        _ctl("FG-DNS-003", "Apply DNS Filter Security Profile to policies", "4.3.3", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="dnsfilter-profile",
                            pattern=r"set\s+dnsfilter-profile\s+\S")],
             "Apply a DNS filter profile to relevant firewall policies.",
             review_required=True),

        # ===== 4.4 Application Control =====  (profiles only matter once applied → review)
        _ctl("FG-APP-001", "Block high risk categories on Application Control", "4.4.1", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=APPL, key="block entries",
                            pattern=r"set\s+(category|risk|application)\s+\S")],
             "config application list\n edit <list>\n config entries\n ... set action block (high risk)\nend",
             review_required=True),
        _ctl("FG-APP-002", "Block applications running on non-default ports", "4.4.2", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=APPL, key="enforce-default-app-port",
                            pattern=r"set\s+enforce-default-app-port\s+enable")],
             "config application list\n edit <list>\n set enforce-default-app-port enable\nend",
             review_required=True),
        _ctl("FG-APP-003", "Application Control related traffic is logged", "4.4.3", "Manual", SCOPE_VDOM, "Low", "L1",
             [FortiGateRule(type="table_any_match", cmd=APPL, key="app-control logging",
                            pattern=r"set\s+(other-application-log|unknown-application-log)\s+enable")],
             "config application list\n edit <list>\n set other-application-log enable\nend",
             review_required=True),
        _ctl("FG-APP-004", "Apply Application Control Security Profile to policies", "4.4.4", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=POL, key="application-list",
                            pattern=r"set\s+application-list\s+\S")],
             "Apply an application-list profile to relevant firewall policies.",
             review_required=True),

        # ===== 5 Security Fabric =====
        # `show system automation-stitch` → best-effort: report stitches with a
        # quarantine action (the action set is site-specific → review flag).
        _ctl("FG-FAB-001", "Compromised Host Quarantine enabled", "5.1.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=STITCH, key="quarantine action", pattern=r"quarantine")],
             "Create an automation stitch with a quarantine action (e.g. Quarantine FortiClient via EMS).",
             review_required=True),
        # `get system csf` → Security Fabric status must read enable.
        _ctl("FG-FAB-002", "Security Fabric is Configured", "5.2.1.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GCSF, key="status", expected="enable")],
             "config system csf\n set status enable\n set group-name <name>\nend"),

        # ===== 6 VPN =====
        # `get vpn ssl settings` → servercert must not be the factory/self-signed
        # cert; ssl-min-proto-version must be tlsv1-2 or tlsv1-3.
        _ctl("FG-VPN-SSL-003", "Trusted signed certificate applied for SSL-VPN portal", "6.1.1", "Manual", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="get_field_not_match", cmd=GSSLVPN, key="servercert",
                            pattern=r"^(Fortinet_|self-sign)")],
             "config vpn ssl settings\n set servercert <trusted-cert>\nend"),
        _ctl("FG-VPN-SSL-001", "Limited TLS versions enabled for SSL VPN", "6.1.2", "Manual", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="get_field_in", cmd=GSSLVPN, key="ssl-min-proto-version",
                            expected=["tlsv1-2", "tlsv1-3"])],
             "config vpn ssl settings\n set ssl-min-proto-version tlsv1-2\nend"),

        # ===== 7 Users and Authentication =====
        # `get user setting` → auth-lockout-threshold must be >= 1 (not disabled).
        _ctl("FG-USER-001", "Maximum login attempts and lockout period configured", "7.1", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="get_field_int_ge", cmd=GUSRSET, key="auth-lockout-threshold",
                            expected=1, default=3)],
             "config user setting\n set auth-lockout-threshold 3\n set auth-lockout-duration 60\nend"),

        # ===== 8 Logs and Reports =====
        # `get log eventfilter` → event must read enable.
        _ctl("FG-LOG-001", "Event Logging enabled", "8.1.1", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GEVENTF, key="event", expected="enable")],
             "config log eventfilter\n set event enable\nend"),
        # `get log fortianalyzer setting` → enc-algorithm must not be disable, and
        # status must be enable for the FAZ destination.
        _ctl("FG-LOG-002", "Log transmission to FortiAnalyzer/FortiManager encrypted", "8.2.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GFAZ, key="enc-algorithm", expected="disable")],
             "config log fortianalyzer setting\n set reliable enable\n set enc-algorithm high\nend"),
        _ctl("FG-FAZ-001", "Centralized Logging and Reporting configured", "8.3.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GFAZ, key="status", expected="enable")],
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
