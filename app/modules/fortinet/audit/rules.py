"""
FortiGate CIS Benchmark control catalog.

Exactly the 49 recommendations of the CIS FortiGate Benchmark
(``docs/forti_cis_benchmark.docx`` — 8 sections, 25 Automated / 24 Manual).

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
    # Optional regex restricting which table entries a per-entry rule applies to
    # (e.g. r"set\s+action\s+accept" so a profile check only targets accept
    # policies). When None, every entry is in scope. Used by policy_field_* rules.
    scope_pattern: Optional[str] = None
    # Optional SECOND command collected alongside ``cmd`` for rule types that
    # correlate two outputs (e.g. "policy_unused" joins `show firewall policy`
    # with the per-policy byte counters from `diagnose firewall iprope list`).
    aux_cmd: Optional[str] = None


@dataclass
class ApplicabilityGate:
    """Marks a control NOT_APPLICABLE when the underlying feature is off/absent.

    Some controls check a sub-setting that only exists once a feature is enabled
    (HA reserved-mgmt only when HA is configured, FAZ log encryption only when FAZ
    logging is on), or a feature that a given FortiOS build/model doesn't ship at
    all (e.g. FortiGuard AV push-update on a 60F). Reporting NON-COMPLIANT there is
    a false finding, so the control is scored NOT_APPLICABLE.

    N/A when either:
      * ``key`` is set and field ``key`` in ``cmd``'s output equals one of
        ``off_values`` (case/space-insensitive)  — feature switched off; or
      * ``na_if_cmd_error`` and ``cmd``'s output is a device rejection (parse
        error / unknown action / command fail) — feature not present on this build.
    """
    cmd: str
    key: Optional[str] = None
    off_values: List[str] = field(default_factory=list)
    note: str = ""
    na_if_cmd_error: bool = False


# FortiOS keywords that begin a configuration line. Used to split a control's
# free-text ``remediation`` into copy-pasteable CLI commands vs human guidance.
_CLI_LINE_PREFIXES = (
    "config ", "edit ", "set ", "unset ", "get ", "show ", "diagnose ", "diag ",
    "execute ", "exec ", "delete ", "append ", "select ", "clear ", "purge",
)


def _is_cli_line(line: str) -> bool:
    """Whether a remediation line is a FortiOS CLI command (vs prose)."""
    low = line.strip().lower()
    return low in ("end", "next") or low.startswith(_CLI_LINE_PREFIXES)


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
    # Optional gate: when set and matched, the control is scored NOT_APPLICABLE
    # (feature switched off) rather than NON-COMPLIANT. See ApplicabilityGate.
    na_gate: Optional[ApplicabilityGate] = None
    # How to combine multiple rules: "all" (AND, default) or "any" (OR — for a
    # control whose setting has more than one build-specific spelling, so ANY
    # matching form is enough, e.g. ML-detection vs the older heuristic node).
    rule_combine: str = "all"
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

    @property
    def remediation_commands(self) -> List[str]:
        """The copy-pasteable CLI lines from ``remediation`` (config/edit/set/…),
        in order, with catalog indentation preserved. Empty when the remediation
        is pure prose (e.g. 'upgrade to the latest firmware'). Used by the manual
        'View Fix' guidance so the operator can copy the exact commands."""
        return [ln.rstrip() for ln in self.remediation.splitlines() if _is_cli_line(ln)]

    @property
    def remediation_guidance(self) -> str:
        """The human-readable (non-CLI) portion of ``remediation`` — the sentences
        that explain what to do. Empty when the remediation is entirely CLI."""
        prose = [ln.strip() for ln in self.remediation.splitlines()
                 if ln.strip() and not _is_cli_line(ln)]
        return " ".join(prose)


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
         review_required=False, na_gate=None, rule_combine="all") -> FortiGateControl:
    return FortiGateControl(
        id=id, title=title, cis_id=cis_id, cis_section=_section_name(cis_id),
        cis_type=cis_type, scope=scope, severity=severity, level=level,
        rules=rules, remediation=remediation, review_required=review_required,
        na_gate=na_gate, rule_combine=rule_combine,
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
# Kernel forward-policy table (group 100004) — per-policy traffic counters
# ("pol_stats: bytes=N(all) ..."). Read in the control's VDOM context; a policy
# absent from it (disabled policies are unloaded from the kernel) counts as
# 0 bytes. Used by FG-POL-001 to find disabled-AND-never-used policies.
POLSTATS = "diagnose firewall iprope list 100004"
IPSSENS = "show ips sensor"            # botnet C&C scanning lives here in 7.0.x
AVSET = "show antivirus settings"
DNSF = "show dnsfilter profile"
APPL = "show application list"
CSF = "show system csf"
SSLVPN = "show vpn ssl settings"
USRSET = "show user setting"
EVENTF = "show log eventfilter"
FAZ = "show log fortianalyzer setting"

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
GAVHEUR = "get antivirus heuristic"   # older/lower-end builds (e.g. 60F) put AI/heuristic here


def get_fortinet_controls() -> List[FortiGateControl]:
    """Return all 49 CIS FortiGate Benchmark controls."""
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
        # Only the cleartext/interactive management services count here; ping,
        # snmp and radius-acct are intentionally NOT flagged (per client scope).
        _ctl("FG-NET-002", "Management services disabled on WAN interface", "1.3", "Manual",
             SCOPE_GLOBAL, "High", "L1",
             [FortiGateRule(type="wan_mgmt_exposed", cmd=IFACE,
                            expected=["http", "https", "ssh", "telnet"])],
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
        # `get system password-policy` → status must read enable. Read in GLOBAL
        # scope: the admin password-policy is global in multi-VDOM mode (reading it
        # inside a VDOM returns "command parse error before 'password-policy'").
        _ctl("FG-BL-030", "Password Policy is enabled", "2.2.1", "Automated", SCOPE_GLOBAL, "High", "L1",
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
        # N/A on standalone devices: ha-mgmt-status only exists once HA is set up,
        # so its absence when mode=standalone is "HA not configured", not a finding.
        _ctl("FG-HA-006", "HA Reserved Management Interface configured", "2.5.3", "Manual", SCOPE_GLOBAL, "Low", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GHA, key="ha-mgmt-status", expected="enable")],
             "config system ha\n set ha-mgmt-status enable\n config ha-mgmt-interfaces\n ...\nend",
             na_gate=ApplicabilityGate(cmd=GHA, key="mode", off_values=["standalone"],
                                       note="HA not configured (mode=standalone)")),

        # ===== 3 Policy and Objects =====
        # `show firewall policy` + `diagnose firewall iprope list 100004` →
        # NON-COMPLIANT when any policy is DISABLED *or* has 0 traffic bytes
        # (never used) — those are unused policies that must be deleted. Policies
        # that are both enabled and carry traffic get a review worksheet in the
        # evidence. An EMPTY policy table is compliant (nothing to review).
        _ctl("FG-POL-001", "Unused policies are reviewed regularly", "3.1", "Manual", SCOPE_VDOM, "Low", "L1",
             [FortiGateRule(type="policy_unused", cmd=POL, key="firewall policy",
                            aux_cmd=POLSTATS)],
             "Per unused (disabled or 0-byte) policy:\nconfig firewall policy\n delete <policy ID>\nend",
             review_required=True),
        # `show firewall policy` → no policy's `set service` list may contain the
        # object "ALL" (exact token, ANY position — client confirmed: ALL policies
        # including deny, per the CIS text). Exact-token match so the specific
        # ALL_TCP / ALL_UDP / ALL_ICMP objects do NOT false-flag; evidence lists
        # each failing Policy ID with its full service list.
        _ctl("FG-BL-080", "Policies do not use 'ALL' as Service", "3.2", "Automated", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="policy_field_forbidden_token", cmd=POL, key="service",
                            expected="ALL")],
             "Per non-compliant policy:\nconfig firewall policy\n edit <policy ID>\n set service <specific services>\nend"),
        # `show firewall policy` → best-effort: a qualifying entry must be a DENY
        # policy (deny is the action default, so `show` prints no `set action`
        # line for it) that references Tor/Malicious/Scanner/Botnet ISDB objects
        # (`set internet-service(-src)-name|-id ...`, 7.0.x spelling). A mere
        # `set internet-service enable` on an accept policy (SD-WAN steering,
        # ISDB allow rules) is NOT evidence of this control.
        _ctl("FG-POL-002", "Deny traffic to/from Tor, malicious or scanner IPs (ISDB)", "3.3", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="isdb_deny_present", cmd=POL, key="ISDB deny policy",
                            pattern=r"tor|malicious|scanner|botnet")],
             "Create deny policies using Internet Service DB objects (Tor/Botnet/Scanner).",
             review_required=True),
        # `show firewall policy` → EVERY policy must have logtraffic explicitly set
        # to "all". Anything else (disable, utm, or unset→default) is NON-COMPLIANT;
        # the report lists each failing Policy ID with its current value.
        _ctl("FG-BL-082", "Logging enabled on all firewall policies", "3.4", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="policy_field_eq", cmd=POL, key="logtraffic", expected="all")],
             "Per non-compliant policy:\nconfig firewall policy\n edit <policy ID>\n set logtraffic all\nend"),

        # ===== 4.1 Intrusion Prevention System =====
        # `show ips sensor` → in FortiOS 7.0.x `scan-botnet-connections` moved
        # OFF the firewall policy and onto the IPS sensor — reading the policy
        # table (the 6.x location) always found nothing and produced a permanent
        # false NON-COMPLIANT. Best-effort PASS when at least one sensor scans
        # botnet connections (block|monitor); FG-UTM-003 (4.1.2) covers whether
        # sensors are actually applied to policies.
        _ctl("FG-IPS-001", "Detect Botnet connections", "4.1.1", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="table_any_match", cmd=IPSSENS, key="scan-botnet-connections block/monitor",
                            pattern=r"set\s+scan-botnet-connections\s+(?:block|monitor)")],
             "config ips sensor\n edit <sensor>\n  set scan-botnet-connections block\n next\nend",
             review_required=True),
        # `show firewall policy` → each ACCEPT policy should carry an IPS sensor;
        # the report lists every accept Policy ID missing `set ips-sensor`.
        _ctl("FG-UTM-003", "Apply IPS Security Profile to policies", "4.1.2", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="policy_field_present", cmd=POL, key="ips-sensor",
                            scope_pattern=r"set\s+action\s+accept")],
             "On each accept policy missing it:\nconfig firewall policy\n edit <policy ID>\n set ips-sensor <sensor>\nend",
             review_required=True),

        # ===== 4.2 Antivirus =====
        # `show firewall policy` → each ACCEPT policy should carry an AV profile;
        # the report lists every accept Policy ID missing `set av-profile`.
        _ctl("FG-UTM-002", "Apply Antivirus Security Profile to policies", "4.2.2", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="policy_field_present", cmd=POL, key="av-profile",
                            scope_pattern=r"set\s+action\s+accept")],
             "On each accept policy missing it:\nconfig firewall policy\n edit <policy ID>\n set av-profile <profile>\nend",
             review_required=True),
        # `get antivirus settings` → ML detection enabled, grayware enabled.
        # Two build spellings for AI/heuristic AV: newer builds expose
        # `machine-learning-detection` under `get antivirus settings`; older/60F
        # builds have no such field and use `config antivirus heuristic` (mode:
        # pass|block|disable). rule_combine="any" -> compliant if EITHER form is
        # enabled (the other's field is simply absent on that build).
        _ctl("FG-AV-003", "AI/heuristic based malware detection enabled", "4.2.4", "Automated", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GAVSET, key="machine-learning-detection", expected="disable"),
              FortiGateRule(type="get_field_ne", cmd=GAVHEUR, key="mode", expected="disable")],
             "config antivirus settings\n set machine-learning-detection enable\nend\n"
             "(on builds without that field: config antivirus heuristic / set mode pass)",
             rule_combine="any"),
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
        # `show firewall policy` → each ACCEPT policy should carry an application
        # control list; the report lists every accept Policy ID missing it.
        _ctl("FG-APP-004", "Apply Application Control Security Profile to policies", "4.4.4", "Manual", SCOPE_VDOM, "Medium", "L1",
             [FortiGateRule(type="policy_field_present", cmd=POL, key="application-list",
                            scope_pattern=r"set\s+action\s+accept")],
             "On each accept policy missing it:\nconfig firewall policy\n edit <policy ID>\n set application-list <list>\nend",
             review_required=True),

        # ===== 5 Security Fabric =====
        # `get system csf` → Security Fabric status must read enable.
        _ctl("FG-FAB-002", "Security Fabric is Configured", "5.2.1.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_eq", cmd=GCSF, key="status", expected="enable")],
             "config system csf\n set status enable\n set group-name <name>\nend"),

        # ===== 6 VPN =====
        # `get vpn ssl settings` → servercert must not be the factory/self-signed
        # cert; ssl-min-proto-ver must be tls1-2 or tls1-3. NOTE: the `get` output
        # field is `ssl-min-proto-ver` with values `tls1-N` (not the config/GUI
        # spelling `ssl-min-proto-version` / `tlsv1-N`).
        _ctl("FG-VPN-SSL-003", "Trusted signed certificate applied for SSL-VPN portal", "6.1.1", "Manual", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="get_field_not_match", cmd=GSSLVPN, key="servercert",
                            pattern=r"^(Fortinet_|self-sign)")],
             "config vpn ssl settings\n set servercert <trusted-cert>\nend"),
        # Two output formats across builds: a single `ssl-min-proto-ver : tls1-2`
        # field, OR per-version booleans `tlsv1-0/1/2/3 : enable/disable`. The
        # sslvpn_min_tls evaluator handles both (compliant only when no TLS < 1.2
        # is enabled). key is kept for evidence.
        _ctl("FG-VPN-SSL-001", "Limited TLS versions enabled for SSL VPN", "6.1.2", "Manual", SCOPE_VDOM, "High", "L1",
             [FortiGateRule(type="sslvpn_min_tls", cmd=GSSLVPN, key="ssl-min-proto-ver")],
             "config vpn ssl settings\n set ssl-min-proto-ver tls1-2\nend\n"
             "(on builds without ssl-min-proto-ver: set tlsv1-0 disable / set tlsv1-1 disable)"),

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
        # N/A when FortiAnalyzer logging is off: enc-algorithm only appears once
        # `status` is enable, so its absence with status=disable means "no FAZ
        # configured", not unencrypted transmission.
        _ctl("FG-LOG-002", "Log transmission to FortiAnalyzer/FortiManager encrypted", "8.2.1", "Automated", SCOPE_GLOBAL, "Medium", "L1",
             [FortiGateRule(type="get_field_ne", cmd=GFAZ, key="enc-algorithm", expected="disable")],
             "config log fortianalyzer setting\n set reliable enable\n set enc-algorithm high\nend",
             na_gate=ApplicabilityGate(cmd=GFAZ, key="status", off_values=["disable"],
                                       note="FortiAnalyzer logging disabled (status=disable)")),
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
