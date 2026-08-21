"""
Windows Server CIS Benchmark Rules — version-aware (2016 / 2022 / 2025)

The rule set is built the same way the MSSQL / RHEL modules build theirs: a
single base builder for the newest benchmark (Windows Server 2025 v1.0.0) and
thin derived builders that *extend* it for the older versions.

Version gate keys (the equivalent of the Linux ``rhel_10`` profile / MSSQL
``mssql_2022``) select the rule set:

    win_2016  -> build_win2016_cis_rules()
    win_2022  -> build_win2022_cis_rules()
    win_2025  -> build_win2025_cis_rules()

The gate key is resolved from the collected ``CurrentBuildNumber`` /
``OS_VERSION`` (``_detect_version`` / ``_detect_gate``) so callers never have to
know the build number.

Check IDs are stable, section-based slugs (``WIN-2025-1.1.1``,
``WIN-2025-2.3.11.7`` …) that are shared 1:1 with the hardening templates. A
large share of Section 2.3 / Section 18 checks are pure registry DWORD
comparisons, so those are declared once in ``REGISTRY_CHECKS`` and both the
audit ``check_fn`` and the hardening ``Set-ItemProperty`` template are generated
from that single table — eliminating audit↔hardening drift.

All checks read the structured dump produced by
``WindowsWinRMClient.collect_audit_data`` using regex/JSON over the
``===SECTION:NAME===`` markers. Everything is read-only (WinRM PowerShell
``Get-*`` / ``secedit /export`` / ``auditpol /get``); the audit path never
writes. Manual controls (message text, GPO-only, HKU-scoped, patch level …) are
reported NOT_APPLICABLE and never scored.

CIS sections covered by the 2025 base:
  1.x   Account Policies (Password, Lockout)          — secedit [System Access]
  2.2   User Rights Assignment                        — secedit [Privilege Rights]
  2.3   Security Options                               — registry / secedit / local users
  9.x   Windows Defender Firewall                      — Get-NetFirewallProfile
  17.x  Advanced Audit Policy                          — auditpol /get
  18.x  Administrative Templates (Computer)            — registry
  19.x  Administrative Templates (User)                — HKU (manual)
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ============================================================ #
#  Rule dataclass                                              #
# ============================================================ #

@dataclass
class WindowsCISRule:
    """A single CIS Windows Server compliance check."""
    id: str                          # stable slug, e.g. "WIN-2025-2.3.11.7"
    section: str                     # CIS section number, e.g. "2.3.11.7"
    title: str
    severity: str                    # high / medium / low / info
    level: str                       # L1 / L2
    check_fn: Callable[[str], bool]  # True = compliant
    evidence_fn: Callable[[str], str]
    remediation: str
    description: str = ""
    manual: bool = False             # Manual controls: reported NA, never scored
    scored: bool = True              # False for manual/info controls
    scope: str = "all"               # all / MS (member server) / DC (domain controller)
    audit_key: str = ""              # data key the check reads (debug/evidence aid)
    versions: List[str] = field(default_factory=lambda: ["win_2025"])
    # Collection sections this check reads. When every one of them failed to
    # collect, the check is unevaluable and is reported ERROR instead of being
    # silently scored (a missing secedit export must never read as "No One").
    # Several entries mean "any one of these is enough" (USER_RIGHTS falls back
    # to SECURITY_POLICY).
    data_sections: List[str] = field(default_factory=list)


# ============================================================ #
#  Section extraction                                         #
# ============================================================ #

def _section(dump: str, name: str) -> str:
    """Extract the content of a named section from the audit dump."""
    pattern = re.compile(
        rf"===SECTION:{re.escape(name)}===\n(.*?)(?=\n===SECTION:|\Z)",
        re.S,
    )
    m = pattern.search(dump)
    return m.group(1).strip() if m else ""


def _ev_section(dump: str, section: str, max_chars: int = 400) -> str:
    content = _section(dump, section)
    return content[:max_chars] + ("..." if len(content) > max_chars else "")


def _parse_json(text: str) -> Any:
    """Safely parse JSON from a section, returning None on failure/error."""
    if not text or text.startswith(("PS_ERROR", "CMD_ERROR", "COLLECTION_ERROR",
                                    "(no output)", "(empty)", "SECEDIT_EXPORT_FAILED")):
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _json_section(dump: str, name: str) -> Any:
    return _parse_json(_section(dump, name))


# ============================================================ #
#  Collection health                                          #
# ============================================================ #

# Markers emitted by the collector when a PowerShell command failed. A section
# carrying one of these holds no configuration data, so every rule that reads it
# is unevaluable — reporting it as compliant (or even as non-compliant) would be
# a guess.
_SECTION_FAILURE_PREFIXES = ("PS_ERROR", "CMD_ERROR", "COLLECTION_ERROR")
_SECTION_EMPTY_MARKERS = ("", "(no output)", "(empty)", "SECEDIT_EXPORT_FAILED")

# Sections whose payload must parse as JSON; anything else means the command
# produced an error page / partial output rather than data.
_JSON_SECTIONS = frozenset({
    "OS_VERSION", "DOMAIN_ROLE", "REGISTRY", "FIREWALL_PROFILES", "LOCAL_USERS",
})


def section_failure(dump: str, name: str) -> Optional[str]:
    """
    Return a short reason when a collection section is unusable, else None.

    Used by evaluate_compliance to mark dependent checks ERROR rather than
    scoring them: a failed ``secedit /export`` used to make every
    'set to No One' user-rights check read as compliant.
    """
    content = _section(dump, name).strip()
    if content in _SECTION_EMPTY_MARKERS:
        return f"{name} was not collected"
    if content.startswith(_SECTION_FAILURE_PREFIXES):
        return f"{name} collection failed: {content.splitlines()[0][:160]}"
    if "SECEDIT_EXPORT_FAILED" in content:
        return f"{name} collection failed: secedit /export returned no policy file"
    if name in _JSON_SECTIONS and _parse_json(content) is None:
        return f"{name} returned unparseable output: {content.splitlines()[0][:160]}"
    return None


def rule_data_failure(dump: str, rule: "WindowsCISRule") -> Optional[str]:
    """
    Return a reason when none of a rule's data sections could be collected.

    A rule listing several sections needs only one of them (USER_RIGHTS falls
    back to the full SECURITY_POLICY export), so this reports a failure only
    when every declared section is unusable.
    """
    if not rule.data_sections:
        return None
    reasons = []
    for name in rule.data_sections:
        reason = section_failure(dump, name)
        if reason is None:
            return None
        reasons.append(reason)
    return "; ".join(reasons)


# ============================================================ #
#  Version / role detection                                   #
# ============================================================ #

_BUILD_TO_GATE = {
    "14393": "win_2016",
    "17763": "win_2022",   # 2019 shares the 2022 control set (nearest gate)
    "20348": "win_2022",
    "26100": "win_2025",
}


def _detect_version(dump: str) -> str:
    """Return the human version year ('2016'/'2019'/'2022'/'2025'/'unknown')."""
    data = _json_section(dump, "OS_VERSION")
    if isinstance(data, dict):
        build = str(data.get("BuildNumber", ""))
        gate = _BUILD_TO_GATE.get(build)
        if gate:
            return gate.replace("win_", "")
        caption = str(data.get("Caption", ""))
        for year in ("2025", "2022", "2019", "2016"):
            if year in caption:
                return year
    raw = _section(dump, "OS_VERSION")
    for year in ("2025", "2022", "2019", "2016"):
        if year in raw:
            return year
    return "unknown"


def _detect_gate(dump: str) -> str:
    """
    Resolve the collected OS dump to a version gate key. Unknown builds fall
    back to the newest benchmark (superset) so nothing goes unscored.
    """
    data = _json_section(dump, "OS_VERSION")
    if isinstance(data, dict):
        gate = _BUILD_TO_GATE.get(str(data.get("BuildNumber", "")))
        if gate:
            return gate
    year = _detect_version(dump)
    return {"2016": "win_2016", "2019": "win_2022",
            "2022": "win_2022", "2025": "win_2025"}.get(year, "win_2025")


def is_domain_controller(dump: str) -> bool:
    """
    True when the host is a domain controller (Win32_ComputerSystem.DomainRole
    >= 4). DomainRole: 0/1 standalone, 2/3 member server, 4/5 domain controller.
    """
    data = _json_section(dump, "DOMAIN_ROLE")
    role = None
    if isinstance(data, dict):
        role = data.get("DomainRole")
    elif isinstance(data, int):
        role = data
    try:
        return int(role) >= 4
    except (TypeError, ValueError):
        return False  # default to member-server rule set when unknown


# ============================================================ #
#  secedit (INF) parsing — [System Access] & [Privilege Rights]#
# ============================================================ #

def _secpol_value(dump: str, key: str) -> Optional[str]:
    section = _section(dump, "SECURITY_POLICY")
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=[^\S\n]*(.+)$", re.M | re.I)
    m = pattern.search(section)
    return m.group(1).strip() if m else None


def _secpol_int(dump: str, key: str) -> Optional[int]:
    val = _secpol_value(dump, key)
    if val is None:
        return None
    try:
        return int(val.split(",")[0].strip())
    except (ValueError, IndexError):
        return None


def _user_right_sids(dump: str, privilege: str) -> List[str]:
    """Extract the SID/account list for a [Privilege Rights] assignment."""
    section = _section(dump, "USER_RIGHTS")
    if not section or "SECEDIT_EXPORT_FAILED" in section:
        section = _section(dump, "SECURITY_POLICY")
    pattern = re.compile(rf"^\s*{re.escape(privilege)}\s*=[^\S\n]*(.*?)$", re.M | re.I)
    m = pattern.search(section)
    if m and m.group(1).strip():
        return [s.strip().lstrip("*").upper() for s in m.group(1).split(",") if s.strip()]
    return []


# Friendly principal name -> well-known SID (as they appear in secedit export)
_SID = {
    "No One": set(),
    "Administrators": {"S-1-5-32-544"},
    "Authenticated Users": {"S-1-5-11"},
    "ENTERPRISE DOMAIN CONTROLLERS": {"S-1-5-9"},
    "LOCAL SERVICE": {"S-1-5-19"},
    "NETWORK SERVICE": {"S-1-5-20"},
    "SERVICE": {"S-1-5-6"},
    "Guests": {"S-1-5-32-546"},
    "Local account": {"S-1-5-113"},
    "Remote Desktop Users": {"S-1-5-32-555"},
    "Window Manager\\Window Manager Group": {"S-1-5-90-0"},
    "NT SERVICE\\WdiServiceHost":
        {"S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"},
    "NT VIRTUAL MACHINE\\Virtual Machines": {"S-1-5-83-0"},
}


def _expected_sids(names: List[str]) -> set:
    out = set()
    for n in names:
        out |= _SID.get(n, set())
    return out


def _rights_exact(dump: str, privilege: str, names: List[str]) -> bool:
    """Compliant when the assigned SID set exactly equals the expected set."""
    return set(_user_right_sids(dump, privilege)) == _expected_sids(names)


def _rights_empty(dump: str, privilege: str) -> bool:
    """Compliant when no principal holds the right ('No One')."""
    return len(_user_right_sids(dump, privilege)) == 0


def _rights_include(dump: str, privilege: str, names: List[str]) -> bool:
    """Compliant when every expected principal is present (subset)."""
    return _expected_sids(names).issubset(set(_user_right_sids(dump, privilege)))


# ============================================================ #
#  auditpol (CSV) parsing                                     #
# ============================================================ #

def _audit_policy_setting(dump: str, subcategory: str) -> str:
    """Return the 'Inclusion Setting' for an audit subcategory (exact match)."""
    section = _section(dump, "AUDIT_POLICY")
    target = subcategory.lower()
    fallback = ""
    for line in section.split("\n"):
        parts = line.split(",")
        if len(parts) < 5:
            continue
        row_subcat = parts[2].strip().lower()
        if row_subcat == target:
            return parts[4].strip()
        if not fallback and target in row_subcat:
            fallback = parts[4].strip()
    return fallback


def _audit_matches(dump: str, subcategory: str, expected: str) -> bool:
    """
    Compliant when the inclusion setting matches exactly. 'Success and Failure'
    must not be satisfied by a bare 'Success', so we compare normalised strings.
    """
    setting = _audit_policy_setting(dump, subcategory).strip().lower()
    want = expected.strip().lower()
    if not setting:
        return False
    if want == "success and failure":
        return "success" in setting and "failure" in setting
    if want == "success":
        return "success" in setting
    if want == "failure":
        return "failure" in setting
    return setting == want


# ============================================================ #
#  Registry parsing                                           #
# ============================================================ #

def _reg(dump: str, path: str, prop: str) -> Any:
    """
    Return a registry value collected under the REGISTRY section.

    The section is a dict of {full_path: {prop: value}}; values may be ints,
    strings or lists. Returns None when the path or property is absent.
    """
    data = _json_section(dump, "REGISTRY")
    if not isinstance(data, dict):
        return None
    want = path.rstrip("\\").lower()
    for path_key, props in data.items():
        if path_key.rstrip("\\").lower() != want:
            continue
        if isinstance(props, str):
            try:
                props = json.loads(props)
            except (json.JSONDecodeError, ValueError):
                return None
        if isinstance(props, dict) and prop in props:
            return props[prop]
        return None
    return None


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _pred(value: Any, op: str, target: Any) -> bool:
    """Evaluate a registry predicate. Fails closed on a missing/unparseable value."""
    if op == "absent":
        return value is None
    if op == "empty":
        if value is None:
            return True
        if isinstance(value, (list, tuple)):
            return len(value) == 0
        return str(value).strip() == ""
    if op == "eq_str":
        return value is not None and str(value).strip() == str(target)
    if value is None:
        return False
    iv = _to_int(value)
    if iv is None:
        return False
    if op == "eq":
        return iv == target
    if op == "ne":
        return iv != target
    if op == "gte":
        return iv >= target
    if op == "lte":
        return iv <= target
    if op == "lte_nz":
        return 0 < iv <= target
    if op == "range":
        return target[0] <= iv <= target[1]
    return False


# ============================================================ #
#  Firewall parsing                                           #
# ============================================================ #

def _firewall_profile(dump: str, name: str) -> Optional[Dict]:
    data = _json_section(dump, "FIREWALL_PROFILES")
    if not data:
        return None
    profiles = data if isinstance(data, list) else [data]
    for p in profiles:
        if isinstance(p, dict) and str(p.get("Name", "")).lower() == name.lower():
            return p
    return None


# MSFT_NetFirewallProfile stores these flags as uint16 GpoBoolean enums, not
# booleans, and publishes no ValueMap. The collector now casts them to their
# member name ("True"/"False"/"NotConfigured") so the value is unambiguous; this
# map only interprets integers from dumps collected before that change.
# Unverified against a live host on purpose — anything not listed is treated as
# unknown and fails closed, rather than the old "non-zero means on", which read
# a disabled firewall as compliant.
_GPO_BOOL_INTS = {1: True, 2: False}

# LogMaxSizeKilobytes is a uint64 where MAXUINT64 means "Not Configured"
# (documented on MSFT_NetFirewallProfile) — not an enormous configured size.
_UINT64_MAX = 18446744073709551615


def _fw_bool(p: Optional[Dict], key: str, want: bool) -> bool:
    """Compliant when a firewall GpoBoolean equals ``want``.

    Anything indeterminate — NotConfigured, an unmapped integer, a missing key —
    is not compliant; this never guesses a verdict from an unrecognised value.
    """
    if not p or key not in p:
        return False
    v = p.get(key)
    if isinstance(v, bool):      # a real JSON boolean (hand-authored fixtures)
        return v == want
    if isinstance(v, int):       # legacy dumps: the raw enum integer
        state = _GPO_BOOL_INTS.get(v)
        return state is not None and state == want
    text = str(v).strip().lower()
    if text in ("true", "1"):
        return want is True
    if text in ("false", "0"):
        return want is False
    return False                 # NotConfigured / unrecognised


def _fw_enabled(dump: str, name: str) -> bool:
    return _fw_bool(_firewall_profile(dump, name), "Enabled", True)


def _fw_inbound_block(dump: str, name: str) -> bool:
    p = _firewall_profile(dump, name)
    if not p:
        return False
    action = p.get("DefaultInboundAction")
    if isinstance(action, int):
        # Legacy dumps carry the raw Action enum; the collector now sends the
        # member name instead (see audit_commands.FIREWALL_PROFILES).
        return action == 4          # NetSecurity Action enum: 4 = Block
    return str(action).strip().lower() == "block"


def _fw_int_gte(dump: str, name: str, key: str, target: int) -> bool:
    p = _firewall_profile(dump, name)
    if not p:
        return False
    iv = _to_int(p.get(key))
    if iv is None or iv == _UINT64_MAX:  # MAXUINT64 = Not Configured, not "huge"
        return False
    return iv >= target


def _fw_logname(dump: str, name: str, expected_file: str) -> bool:
    p = _firewall_profile(dump, name)
    if not p:
        return False
    return expected_file.lower() in str(p.get("LogFileName", "")).lower()


# ============================================================ #
#  Local users (Guest account status)                         #
# ============================================================ #

def _guest_disabled(dump: str) -> bool:
    data = _json_section(dump, "LOCAL_USERS")
    if not data:
        return False
    users = data if isinstance(data, list) else [data]
    for u in users:
        if isinstance(u, dict) and str(u.get("Name", "")).lower() == "guest":
            enabled = u.get("Enabled")
            if isinstance(enabled, bool):
                return not enabled
            return str(enabled).strip().lower() in ("false", "0")
    return True  # no Guest account present -> nothing enabled


# ============================================================ #
#  REGISTRY_CHECKS — shared audit + hardening table            #
# ============================================================ #
#
# Each entry drives BOTH the audit check_fn and (when fixable) the hardening
# Set-ItemProperty template. This is the single source of truth for every
# Section 2.3 / Section 18 registry DWORD/string control.

def _R(section, title, path, prop, op, target, *, level="L1", scope="all",
       set=None, rtype="dword", restart=False, fixable=True, severity="medium"):
    return {
        "section": section, "title": title, "path": path, "prop": prop,
        "op": op, "target": target, "level": level, "scope": scope,
        "set": (target if set is None else set), "rtype": rtype,
        "restart": restart, "fixable": fixable, "severity": severity,
    }


_LSA = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
_MSV = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
_NETLOGON = r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
_WKSTA = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
_SRV = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
_POLSYS = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_WINLOGON = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_TS = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
_DEFENDER = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
_WINRM_C = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
_WINRM_S = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"


REGISTRY_CHECKS: List[Dict[str, Any]] = [
    # ---- 1.1.6 Relax minimum password length (registry-backed) ----
    _R("1.1.6", "Relax minimum password length limits = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\SAM", "RelaxMinimumPasswordLengthLimits",
       "eq", 1, severity="low"),

    # ---- 2.3.1 Accounts ----
    _R("2.3.1.2", "Accounts: Limit local account use of blank passwords = Enabled",
       _LSA, "LimitBlankPasswordUse", "eq", 1, severity="high"),

    # ---- 2.3.2 Audit ----
    _R("2.3.2.1", "Audit: Force audit policy subcategory settings = Enabled",
       _LSA, "SCENoApplyLegacyAuditPolicy", "eq", 1),
    _R("2.3.2.2", "Audit: Shut down system if unable to log security audits = Disabled",
       _LSA, "CrashOnAuditFail", "eq", 0),

    # ---- 2.3.4 Devices ----
    _R("2.3.4.1", "Devices: Prevent users from installing printer drivers = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers",
       "AddPrinterDrivers", "eq", 1),

    # ---- 2.3.5 Domain controller (DC only) ----
    _R("2.3.5.3", "DC: LDAP server channel binding = Always",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
       "LdapEnforceChannelBinding", "eq", 2, scope="DC"),
    _R("2.3.5.4", "DC: LDAP server signing requirements = Require signing",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
       "ldapserverintegrity", "eq", 2, scope="DC"),
    _R("2.3.5.6", "DC: Refuse machine account password changes = Disabled",
       _NETLOGON, "RefusePasswordChange", "eq", 0, scope="DC"),

    # ---- 2.3.6 Domain member ----
    _R("2.3.6.1", "Domain member: Digitally encrypt or sign secure channel data (always) = Enabled",
       _NETLOGON, "RequireSignOrSeal", "eq", 1, severity="high"),
    _R("2.3.6.2", "Domain member: Digitally encrypt secure channel data (when possible) = Enabled",
       _NETLOGON, "SealSecureChannel", "eq", 1),
    _R("2.3.6.3", "Domain member: Digitally sign secure channel data (when possible) = Enabled",
       _NETLOGON, "SignSecureChannel", "eq", 1),
    _R("2.3.6.4", "Domain member: Disable machine account password changes = Disabled",
       _NETLOGON, "DisablePasswordChange", "eq", 0),
    _R("2.3.6.5", "Domain member: Maximum machine account password age <= 30 days",
       _NETLOGON, "MaximumPasswordAge", "lte_nz", 30, set=30),
    _R("2.3.6.6", "Domain member: Require strong (Windows 2000 or later) session key = Enabled",
       _NETLOGON, "RequireStrongKey", "eq", 1),

    # ---- 2.3.7 Interactive logon ----
    _R("2.3.7.1", "Interactive logon: Do not require CTRL+ALT+DEL = Disabled",
       _POLSYS, "DisableCAD", "eq", 0),
    _R("2.3.7.2", "Interactive logon: Don't display last signed-in = Enabled",
       _POLSYS, "DontDisplayLastUserName", "eq", 1),
    _R("2.3.7.3", "Interactive logon: Machine inactivity limit <= 900s, not 0",
       _POLSYS, "InactivityTimeoutSecs", "lte_nz", 900, set=900),
    _R("2.3.7.6", "Interactive logon: Number of previous logons to cache <= 4",
       _WINLOGON, "CachedLogonsCount", "lte", 4, set="4", rtype="string",
       level="L2", scope="MS"),
    _R("2.3.7.7", "Interactive logon: Prompt user to change password 5-14 days before expiration",
       _WINLOGON, "PasswordExpiryWarning", "range", (5, 14), set=14),
    _R("2.3.7.8", "Interactive logon: Require Domain Controller authentication to unlock = Enabled",
       _WINLOGON, "ForceUnlockLogon", "eq", 1, scope="MS"),
    _R("2.3.7.9", "Interactive logon: Smart card removal behavior = Lock Workstation",
       _WINLOGON, "ScRemoveOption", "gte", 1, set="1", rtype="string"),

    # ---- 2.3.8 MS network client ----
    _R("2.3.8.1", "MS network client: Digitally sign communications (always) = Enabled",
       _WKSTA, "RequireSecuritySignature", "eq", 1, severity="high"),
    _R("2.3.8.2", "MS network client: Digitally sign communications (if server agrees) = Enabled",
       _WKSTA, "EnableSecuritySignature", "eq", 1),
    _R("2.3.8.3", "MS network client: Send unencrypted password to third-party SMB servers = Disabled",
       _WKSTA, "EnablePlainTextPassword", "eq", 0, severity="high"),

    # ---- 2.3.9 MS network server ----
    _R("2.3.9.1", "MS network server: Idle time before suspending session <= 15 min",
       _SRV, "AutoDisconnect", "lte", 15, set=15),
    _R("2.3.9.2", "MS network server: Digitally sign communications (always) = Enabled",
       _SRV, "RequireSecuritySignature", "eq", 1, severity="high"),
    _R("2.3.9.3", "MS network server: Digitally sign communications (if client agrees) = Enabled",
       _SRV, "EnableSecuritySignature", "eq", 1),
    _R("2.3.9.4", "MS network server: Disconnect clients when logon hours expire = Enabled",
       _SRV, "EnableForcedLogOff", "eq", 1),
    _R("2.3.9.5", "MS network server: Server SPN target name validation level = Accept if provided",
       _SRV, "SMBServerNameHardeningLevel", "gte", 1, set=1, scope="MS"),

    # ---- 2.3.10 Network access ----
    _R("2.3.10.1", "Network access: Allow anonymous SID/Name translation = Disabled",
       _LSA, "TurnOffAnonymousBlock", "eq", 0),
    _R("2.3.10.2", "Network access: Do not allow anonymous enumeration of SAM accounts = Enabled",
       _LSA, "RestrictAnonymousSAM", "eq", 1, scope="MS", severity="high"),
    _R("2.3.10.3", "Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled",
       _LSA, "RestrictAnonymous", "eq", 1, scope="MS", severity="high"),
    _R("2.3.10.4", "Network access: Do not allow storage of passwords and credentials = Enabled",
       _LSA, "DisableDomainCreds", "eq", 1, level="L2"),
    _R("2.3.10.5", "Network access: Let Everyone permissions apply to anonymous users = Disabled",
       _LSA, "EveryoneIncludesAnonymous", "eq", 0, severity="high"),
    _R("2.3.10.7", "Network access: Named pipes accessible anonymously (MS) = None",
       _SRV, "NullSessionPipes", "empty", None, scope="MS", fixable=False),
    _R("2.3.10.10", "Network access: Restrict anonymous access to Named Pipes and Shares = Enabled",
       _SRV, "RestrictNullSessAccess", "eq", 1),
    _R("2.3.10.12", "Network access: Shares accessible anonymously = None",
       _SRV, "NullSessionShares", "empty", None, fixable=False),
    _R("2.3.10.13", "Network access: Sharing and security model for local accounts = Classic",
       _LSA, "ForceGuest", "eq", 0),

    # ---- 2.3.11 Network security ----
    _R("2.3.11.1", "Network security: Allow Local System to use computer identity for NTLM = Enabled",
       _LSA, "UseMachineId", "eq", 1),
    _R("2.3.11.2", "Network security: Allow LocalSystem NULL session fallback = Disabled",
       _MSV, "allownullsessionfallback", "eq", 0),
    _R("2.3.11.3", "Network security: Allow PKU2U authentication requests = Disabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u", "AllowOnlineID", "eq", 0),
    _R("2.3.11.4", "Network security: Configure encryption types allowed for Kerberos = AES128/AES256/Future",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
       "SupportedEncryptionTypes", "eq", 2147483640, set=2147483640),
    _R("2.3.11.5", "Network security: Do not store LAN Manager hash value on next password change = Enabled",
       _LSA, "NoLMHash", "eq", 1, severity="high"),
    _R("2.3.11.7", "Network security: LAN Manager authentication level = NTLMv2 only, refuse LM & NTLM",
       _LSA, "LmCompatibilityLevel", "eq", 5, severity="high"),
    _R("2.3.11.8", "Network security: LDAP client signing requirements = Negotiate signing or higher",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\ldap", "LDAPClientIntegrity", "gte", 1, set=1),
    _R("2.3.11.10", "Network security: Minimum session security for NTLM SSP clients = NTLMv2 & 128-bit",
       _MSV, "NTLMMinClientSec", "eq", 537395200, set=537395200),
    _R("2.3.11.11", "Network security: Minimum session security for NTLM SSP servers = NTLMv2 & 128-bit",
       _MSV, "NTLMMinServerSec", "eq", 537395200, set=537395200),
    _R("2.3.11.12", "Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable all",
       _MSV, "AuditReceivingNTLMTraffic", "eq", 2),
    _R("2.3.11.13", "Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all",
       _NETLOGON, "AuditNTLMInDomain", "eq", 7, scope="DC"),
    _R("2.3.11.14", "Network security: Restrict NTLM: Outgoing NTLM traffic = Audit all or higher",
       _MSV, "RestrictSendingNTLMTraffic", "gte", 1, set=1),

    # ---- 2.3.13 / 2.3.15 System settings ----
    _R("2.3.13.1", "Shutdown: Allow system to be shut down without having to log on = Disabled",
       _POLSYS, "ShutdownWithoutLogon", "eq", 0),
    _R("2.3.15.1", "System objects: Require case insensitivity for non-Windows subsystems = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel",
       "ObCaseInsensitive", "eq", 1),
    _R("2.3.15.2", "System objects: Strengthen default permissions of internal system objects = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager", "ProtectionMode", "eq", 1),

    # ---- 2.3.17 UAC ----
    _R("2.3.17.1", "UAC: Admin Approval Mode for the Built-in Administrator account = Enabled",
       _POLSYS, "FilterAdministratorToken", "eq", 1, severity="high"),
    _R("2.3.17.2", "UAC: Behavior of elevation prompt for admins in Admin Approval Mode = Prompt for consent on secure desktop",
       _POLSYS, "ConsentPromptBehaviorAdmin", "eq", 2),
    _R("2.3.17.3", "UAC: Behavior of elevation prompt for standard users = Automatically deny",
       _POLSYS, "ConsentPromptBehaviorUser", "eq", 0),
    _R("2.3.17.4", "UAC: Detect application installations and prompt for elevation = Enabled",
       _POLSYS, "EnableInstallerDetection", "eq", 1),
    _R("2.3.17.5", "UAC: Only elevate UIAccess applications installed in secure locations",
       _POLSYS, "ValidateAdminCodeSignatures", "eq", 0),
    _R("2.3.17.7", "UAC: Switch to the secure desktop when prompting for elevation = Enabled",
       _POLSYS, "PromptOnSecureDesktop", "eq", 1),
    _R("2.3.17.8", "UAC: Virtualize file and registry write failures to per-user locations = Enabled",
       _POLSYS, "EnableVirtualization", "eq", 1, severity="low"),

    # ================= Section 18 — Administrative Templates =================
    _R("18.1.1.1", "Prevent enabling lock screen camera = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
       "NoLockScreenCamera", "eq", 1, severity="low"),
    _R("18.1.1.2", "Prevent enabling lock screen slide show = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
       "NoLockScreenSlideshow", "eq", 1, severity="low"),
    _R("18.1.2.2", "Allow users to enable online speech recognition services = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization",
       "AllowInputPersonalization", "eq", 0, severity="low"),

    _R("18.4.1", "Apply UAC restrictions to local accounts on network logons = Enabled",
       _POLSYS, "LocalAccountTokenFilterPolicy", "eq", 0, scope="MS"),
    _R("18.4.2", "Configure SMB v1 client driver = Disable driver",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", "eq", 4,
       severity="high", restart=True),
    _R("18.4.3", "Configure SMB v1 server = Disabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
       "SMB1", "eq", 0, severity="high", restart=True),
    _R("18.4.5", "Enable Structured Exception Handling Overwrite Protection (SEHOP) = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
       "DisableExceptionChainValidation", "eq", 0),
    _R("18.4.7", "WDigest Authentication = Disabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
       "UseLogonCredential", "eq", 0, severity="high"),

    _R("18.5.1", "MSS: (AutoAdminLogon) Enable Automatic Logon = Disabled",
       _WINLOGON, "AutoAdminLogon", "eq", 0, set="0", rtype="string", severity="high"),
    _R("18.5.2", "MSS: (DisableIPSourceRouting IPv6) = Highest protection",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
       "DisableIPSourceRouting", "eq", 2),
    _R("18.5.3", "MSS: (DisableIPSourceRouting) = Highest protection",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
       "DisableIPSourceRouting", "eq", 2),
    _R("18.5.6", "MSS: (NoNameReleaseOnDemand) = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
       "NoNameReleaseOnDemand", "eq", 1),
    _R("18.5.8", "MSS: (SafeDllSearchMode) = Enabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
       "SafeDllSearchMode", "eq", 1),
    _R("18.5.9", "MSS: (ScreenSaverGracePeriod) <= 5 seconds",
       _WINLOGON, "ScreenSaverGracePeriod", "lte", 5, set="5", rtype="string",
       severity="low"),
    _R("18.5.12", "MSS: (WarningLevel) Percentage threshold for security event log <= 90",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security",
       "WarningLevel", "lte", 90, set=90, severity="low"),

    _R("18.6.4.1", "Configure DNS over HTTPS / mDNS: Turn off mDNS = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
       "EnableMulticast", "eq", 0),
    _R("18.6.4.4", "Turn off multicast name resolution (LLMNR) = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
       "EnableMulticast", "eq", 0, severity="high"),
    _R("18.6.7.4", "Enable insecure guest logons: remote mailslots (LanmanServer) = Disabled",
       r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
       "EnableMailslots", "eq", 0),
    _R("18.6.8.5", "Enable insecure guest logons = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
       "AllowInsecureGuestAuth", "eq", 0, severity="high"),
    _R("18.6.11.2", "Prohibit installation and configuration of Network Bridge = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
       "NC_AllowNetBridge_NLA", "eq", 0, severity="low"),
    _R("18.6.11.3", "Prohibit use of Internet Connection Sharing = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
       "NC_ShowSharedAccessUI", "eq", 0, severity="low"),

    _R("18.7.1", "Allow Print Spooler to accept client connections = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers",
       "RegisterSpoolerRemoteRpcEndPoint", "eq", 2, severity="high"),
    _R("18.7.10", "Limits print driver installation to Administrators = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint",
       "RestrictDriverInstallationToAdministrators", "eq", 1, severity="high"),

    _R("18.9.4.1", "Encryption Oracle Remediation = Force Updated Clients",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters",
       "AllowEncryptionOracle", "eq", 0),
    _R("18.9.4.2", "Remote host allows delegation of non-exportable credentials = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
       "AllowProtectedCreds", "eq", 1),
    _R("18.9.13.1", "Boot-Start Driver Initialization Policy = Good, unknown and bad but critical",
       r"HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch",
       "DriverLoadPolicy", "eq", 3),
    _R("18.9.19.2", "Configure registry policy processing: Do not apply during periodic background = FALSE",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
       "NoBackgroundPolicy", "eq", 0),
    _R("18.9.19.3", "Configure registry policy processing: Process even if GPOs have not changed = TRUE",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
       "NoGPOListChanges", "eq", 0),

    _R("18.10.8.2", "Disallow Autoplay for non-volume devices / AutoRun default = Do not execute",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
       "NoAutorun", "eq", 1),
    _R("18.10.8.3", "Turn off Autoplay = Enabled: All drives",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
       "NoDriveTypeAutoRun", "eq", 255, severity="high"),
    _R("18.10.13.1", "Turn off cloud consumer account state content = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
       "DisableConsumerAccountStateContent", "eq", 1, severity="low"),
    _R("18.10.13.3", "Turn off Microsoft consumer experiences = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
       "DisableWindowsConsumerFeatures", "eq", 1, severity="low"),
    _R("18.10.15.1", "Do not display the password reveal button = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI",
       "DisablePasswordReveal", "eq", 1),
    _R("18.10.15.2", "Enumerate administrator accounts on elevation = Disabled",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI",
       "EnumerateAdministrators", "eq", 0),
    _R("18.10.16.1", "Allow Diagnostic Data = Diagnostic data off or Send required",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
       "AllowTelemetry", "lte", 1, set=1, severity="low"),

    _R("18.10.26.1.1", "Application event log: Control Event Log behavior when full = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application",
       "Retention", "eq_str", "0", set="0", rtype="string", severity="low"),
    _R("18.10.26.1.2", "Application event log: Maximum log size >= 32768 KB",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application",
       "MaxSize", "gte", 32768, set=32768, severity="low"),
    _R("18.10.26.2.1", "Security event log: Control Event Log behavior when full = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",
       "Retention", "eq_str", "0", set="0", rtype="string"),
    _R("18.10.26.2.2", "Security event log: Maximum log size >= 196608 KB",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",
       "MaxSize", "gte", 196608, set=196608),
    _R("18.10.26.3.1", "Setup event log: Control Event Log behavior when full = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup",
       "Retention", "eq_str", "0", set="0", rtype="string", severity="low"),
    _R("18.10.26.3.2", "Setup event log: Maximum log size >= 32768 KB",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup",
       "MaxSize", "gte", 32768, set=32768, severity="low"),
    _R("18.10.26.4.1", "System event log: Control Event Log behavior when full = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System",
       "Retention", "eq_str", "0", set="0", rtype="string", severity="low"),
    _R("18.10.26.4.2", "System event log: Maximum log size >= 32768 KB",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System",
       "MaxSize", "gte", 32768, set=32768, severity="low"),

    _R("18.10.29.2", "Configure Windows Defender SmartScreen / Do not apply Mark of the Web = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Attachment Manager",
       "ScanWithAntiVirus", "ne", 1, set=3),
    _R("18.10.29.3", "Turn off Data Execution Prevention for Explorer = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
       "NoDataExecutionPrevention", "eq", 0),
    _R("18.10.29.4", "Turn off heap termination on corruption = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
       "NoHeapTerminationOnCorruption", "eq", 0),
    _R("18.10.29.5", "Turn off shell protocol protected mode = Disabled",
       r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
       "PreXPSP2ShellProtocolBehavior", "eq", 0),
    _R("18.10.42.1", "Block all consumer Microsoft account user authentication = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount", "DisableUserAuth", "eq", 1),

    _R("18.10.43.5.1", "MAPS: Configure local setting override for reporting = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
       "LocalSettingOverrideSpynetReporting", "eq", 0),
    _R("18.10.43.6.1.1", "Configure Attack Surface Reduction rules = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR",
       "ExploitGuard_ASR_Rules", "eq", 1),
    _R("18.10.43.6.3.1", "Prevent users and apps from accessing dangerous websites = Block",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
       "EnableNetworkProtection", "eq", 1),
    _R("18.10.43.7.1", "Enable file hash computation feature = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine",
       "EnableFileHashComputation", "eq", 1, severity="low"),
    _R("18.10.43.10.2", "Scan all downloaded files and attachments = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
       "DisableIOAVProtection", "eq", 0),
    _R("18.10.43.10.3", "Turn off real-time protection = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
       "DisableRealtimeMonitoring", "eq", 0, severity="high"),
    _R("18.10.43.10.4", "Turn on behavior monitoring = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
       "DisableBehaviorMonitoring", "eq", 0),
    _R("18.10.43.16", "Configure detection for potentially unwanted applications = Block",
       _DEFENDER, "PUAProtection", "eq", 1),

    _R("18.10.51.1", "Prevent the usage of OneDrive for file storage = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive",
       "DisableFileSyncNGSC", "eq", 1, severity="low"),

    _R("18.10.57.2.2", "Do not allow passwords to be saved (RDS) = Enabled",
       _TS, "DisablePasswordSaving", "eq", 1),
    _R("18.10.57.3.3.3", "Do not allow drive redirection (RDS) = Enabled",
       _TS, "fDisableCdm", "eq", 1),
    _R("18.10.57.3.9.1", "Always prompt for password upon connection (RDS) = Enabled",
       _TS, "fPromptForPassword", "eq", 1),
    _R("18.10.57.3.9.2", "Require secure RPC communication (RDS) = Enabled",
       _TS, "fEncryptRPCTraffic", "eq", 1),
    _R("18.10.57.3.9.3", "Require use of specific security layer for RDP (RDS) = SSL",
       _TS, "SecurityLayer", "eq", 2),
    _R("18.10.57.3.9.4", "Require user authentication for remote connections (NLA) = Enabled",
       _TS, "UserAuthentication", "eq", 1, severity="high"),
    _R("18.10.57.3.9.5", "Set client connection encryption level = High Level",
       _TS, "MinEncryptionLevel", "eq", 3),

    _R("18.10.58.1", "Prevent downloading of enclosures (RSS feeds) = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds",
       "DisableEnclosureDownload", "eq", 1, severity="low"),
    _R("18.10.59.3", "Allow indexing of encrypted files = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
       "AllowIndexingEncryptedStoresOrItems", "eq", 0),
    _R("18.10.76.2.1", "Configure Windows Defender SmartScreen = Warn and prevent bypass",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
       "EnableSmartScreen", "eq", 1),
    _R("18.10.80.2", "Allow Windows Ink Workspace = Disabled or on above lock only",
       r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
       "AllowWindowsInkWorkspace", "lte", 1, set=1, severity="low"),
    _R("18.10.81.1", "Allow user control over installs = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
       "EnableUserControl", "eq", 0),
    _R("18.10.81.2", "Always install with elevated privileges = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
       "AlwaysInstallElevated", "eq", 0, severity="high"),
    _R("18.10.82.1", "Allow Basic authentication for MPR notifications = Disabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
       "EnableMPRNotifications", "eq", 0),
    _R("18.10.82.2", "Sign-in and lock last interactive user automatically after a restart = Disabled",
       _POLSYS, "DisableAutomaticRestartSignOn", "eq", 1),

    _R("18.10.89.1.1", "WinRM Client: Allow Basic authentication = Disabled",
       _WINRM_C, "AllowBasic", "eq", 0, severity="high"),
    _R("18.10.89.1.2", "WinRM Client: Allow unencrypted traffic = Disabled",
       _WINRM_C, "AllowUnencryptedTraffic", "eq", 0, severity="high"),
    _R("18.10.89.1.3", "WinRM Client: Disallow Digest authentication = Enabled",
       _WINRM_C, "AllowDigest", "eq", 0),
    _R("18.10.89.2.1", "WinRM Service: Allow Basic authentication = Disabled",
       _WINRM_S, "AllowBasic", "eq", 0, severity="high"),
    _R("18.10.89.2.3", "WinRM Service: Allow unencrypted traffic = Disabled",
       _WINRM_S, "AllowUnencryptedTraffic", "eq", 0, severity="high"),
    _R("18.10.89.2.4", "WinRM Service: Disallow WinRM from storing RunAs credentials = Enabled",
       _WINRM_S, "DisableRunAs", "eq", 1),
    _R("18.10.93.2.1", "Configure Automatic Updates = Enabled",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
       "NoAutoUpdate", "eq", 0),
    _R("18.10.93.2.2", "Configure Automatic Updates: Scheduled install day = Every day",
       r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
       "ScheduledInstallDay", "eq", 0, severity="low"),
]


def get_registry_properties() -> Dict[str, List[str]]:
    """
    ``{registry path: [property names]}`` the rule engine actually reads.

    The collector uses this to fetch named values only. Dumping whole keys used
    to sweep up neighbouring secrets — ``Winlogon`` is read for AutoAdminLogon
    and also holds ``DefaultPassword`` in cleartext when autologon is on.
    """
    wanted: Dict[str, set] = {}
    for c in REGISTRY_CHECKS:
        wanted.setdefault(c["path"], set()).add(c["prop"])
    # Properties read by rules that are not in the table.
    wanted.setdefault(_NETLOGON, set()).add("VulnerableChannelAllowList")  # 2.3.5.2
    return {path: sorted(props) for path, props in sorted(wanted.items())}


def get_registry_paths() -> List[str]:
    """Distinct registry paths referenced by REGISTRY_CHECKS (+ non-table reads)."""
    return list(get_registry_properties())


# ============================================================ #
#  Rule builders                                              #
# ============================================================ #

def _add(rules, id, section, title, severity, level, check_fn, evidence_fn,
         remediation, description="", manual=False, scope="all", audit_key="",
         versions=None, data_sections=None):
    rules.append(WindowsCISRule(
        id=id, section=section, title=title,
        description=description or title,
        severity=severity, level=level,
        check_fn=check_fn, evidence_fn=evidence_fn,
        remediation=remediation, manual=manual, scored=not manual,
        scope=scope, audit_key=audit_key,
        versions=versions or ["win_2025"],
        data_sections=list(data_sections or []),
    ))


def _build_section1(rules):
    """1.x Account Policies — secedit [System Access]."""
    def secpol_rule(sec, title, key, ok, sev="high", remediation=None):
        _add(rules, f"WIN-2025-{sec}", sec, title, sev, "L1",
             check_fn=(lambda d, k=key, f=ok: f(_secpol_int(d, k))),
             evidence_fn=(lambda d, k=key: f"{k} = {_secpol_value(d, k)}"),
             remediation=remediation or f"Account Policies > set '{title}'.",
             audit_key=key, data_sections=["SECURITY_POLICY"])

    secpol_rule("1.1.1", "Enforce password history >= 24 passwords",
                "PasswordHistorySize", lambda v: v is not None and v >= 24)
    secpol_rule("1.1.2", "Maximum password age <= 365 days, not 0",
                "MaximumPasswordAge", lambda v: v is not None and 0 < v <= 365)
    secpol_rule("1.1.3", "Minimum password age >= 1 day",
                "MinimumPasswordAge", lambda v: v is not None and v >= 1, sev="medium")
    secpol_rule("1.1.4", "Minimum password length >= 14 characters",
                "MinimumPasswordLength", lambda v: v is not None and v >= 14)
    secpol_rule("1.1.5", "Password must meet complexity requirements = Enabled",
                "PasswordComplexity", lambda v: v == 1)
    # 1.1.6 relax min length -> REGISTRY_CHECKS
    secpol_rule("1.1.7", "Store passwords using reversible encryption = Disabled",
                "ClearTextPassword", lambda v: v == 0)

    secpol_rule("1.2.1", "Account lockout duration >= 15 minutes",
                "LockoutDuration", lambda v: v is not None and v >= 15)
    secpol_rule("1.2.2", "Account lockout threshold <= 5, not 0",
                "LockoutBadCount", lambda v: v is not None and 0 < v <= 5)
    _add(rules, "WIN-2025-1.2.3",
         "1.2.3", "Allow Administrator account lockout = Enabled", "medium", "L1",
         check_fn=lambda d: False,
         evidence_fn=lambda d: "Manual: verify AllowAdministratorLockout is Enabled (secpol.msc).",
         remediation="Account Policies > Account Lockout > Allow Administrator account lockout: Enabled.",
         manual=True, scope="MS")
    secpol_rule("1.2.4", "Reset account lockout counter after >= 15 minutes",
                "ResetLockoutCount", lambda v: v is not None and v >= 15, sev="medium")


def _build_user_rights(rules):
    """2.2 User Rights Assignment — secedit [Privilege Rights]."""
    # (section, title, privilege, mode, [names], level, scope, severity)
    URA = [
        ("2.2.1", "Access Credential Manager as a trusted caller = No One",
         "SeTrustedCredManAccessPrivilege", "empty", [], "L1", "all", "medium"),
        ("2.2.2", "Access this computer from the network (DC)",
         "SeNetworkLogonRight", "exact",
         ["Administrators", "Authenticated Users", "ENTERPRISE DOMAIN CONTROLLERS"],
         "L1", "DC", "medium"),
        ("2.2.3", "Access this computer from the network (MS)",
         "SeNetworkLogonRight", "exact", ["Administrators", "Authenticated Users"],
         "L1", "MS", "medium"),
        ("2.2.4", "Act as part of the operating system = No One",
         "SeTcbPrivilege", "empty", [], "L1", "all", "high"),
        ("2.2.6", "Adjust memory quotas for a process",
         "SeIncreaseQuotaPrivilege", "exact",
         ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"], "L1", "all", "low"),
        ("2.2.7", "Allow log on locally (DC)", "SeInteractiveLogonRight", "exact",
         ["Administrators", "ENTERPRISE DOMAIN CONTROLLERS"], "L1", "DC", "medium"),
        ("2.2.8", "Allow log on locally (MS)", "SeInteractiveLogonRight", "exact",
         ["Administrators"], "L1", "MS", "medium"),
        ("2.2.9", "Allow log on through Remote Desktop Services (DC)",
         "SeRemoteInteractiveLogonRight", "exact", ["Administrators"], "L1", "DC", "high"),
        ("2.2.10", "Allow log on through Remote Desktop Services (MS)",
         "SeRemoteInteractiveLogonRight", "exact",
         ["Administrators", "Remote Desktop Users"], "L1", "MS", "high"),
        ("2.2.11", "Back up files and directories", "SeBackupPrivilege", "exact",
         ["Administrators"], "L1", "all", "medium"),
        ("2.2.12", "Change the system time", "SeSystemtimePrivilege", "exact",
         ["Administrators", "LOCAL SERVICE"], "L1", "all", "low"),
        ("2.2.13", "Change the time zone", "SeTimeZonePrivilege", "exact",
         ["Administrators", "LOCAL SERVICE"], "L1", "all", "low"),
        ("2.2.14", "Create a pagefile", "SeCreatePagefilePrivilege", "exact",
         ["Administrators"], "L1", "all", "low"),
        ("2.2.15", "Create a token object = No One", "SeCreateTokenPrivilege",
         "empty", [], "L1", "all", "high"),
        ("2.2.16", "Create global objects", "SeCreateGlobalPrivilege", "exact",
         ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"],
         "L1", "all", "medium"),
        ("2.2.17", "Create permanent shared objects = No One",
         "SeCreatePermanentPrivilege", "empty", [], "L1", "all", "medium"),
        ("2.2.18", "Create symbolic links (DC)", "SeCreateSymbolicLinkPrivilege",
         "exact", ["Administrators"], "L1", "DC", "low"),
        ("2.2.19", "Create symbolic links (MS)", "SeCreateSymbolicLinkPrivilege",
         "exact", ["Administrators", "NT VIRTUAL MACHINE\\Virtual Machines"],
         "L1", "MS", "low"),
        ("2.2.20", "Debug programs", "SeDebugPrivilege", "exact",
         ["Administrators"], "L1", "all", "high"),
        ("2.2.21", "Deny access to this computer from the network includes Guests (DC)",
         "SeDenyNetworkLogonRight", "include", ["Guests"], "L1", "DC", "medium"),
        ("2.2.22", "Deny access to this computer from the network includes Guests, Local account (MS)",
         "SeDenyNetworkLogonRight", "include", ["Guests", "Local account"], "L1", "MS", "medium"),
        ("2.2.23", "Deny log on as a batch job includes Guests",
         "SeDenyBatchLogonRight", "include", ["Guests"], "L1", "all", "medium"),
        ("2.2.24", "Deny log on as a service includes Guests",
         "SeDenyServiceLogonRight", "include", ["Guests"], "L1", "all", "medium"),
        ("2.2.25", "Deny log on locally includes Guests",
         "SeDenyInteractiveLogonRight", "include", ["Guests"], "L1", "all", "medium"),
        ("2.2.26", "Deny log on through Remote Desktop Services includes Guests (DC)",
         "SeDenyRemoteInteractiveLogonRight", "include", ["Guests"], "L1", "DC", "high"),
        ("2.2.27", "Deny log on through Remote Desktop Services includes Guests, Local account (MS)",
         "SeDenyRemoteInteractiveLogonRight", "include", ["Guests", "Local account"],
         "L1", "MS", "high"),
        ("2.2.28", "Enable computer and user accounts to be trusted for delegation (DC)",
         "SeEnableDelegationPrivilege", "exact", ["Administrators"], "L1", "DC", "medium"),
        ("2.2.29", "Enable computer and user accounts to be trusted for delegation = No One (MS)",
         "SeEnableDelegationPrivilege", "empty", [], "L1", "MS", "medium"),
        ("2.2.30", "Force shutdown from a remote system", "SeRemoteShutdownPrivilege",
         "exact", ["Administrators"], "L1", "all", "low"),
        ("2.2.31", "Generate security audits", "SeAuditPrivilege", "exact",
         ["LOCAL SERVICE", "NETWORK SERVICE"], "L1", "all", "medium"),
        ("2.2.32", "Impersonate a client after authentication (DC)",
         "SeImpersonatePrivilege", "exact",
         ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"],
         "L1", "DC", "medium"),
        ("2.2.34", "Increase scheduling priority", "SeIncreaseBasePriorityPrivilege",
         "exact", ["Administrators", "Window Manager\\Window Manager Group"],
         "L1", "all", "low"),
        ("2.2.35", "Load and unload device drivers", "SeLoadDriverPrivilege",
         "exact", ["Administrators"], "L1", "all", "medium"),
        ("2.2.36", "Lock pages in memory = No One", "SeLockMemoryPrivilege",
         "empty", [], "L1", "all", "low"),
        ("2.2.37", "Log on as a batch job (DC)", "SeBatchLogonRight", "exact",
         ["Administrators"], "L2", "DC", "low"),
        ("2.2.38", "Manage auditing and security log (DC)", "SeSecurityPrivilege",
         "exact", ["Administrators"], "L1", "DC", "medium"),
        ("2.2.39", "Manage auditing and security log (MS)", "SeSecurityPrivilege",
         "exact", ["Administrators"], "L1", "MS", "medium"),
        ("2.2.40", "Modify an object label = No One", "SeRelabelPrivilege",
         "empty", [], "L1", "all", "low"),
        ("2.2.41", "Modify firmware environment values", "SeSystemEnvironmentPrivilege",
         "exact", ["Administrators"], "L1", "all", "low"),
        ("2.2.42", "Perform volume maintenance tasks", "SeManageVolumePrivilege",
         "exact", ["Administrators"], "L1", "all", "low"),
        ("2.2.43", "Profile single process", "SeProfileSingleProcessPrivilege",
         "exact", ["Administrators"], "L1", "all", "low"),
        ("2.2.44", "Profile system performance", "SeSystemProfilePrivilege",
         "exact", ["Administrators", "NT SERVICE\\WdiServiceHost"], "L1", "all", "low"),
        ("2.2.45", "Replace a process level token", "SeAssignPrimaryTokenPrivilege",
         "exact", ["LOCAL SERVICE", "NETWORK SERVICE"], "L1", "all", "low"),
        ("2.2.46", "Restore files and directories", "SeRestorePrivilege", "exact",
         ["Administrators"], "L1", "all", "medium"),
        ("2.2.47", "Shut down the system", "SeShutdownPrivilege", "exact",
         ["Administrators"], "L1", "all", "low"),
        ("2.2.48", "Synchronize directory service data = No One (DC)",
         "SeSyncAgentPrivilege", "empty", [], "L1", "DC", "medium"),
        ("2.2.49", "Take ownership of files or other objects", "SeTakeOwnershipPrivilege",
         "exact", ["Administrators"], "L1", "all", "medium"),
    ]
    for sec, title, priv, mode, names, level, scope, sev in URA:
        if mode == "empty":
            fn = (lambda d, p=priv: _rights_empty(d, p))
        elif mode == "include":
            fn = (lambda d, p=priv, n=names: _rights_include(d, p, n))
        else:
            fn = (lambda d, p=priv, n=names: _rights_exact(d, p, n))
        _add(rules, f"WIN-2025-{sec}", sec,
             f"Ensure '{title}'", sev, level,
             check_fn=fn,
             evidence_fn=(lambda d, p=priv: f"{p} = {_user_right_sids(d, p)}"),
             remediation=f"User Rights Assignment > set '{title}'.",
             scope=scope, audit_key=priv,
             data_sections=["USER_RIGHTS", "SECURITY_POLICY"])

    # 2.2.33 Impersonate a client (MS) — set may include IIS_IUSRS when IIS present,
    # so an exact match false-fails IIS hosts; verified manually.
    _add(rules, "WIN-2025-2.2.33", "2.2.33",
         "Ensure 'Impersonate a client after authentication' is set correctly (MS)",
         "medium", "L1",
         check_fn=lambda d: _rights_include(
             d, "SeImpersonatePrivilege",
             ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"]),
         evidence_fn=lambda d: f"SeImpersonatePrivilege = {_user_right_sids(d, 'SeImpersonatePrivilege')}",
         remediation="Set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE (+ IIS_IUSRS when IIS is installed).",
         scope="MS", audit_key="SeImpersonatePrivilege",
         data_sections=["USER_RIGHTS", "SECURITY_POLICY"])


def _build_security_options_misc(rules):
    """2.3 Security Options that are not simple registry DWORDs."""
    _add(rules, "WIN-2025-2.3.1.1", "2.3.1.1",
         "Ensure 'Accounts: Guest account status' is set to 'Disabled'", "high", "L1",
         check_fn=_guest_disabled,
         evidence_fn=lambda d: _ev_section(d, "LOCAL_USERS", 300),
         remediation="Disable-LocalUser -Name Guest.", scope="MS", audit_key="Guest",
         data_sections=["LOCAL_USERS"])

    for sec, title in [
        ("2.3.1.3", "Accounts: Rename administrator account"),
        ("2.3.1.4", "Accounts: Rename guest account"),
        ("2.3.7.4", "Interactive logon: Message text for users attempting to log on"),
        ("2.3.7.5", "Interactive logon: Message title for users attempting to log on"),
        ("2.3.10.6", "Network access: Named Pipes that can be accessed anonymously (DC)"),
        ("2.3.10.8", "Network access: Remotely accessible registry paths"),
        ("2.3.10.9", "Network access: Remotely accessible registry paths and sub-paths"),
        ("2.3.10.11", "Network access: Restrict clients allowed to make remote calls to SAM (MS)"),
        ("2.3.11.6", "Network security: Force logoff when logon hours expire"),
        ("2.3.5.1", "Domain controller: Allow server operators to schedule tasks (DC)"),
    ]:
        scope = "DC" if "(DC)" in title else ("MS" if "(MS)" in title else "all")
        _add(rules, f"WIN-2025-{sec}", sec, f"Ensure '{title}' is configured",
             "medium", "L1",
             check_fn=lambda d: False,
             evidence_fn=(lambda d, t=title: f"Manual verification required: {t}"),
             remediation=f"Configure '{title}' per the CIS benchmark (manual / GPO).",
             manual=True, scope=scope)

    # 2.3.5.2 DC: Allow vulnerable Netlogon secure channel connections = Not Configured
    _add(rules, "WIN-2025-2.3.5.2", "2.3.5.2",
         "Ensure 'DC: Allow vulnerable Netlogon secure channel connections' is 'Not Configured'",
         "high", "L1",
         check_fn=lambda d: _reg(d, _NETLOGON, "VulnerableChannelAllowList") is None,
         evidence_fn=lambda d: f"VulnerableChannelAllowList = {_reg(d, _NETLOGON, 'VulnerableChannelAllowList')}",
         remediation="Remove any VulnerableChannelAllowList entry (leave Not Configured).",
         scope="DC", audit_key="VulnerableChannelAllowList",
         data_sections=["REGISTRY"])


def _build_registry_rules(rules, version="win_2025"):
    """Section 2.3 (registry) + Section 18 — generated from REGISTRY_CHECKS."""
    for c in REGISTRY_CHECKS:
        sec = c["section"]
        path, prop, op, target = c["path"], c["prop"], c["op"], c["target"]
        _add(rules, f"WIN-{version.split('_')[1]}-{sec}", sec,
             f"Ensure '{c['title']}'", c["severity"], c["level"],
             check_fn=(lambda d, p=path, pr=prop, o=op, t=target: _pred(_reg(d, p, pr), o, t)),
             evidence_fn=(lambda d, p=path, pr=prop: f"{pr} = {_reg(d, p, pr)}"),
             remediation=f"Set-ItemProperty '{path}' -Name {prop} to the CIS value.",
             scope=c["scope"], audit_key=f"{path}\\{prop}",
             versions=[version], data_sections=["REGISTRY"])


def _build_firewall(rules):
    """9.x Windows Defender Firewall — Get-NetFirewallProfile."""
    specs = {
        "Domain": ("9.1", "domainfw.log", 5),
        "Private": ("9.2", "privatefw.log", 5),
        "Public": ("9.3", "publicfw.log", 5),
    }
    for prof, (base, logfile, _) in specs.items():
        n = 1
        def fwrule(sub, title, fn, sev="medium"):
            _add(rules, f"WIN-2025-{base}.{sub}", f"{base}.{sub}",
                 f"Ensure 'Windows Firewall: {prof}: {title}'", sev, "L1",
                 check_fn=fn,
                 evidence_fn=(lambda d, p=prof: _json_section(d, "FIREWALL_PROFILES") and
                              f"{p}: {_firewall_profile(d, p)}" or "(no firewall data)"),
                 remediation=f"Set-NetFirewallProfile -Profile {prof} accordingly.",
                 audit_key=f"firewall/{prof}", data_sections=["FIREWALL_PROFILES"])

        fwrule("1", "Firewall state = On", (lambda d, p=prof: _fw_enabled(d, p)), "high")
        fwrule("2", "Inbound connections = Block", (lambda d, p=prof: _fw_inbound_block(d, p)), "high")
        fwrule("3", "Display a notification = No",
               (lambda d, p=prof: _fw_bool(_firewall_profile(d, p), "NotifyOnListen", False)))
        if prof == "Public":
            fwrule("4", "Apply local firewall rules = No",
                   (lambda d, p=prof: _fw_bool(_firewall_profile(d, p), "AllowLocalFirewallRules", False)))
            fwrule("5", "Apply local connection security rules = No",
                   (lambda d, p=prof: _fw_bool(_firewall_profile(d, p), "AllowLocalIPsecRules", False)))
            ln, sz, dr, sc = "6", "7", "8", "9"
        else:
            ln, sz, dr, sc = "4", "5", "6", "7"
        fwrule(ln, f"Logging: Name = %SystemRoot%...{logfile}",
               (lambda d, p=prof, lf=logfile: _fw_logname(d, p, lf)), "low")
        fwrule(sz, "Logging: Size limit >= 16384 KB",
               (lambda d, p=prof: _fw_int_gte(d, p, "LogMaxSizeKilobytes", 16384)), "low")
        fwrule(dr, "Logging: Log dropped packets = Yes",
               (lambda d, p=prof: _fw_bool(_firewall_profile(d, p), "LogBlocked", True)))
        fwrule(sc, "Logging: Log successful connections = Yes",
               (lambda d, p=prof: _fw_bool(_firewall_profile(d, p), "LogAllowed", True)))


def _build_audit_policy(rules):
    """17.x Advanced Audit Policy — auditpol /get."""
    A = [
        ("17.1.1", "Credential Validation", "Success and Failure", "high", "all"),
        ("17.1.2", "Kerberos Authentication Service", "Success and Failure", "medium", "DC"),
        ("17.1.3", "Kerberos Service Ticket Operations", "Success and Failure", "medium", "DC"),
        ("17.2.1", "Application Group Management", "Success and Failure", "medium", "all"),
        ("17.2.2", "Computer Account Management", "Success", "medium", "DC"),
        ("17.2.3", "Distribution Group Management", "Success", "low", "DC"),
        ("17.2.4", "Other Account Management Events", "Success", "medium", "DC"),
        ("17.2.5", "Security Group Management", "Success", "medium", "all"),
        ("17.2.6", "User Account Management", "Success and Failure", "medium", "all"),
        ("17.3.1", "Plug and Play Events", "Success", "low", "all"),
        ("17.3.2", "Process Creation", "Success", "medium", "all"),
        ("17.4.1", "Directory Service Access", "Failure", "medium", "DC"),
        ("17.4.2", "Directory Service Changes", "Success", "medium", "DC"),
        ("17.5.1", "Account Lockout", "Failure", "high", "all"),
        ("17.5.2", "Group Membership", "Success", "medium", "all"),
        ("17.5.3", "Logoff", "Success", "low", "all"),
        ("17.5.4", "Logon", "Success and Failure", "high", "all"),
        ("17.5.5", "Other Logon/Logoff Events", "Success and Failure", "medium", "all"),
        ("17.5.6", "Special Logon", "Success", "medium", "all"),
        ("17.6.1", "Detailed File Share", "Failure", "medium", "all"),
        ("17.6.2", "File Share", "Success and Failure", "medium", "all"),
        ("17.6.3", "Other Object Access Events", "Success and Failure", "medium", "all"),
        ("17.6.4", "Removable Storage", "Success and Failure", "medium", "all"),
        ("17.7.1", "Audit Policy Change", "Success", "high", "all"),
        ("17.7.2", "Authentication Policy Change", "Success", "medium", "all"),
        ("17.7.3", "Authorization Policy Change", "Success", "medium", "all"),
        ("17.7.4", "MPSSVC Rule-Level Policy Change", "Success and Failure", "medium", "all"),
        ("17.7.5", "Other Policy Change Events", "Failure", "low", "all"),
        ("17.8.1", "Sensitive Privilege Use", "Success and Failure", "high", "all"),
        ("17.9.1", "IPsec Driver", "Success and Failure", "medium", "all"),
        ("17.9.2", "Other System Events", "Success and Failure", "medium", "all"),
        ("17.9.3", "Security State Change", "Success", "high", "all"),
        ("17.9.4", "Security System Extension", "Success", "high", "all"),
        ("17.9.5", "System Integrity", "Success and Failure", "high", "all"),
    ]
    for sec, subcat, expected, sev, scope in A:
        _add(rules, f"WIN-2025-{sec}", sec,
             f"Ensure 'Audit {subcat}' is set to '{expected}'", sev, "L1",
             check_fn=(lambda d, s=subcat, e=expected: _audit_matches(d, s, e)),
             evidence_fn=(lambda d, s=subcat: f"{s}: {_audit_policy_setting(d, s) or '(not found)'}"),
             remediation=f"auditpol /set /subcategory:\"{subcat}\" for '{expected}'.",
             scope=scope, audit_key=f"auditpol/{subcat}",
             data_sections=["AUDIT_POLICY"])


def _build_user_templates(rules):
    """19.x Administrative Templates (User) — HKU-scoped, all manual."""
    U = [
        ("19.5.1.1", "Turn off toast notifications on the lock screen = Enabled"),
        ("19.7.5.1", "Do not preserve zone information in file attachments = Disabled"),
        ("19.7.5.2", "Notify antivirus programs when opening attachments = Enabled"),
        ("19.7.8.1", "Configure Windows spotlight on lock screen = Disabled"),
        ("19.7.26.1", "Prevent users from sharing files within their profile = Enabled"),
        ("19.7.44.1", "Always install with elevated privileges (user) = Disabled"),
    ]
    for sec, title in U:
        _add(rules, f"WIN-2025-{sec}", sec, f"Ensure '{title}'", "low", "L1",
             check_fn=lambda d: False,
             evidence_fn=(lambda d, t=title: f"Manual: HKU per-user policy — {t}"),
             remediation="Configure via User Configuration Group Policy (HKU write, per logged-in user).",
             manual=True, audit_key="HKU")


# ============================================================ #
#  Version builders + dispatch                                #
# ============================================================ #

def build_win2025_cis_rules() -> List[WindowsCISRule]:
    """Full CIS Microsoft Windows Server 2025 Benchmark v1.0.0 rule set."""
    rules: List[WindowsCISRule] = []
    _build_section1(rules)
    _build_user_rights(rules)
    _build_security_options_misc(rules)
    _build_registry_rules(rules, "win_2025")
    _build_firewall(rules)
    _build_audit_policy(rules)
    _build_user_templates(rules)
    return rules


def build_win2022_cis_rules() -> List[WindowsCISRule]:
    """
    CIS Windows Server 2022 Benchmark.

    Win 2022 CIS data pending — will be populated when the CIS file is provided.
    Until then this extends the win_2025 base (superset) so 2022 hosts are still
    audited rather than left unscored.
    """
    rules = build_win2025_cis_rules()
    for r in rules:
        r.versions = ["win_2022"]
    return rules


def build_win2016_cis_rules() -> List[WindowsCISRule]:
    """
    CIS Windows Server 2016 Benchmark.

    Win 2016 CIS data pending — will be populated when the CIS file is provided.
    Extends the win_2025 base (superset) as a functional fallback.
    """
    rules = build_win2025_cis_rules()
    for r in rules:
        r.versions = ["win_2016"]
    return rules


_VERSION_BUILDERS = {
    "win_2016": build_win2016_cis_rules,
    "win_2022": build_win2022_cis_rules,
    "win_2025": build_win2025_cis_rules,
}


def build_windows_cis_rules_for_version(gate: str) -> List[WindowsCISRule]:
    """Return the rule set for a resolved version gate key (defaults to 2025)."""
    return _VERSION_BUILDERS.get(gate, build_win2025_cis_rules)()


# Public dispatcher name (parity with linux build_linux_cis_rules / mssql).
def build_windows_cis_rules(gate: str = "win_2025") -> List[WindowsCISRule]:
    """Dispatcher: build the CIS rule set for the given version gate key."""
    return build_windows_cis_rules_for_version(gate)


def build_all_windows_cis_rules() -> List[WindowsCISRule]:
    """Backward-compatible entry point — the newest (superset) rule set."""
    return build_win2025_cis_rules()


# ============================================================ #
#  Filtering                                                  #
# ============================================================ #

def filter_rules_by_profile(rules: List[WindowsCISRule], profile: str) -> List[WindowsCISRule]:
    """L1 returns only L1 rules (manual controls are L1); FULL returns all."""
    if profile == "L1":
        return [r for r in rules if r.level == "L1"]
    return rules


def filter_rules_by_scope(rules: List[WindowsCISRule], is_dc: bool) -> List[WindowsCISRule]:
    """
    Drop rules that do not apply to this host's role. DC-only rules are skipped
    on member servers and vice-versa; 'all' rules always apply.
    """
    want = "DC" if is_dc else "MS"
    return [r for r in rules if r.scope in ("all", want)]


# ============================================================ #
#  Compliance evaluation                                      #
# ============================================================ #

# Severity weights behind weighted_compliance_pct. Module-level so hardening can
# recompute the same score after it flips results, instead of leaving the audit's
# value frozen next to an updated compliance_pct.
SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "info": 0}
DEFAULT_SEVERITY_WEIGHT = 1

def evaluate_compliance(dump: str, rules: List[WindowsCISRule]) -> Dict[str, Any]:
    """
    Evaluate all rules against the collected audit dump.

    Manual controls are reported (status "skipped", surfaced NOT_APPLICABLE by
    the service) but never scored. Checks whose data could not be collected are
    reported (status "error", surfaced ERROR by the service) and are likewise
    never scored — an absent secedit export must not read as "No One".
    Returns a summary + per-finding list.
    """
    findings = []
    passed_scored = 0
    failed_scored = 0
    manual_checks = 0
    error_checks = 0
    total_weight = 0
    passed_weight = 0

    for rule in rules:
        if rule.manual:
            manual_checks += 1
            try:
                evidence = rule.evidence_fn(dump)
            except Exception:
                evidence = "(evidence extraction failed)"
            findings.append({
                "id": rule.id, "title": rule.title, "description": rule.description,
                "section": rule.section, "severity": rule.severity, "level": rule.level,
                "compliant": False, "manual": True, "error": False, "status": "skipped",
                "evidence": (
                    f"SKIPPED — manual verification required. {rule.remediation}\n\n"
                    f"Collected evidence:\n{evidence}"
                )[:1000],
                "remediation": rule.remediation,
            })
            continue

        # Unevaluable: the section(s) this rule reads never made it back from
        # the host. Report ERROR rather than guessing a verdict.
        data_failure = rule_data_failure(dump, rule)
        if data_failure:
            error_checks += 1
            findings.append({
                "id": rule.id, "title": rule.title, "description": rule.description,
                "section": rule.section, "severity": rule.severity, "level": rule.level,
                "compliant": False, "manual": False, "error": True, "status": "error",
                "evidence": (
                    f"ERROR — not evaluated: {data_failure}. "
                    "Re-run the audit with an account that can read this data."
                )[:1000],
                "remediation": rule.remediation,
            })
            continue

        try:
            compliant = rule.check_fn(dump)
        except Exception:
            compliant = False
        try:
            evidence = rule.evidence_fn(dump)
        except Exception:
            evidence = "(evidence extraction failed)"

        weight = SEVERITY_WEIGHTS.get(rule.severity, DEFAULT_SEVERITY_WEIGHT)
        if rule.level != "INFO":
            total_weight += weight
            if compliant:
                passed_scored += 1
                passed_weight += weight
            else:
                failed_scored += 1

        findings.append({
            "id": rule.id, "title": rule.title, "description": rule.description,
            "section": rule.section, "severity": rule.severity, "level": rule.level,
            "compliant": compliant, "manual": False, "error": False,
            "status": "pass" if compliant else "fail",
            "evidence": evidence, "remediation": rule.remediation,
        })

    total_scored = passed_scored + failed_scored
    compliance_pct = round(100.0 * passed_scored / total_scored, 2) if total_scored else 0.0
    weighted_pct = round(100.0 * passed_weight / total_weight, 2) if total_weight else 0.0

    return {
        "summary": {
            "total_rules_scored": total_scored,
            "manual_checks": manual_checks,
            "error_checks": error_checks,
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": compliance_pct,
            "weighted_compliance_pct": weighted_pct,
        },
        "findings": findings,
    }


# Backward-compatible alias (older callers imported the private name).
_detect_os_version = _detect_version
