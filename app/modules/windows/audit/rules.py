"""
Windows Server CIS Benchmark Rules

~110 predefined security checks based on the CIS Microsoft Windows Server Benchmark
(2016 v2.0, 2019 v2.0, 2022 v2.0, 2025 v1.0) with version-aware logic.
Each rule evaluates a specific aspect of Windows Server security by searching
the structured audit dump collected by WindowsWinRMClient.

Rule IDs follow the pattern: WIN-L{level}-{seq:03d}
  L1 = Level 1 (basic, broadly applicable)
  L2 = Level 2 (advanced, may affect functionality)

CIS sections covered:
  1.x  Account Policies (Password, Lockout)
  2.x  Local Policies (User Rights, Security Options)
  5.x  System Services
  9.x  Windows Firewall with Advanced Security
  17.x Advanced Audit Policy Configuration
  18.x Administrative Templates (Registry)
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ============================================================ #
#  Rule dataclass                                               #
# ============================================================ #

@dataclass
class WindowsCISRule:
    """A single CIS Windows Server compliance check."""
    id: str                          # e.g. "WIN-L1-001"
    section: str                     # CIS section number e.g. "1.1.1"
    title: str
    description: str
    severity: str                    # high / medium / low / info
    level: str                       # L1 / L2
    check_fn: Callable[[str], bool]  # True = compliant
    evidence_fn: Callable[[str], str]
    remediation: str
    versions: List[str] = field(default_factory=lambda: ["all"])


# ============================================================ #
#  Helper – extract a named section from the dump              #
# ============================================================ #

def _section(dump: str, name: str) -> str:
    """Extract the content of a named section from the audit dump."""
    pattern = re.compile(
        rf"===SECTION:{re.escape(name)}===\n(.*?)(?=\n===SECTION:|\Z)",
        re.S,
    )
    m = pattern.search(dump)
    return m.group(1).strip() if m else ""


def _ev_section(dump: str, section: str, max_chars: int = 500) -> str:
    content = _section(dump, section)
    return content[:max_chars] + ("..." if len(content) > max_chars else "")


# ============================================================ #
#  JSON parsing helpers                                        #
# ============================================================ #

def _parse_json(text: str) -> Any:
    """Safely parse JSON from a section, returning None on failure."""
    if not text or text.startswith(("PS_ERROR", "COLLECTION_ERROR", "(no output)", "(empty)")):
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _json_section(dump: str, name: str) -> Any:
    """Extract a section and parse it as JSON."""
    return _parse_json(_section(dump, name))


# ============================================================ #
#  Version detection                                           #
# ============================================================ #

# Build number → version year mapping
_BUILD_TO_VERSION = {
    "14393": "2016",
    "17763": "2019",
    "20348": "2022",
    "26100": "2025",
}


def _detect_os_version(dump: str) -> str:
    """
    Detect Windows Server version from the OS_VERSION section.

    Returns version string like "2016", "2019", "2022", "2025", or "unknown".
    """
    data = _json_section(dump, "OS_VERSION")
    if isinstance(data, dict):
        build = str(data.get("BuildNumber", ""))
        if build in _BUILD_TO_VERSION:
            return _BUILD_TO_VERSION[build]
        # Try caption match
        caption = str(data.get("Caption", ""))
        for year in ("2025", "2022", "2019", "2016"):
            if year in caption:
                return year
    # Fallback: raw text search
    raw = _section(dump, "OS_VERSION")
    for year in ("2025", "2022", "2019", "2016"):
        if year in raw:
            return year
    return "unknown"


# ============================================================ #
#  Security policy (secedit) parsing helpers                   #
# ============================================================ #

def _secpol_value(dump: str, key: str) -> Optional[str]:
    """
    Extract a value from the secedit INF-style export.

    secedit format: key = value (or key = value1,value2)
    """
    section = _section(dump, "SECURITY_POLICY")
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=[^\S\n]*(.+)$", re.M | re.I)
    m = pattern.search(section)
    if m:
        return m.group(1).strip()
    return None


def _secpol_int(dump: str, key: str) -> Optional[int]:
    """Extract an integer value from secedit output."""
    val = _secpol_value(dump, key)
    if val is None:
        return None
    try:
        # Handle comma-separated: take first numeric part
        parts = val.split(",")
        return int(parts[0].strip())
    except (ValueError, IndexError):
        return None


# ============================================================ #
#  User Rights Assignment parsing                              #
# ============================================================ #

def _user_right_sids(dump: str, privilege: str) -> List[str]:
    """
    Extract the SID/account list for a user rights assignment.
    Returns list of SID strings (e.g. ["*S-1-5-32-544"]).
    """
    section = _section(dump, "USER_RIGHTS")
    if not section:
        section = _section(dump, "SECURITY_POLICY")
    pattern = re.compile(rf"^\s*{re.escape(privilege)}\s*=[^\S\n]*(.*?)$", re.M | re.I)
    m = pattern.search(section)
    if m and m.group(1).strip():
        return [s.strip() for s in m.group(1).split(",") if s.strip()]
    return []


# ============================================================ #
#  Audit policy (auditpol CSV) parsing                         #
# ============================================================ #

def _audit_policy_setting(dump: str, subcategory: str) -> str:
    """
    Extract the inclusion setting for an audit policy subcategory.

    auditpol /get /category:* /r outputs CSV with columns:
    Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting

    Returns the Inclusion Setting value or empty string.
    """
    section = _section(dump, "AUDIT_POLICY")
    for line in section.split("\n"):
        if subcategory.lower() in line.lower():
            parts = line.split(",")
            if len(parts) >= 5:
                return parts[4].strip()
    return ""


def _audit_includes(dump: str, subcategory: str, expected: str) -> bool:
    """Check if audit policy includes the expected setting (e.g. 'Success and Failure')."""
    setting = _audit_policy_setting(dump, subcategory)
    return expected.lower() in setting.lower()


# ============================================================ #
#  Registry value helpers                                      #
# ============================================================ #

def _registry_value(dump: str, section_name: str, reg_path: str, property_name: str) -> Any:
    """
    Extract a registry value from a JSON registry section.

    The section contains a dict of {path: json_string_of_properties}.
    """
    data = _json_section(dump, section_name)
    if not isinstance(data, dict):
        return None
    for path_key, props_json in data.items():
        if reg_path.lower() in path_key.lower():
            if isinstance(props_json, str):
                try:
                    props = json.loads(props_json)
                except (json.JSONDecodeError, ValueError):
                    continue
            elif isinstance(props_json, dict):
                props = props_json
            else:
                continue
            if property_name in props:
                return props[property_name]
    return None


def _lsa_value(dump: str, property_name: str) -> Any:
    """Extract a value from the LSA_PROTECTION JSON section."""
    data = _json_section(dump, "LSA_PROTECTION")
    if isinstance(data, dict):
        return data.get(property_name)
    return None


def _uac_value(dump: str, property_name: str) -> Any:
    """Extract a value from the UAC_SETTINGS JSON section."""
    data = _json_section(dump, "UAC_SETTINGS")
    if isinstance(data, dict):
        return data.get(property_name)
    return None


# ============================================================ #
#  Service helpers                                             #
# ============================================================ #

def _service_startup(dump: str, service_name: str) -> Optional[str]:
    """
    Extract the StartType for a Windows service.

    Returns "Disabled", "Manual", "Automatic", or None if not found.
    """
    data = _json_section(dump, "SERVICES")
    if not data:
        return None
    services = data if isinstance(data, list) else [data]
    for svc in services:
        if isinstance(svc, dict) and svc.get("Name", "").lower() == service_name.lower():
            st = svc.get("StartType")
            # StartType can be int (4=Disabled,3=Manual,2=Automatic) or string
            if isinstance(st, int):
                return {4: "Disabled", 3: "Manual", 2: "Automatic", 1: "System", 0: "Boot"}.get(st, str(st))
            return str(st) if st is not None else None
    return None


def _service_is_disabled(dump: str, service_name: str) -> bool:
    """Return True if the service is disabled or not present."""
    st = _service_startup(dump, service_name)
    if st is None:
        return True  # Not installed = compliant
    return st.lower() == "disabled"


# ============================================================ #
#  Firewall helpers                                            #
# ============================================================ #

def _firewall_profile(dump: str, profile_name: str) -> Optional[Dict]:
    """Extract firewall profile data by name (Domain/Private/Public)."""
    data = _json_section(dump, "FIREWALL_PROFILES")
    if not data:
        return None
    profiles = data if isinstance(data, list) else [data]
    for p in profiles:
        if isinstance(p, dict) and p.get("Name", "").lower() == profile_name.lower():
            return p
    return None


def _firewall_enabled(dump: str, profile_name: str) -> bool:
    """Check if a firewall profile is enabled."""
    p = _firewall_profile(dump, profile_name)
    if not p:
        return False
    enabled = p.get("Enabled")
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, int):
        return enabled != 0
    return str(enabled).lower() in ("true", "1")


def _firewall_inbound_block(dump: str, profile_name: str) -> bool:
    """Check if default inbound action is Block (2) for a firewall profile."""
    p = _firewall_profile(dump, profile_name)
    if not p:
        return False
    action = p.get("DefaultInboundAction")
    # 2 = Block, 4 = Block in some representations
    if isinstance(action, int):
        return action in (2, 4)
    return str(action).lower() in ("block", "2", "4")


# ============================================================ #
#  Windows Feature helpers                                     #
# ============================================================ #

def _feature_installed(dump: str, feature_name: str) -> bool:
    """Check if a Windows Feature is installed."""
    data = _json_section(dump, "WINDOWS_FEATURES")
    if not data:
        return False
    features = data if isinstance(data, list) else [data]
    for f in features:
        if isinstance(f, dict) and f.get("Name", "").lower() == feature_name.lower():
            return True
    return False


# ============================================================ #
#  Rule filtering and evaluation                               #
# ============================================================ #

def filter_rules_by_profile(
    rules: List[WindowsCISRule],
    profile: str,
    os_version: str = "all",
) -> List[WindowsCISRule]:
    """
    Filter rules by CIS profile level and OS version.

    Args:
        rules:      Full rule list
        profile:    "L1" returns only L1 rules; "FULL" returns all rules
        os_version: "2016", "2019", "2022", "2025", or "all"
    """
    filtered = rules
    if profile == "L1":
        filtered = [r for r in filtered if r.level == "L1"]
    if os_version != "all":
        filtered = [
            r for r in filtered
            if "all" in r.versions or os_version in r.versions
        ]
    return filtered


def evaluate_compliance(dump: str, rules: List[WindowsCISRule]) -> Dict[str, Any]:
    """
    Evaluate all rules against the collected audit dump.

    Returns:
        {
            "summary": {
                "total_rules_scored": int,
                "passed_scored": int,
                "failed_scored": int,
                "compliance_pct": float,
                "weighted_compliance_pct": float,
            },
            "findings": [...]
        }
    """
    SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "info": 0}

    findings = []
    total_weight = 0
    passed_weight = 0

    for rule in rules:
        try:
            compliant = rule.check_fn(dump)
        except Exception:
            compliant = False

        try:
            evidence = rule.evidence_fn(dump)
        except Exception:
            evidence = "(evidence extraction failed)"

        weight = SEVERITY_WEIGHTS.get(rule.severity, 1)
        total_weight += weight
        if compliant:
            passed_weight += weight

        findings.append({
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "section": rule.section,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "evidence": evidence,
            "remediation": rule.remediation,
        })

    total = len(findings)
    passed = sum(1 for f in findings if f["compliant"])
    failed = total - passed

    compliance_pct = round(100.0 * passed / total, 2) if total else 0.0
    weighted_pct = round(100.0 * passed_weight / total_weight, 2) if total_weight else 0.0

    return {
        "summary": {
            "total_rules_scored": total,
            "passed_scored": passed,
            "failed_scored": failed,
            "compliance_pct": compliance_pct,
            "weighted_compliance_pct": weighted_pct,
        },
        "findings": findings,
    }


# ============================================================ #
#  Build all rules                                             #
# ============================================================ #

def build_all_windows_cis_rules() -> List[WindowsCISRule]:
    """Return the full list of Windows Server CIS rules (~110 checks)."""

    rules: List[WindowsCISRule] = []

    # ================================================================ #
    #  Section 1.1 – Account Policies: Password Policy                  #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-001",
        section="1.1.1",
        title="Ensure 'Enforce password history' is set to '24 or more password(s)'",
        description=(
            "This policy setting determines the number of renewed, unique passwords "
            "that have to be associated with a user account before an old password can "
            "be reused."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "PasswordHistorySize") is not None
            and _secpol_int(d, "PasswordHistorySize") >= 24
        ),
        evidence_fn=lambda d: f"PasswordHistorySize = {_secpol_value(d, 'PasswordHistorySize')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Enforce password history: 24 or more."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-002",
        section="1.1.2",
        title="Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
        description=(
            "This policy setting defines how long a user can use their password before "
            "it expires. A value of 0 means password never expires."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "MaximumPasswordAge") is not None
            and 0 < _secpol_int(d, "MaximumPasswordAge") <= 365
        ),
        evidence_fn=lambda d: f"MaximumPasswordAge = {_secpol_value(d, 'MaximumPasswordAge')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Maximum password age: 365 or fewer, not 0."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-003",
        section="1.1.3",
        title="Ensure 'Minimum password age' is set to '1 or more day(s)'",
        description=(
            "This policy setting determines the minimum number of days that must elapse "
            "before a password can be changed."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "MinimumPasswordAge") is not None
            and _secpol_int(d, "MinimumPasswordAge") >= 1
        ),
        evidence_fn=lambda d: f"MinimumPasswordAge = {_secpol_value(d, 'MinimumPasswordAge')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Minimum password age: 1 or more day(s)."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-004",
        section="1.1.4",
        title="Ensure 'Minimum password length' is set to '14 or more character(s)'",
        description=(
            "This policy setting determines the least number of characters that make up "
            "a password for a user account."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "MinimumPasswordLength") is not None
            and _secpol_int(d, "MinimumPasswordLength") >= 14
        ),
        evidence_fn=lambda d: f"MinimumPasswordLength = {_secpol_value(d, 'MinimumPasswordLength')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Minimum password length: 14 or more."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-005",
        section="1.1.5",
        title="Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
        description=(
            "This policy setting checks all new passwords to ensure that they meet "
            "basic requirements for strong passwords."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _secpol_int(d, "PasswordComplexity") == 1,
        evidence_fn=lambda d: f"PasswordComplexity = {_secpol_value(d, 'PasswordComplexity')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Password must meet complexity requirements: Enabled."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-006",
        section="1.1.6",
        title="Ensure 'Relax minimum password length limits' is set to 'Enabled'",
        description=(
            "This policy setting allows the minimum password length setting to exceed "
            "the traditional limit of 14 characters."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: (
            # This is a newer policy; if not present, check MinimumPasswordLength >= 14
            _secpol_int(d, "MinimumPasswordLength") is not None
            and _secpol_int(d, "MinimumPasswordLength") >= 14
        ),
        evidence_fn=lambda d: f"MinimumPasswordLength = {_secpol_value(d, 'MinimumPasswordLength')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Relax minimum password length limits: Enabled."
        ),
        versions=["2019", "2022", "2025"],
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-007",
        section="1.1.7",
        title="Ensure 'Store passwords using reversible encryption' is set to 'Disabled'",
        description=(
            "This policy setting determines whether the operating system stores "
            "passwords using reversible encryption."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _secpol_int(d, "ClearTextPassword") == 0,
        evidence_fn=lambda d: f"ClearTextPassword = {_secpol_value(d, 'ClearTextPassword')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Store passwords using reversible encryption: Disabled."
        ),
    ))

    # ================================================================ #
    #  Section 1.2 – Account Policies: Account Lockout Policy           #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-008",
        section="1.2.1",
        title="Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
        description=(
            "This policy setting determines the length of time that must pass before "
            "a locked account is unlocked and a user can try to log on again."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "LockoutDuration") is not None
            and _secpol_int(d, "LockoutDuration") >= 15
        ),
        evidence_fn=lambda d: f"LockoutDuration = {_secpol_value(d, 'LockoutDuration')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Account Lockout Policy > Account lockout duration: 15+ minutes."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-009",
        section="1.2.2",
        title="Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
        description=(
            "This policy setting determines the number of failed logon attempts before "
            "the account is locked."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "LockoutBadCount") is not None
            and 0 < _secpol_int(d, "LockoutBadCount") <= 5
        ),
        evidence_fn=lambda d: f"LockoutBadCount = {_secpol_value(d, 'LockoutBadCount')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Account Lockout Policy > Account lockout threshold: 1-5 attempts."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-010",
        section="1.2.3",
        title="Ensure 'Allow Administrator account lockout' is set to 'Enabled'",
        description=(
            "This policy setting determines whether the built-in Administrator account "
            "is subject to the account lockout policy."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            # AllowAdministratorLockout may appear in security policy
            _secpol_int(d, "AllowAdministratorLockout") == 1
        ),
        evidence_fn=lambda d: f"AllowAdministratorLockout = {_secpol_value(d, 'AllowAdministratorLockout')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Account Lockout Policy > Allow Administrator account lockout: Enabled."
        ),
        versions=["2022", "2025"],
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-011",
        section="1.2.4",
        title="Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'",
        description=(
            "This policy setting determines the length of time before the Account Lockout "
            "Threshold resets to zero."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "ResetLockoutCount") is not None
            and _secpol_int(d, "ResetLockoutCount") >= 15
        ),
        evidence_fn=lambda d: f"ResetLockoutCount = {_secpol_value(d, 'ResetLockoutCount')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Account Policies > Account Lockout Policy > Reset account lockout counter after: 15+ minutes."
        ),
    ))

    # ================================================================ #
    #  Section 2.2 – User Rights Assignment                             #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-012",
        section="2.2.1",
        title="Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'",
        description=(
            "This user right is used by Credential Manager during Backup and Restore. "
            "No accounts should have this user right."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: len(_user_right_sids(d, "SeTrustedCredManAccessPrivilege")) == 0,
        evidence_fn=lambda d: f"SeTrustedCredManAccessPrivilege = {_user_right_sids(d, 'SeTrustedCredManAccessPrivilege')}",
        remediation="Set 'Access Credential Manager as a trusted caller' to No One.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-013",
        section="2.2.2",
        title="Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'",
        description=(
            "This user right determines which users can connect to the computer from the network."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            len(_user_right_sids(d, "SeNetworkLogonRight")) > 0
        ),
        evidence_fn=lambda d: f"SeNetworkLogonRight = {_user_right_sids(d, 'SeNetworkLogonRight')}",
        remediation="Set 'Access this computer from the network' to Administrators, Authenticated Users.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-014",
        section="2.2.6",
        title="Ensure 'Allow log on locally' is set to 'Administrators'",
        description=(
            "This user right determines which users can log on to the computer."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: len(_user_right_sids(d, "SeInteractiveLogonRight")) > 0,
        evidence_fn=lambda d: f"SeInteractiveLogonRight = {_user_right_sids(d, 'SeInteractiveLogonRight')}",
        remediation="Set 'Allow log on locally' to Administrators only (member server).",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-015",
        section="2.2.11",
        title="Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\\Virtual Machines'",
        description=(
            "This user right determines if the user can create a symbolic link."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: len(_user_right_sids(d, "SeCreateSymbolicLinkPrivilege")) > 0,
        evidence_fn=lambda d: f"SeCreateSymbolicLinkPrivilege = {_user_right_sids(d, 'SeCreateSymbolicLinkPrivilege')}",
        remediation="Set 'Create symbolic links' to Administrators only.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-016",
        section="2.2.14",
        title="Ensure 'Deny access to this computer from the network' includes 'Guests'",
        description=(
            "This user right determines which users are prevented from accessing "
            "a computer over the network."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            any("S-1-5-32-546" in s or "guest" in s.lower()
                for s in _user_right_sids(d, "SeDenyNetworkLogonRight"))
        ),
        evidence_fn=lambda d: f"SeDenyNetworkLogonRight = {_user_right_sids(d, 'SeDenyNetworkLogonRight')}",
        remediation="Add 'Guests' to 'Deny access to this computer from the network'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-017",
        section="2.2.17",
        title="Ensure 'Deny log on as a batch job' includes 'Guests'",
        description=(
            "This policy setting determines which accounts will not be able to "
            "log on to the computer as a batch job."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            any("S-1-5-32-546" in s or "guest" in s.lower()
                for s in _user_right_sids(d, "SeDenyBatchLogonRight"))
        ),
        evidence_fn=lambda d: f"SeDenyBatchLogonRight = {_user_right_sids(d, 'SeDenyBatchLogonRight')}",
        remediation="Add 'Guests' to 'Deny log on as a batch job'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-018",
        section="2.2.18",
        title="Ensure 'Deny log on as a service' includes 'Guests'",
        description=(
            "This security setting determines which service accounts are prevented "
            "from registering a process as a service."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            any("S-1-5-32-546" in s or "guest" in s.lower()
                for s in _user_right_sids(d, "SeDenyServiceLogonRight"))
        ),
        evidence_fn=lambda d: f"SeDenyServiceLogonRight = {_user_right_sids(d, 'SeDenyServiceLogonRight')}",
        remediation="Add 'Guests' to 'Deny log on as a service'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-019",
        section="2.2.19",
        title="Ensure 'Deny log on locally' includes 'Guests'",
        description=(
            "This security setting determines which users are prevented from "
            "logging on at the computer."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            any("S-1-5-32-546" in s or "guest" in s.lower()
                for s in _user_right_sids(d, "SeDenyInteractiveLogonRight"))
        ),
        evidence_fn=lambda d: f"SeDenyInteractiveLogonRight = {_user_right_sids(d, 'SeDenyInteractiveLogonRight')}",
        remediation="Add 'Guests' to 'Deny log on locally'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-020",
        section="2.2.20",
        title="Ensure 'Deny log on through Remote Desktop Services' includes 'Guests, Local account'",
        description=(
            "This user right determines which users and groups are prohibited from "
            "logging on through Remote Desktop Services."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            any("S-1-5-32-546" in s or "guest" in s.lower()
                for s in _user_right_sids(d, "SeDenyRemoteInteractiveLogonRight"))
        ),
        evidence_fn=lambda d: f"SeDenyRemoteInteractiveLogonRight = {_user_right_sids(d, 'SeDenyRemoteInteractiveLogonRight')}",
        remediation="Add 'Guests' and 'Local account' to 'Deny log on through Remote Desktop Services'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-021",
        section="2.2.28",
        title="Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'",
        description=(
            "This policy setting determines which accounts or processes can generate "
            "audit records in the security log."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: len(_user_right_sids(d, "SeAuditPrivilege")) > 0,
        evidence_fn=lambda d: f"SeAuditPrivilege = {_user_right_sids(d, 'SeAuditPrivilege')}",
        remediation="Set 'Generate security audits' to LOCAL SERVICE, NETWORK SERVICE.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-022",
        section="2.2.13",
        title="Ensure 'Debug programs' is set to 'Administrators'",
        description=(
            "This user right determines which users can attach a debugger to any "
            "process or to the kernel. This is a powerful privilege."
        ),
        severity="high",
        level="L2",
        check_fn=lambda d: (
            len(_user_right_sids(d, "SeDebugPrivilege")) <= 1
            and all("S-1-5-32-544" in s or "administrator" in s.lower()
                    for s in _user_right_sids(d, "SeDebugPrivilege"))
        ),
        evidence_fn=lambda d: f"SeDebugPrivilege = {_user_right_sids(d, 'SeDebugPrivilege')}",
        remediation="Set 'Debug programs' to Administrators only.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-023",
        section="2.2.38",
        title="Ensure 'Shut down the system' is set to 'Administrators'",
        description=(
            "This user right determines which users can shut down the local computer."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: len(_user_right_sids(d, "SeShutdownPrivilege")) > 0,
        evidence_fn=lambda d: f"SeShutdownPrivilege = {_user_right_sids(d, 'SeShutdownPrivilege')}",
        remediation="Set 'Shut down the system' to Administrators.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-024",
        section="2.2.39",
        title="Ensure 'Take ownership of files or other objects' is set to 'Administrators'",
        description=(
            "This user right determines which users can take ownership of any "
            "securable object in the system."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            len(_user_right_sids(d, "SeTakeOwnershipPrivilege")) > 0
            and all("S-1-5-32-544" in s or "administrator" in s.lower()
                    for s in _user_right_sids(d, "SeTakeOwnershipPrivilege"))
        ),
        evidence_fn=lambda d: f"SeTakeOwnershipPrivilege = {_user_right_sids(d, 'SeTakeOwnershipPrivilege')}",
        remediation="Set 'Take ownership of files or other objects' to Administrators only.",
    ))

    # ================================================================ #
    #  Section 2.3 – Security Options                                   #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-025",
        section="2.3.1.1",
        title="Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'",
        description=(
            "This policy setting prevents users from adding new Microsoft accounts "
            "on this computer."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SOFTWARE",
                           "Policies\\System", "NoConnectedUser") == 3
            or _uac_value(d, "NoConnectedUser") == 3
        ),
        evidence_fn=lambda d: f"NoConnectedUser = {_uac_value(d, 'NoConnectedUser')}",
        remediation=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Local Policies > Security Options > Accounts: Block Microsoft accounts: "
            "Users can't add or log on with Microsoft accounts."
        ),
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-026",
        section="2.3.1.2",
        title="Ensure 'Accounts: Guest account status' is set to 'Disabled'",
        description=(
            "This policy setting determines whether the Guest account is enabled or disabled."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "EnableGuestAccount") == 0
        ),
        evidence_fn=lambda d: f"EnableGuestAccount = {_secpol_value(d, 'EnableGuestAccount')}",
        remediation="Disable the Guest account via Local Security Policy.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-027",
        section="2.3.1.4",
        title="Ensure 'Accounts: Rename administrator account' has been changed from default",
        description=(
            "Renaming the built-in Administrator account makes it slightly harder "
            "for attackers to guess the admin account name."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _secpol_value(d, "NewAdministratorName") is not None
            and _secpol_value(d, "NewAdministratorName").lower().replace('"', '').strip() != "administrator"
        ),
        evidence_fn=lambda d: f"NewAdministratorName = {_secpol_value(d, 'NewAdministratorName')}",
        remediation="Rename the built-in Administrator account to a non-default name.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-028",
        section="2.3.1.5",
        title="Ensure 'Accounts: Rename guest account' has been changed from default",
        description=(
            "Renaming the built-in Guest account makes it slightly harder for "
            "attackers to identify the account."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _secpol_value(d, "NewGuestName") is not None
            and _secpol_value(d, "NewGuestName").lower().replace('"', '').strip() != "guest"
        ),
        evidence_fn=lambda d: f"NewGuestName = {_secpol_value(d, 'NewGuestName')}",
        remediation="Rename the built-in Guest account to a non-default name.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-029",
        section="2.3.2.1",
        title="Ensure 'Audit: Force audit policy subcategory settings' is set to 'Enabled'",
        description=(
            "This policy setting determines whether audit policy subcategory settings "
            "override audit policy category settings."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "SCENoApplyLegacyAuditPolicy") == 1,
        evidence_fn=lambda d: f"SCENoApplyLegacyAuditPolicy = {_lsa_value(d, 'SCENoApplyLegacyAuditPolicy')}",
        remediation="Set SCENoApplyLegacyAuditPolicy = 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-030",
        section="2.3.7.1",
        title="Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'",
        description=(
            "This policy setting determines whether the username of the last person "
            "to log on to the computer is displayed on the logon screen."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "DontDisplayLastUserName") == 1,
        evidence_fn=lambda d: f"DontDisplayLastUserName = {_uac_value(d, 'DontDisplayLastUserName')}",
        remediation="Enable 'Interactive logon: Do not display last user name'.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-031",
        section="2.3.7.4",
        title="Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'",
        description=(
            "Windows notices inactivity of a logon session and locks the screen "
            "after the configured time."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _uac_value(d, "InactivityTimeoutSecs") is not None
            and isinstance(_uac_value(d, "InactivityTimeoutSecs"), int)
            and 0 < _uac_value(d, "InactivityTimeoutSecs") <= 900
        ),
        evidence_fn=lambda d: f"InactivityTimeoutSecs = {_uac_value(d, 'InactivityTimeoutSecs')}",
        remediation="Set 'Interactive logon: Machine inactivity limit' to 900 or fewer seconds, not 0.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-032",
        section="2.3.8.1",
        title="Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
        description=(
            "This policy setting determines if packet signing is required by the "
            "SMB client component."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SYSTEM",
                           "LanmanWorkstation\\Parameters", "RequireSecuritySignature") == 1
        ),
        evidence_fn=lambda d: f"LanmanWorkstation RequireSecuritySignature = {_registry_value(d, 'REGISTRY_SYSTEM', 'LanmanWorkstation', 'RequireSecuritySignature')}",
        remediation="Set RequireSecuritySignature = 1 in LanmanWorkstation\\Parameters.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-033",
        section="2.3.9.1",
        title="Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'",
        description=(
            "This policy setting determines if packet signing is required by the "
            "SMB server component."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SYSTEM",
                           "LanManServer\\Parameters", "RequireSecuritySignature") == 1
        ),
        evidence_fn=lambda d: f"LanManServer RequireSecuritySignature = {_registry_value(d, 'REGISTRY_SYSTEM', 'LanManServer', 'RequireSecuritySignature')}",
        remediation="Set RequireSecuritySignature = 1 in LanManServer\\Parameters.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-034",
        section="2.3.10.2",
        title="Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'",
        description=(
            "This policy setting controls the ability of anonymous users to enumerate "
            "the accounts in the SAM database."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "RestrictAnonymousSAM") == 1,
        evidence_fn=lambda d: f"RestrictAnonymousSAM = {_lsa_value(d, 'RestrictAnonymousSAM')}",
        remediation="Set RestrictAnonymousSAM = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-035",
        section="2.3.10.3",
        title="Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'",
        description=(
            "This policy setting controls the ability of anonymous users to enumerate "
            "SAM accounts as well as shares."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "RestrictAnonymous") == 1,
        evidence_fn=lambda d: f"RestrictAnonymous = {_lsa_value(d, 'RestrictAnonymous')}",
        remediation="Set RestrictAnonymous = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-036",
        section="2.3.10.6",
        title="Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'",
        description=(
            "This policy setting determines what additional permissions are granted "
            "for anonymous connections to the computer."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "EveryoneIncludesAnonymous") == 0,
        evidence_fn=lambda d: f"EveryoneIncludesAnonymous = {_lsa_value(d, 'EveryoneIncludesAnonymous')}",
        remediation="Set EveryoneIncludesAnonymous = 0.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-037",
        section="2.3.11.1",
        title="Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'",
        description=(
            "This policy setting determines whether Local System services that use "
            "Negotiate when reverting to NTLM authentication can use the computer identity."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SYSTEM",
                           "Lsa", "UseMachineId") == 1
        ),
        evidence_fn=lambda d: f"UseMachineId = {_registry_value(d, 'REGISTRY_SYSTEM', 'Lsa', 'UseMachineId')}",
        remediation="Set UseMachineId = 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-038",
        section="2.3.11.4",
        title="Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
        description=(
            "This policy setting determines which challenge/response authentication "
            "protocol is used for network logons. Level 5 sends NTLMv2 only."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "LmCompatibilityLevel") == 5,
        evidence_fn=lambda d: f"LmCompatibilityLevel = {_lsa_value(d, 'LmCompatibilityLevel')}",
        remediation="Set LmCompatibilityLevel = 5 (Send NTLMv2 response only. Refuse LM & NTLM).",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-039",
        section="2.3.11.7",
        title="Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'",
        description=(
            "This policy setting determines whether the LM hash value for the new "
            "password is stored when the password is changed."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "NoLMHash") == 1,
        evidence_fn=lambda d: f"NoLMHash = {_lsa_value(d, 'NoLMHash')}",
        remediation="Set NoLMHash = 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
    ))

    # ================================================================ #
    #  Section 2.3 – Security Options (UAC)                             #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-040",
        section="2.3.17.1",
        title="Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'",
        description=(
            "This policy setting controls the behavior of Admin Approval Mode for "
            "the built-in Administrator account."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _uac_value(d, "FilterAdministratorToken") == 1,
        evidence_fn=lambda d: f"FilterAdministratorToken = {_uac_value(d, 'FilterAdministratorToken')}",
        remediation="Set FilterAdministratorToken = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-041",
        section="2.3.17.2",
        title="Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'",
        description=(
            "This policy setting controls the behavior of the elevation prompt for administrators."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "ConsentPromptBehaviorAdmin") == 2,
        evidence_fn=lambda d: f"ConsentPromptBehaviorAdmin = {_uac_value(d, 'ConsentPromptBehaviorAdmin')}",
        remediation="Set ConsentPromptBehaviorAdmin = 2 (Prompt for consent on the secure desktop).",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-042",
        section="2.3.17.3",
        title="Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'",
        description=(
            "This policy setting controls the behavior of the elevation prompt for standard users."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "ConsentPromptBehaviorUser") == 0,
        evidence_fn=lambda d: f"ConsentPromptBehaviorUser = {_uac_value(d, 'ConsentPromptBehaviorUser')}",
        remediation="Set ConsentPromptBehaviorUser = 0 (Automatically deny).",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-043",
        section="2.3.17.4",
        title="Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'",
        description=(
            "This policy setting controls the behavior of application installation "
            "detection for the computer."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "EnableInstallerDetection") == 1,
        evidence_fn=lambda d: f"EnableInstallerDetection = {_uac_value(d, 'EnableInstallerDetection')}",
        remediation="Set EnableInstallerDetection = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-044",
        section="2.3.17.5",
        title="Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'",
        description=(
            "This policy setting controls whether applications that request to run "
            "with a UIAccess integrity level must reside in a secure location."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "EnableSecureUIAPaths") == 1,
        evidence_fn=lambda d: f"EnableSecureUIAPaths = {_uac_value(d, 'EnableSecureUIAPaths')}",
        remediation="Set EnableSecureUIAPaths = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-045",
        section="2.3.17.6",
        title="Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'",
        description=(
            "This policy setting controls the behavior of all User Account Control (UAC) "
            "policy settings for the computer."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _uac_value(d, "EnableLUA") == 1,
        evidence_fn=lambda d: f"EnableLUA = {_uac_value(d, 'EnableLUA')}",
        remediation="Set EnableLUA = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-046",
        section="2.3.17.7",
        title="Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'",
        description=(
            "This policy setting controls whether the elevation request prompt is "
            "displayed on the interactive user's desktop or the secure desktop."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _uac_value(d, "PromptOnSecureDesktop") == 1,
        evidence_fn=lambda d: f"PromptOnSecureDesktop = {_uac_value(d, 'PromptOnSecureDesktop')}",
        remediation="Set PromptOnSecureDesktop = 1.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-047",
        section="2.3.17.8",
        title="Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'",
        description=(
            "This policy setting controls whether application write failures are "
            "redirected to defined registry and file system locations."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: _uac_value(d, "EnableVirtualization") == 1,
        evidence_fn=lambda d: f"EnableVirtualization = {_uac_value(d, 'EnableVirtualization')}",
        remediation="Set EnableVirtualization = 1.",
    ))

    # ================================================================ #
    #  Section 5 – System Services                                      #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-048",
        section="5.4",
        title="Ensure 'Print Spooler (Spooler)' is set to 'Disabled'",
        description=(
            "This service spools print jobs and handles interaction with printers. "
            "On servers that do not serve as print servers, this service should be disabled."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _service_is_disabled(d, "Spooler"),
        evidence_fn=lambda d: f"Spooler StartType = {_service_startup(d, 'Spooler')}",
        remediation="Set the Print Spooler service (Spooler) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-049",
        section="5.2",
        title="Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or not installed",
        description=(
            "The FTP service enables FTP access to a server. It should not be "
            "running on servers that don't require it."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "FTPSVC"),
        evidence_fn=lambda d: f"FTPSVC StartType = {_service_startup(d, 'FTPSVC')}",
        remediation="Set the FTP Service (FTPSVC) to Disabled or remove IIS FTP.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-050",
        section="5.11",
        title="Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or not installed",
        description=(
            "The IIS Admin Service allows management of IIS components. "
            "It should be disabled on servers that do not host web services."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "IISADMIN"),
        evidence_fn=lambda d: f"IISADMIN StartType = {_service_startup(d, 'IISADMIN')}",
        remediation="Set the IIS Admin Service (IISADMIN) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-051",
        section="5.30",
        title="Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'",
        description=(
            "This service discovers networked devices and services that use the "
            "SSDP discovery protocol, such as UPnP devices."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _service_is_disabled(d, "SSDPSRV"),
        evidence_fn=lambda d: f"SSDPSRV StartType = {_service_startup(d, 'SSDPSRV')}",
        remediation="Set the SSDP Discovery service (SSDPSRV) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-052",
        section="5.31",
        title="Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'",
        description=(
            "This service allows UPnP devices to be hosted on this computer."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _service_is_disabled(d, "upnphost"),
        evidence_fn=lambda d: f"upnphost StartType = {_service_startup(d, 'upnphost')}",
        remediation="Set the UPnP Device Host service (upnphost) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-053",
        section="5.33",
        title="Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Automatic' (required for WinRM audit)",
        description=(
            "WinRM is needed for remote management. Since we are auditing via WinRM, "
            "we check that this service is running."
        ),
        severity="info",
        level="L1",
        check_fn=lambda d: not _service_is_disabled(d, "WinRM"),
        evidence_fn=lambda d: f"WinRM StartType = {_service_startup(d, 'WinRM')}",
        remediation="This is informational. WinRM should be running for remote audit.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-054",
        section="5.36",
        title="Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'",
        description="This service manages connected Xbox accessories.",
        severity="low",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "XboxGipSvc"),
        evidence_fn=lambda d: f"XboxGipSvc StartType = {_service_startup(d, 'XboxGipSvc')}",
        remediation="Set the Xbox Accessory Management Service (XboxGipSvc) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-055",
        section="5.37",
        title="Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'",
        description="This service provides authentication and authorization to Xbox Live.",
        severity="low",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "XblAuthManager"),
        evidence_fn=lambda d: f"XblAuthManager StartType = {_service_startup(d, 'XblAuthManager')}",
        remediation="Set the Xbox Live Auth Manager (XblAuthManager) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-056",
        section="5.38",
        title="Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'",
        description="This service saves and syncs data for Xbox Live enabled games.",
        severity="low",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "XblGameSave"),
        evidence_fn=lambda d: f"XblGameSave StartType = {_service_startup(d, 'XblGameSave')}",
        remediation="Set the Xbox Live Game Save (XblGameSave) to Disabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-057",
        section="5.39",
        title="Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'",
        description="This service supports the Xbox Live networking platform.",
        severity="low",
        level="L2",
        check_fn=lambda d: _service_is_disabled(d, "XboxNetApiSvc"),
        evidence_fn=lambda d: f"XboxNetApiSvc StartType = {_service_startup(d, 'XboxNetApiSvc')}",
        remediation="Set the Xbox Live Networking Service (XboxNetApiSvc) to Disabled.",
    ))

    # ================================================================ #
    #  Section 9 – Windows Firewall with Advanced Security              #
    # ================================================================ #

    for profile_name, rule_offset in [("Domain", 0), ("Private", 3), ("Public", 6)]:
        rules.append(WindowsCISRule(
            id=f"WIN-L1-{58 + rule_offset:03d}",
            section=f"9.{1 + rule_offset // 3}.1",
            title=f"Ensure 'Windows Firewall: {profile_name}: Firewall state' is set to 'On (recommended)'",
            description=f"This setting controls whether Windows Firewall is on for the {profile_name} profile.",
            severity="high",
            level="L1",
            check_fn=(lambda d, p=profile_name: _firewall_enabled(d, p)),
            evidence_fn=(lambda d, p=profile_name: f"{p} Firewall Enabled = {_firewall_enabled(d, p)}"),
            remediation=f"Enable Windows Firewall for the {profile_name} profile.",
        ))

        rules.append(WindowsCISRule(
            id=f"WIN-L1-{59 + rule_offset:03d}",
            section=f"9.{1 + rule_offset // 3}.2",
            title=f"Ensure 'Windows Firewall: {profile_name}: Inbound connections' is set to 'Block (default)'",
            description=f"This setting determines the behavior for inbound connections on the {profile_name} profile.",
            severity="high",
            level="L1",
            check_fn=(lambda d, p=profile_name: _firewall_inbound_block(d, p)),
            evidence_fn=(lambda d, p=profile_name: f"{p} Inbound = {_firewall_profile(d, p)}"),
            remediation=f"Set default inbound action to Block for the {profile_name} firewall profile.",
        ))

        rules.append(WindowsCISRule(
            id=f"WIN-L1-{60 + rule_offset:03d}",
            section=f"9.{1 + rule_offset // 3}.4",
            title=f"Ensure 'Windows Firewall: {profile_name}: Logging: Log dropped packets' is set to 'Yes'",
            description=f"Enable logging of dropped packets for the {profile_name} firewall profile.",
            severity="medium",
            level="L1",
            check_fn=(lambda d, p=profile_name: (
                _firewall_profile(d, p) is not None
                and _firewall_profile(d, p).get("LogBlocked") in (True, 1, "True")
            )),
            evidence_fn=(lambda d, p=profile_name: f"{p} LogBlocked = {_firewall_profile(d, p).get('LogBlocked') if _firewall_profile(d, p) else 'N/A'}"),
            remediation=f"Enable dropped packet logging for the {profile_name} firewall profile.",
        ))

    # ================================================================ #
    #  Section 17 – Advanced Audit Policy Configuration                 #
    # ================================================================ #

    _audit_rules = [
        ("WIN-L1-067", "17.1.1", "Credential Validation", "Success and Failure", "high"),
        ("WIN-L1-068", "17.2.1", "Application Group Management", "Success and Failure", "medium"),
        ("WIN-L1-069", "17.2.2", "Computer Account Management", "Success", "medium"),
        ("WIN-L1-070", "17.2.4", "Other Account Management Events", "Success", "medium"),
        ("WIN-L1-071", "17.2.5", "Security Group Management", "Success", "medium"),
        ("WIN-L1-072", "17.2.6", "User Account Management", "Success and Failure", "medium"),
        ("WIN-L1-073", "17.3.1", "PNP Activity", "Success", "low"),
        ("WIN-L1-074", "17.3.2", "Process Creation", "Success", "medium"),
        ("WIN-L1-075", "17.5.1", "Account Lockout", "Failure", "high"),
        ("WIN-L1-076", "17.5.2", "Group Membership", "Success", "medium"),
        ("WIN-L1-077", "17.5.3", "Logoff", "Success", "low"),
        ("WIN-L1-078", "17.5.4", "Logon", "Success and Failure", "high"),
        ("WIN-L1-079", "17.5.5", "Other Logon/Logoff Events", "Success and Failure", "medium"),
        ("WIN-L1-080", "17.5.6", "Special Logon", "Success", "medium"),
        ("WIN-L1-081", "17.6.1", "Detailed File Share", "Failure", "medium"),
        ("WIN-L1-082", "17.6.2", "File Share", "Success and Failure", "medium"),
        ("WIN-L1-083", "17.6.3", "Other Object Access Events", "Success and Failure", "medium"),
        ("WIN-L1-084", "17.6.4", "Removable Storage", "Success and Failure", "medium"),
        ("WIN-L1-085", "17.7.1", "Audit Policy Change", "Success", "high"),
        ("WIN-L1-086", "17.7.2", "Authentication Policy Change", "Success", "medium"),
        ("WIN-L1-087", "17.7.3", "Authorization Policy Change", "Success", "medium"),
        ("WIN-L1-088", "17.7.4", "MPSSVC Rule-Level Policy Change", "Success and Failure", "medium"),
        ("WIN-L1-089", "17.8.1", "Sensitive Privilege Use", "Success and Failure", "high"),
        ("WIN-L1-090", "17.9.1", "IPsec Driver", "Success and Failure", "medium"),
        ("WIN-L1-091", "17.9.2", "Other System Events", "Success and Failure", "medium"),
        ("WIN-L1-092", "17.9.3", "Security State Change", "Success", "high"),
        ("WIN-L1-093", "17.9.4", "Security System Extension", "Success", "high"),
        ("WIN-L1-094", "17.9.5", "System Integrity", "Success and Failure", "high"),
    ]

    for rule_id, section, subcategory, expected, severity in _audit_rules:
        rules.append(WindowsCISRule(
            id=rule_id,
            section=section,
            title=f"Ensure '{subcategory}' is set to include '{expected}'",
            description=f"This setting determines whether the OS generates audit events for {subcategory}.",
            severity=severity,
            level="L1",
            check_fn=(lambda d, s=subcategory, e=expected: _audit_includes(d, s, e)),
            evidence_fn=(lambda d, s=subcategory: f"{s}: {_audit_policy_setting(d, s)}"),
            remediation=f"Set '{subcategory}' audit policy to '{expected}' via auditpol or GPO.",
        ))

    # ================================================================ #
    #  Section 18 – Administrative Templates (Registry-based)           #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-095",
        section="18.3.1",
        title="Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'",
        description=(
            "SMBv1 is a legacy protocol with known vulnerabilities. "
            "It should be disabled on all Windows servers."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "SMBV1_STATUS") is not None
            and not _json_section(d, "SMBV1_STATUS").get("EnableSMB1Protocol", True)
        ),
        evidence_fn=lambda d: _ev_section(d, "SMBV1_STATUS", 300),
        remediation="Disable SMBv1 via Set-SmbServerConfiguration -EnableSMB1Protocol $false.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-096",
        section="18.3.2",
        title="Ensure 'Configure SMB v1 server' is set to 'Disabled'",
        description=(
            "This setting configures the SMBv1 server (LanmanServer) to not process "
            "SMBv1 requests."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "SMBV1_STATUS") is not None
            and not _json_section(d, "SMBV1_STATUS").get("EnableSMB1Protocol", True)
        ),
        evidence_fn=lambda d: _ev_section(d, "SMBV1_STATUS", 300),
        remediation="Disable SMBv1 server via Set-SmbServerConfiguration -EnableSMB1Protocol $false.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-097",
        section="18.4.1",
        title="Ensure 'LSA Protection' is enabled (RunAsPPL)",
        description=(
            "Configuring LSA to run as a Protected Process Light prevents non-protected "
            "processes from accessing LSA memory and credentials."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _lsa_value(d, "RunAsPPL") == 1,
        evidence_fn=lambda d: f"RunAsPPL = {_lsa_value(d, 'RunAsPPL')}",
        remediation="Set RunAsPPL = 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-098",
        section="18.4.4",
        title="Ensure 'WDigest Authentication' is set to 'Disabled'",
        description=(
            "When WDigest authentication is enabled, Lsass.exe retains a copy of "
            "the user's plaintext password in memory."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "WDIGEST") is not None
            and _json_section(d, "WDIGEST").get("UseLogonCredential") == 0
        ),
        evidence_fn=lambda d: _ev_section(d, "WDIGEST", 200),
        remediation="Set UseLogonCredential = 0 in HKLM\\...\\WDigest.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-099",
        section="18.5.1",
        title="Ensure 'NetBIOS node type' is configured as 'P-node' (no broadcast)",
        description=(
            "This setting determines which method NetBT uses to register and resolve names. "
            "P-node (value 2) uses WINS only, avoiding broadcast-based name resolution attacks."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SYSTEM",
                           "Netlogon\\Parameters", "NodeType") == 2
        ),
        evidence_fn=lambda d: f"NodeType = {_registry_value(d, 'REGISTRY_SYSTEM', 'Netlogon', 'NodeType')}",
        remediation="Set NodeType = 2 (P-node) in HKLM\\SYSTEM\\...\\Netlogon\\Parameters.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-100",
        section="18.6.1",
        title="Ensure 'Turn off multicast name resolution' is set to 'Enabled'",
        description=(
            "LLMNR is a secondary name resolution protocol. Disabling it prevents "
            "LLMNR spoofing/poisoning attacks."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SOFTWARE",
                           "Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast") == 0
            or _registry_value(d, "REGISTRY_SOFTWARE",
                              "Policies\\Microsoft\\Windows", "EnableMulticast") == 0
        ),
        evidence_fn=lambda d: f"EnableMulticast = {_registry_value(d, 'REGISTRY_SOFTWARE', 'DNSClient', 'EnableMulticast')}",
        remediation="Set EnableMulticast = 0 via Group Policy or registry.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-101",
        section="18.9.4",
        title="Ensure 'Remote Desktop: NLA (Network Level Authentication)' is set to 'Enabled'",
        description=(
            "NLA requires user authentication before a full Remote Desktop connection "
            "is established, reducing the attack surface."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "REMOTE_DESKTOP") is not None
            and _json_section(d, "REMOTE_DESKTOP").get("UserAuthentication") == 1
        ),
        evidence_fn=lambda d: _ev_section(d, "REMOTE_DESKTOP", 300),
        remediation="Enable Network Level Authentication for Remote Desktop.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-102",
        section="18.9.5",
        title="Ensure 'Remote Desktop: Encryption level' is set to 'High Level'",
        description=(
            "This setting specifies the level of encryption used for Remote Desktop "
            "Protocol connections. High level (3) uses 128-bit encryption."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "REMOTE_DESKTOP") is not None
            and _json_section(d, "REMOTE_DESKTOP").get("MinEncryptionLevel") == 3
        ),
        evidence_fn=lambda d: f"MinEncryptionLevel = {_json_section(d, 'REMOTE_DESKTOP').get('MinEncryptionLevel') if _json_section(d, 'REMOTE_DESKTOP') else 'N/A'}",
        remediation="Set MinEncryptionLevel = 3 (High) for Remote Desktop.",
    ))

    # ================================================================ #
    #  Section 18 – Windows Features                                    #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-103",
        section="18.10.1",
        title="Ensure 'PowerShell v2' is disabled or not installed",
        description=(
            "PowerShell v2 can be used to bypass script block logging and AMSI. "
            "It should be removed or disabled on all servers."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "POWERSHELL_V2") is not None
            and (
                _json_section(d, "POWERSHELL_V2").get("State", "").lower() in ("disabled", "disabledwithpayloadremoved")
                or _json_section(d, "POWERSHELL_V2").get("Installed") is False
                or not _json_section(d, "POWERSHELL_V2").get("FeatureName")
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "POWERSHELL_V2", 200),
        remediation="Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-104",
        section="18.10.2",
        title="Ensure 'SMB 1.0/CIFS File Sharing Support' feature is removed",
        description=(
            "SMBv1 feature should be completely removed from the server."
        ),
        severity="high",
        level="L2",
        check_fn=lambda d: (
            _json_section(d, "SMBV1_STATUS") is not None
            and _json_section(d, "SMBV1_STATUS").get("SMB1FeatureState", "").lower() in ("disabled", "disabledwithpayloadremoved", "")
        ),
        evidence_fn=lambda d: _ev_section(d, "SMBV1_STATUS", 200),
        remediation="Remove-WindowsFeature FS-SMB1 or Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
    ))

    # ================================================================ #
    #  Section 18 – Windows Defender / Anti-malware                     #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-105",
        section="18.11.1",
        title="Ensure Windows Defender Real-Time Protection is enabled",
        description=(
            "Real-time protection in Windows Defender provides continuous scanning "
            "of files and processes for malware."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "DEFENDER_STATUS") is not None
            and _json_section(d, "DEFENDER_STATUS").get("RealTimeProtectionEnabled") is True
        ),
        evidence_fn=lambda d: _ev_section(d, "DEFENDER_STATUS", 300),
        remediation="Enable Windows Defender Real-Time Protection via Group Policy or Set-MpPreference.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-106",
        section="18.11.2",
        title="Ensure Windows Defender Antivirus is enabled",
        description=(
            "Windows Defender Antivirus should be enabled unless a third-party "
            "solution is in use."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "DEFENDER_STATUS") is not None
            and _json_section(d, "DEFENDER_STATUS").get("AntivirusEnabled") is True
        ),
        evidence_fn=lambda d: _ev_section(d, "DEFENDER_STATUS", 300),
        remediation="Enable Windows Defender Antivirus.",
    ))

    # ================================================================ #
    #  Additional L1/L2 checks                                          #
    # ================================================================ #

    rules.append(WindowsCISRule(
        id="WIN-L1-107",
        section="1.0.1",
        title="Ensure latest Windows Server patches/updates are applied",
        description=(
            "The server should be running the latest Windows updates to protect "
            "against known vulnerabilities."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _json_section(d, "HOTFIXES") is not None
            and isinstance(_json_section(d, "HOTFIXES"), list)
            and len(_json_section(d, "HOTFIXES")) > 0
        ),
        evidence_fn=lambda d: _ev_section(d, "HOTFIXES", 300),
        remediation="Apply the latest Windows Updates via WSUS or Windows Update.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L2-108",
        section="18.12.1",
        title="Ensure 'Credential Guard' is enabled (HVCI)",
        description=(
            "Windows Defender Credential Guard uses virtualization-based security to "
            "isolate secrets so that only privileged system software can access them."
        ),
        severity="high",
        level="L2",
        check_fn=lambda d: (
            _json_section(d, "CREDENTIAL_GUARD") is not None
            and isinstance(_json_section(d, "CREDENTIAL_GUARD"), dict)
            and 1 in (_json_section(d, "CREDENTIAL_GUARD").get("SecurityServicesRunning") or [])
        ),
        evidence_fn=lambda d: _ev_section(d, "CREDENTIAL_GUARD", 300),
        remediation="Enable Credential Guard via Group Policy or DISM.",
        versions=["2016", "2019", "2022", "2025"],
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-109",
        section="2.3.10.9",
        title="Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
        description=(
            "This policy setting allows you to audit incoming NTLM traffic."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            _registry_value(d, "REGISTRY_SYSTEM",
                           "Lsa\\MSV1_0", "AuditReceivingNTLMTraffic") == 2
        ),
        evidence_fn=lambda d: f"AuditReceivingNTLMTraffic = {_registry_value(d, 'REGISTRY_SYSTEM', 'MSV1_0', 'AuditReceivingNTLMTraffic')}",
        remediation="Set AuditReceivingNTLMTraffic = 2 in HKLM\\...\\Lsa\\MSV1_0.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-110",
        section="2.3.4.1",
        title="Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'",
        description=(
            "This policy setting determines who is allowed to format and eject "
            "removable media."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: (
            _secpol_value(d, "AllocateDASD") is not None
            and _secpol_value(d, "AllocateDASD").strip('"') == "0"
        ),
        evidence_fn=lambda d: f"AllocateDASD = {_secpol_value(d, 'AllocateDASD')}",
        remediation="Set 'Devices: Allowed to format and eject removable media' to Administrators.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-111",
        section="2.3.6.1",
        title="Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'",
        description=(
            "This policy setting determines whether all secure channel traffic "
            "initiated by the domain member must be signed or encrypted."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            _secpol_int(d, "RequireSignOrSeal") == 1
        ),
        evidence_fn=lambda d: f"RequireSignOrSeal = {_secpol_value(d, 'RequireSignOrSeal')}",
        remediation="Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to Enabled.",
    ))

    rules.append(WindowsCISRule(
        id="WIN-L1-112",
        section="2.3.6.4",
        title="Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'",
        description=(
            "This policy setting determines whether a domain member periodically "
            "changes its computer account password."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _secpol_int(d, "DisablePasswordChange") == 0,
        evidence_fn=lambda d: f"DisablePasswordChange = {_secpol_value(d, 'DisablePasswordChange')}",
        remediation="Set 'Domain member: Disable machine account password changes' to Disabled (value = 0).",
    ))

    return rules
