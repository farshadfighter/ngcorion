"""
Active Directory rules.

Two parts, labelled separately:

* AD-CIS-<section>  CIS Microsoft Windows Server Benchmark, domain-controller
  profile: every control that applies to a DC ("all" + "DC only"). These are
  the Windows module's own rules, evaluated on the same collected data, plus
  the DC controls that module leaves manual or does not carry (2.2.5,
  2.3.5.1, 2.3.10.6, 5.1).
* AD-DOM-<n>  Domain checks beyond CIS: privileged groups, Kerberos, account
  hygiene, delegation, domain configuration and DC host settings, after
  Microsoft's "Best Practices for Securing Active Directory" and common AD
  security assessment practice. CIS has no benchmark for the directory
  itself.

Thresholds (90 days stale, 180 days krbtgt, 365 days privileged passwords,
5 Domain Admins) are the usual assessment values; the evidence always lists
what was found so a reviewer can judge.
"""

import re
from typing import Any, Callable, Dict, List, Optional

from app.modules.benchmark.rules import BenchmarkRule, as_list, json_section, section
from app.modules.benchmark.winps import registry_value
from app.modules.windows.audit import rules as W

from .collect import KDC, LSA, NETLOGON, SRV

JSON_SECTIONS = frozenset(W._JSON_SECTIONS | {
    "AD_DOMAIN", "AD_PRIVILEGED", "AD_ACCOUNTS", "AD_TRUSTS", "AD_GPP", "AD_DC_CONFIG", "AD_REGISTRY",
})

# Windows rules this module replaces with an automated DC version.
_REPLACED = {"2.3.5.1", "2.3.10.6"}

PRIVILEGED_GROUPS = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                     "Account Operators", "Server Operators", "Print Operators", "Backup Operators",
                     "Key Admins", "Enterprise Key Admins", "Group Policy Creator Owners")
OPERATOR_GROUPS = ("Account Operators", "Server Operators", "Print Operators", "Backup Operators")
SUPPORTED_DOMAIN_MODES = ("Windows2016Domain", "Windows2025Domain")
SUPPORTED_FOREST_MODES = ("Windows2016Forest", "Windows2025Forest")


# ── data access ────────────────────────────────────────────────────────────

def domain(d: str) -> Dict[str, Any]:
    v = json_section(d, "AD_DOMAIN")
    return v if isinstance(v, dict) else {}


def groups(d: str) -> Dict[str, Any]:
    v = json_section(d, "AD_PRIVILEGED")
    return v if isinstance(v, dict) else {}


def members(d: str, name: str) -> List[Dict[str, Any]]:
    g = groups(d).get(name) or {}
    return [m for m in as_list(g.get("Members")) if isinstance(m, dict)]


def accounts(d: str) -> Dict[str, Any]:
    v = json_section(d, "AD_ACCOUNTS")
    return v if isinstance(v, dict) else {}


def bucket(d: str, key: str) -> Dict[str, Any]:
    v = accounts(d).get(key)
    return v if isinstance(v, dict) else {"Count": None, "Sample": []}


def count(d: str, key: str) -> Optional[int]:
    c = bucket(d, key).get("Count")
    return int(c) if isinstance(c, (int, float)) else None


def dc_config(d: str) -> Dict[str, Any]:
    v = json_section(d, "AD_DC_CONFIG")
    return v if isinstance(v, dict) else {}


def ad_reg(d: str, path: str, name: str):
    return registry_value(json_section(d, "AD_REGISTRY"), path, name)


def trusts(d: str) -> List[Dict[str, Any]]:
    return [t for t in as_list(json_section(d, "AD_TRUSTS")) if isinstance(t, dict)]


def domain_sid(d: str) -> str:
    return str(domain(d).get("DomainSID") or "")


def privileged_users(d: str) -> Dict[str, Dict[str, Any]]:
    """Every user account in a privileged group (nested), keyed by SID."""
    out: Dict[str, Dict[str, Any]] = {}
    for g in PRIVILEGED_GROUPS:
        for m in members(d, g):
            if m.get("Class") == "user" and m.get("Sid"):
                entry = out.setdefault(m["Sid"], dict(m, Groups=[]))
                entry["Groups"].append(g)
    return out


def _is_rid(sid: str, rid: int) -> bool:
    return bool(sid) and sid.endswith(f"-{rid}")


def _names(items, limit: int = 20) -> str:
    items = list(items)
    shown = ", ".join(str(i) for i in items[:limit])
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return (shown + more) if items else "none"


def _bucket_evidence(d: str, key: str, label: str) -> str:
    b = bucket(d, key)
    if b.get("Count") is None:
        return f"{label}: not collected"
    return f"{label}: {b.get('Count')} — {_names(as_list(b.get('Sample')))}"


# ── CIS (DC profile) ───────────────────────────────────────────────────────

def _from_windows(r) -> BenchmarkRule:
    return BenchmarkRule(
        id=f"AD-CIS-{r.section}", section=r.section, title=r.title, severity=r.severity, level=r.level,
        check_fn=r.check_fn, evidence_fn=r.evidence_fn, remediation=r.remediation,
        description=r.description, manual=r.manual, scope=r.scope,
        data_sections=list(r.data_sections), source="CIS",
    )


def _allowed_pipes(d: str) -> bool:
    value = ad_reg(d, SRV, "NullSessionPipes")
    if value is None:
        value = W._reg(d, W._SRV, "NullSessionPipes")
    pipes = [p.strip().upper() for p in as_list(value) if str(p).strip()]
    return all(p in {"LSARPC", "NETLOGON", "SAMR", "BROWSER"} for p in pipes)


def cis_extra_rules() -> List[BenchmarkRule]:
    return [
        BenchmarkRule(
            id="AD-CIS-2.2.5", section="2.2.5",
            title="Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)",
            severity="medium", level="L1",
            check_fn=lambda d: W._rights_exact(d, "SeMachineAccountPrivilege", ["Administrators"]),
            evidence_fn=lambda d: f"SeMachineAccountPrivilege = {W._user_right_sids(d, 'SeMachineAccountPrivilege')}",
            remediation="Default Domain Controllers Policy > User Rights Assignment > Add workstations to domain: Administrators.",
            scope="DC", data_sections=["USER_RIGHTS", "SECURITY_POLICY"]),
        BenchmarkRule(
            id="AD-CIS-2.3.5.1", section="2.3.5.1",
            title="Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)",
            severity="medium", level="L1",
            check_fn=lambda d: ad_reg(d, LSA, "SubmitControl") in (None, 0),
            evidence_fn=lambda d: f"SubmitControl = {ad_reg(d, LSA, 'SubmitControl')} (absent = Disabled)",
            remediation=r"Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SubmitControl = 0.",
            scope="DC", data_sections=["AD_REGISTRY"]),
        BenchmarkRule(
            id="AD-CIS-2.3.10.6", section="2.3.10.6",
            title="Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)",
            severity="medium", level="L1",
            check_fn=_allowed_pipes,
            evidence_fn=lambda d: f"NullSessionPipes = {ad_reg(d, SRV, 'NullSessionPipes')} (allowed: LSARPC, NETLOGON, SAMR, BROWSER)",
            remediation="Set NullSessionPipes to LSARPC, NETLOGON, SAMR.",
            scope="DC", data_sections=["AD_REGISTRY"]),
        BenchmarkRule(
            id="AD-CIS-5.1", section="5.1",
            title="Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)",
            severity="high", level="L1",
            check_fn=lambda d: dc_config(d).get("SpoolerStartType") in ("Disabled", "NotInstalled"),
            evidence_fn=lambda d: f"Spooler: {dc_config(d).get('SpoolerStatus')}, start type {dc_config(d).get('SpoolerStartType')}",
            remediation="Stop the Print Spooler service and set its start type to Disabled.",
            scope="DC", data_sections=["AD_DC_CONFIG"]),
    ]


def cis_rules(gate: str = "win_2025") -> List[BenchmarkRule]:
    win = W.filter_rules_by_scope(W.build_windows_cis_rules_for_version(gate), True)
    rules = [_from_windows(r) for r in win if r.section not in _REPLACED]
    rules.extend(cis_extra_rules())
    return sorted(rules, key=lambda r: [int(p) if p.isdigit() else p for p in re.split(r"\.", r.section)])


# ── Beyond CIS: domain checks ──────────────────────────────────────────────

def _dom(rules, n, title, severity, check, evidence, remediation, sections, level="L1", description="",
         unavailable=None):
    rules.append(BenchmarkRule(
        id=f"AD-DOM-{n}", section=n, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation,
        description=description or title, data_sections=list(sections), source="Beyond CIS",
        unavailable_fn=unavailable))


def _groups_unreadable(*names):
    """Reason when one of the groups a rule needs could not be read."""
    def fn(d):
        bad = [f"{n}: {(groups(d).get(n) or {}).get('Error')}" for n in (names or PRIVILEGED_GROUPS)
               if (groups(d).get(n) or {}).get("Error")]
        return "could not read " + "; ".join(bad) if bad else None
    return fn


def _missing(*keys):
    """Reason when an account query did not come back."""
    def fn(d):
        gone = [k for k in keys if accounts(d).get(k) is None]
        return f"{', '.join(gone)} not collected" if gone else None
    return fn


def _group_members_ev(name):
    def ev(d):
        g = groups(d).get(name) or {}
        if g.get("Error"):
            return f"{name}: could not be read — {g['Error']}"
        if not g.get("Exists", True):
            return f"{name}: group not present"
        ms = members(d, name)
        return f"{name}: {len(ms)} member(s) — {_names(m.get('Sam') for m in ms)}"
    return ev


def _only_builtin_admin(name):
    def check(d):
        return all(_is_rid(m.get("Sid", ""), 500) for m in members(d, name))
    return check


def _priv_filter(d, pred) -> List[str]:
    return sorted(u.get("Sam") or sid for sid, u in privileged_users(d).items() if pred(u))


def _priv_check(pred):
    return lambda d: not _priv_filter(d, pred)


def _priv_ev(pred, label):
    return lambda d: f"{label}: {_names(_priv_filter(d, pred))}"


def _none_in(key):
    return lambda d: count(d, key) == 0


def _stale(u, days):
    if not u.get("Enabled"):
        return False
    last = u.get("LastLogonDays")
    return last is None or last > days


def _trust_type(t) -> str:
    return str(t.get("TrustType") or "")


def _external(t) -> bool:
    return not t.get("IntraForest") and not t.get("ForestTransitive")


def _dc_os_ok(dc) -> bool:
    os_name = str(dc.get("OperatingSystem") or "")
    return bool(re.search(r"Windows Server (2016|2019|2022|2025)", os_name))


def _laps_coverage(d) -> Optional[float]:
    total = count(d, "WindowsComputers")
    if total is None:
        return None
    if total == 0:
        return 100.0
    managed = max(count(d, "LapsWindowsManaged") or 0, count(d, "LapsLegacyManaged") or 0)
    return round(100.0 * managed / total, 1)


def _ds_heuristics_anonymous(d) -> bool:
    h = str(domain(d).get("DsHeuristics") or "")
    return len(h) >= 7 and h[6] == "2"


def _rid_user(d, key) -> Dict[str, Any]:
    v = accounts(d).get(key)
    return v if isinstance(v, dict) else {}


def domain_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    P = ["AD_PRIVILEGED"]
    A = ["AD_ACCOUNTS"]
    D = ["AD_DOMAIN"]

    # 1 — Privileged access
    _dom(r, "1.1", "Ensure 'Schema Admins' has no members other than the built-in Administrator", "high",
         _only_builtin_admin("Schema Admins"), _group_members_ev("Schema Admins"),
         "Remove every account from Schema Admins; add one only for the duration of a schema change.", P)
    _dom(r, "1.2", "Ensure 'Enterprise Admins' has no members other than the built-in Administrator", "high",
         _only_builtin_admin("Enterprise Admins"), _group_members_ev("Enterprise Admins"),
         "Remove standing members from Enterprise Admins; grant it temporarily for forest-wide changes.", P)
    _dom(r, "1.3", "Ensure 'Domain Admins' has no more than 5 members", "medium",
         lambda d: len(members(d, "Domain Admins")) <= 5, _group_members_ev("Domain Admins"),
         "Reduce Domain Admins to the few accounts that administer domain controllers; delegate everything else.", P)
    _dom(r, "1.4", "Ensure the Account, Server, Print and Backup Operators groups have no members", "high",
         lambda d: all(not members(d, g) for g in OPERATOR_GROUPS),
         lambda d: "; ".join(_group_members_ev(g)(d) for g in OPERATOR_GROUPS),
         "Empty the built-in operator groups; their members can log on to and take over domain controllers.", P)
    _dom(r, "1.5", "Ensure 'DnsAdmins' has no members", "medium",
         lambda d: not members(d, "DnsAdmins"), _group_members_ev("DnsAdmins"),
         "Remove members from DnsAdmins (they can load code into the DNS service on DCs); treat it as Tier 0.", P)
    _dom(r, "1.6", "Ensure privileged groups contain no disabled or inactive (90+ days) accounts", "medium",
         _priv_check(lambda u: not u.get("Enabled") or _stale(u, 90)),
         _priv_ev(lambda u: not u.get("Enabled") or _stale(u, 90), "Disabled or inactive privileged accounts"),
         "Remove disabled and unused accounts from privileged groups.", P)
    _dom(r, "1.7", "Ensure privileged accounts do not have 'Password never expires'", "high",
         _priv_check(lambda u: u.get("Enabled") and u.get("PwdNeverExpires")),
         _priv_ev(lambda u: u.get("Enabled") and u.get("PwdNeverExpires"), "Privileged accounts with non-expiring passwords"),
         "Clear 'Password never expires' on privileged accounts and rotate their passwords.", P)
    _dom(r, "1.8", "Ensure privileged account passwords were changed in the last 365 days", "medium",
         _priv_check(lambda u: u.get("Enabled") and (u.get("PwdLastSetDays") is None or u.get("PwdLastSetDays") > 365)),
         _priv_ev(lambda u: u.get("Enabled") and (u.get("PwdLastSetDays") is None or u.get("PwdLastSetDays") > 365),
                  "Privileged accounts with passwords older than 365 days"),
         "Change the passwords of privileged accounts at least yearly.", P)
    _dom(r, "1.9", "Ensure privileged accounts are marked 'Account is sensitive and cannot be delegated'", "medium",
         _priv_check(lambda u: u.get("Enabled") and not u.get("NotDelegated")),
         _priv_ev(lambda u: u.get("Enabled") and not u.get("NotDelegated"), "Privileged accounts that can be delegated"),
         "Set 'Account is sensitive and cannot be delegated' on every privileged user account.", P)
    _dom(r, "1.10", "Ensure privileged user accounts are members of 'Protected Users'", "medium",
         lambda d: not [u for sid, u in privileged_users(d).items()
                        if u.get("Enabled") and not _is_rid(sid, 500)
                        and sid not in {m.get("Sid") for m in members(d, "Protected Users")}],
         lambda d: "Privileged accounts outside Protected Users: " + _names(sorted(
             u.get("Sam") for sid, u in privileged_users(d).items()
             if u.get("Enabled") and not _is_rid(sid, 500)
             and sid not in {m.get("Sid") for m in members(d, "Protected Users")})),
         "Add privileged user accounts (not service accounts) to Protected Users after testing their logons.",
         P, level="L2")
    _dom(r, "1.11", "Ensure the built-in Administrator account is marked 'sensitive and cannot be delegated'", "medium",
         lambda d: bool(_rid_user(d, "BuiltinAdmin").get("NotDelegated")),
         lambda d: f"{_rid_user(d, 'BuiltinAdmin').get('Sam')}: NotDelegated = {_rid_user(d, 'BuiltinAdmin').get('NotDelegated')}",
         "Set 'Account is sensitive and cannot be delegated' on the built-in Administrator.", A)
    _dom(r, "1.12", "Ensure privileged accounts have no service principal names (not Kerberoastable)", "high",
         _priv_check(lambda u: u.get("Enabled") and (u.get("Spn") or 0) > 0),
         _priv_ev(lambda u: u.get("Enabled") and (u.get("Spn") or 0) > 0, "Privileged accounts with SPNs"),
         "Remove SPNs from privileged accounts; run services under gMSAs that are not privileged.", P)
    _dom(r, "1.13", "Ensure 'Pre-Windows 2000 Compatible Access' does not contain Everyone or Anonymous Logon", "high",
         lambda d: not ({"S-1-1-0", "S-1-5-7"} & set(as_list((groups(d).get("Pre-Windows 2000 Compatible Access") or {}).get("Members")))),
         lambda d: "Members: " + _names(as_list((groups(d).get("Pre-Windows 2000 Compatible Access") or {}).get("Members"))),
         "Remove Everyone (S-1-1-0) and Anonymous Logon (S-1-5-7) from Pre-Windows 2000 Compatible Access.", P)

    # 2 — Kerberos and accounts
    _dom(r, "2.1", "Ensure the krbtgt account password was changed in the last 180 days", "high",
         lambda d: (_rid_user(d, "Krbtgt").get("PwdLastSetDays") or 10 ** 6) <= 180,
         lambda d: f"krbtgt password last set {_rid_user(d, 'Krbtgt').get('PwdLastSetDays')} days ago",
         "Reset the krbtgt password, wait for replication and the maximum ticket lifetime, then reset it again.", A)
    _dom(r, "2.2", "Ensure no account has Kerberos pre-authentication disabled (AS-REP roasting)", "high",
         _none_in("NoPreAuth"), lambda d: _bucket_evidence(d, "NoPreAuth", "Accounts without pre-authentication"),
         "Clear 'Do not require Kerberos preauthentication' on every account.", A)
    _dom(r, "2.3", "Ensure no account stores its password with reversible encryption", "high",
         _none_in("ReversibleEncryption"), lambda d: _bucket_evidence(d, "ReversibleEncryption", "Accounts with reversible encryption"),
         "Clear 'Store password using reversible encryption' and have the users change their passwords.", A)
    _dom(r, "2.4", "Ensure no account is restricted to DES Kerberos encryption", "medium",
         _none_in("DesOnly"), lambda d: _bucket_evidence(d, "DesOnly", "DES-only accounts"),
         "Clear 'Use only Kerberos DES encryption types' on every account.", A)
    _dom(r, "2.5", "Ensure no enabled account has 'Password not required'", "high",
         _none_in("PwdNotRequired"), lambda d: _bucket_evidence(d, "PwdNotRequired", "Enabled accounts with PASSWD_NOTREQD"),
         "Clear the PASSWD_NOTREQD flag and make sure each of these accounts has a password.", A)
    _dom(r, "2.6", "Ensure user accounts do not carry service principal names (use gMSAs)", "medium",
         _none_in("UserSpn"), lambda d: _bucket_evidence(d, "UserSpn", "Kerberoastable user accounts"),
         "Move services to group Managed Service Accounts, or give these accounts passwords of 25+ random characters.", A)
    _dom(r, "2.7", "Ensure the domain Guest account is disabled", "high",
         lambda d: _rid_user(d, "Guest").get("Enabled") is False,
         lambda d: f"{_rid_user(d, 'Guest').get('Sam')}: Enabled = {_rid_user(d, 'Guest').get('Enabled')}",
         "Disable the domain Guest account.", A)
    _dom(r, "2.8", "Ensure no enabled user account has 'Password never expires'", "medium",
         _none_in("PwdNeverExpires"), lambda d: _bucket_evidence(d, "PwdNeverExpires", "Accounts with non-expiring passwords"),
         "Clear 'Password never expires'; use gMSAs for services.", A)
    _dom(r, "2.9", "Ensure no enabled user account has been inactive for 90 days", "medium",
         _none_in("StaleUsers"), lambda d: _bucket_evidence(d, "StaleUsers", "Inactive enabled users"),
         "Disable user accounts unused for 90 days, then delete them after a retention period.", A)
    _dom(r, "2.10", "Ensure no enabled computer account has been inactive for 90 days", "low",
         _none_in("StaleComputers"), lambda d: _bucket_evidence(d, "StaleComputers", "Inactive enabled computers"),
         "Disable computer accounts unused for 90 days.", A)
    _dom(r, "2.11", "Ensure no enabled computer runs an unsupported Windows version", "medium",
         _none_in("UnsupportedOs"), lambda d: _bucket_evidence(d, "UnsupportedOs", "Computers on unsupported Windows"),
         "Upgrade or retire these computers (Windows 10 counts unless enrolled in Extended Security Updates).", A)

    # 3 — Delegation
    _dom(r, "3.1", "Ensure no computer other than a DC is trusted for unconstrained delegation", "high",
         _none_in("UnconstrainedComputers"), lambda d: _bucket_evidence(d, "UnconstrainedComputers", "Computers with unconstrained delegation"),
         "Replace unconstrained delegation with constrained or resource-based constrained delegation.", A)
    _dom(r, "3.2", "Ensure no user account is trusted for unconstrained delegation", "high",
         _none_in("UnconstrainedUsers"), lambda d: _bucket_evidence(d, "UnconstrainedUsers", "Users with unconstrained delegation"),
         "Clear 'Trust this user for delegation to any service' on user accounts.", A)
    _dom(r, "3.3", "Ensure no account uses constrained delegation with protocol transition", "medium",
         _none_in("ProtocolTransition"), lambda d: _bucket_evidence(d, "ProtocolTransition", "Accounts with protocol transition"),
         "Use 'Kerberos only' constrained delegation unless protocol transition is required and reviewed.", A)
    _dom(r, "3.4", "Ensure 'ms-DS-MachineAccountQuota' is 0", "medium",
         lambda d: domain(d).get("MachineAccountQuota") == 0,
         lambda d: f"ms-DS-MachineAccountQuota = {domain(d).get('MachineAccountQuota')}",
         "Set ms-DS-MachineAccountQuota to 0 and delegate computer joins to a dedicated group.", D)

    # 4 — Domain configuration
    _dom(r, "4.1", "Ensure the domain functional level is Windows Server 2016 or later", "medium",
         lambda d: domain(d).get("DomainMode") in SUPPORTED_DOMAIN_MODES,
         lambda d: f"DomainMode = {domain(d).get('DomainMode')}",
         "Raise the domain functional level once every DC runs Windows Server 2016 or later.", D)
    _dom(r, "4.2", "Ensure the forest functional level is Windows Server 2016 or later", "low",
         lambda d: domain(d).get("ForestMode") in SUPPORTED_FOREST_MODES,
         lambda d: f"ForestMode = {domain(d).get('ForestMode')}",
         "Raise the forest functional level once every domain is at 2016 or later.", D)
    _dom(r, "4.3", "Ensure every domain controller runs a supported Windows Server version", "high",
         lambda d: bool(as_list(domain(d).get("DomainControllers"))) and all(_dc_os_ok(dc) for dc in as_list(domain(d).get("DomainControllers"))),
         lambda d: "DCs: " + _names(f"{dc.get('Name')} ({dc.get('OperatingSystem')})" for dc in as_list(domain(d).get("DomainControllers"))),
         "Replace domain controllers older than Windows Server 2016.", D)
    _dom(r, "4.4", "Ensure the Active Directory Recycle Bin is enabled", "low",
         lambda d: domain(d).get("RecycleBinEnabled") is True,
         lambda d: f"Recycle Bin enabled = {domain(d).get('RecycleBinEnabled')}",
         "Enable the AD Recycle Bin (forest-wide, cannot be turned off).", D)
    _dom(r, "4.5", "Ensure the tombstone lifetime is at least 180 days", "low",
         lambda d: (domain(d).get("TombstoneLifetime") or 60) >= 180,
         lambda d: f"tombstoneLifetime = {domain(d).get('TombstoneLifetime')} (unset = 60)",
         "Set tombstoneLifetime to 180 on CN=Directory Service.", D)
    _dom(r, "4.6", "Ensure anonymous LDAP operations are not allowed (dSHeuristics)", "high",
         lambda d: not _ds_heuristics_anonymous(d),
         lambda d: f"dSHeuristics = {domain(d).get('DsHeuristics')!r}",
         "Set the 7th character of dSHeuristics back to 0.", D)
    _dom(r, "4.7", "Ensure the LAPS schema is installed (Windows LAPS or legacy LAPS)", "high",
         lambda d: bool(domain(d).get("LapsWindowsSchema") or domain(d).get("LapsLegacySchema")),
         lambda d: f"Windows LAPS schema = {domain(d).get('LapsWindowsSchema')}, legacy LAPS schema = {domain(d).get('LapsLegacySchema')}",
         "Run Update-LapsADSchema and deploy a Windows LAPS policy.", D)
    _dom(r, "4.8", "Ensure LAPS manages the local administrator password of at least 95% of Windows computers", "medium",
         lambda d: (_laps_coverage(d) or 0) >= 95,
         lambda d: f"LAPS coverage: {_laps_coverage(d)}% of {count(d, 'WindowsComputers')} enabled Windows computers",
         "Apply the Windows LAPS policy to every computer OU.", A)
    _dom(r, "4.9", "Ensure no Group Policy Preferences file in SYSVOL contains a password (cpassword)", "high",
         lambda d: not as_list((json_section(d, "AD_GPP") or {}).get("Files")),
         lambda d: "Files with cpassword: " + _names(as_list((json_section(d, "AD_GPP") or {}).get("Files"))),
         "Delete the preference items that carry passwords and change those passwords: the key is public.",
         ["AD_GPP"])
    _dom(r, "4.10", "Ensure external trusts have SID filtering (quarantine) enabled", "high",
         lambda d: all(t.get("SIDFilteringQuarantined") for t in trusts(d) if _external(t)),
         lambda d: "External trusts: " + _names(f"{t.get('Name')} (quarantine {t.get('SIDFilteringQuarantined')})"
                                                for t in trusts(d) if _external(t)),
         "netdom trust <trusting> /domain:<trusted> /quarantine:yes", ["AD_TRUSTS"])
    _dom(r, "4.11", "Ensure forest trusts do not allow TGT delegation", "medium",
         lambda d: not [t for t in trusts(d) if t.get("ForestTransitive") and t.get("TGTDelegation")],
         lambda d: "Forest trusts: " + _names(f"{t.get('Name')} (TGT delegation {t.get('TGTDelegation')})"
                                              for t in trusts(d) if t.get("ForestTransitive")),
         "netdom trust <trusting> /domain:<trusted> /EnableTGTDelegation:No", ["AD_TRUSTS"])

    # 5 — Domain controller host
    _dom(r, "5.1", "Ensure SMBv1 is disabled on the domain controller", "high",
         lambda d: dc_config(d).get("EnableSMB1Protocol") is False,
         lambda d: f"EnableSMB1Protocol = {dc_config(d).get('EnableSMB1Protocol')}",
         "Set-SmbServerConfiguration -EnableSMB1Protocol $false", ["AD_DC_CONFIG"])
    _dom(r, "5.2", "Ensure Netlogon secure channel protection is enforced (ZeroLogon, CVE-2020-1472)", "high",
         lambda d: ad_reg(d, NETLOGON, "FullSecureChannelProtection") in (None, 1),
         lambda d: f"FullSecureChannelProtection = {ad_reg(d, NETLOGON, 'FullSecureChannelProtection')} (absent = enforced)",
         r"Set HKLM\...\Netlogon\Parameters\FullSecureChannelProtection = 1.", ["AD_REGISTRY"])
    _dom(r, "5.3", "Ensure the KDC enforces strong certificate binding (CVE-2022-26923)", "medium",
         lambda d: ad_reg(d, KDC, "StrongCertificateBindingEnforcement") in (None, 2),
         lambda d: f"StrongCertificateBindingEnforcement = {ad_reg(d, KDC, 'StrongCertificateBindingEnforcement')} (absent = enforced)",
         r"Set HKLM\...\Services\Kdc\StrongCertificateBindingEnforcement = 2 after mapping certificates strongly.",
         ["AD_REGISTRY"])
    _dom(r, "5.4", "Ensure the DSRM administrator cannot log on while AD DS is running", "medium",
         lambda d: ad_reg(d, LSA, "DsrmAdminLogonBehavior") in (None, 0, 1),
         lambda d: f"DsrmAdminLogonBehavior = {ad_reg(d, LSA, 'DsrmAdminLogonBehavior')} (absent = 0)",
         r"Set HKLM\...\Control\Lsa\DsrmAdminLogonBehavior = 0.", ["AD_REGISTRY"])

    # Parts of a section that can fail on their own (a group in another
    # domain, an attribute the schema lacks) make the rule "not evaluated".
    unavailable = {
        "1.1": _groups_unreadable("Schema Admins"),
        "1.2": _groups_unreadable("Enterprise Admins"),
        "1.3": _groups_unreadable("Domain Admins"),
        "1.4": _groups_unreadable(*OPERATOR_GROUPS),
        "1.5": _groups_unreadable("DnsAdmins"),
        "1.6": _groups_unreadable(), "1.7": _groups_unreadable(), "1.8": _groups_unreadable(),
        "1.9": _groups_unreadable(), "1.12": _groups_unreadable(),
        "1.10": _groups_unreadable(*PRIVILEGED_GROUPS, "Protected Users"),
        "1.11": _missing("BuiltinAdmin"), "2.1": _missing("Krbtgt"), "2.7": _missing("Guest"),
        "2.2": _missing("NoPreAuth"), "2.3": _missing("ReversibleEncryption"), "2.4": _missing("DesOnly"),
        "2.5": _missing("PwdNotRequired"), "2.6": _missing("UserSpn"), "2.8": _missing("PwdNeverExpires"),
        "2.9": _missing("StaleUsers"), "2.10": _missing("StaleComputers"), "2.11": _missing("UnsupportedOs"),
        "3.1": _missing("UnconstrainedComputers"), "3.2": _missing("UnconstrainedUsers"),
        "3.3": _missing("ProtocolTransition"), "4.8": _missing("WindowsComputers"),
    }
    for rule in r:
        rule.unavailable_fn = unavailable.get(rule.section)
    return r


# ── selection ──────────────────────────────────────────────────────────────

def role_of(dump: str) -> Optional[int]:
    data = json_section(dump, "DOMAIN_ROLE")
    try:
        return int(data.get("DomainRole")) if isinstance(data, dict) else None
    except (TypeError, ValueError):
        return None


def rules_for(dump: str) -> List[BenchmarkRule]:
    role = role_of(dump)
    if role is not None and role < 4:
        raise ValueError(
            f"The target is not a domain controller (DomainRole {role}). "
            "Point the Active Directory audit at a domain controller, or audit this host as Windows Server.")
    return cis_rules(W._detect_gate(dump)) + domain_rules()


def all_rules() -> List[BenchmarkRule]:
    return cis_rules("win_2025") + domain_rules()


def describe(dump: str) -> str:
    d = domain(dump)
    return f"{d.get('DNSRoot') or '?'} — Windows Server {W._detect_version(dump)} DC, domain level {d.get('DomainMode')}"
