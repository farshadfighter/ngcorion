"""
Windows Server CIS Benchmark rule tests.

The Section 2.3 / 18 registry controls are generated from REGISTRY_CHECKS, the
same table the hardening templates are generated from, so most coverage here is
property-based over that table: a compliant value passes, a non-compliant or
missing value does not, and the value hardening writes is one the audit accepts.
The remaining families (account policy, user rights, audit policy, firewall,
guest account) are tested against realistic collector output, and collection
failures must surface as ERROR - never as compliant.
"""
import json

import pytest

from app.modules.windows.audit.rules import (
    REGISTRY_CHECKS,
    _audit_matches,
    _audit_policy_setting,
    _detect_gate,
    _detect_version,
    _fw_bool,
    _fw_enabled,
    _fw_inbound_block,
    _fw_int_gte,
    _guest_disabled,
    _pred,
    _reg,
    _rights_empty,
    _rights_exact,
    _rights_include,
    _secpol_int,
    _user_right_sids,
    build_all_windows_cis_rules,
    build_win2016_cis_rules,
    build_win2022_cis_rules,
    build_win2025_cis_rules,
    build_windows_cis_rules_for_version,
    evaluate_compliance,
    filter_rules_by_profile,
    filter_rules_by_scope,
    get_registry_properties,
    is_domain_controller,
    section_failure,
)
from app.modules.windows.hardening.command_templates import (
    WINDOWS_HARDENING_TEMPLATES,
    get_all_supported_checks,
    get_windows_hardening_template,
    get_windows_template_statements,
    get_windows_verify_statements,
)
from app.modules.windows.hardening.parameter_metadata import (
    WINDOWS_CHECK_PARAMETER_MAP,
    WINDOWS_PARAMETER_REGISTRY,
    categorize_windows_checks_by_fixability,
    get_windows_check_defaults,
    is_windows_check_auto_fixable,
)
from app.core.hardening_param_security import ParameterSecurityError


def dump(**sections) -> str:
    return "\n".join(f"===SECTION:{name}===\n{body}" for name, body in sections.items())


def registry(values) -> str:
    """REGISTRY section as the collector emits it: {path: {prop: value}}."""
    out = {}
    for path, prop, value in values:
        out.setdefault(path, {})[prop] = value
    return json.dumps(out)


@pytest.fixture(scope="module")
def rules():
    return build_win2025_cis_rules()


@pytest.fixture(scope="module")
def by_id(rules):
    return {r.id: r for r in rules}


# ================================================================== #
#  Rule-set structure                                                #
# ================================================================== #

class TestRuleSets:
    def test_2025_rule_count(self, rules):
        assert len(rules) == 273
        assert sum(r.manual for r in rules) == 17

    def test_ids_are_unique_and_versioned(self, rules):
        assert len({r.id for r in rules}) == len(rules)
        assert all(r.id == f"WIN-2025-{r.section}" for r in rules)

    @pytest.mark.parametrize("builder, gate", [
        (build_win2022_cis_rules, "win_2022"), (build_win2016_cis_rules, "win_2016"),
    ])
    def test_older_versions_fall_back_to_the_2025_superset(self, rules, builder, gate):
        older = builder()
        assert [r.id for r in older] == [r.id for r in rules]
        assert all(r.versions == [gate] for r in older)

    def test_default_entry_point_and_dispatch(self, rules):
        assert [r.id for r in build_all_windows_cis_rules()] == [r.id for r in rules]
        assert len(build_windows_cis_rules_for_version("no-such-gate")) == len(rules)

    def test_rule_attributes(self, rules):
        for r in rules:
            assert r.severity in ("high", "medium", "low", "info"), r.id
            assert r.level in ("L1", "L2"), r.id
            assert r.scope in ("all", "MS", "DC"), r.id
            assert r.scored is (not r.manual), r.id
            assert r.title and r.remediation, r.id
            if not r.manual:
                assert r.data_sections, f"{r.id} must declare the sections it reads"

    def test_registry_rules_come_from_the_shared_table(self, by_id):
        for c in REGISTRY_CHECKS:
            rule = by_id[f"WIN-2025-{c['section']}"]
            assert rule.audit_key == f"{c['path']}\\{c['prop']}"
            assert rule.data_sections == ["REGISTRY"]

    def test_collector_reads_only_named_registry_values(self):
        props = get_registry_properties()
        for c in REGISTRY_CHECKS:
            assert c["prop"] in props[c["path"]]
        # Winlogon is read for AutoAdminLogon; DefaultPassword lives beside it.
        assert all("DefaultPassword" not in v for v in props.values())

    def test_profile_filter(self, rules):
        l1 = filter_rules_by_profile(rules, "L1")
        assert l1 and all(r.level == "L1" for r in l1)
        assert filter_rules_by_profile(rules, "FULL") == rules

    def test_scope_filter(self, rules):
        ms = filter_rules_by_scope(rules, is_dc=False)
        dc = filter_rules_by_scope(rules, is_dc=True)
        assert all(r.scope in ("all", "MS") for r in ms)
        assert all(r.scope in ("all", "DC") for r in dc)
        assert {r.id for r in ms} != {r.id for r in dc}


# ================================================================== #
#  Version / role detection                                          #
# ================================================================== #

class TestDetection:
    @pytest.mark.parametrize("os_version, year, gate", [
        ({"BuildNumber": "14393"}, "2016", "win_2016"),
        ({"BuildNumber": "17763"}, "2022", "win_2022"),
        ({"BuildNumber": "20348"}, "2022", "win_2022"),
        ({"BuildNumber": "26100"}, "2025", "win_2025"),
        ({"BuildNumber": "1", "Caption": "Microsoft Windows Server 2019 Datacenter"}, "2019", "win_2022"),
        ({"BuildNumber": "1", "Caption": "Something else"}, "unknown", "win_2025"),
    ])
    def test_version_and_gate(self, os_version, year, gate):
        d = dump(OS_VERSION=json.dumps(os_version))
        assert _detect_version(d) == year
        assert _detect_gate(d) == gate

    @pytest.mark.parametrize("role, is_dc", [(2, False), (3, False), (4, True), (5, True)])
    def test_domain_controller(self, role, is_dc):
        assert is_domain_controller(dump(DOMAIN_ROLE=json.dumps({"DomainRole": role}))) is is_dc

    def test_unknown_role_defaults_to_member_server(self):
        assert is_domain_controller(dump(DOMAIN_ROLE="PS_ERROR: access denied")) is False


# ================================================================== #
#  Registry controls - property tests over REGISTRY_CHECKS           #
# ================================================================== #

def _good_and_bad(op, target):
    if op == "eq":
        return target, [target + 1]
    if op == "ne":
        return target + 1, [target]
    if op == "gte":
        return target, [target - 1]
    if op == "lte":
        return target, [target + 1]
    if op == "lte_nz":
        return target, [0, target + 1]
    if op == "range":
        return target[0], [target[0] - 1, target[1] + 1]
    if op == "eq_str":
        return str(target), [str(target) + "x"]
    if op == "empty":
        return [], ["SomeShare"]
    raise AssertionError(f"untested op {op}")


_CHECK_IDS = [f"{c['section']}-{c['prop']}" for c in REGISTRY_CHECKS]


class TestRegistryControls:
    @pytest.mark.parametrize("check", REGISTRY_CHECKS, ids=_CHECK_IDS)
    def test_compliant_value_passes_and_non_compliant_fails(self, by_id, check):
        rule = by_id[f"WIN-2025-{check['section']}"]
        good, bads = _good_and_bad(check["op"], check["target"])
        assert rule.check_fn(dump(REGISTRY=registry([(check["path"], check["prop"], good)]))) is True
        for bad in bads:
            assert rule.check_fn(dump(REGISTRY=registry([(check["path"], check["prop"], bad)]))) is False

    @pytest.mark.parametrize("check", REGISTRY_CHECKS, ids=_CHECK_IDS)
    def test_missing_value_is_not_compliant(self, by_id, check):
        rule = by_id[f"WIN-2025-{check['section']}"]
        # 'empty' controls are satisfied by "Not Configured"; nothing else is.
        expected = check["op"] == "empty"
        assert rule.check_fn(dump(REGISTRY="{}")) is expected

    @pytest.mark.parametrize("check", [c for c in REGISTRY_CHECKS if c["fixable"]],
                             ids=[i for c, i in zip(REGISTRY_CHECKS, _CHECK_IDS) if c["fixable"]])
    def test_hardening_writes_a_value_the_audit_accepts(self, check):
        # No audit<->hardening drift: the value a fix sets must pass the check.
        assert _pred(check["set"], check["op"], check["target"]) is True
        template = WINDOWS_HARDENING_TEMPLATES[f"WIN-2025-{check['section']}"]
        assert not template.manual_only
        assert any(f"'{check['prop']}'" in s for s in template.statements)
        assert template.verify_statements

    def test_registry_lookup_is_case_insensitive_on_path(self):
        c = REGISTRY_CHECKS[0]
        d = dump(REGISTRY=registry([(c["path"].upper(), c["prop"], 7)]))
        assert _reg(d, c["path"], c["prop"]) == 7

    @pytest.mark.parametrize("value", [None, "abc", ""])
    def test_numeric_predicates_fail_closed_on_unusable_values(self, value):
        for op, target in [("eq", 1), ("ne", 0), ("gte", 1), ("lte", 5), ("lte_nz", 5), ("range", (1, 5))]:
            assert _pred(value, op, target) is False


# ================================================================== #
#  Account policy (secedit [System Access])                          #
# ================================================================== #

_COMPLIANT_POLICY = """[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 365
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
ClearTextPassword = 0"""

_ACCOUNT_POLICY_IDS = ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.7", "1.2.1", "1.2.2", "1.2.4"]


class TestAccountPolicy:
    @pytest.mark.parametrize("sec", _ACCOUNT_POLICY_IDS)
    def test_compliant_policy_passes(self, by_id, sec):
        assert by_id[f"WIN-2025-{sec}"].check_fn(dump(SECURITY_POLICY=_COMPLIANT_POLICY)) is True

    @pytest.mark.parametrize("sec, key, bad", [
        ("1.1.1", "PasswordHistorySize", "5"),
        ("1.1.2", "MaximumPasswordAge", "0"),        # never expires
        ("1.1.2", "MaximumPasswordAge", "999"),
        ("1.1.4", "MinimumPasswordLength", "8"),
        ("1.1.5", "PasswordComplexity", "0"),
        ("1.1.7", "ClearTextPassword", "1"),
        ("1.2.2", "LockoutBadCount", "0"),           # lockout disabled
        ("1.2.2", "LockoutBadCount", "10"),
    ])
    def test_weak_policy_fails(self, by_id, sec, key, bad):
        weak = "\n".join(
            f"{key} = {bad}" if line.startswith(f"{key} =") else line
            for line in _COMPLIANT_POLICY.splitlines()
        )
        assert by_id[f"WIN-2025-{sec}"].check_fn(dump(SECURITY_POLICY=weak)) is False

    def test_missing_key_fails(self, by_id):
        policy = "\n".join(l for l in _COMPLIANT_POLICY.splitlines() if not l.startswith("MinimumPasswordLength"))
        assert by_id["WIN-2025-1.1.4"].check_fn(dump(SECURITY_POLICY=policy)) is False

    def test_secpol_int_parsing(self):
        d = dump(SECURITY_POLICY="[System Access]\nLockoutBadCount = 5,extra\nBroken = x")
        assert _secpol_int(d, "LockoutBadCount") == 5
        assert _secpol_int(d, "Broken") is None
        assert _secpol_int(d, "Absent") is None

    @pytest.mark.parametrize("param, check, key", [
        ("MAX_PASSWORD_AGE", "WIN-2025-1.1.2", "MaximumPasswordAge"),
        ("LOCKOUT_DURATION", "WIN-2025-1.2.1", "LockoutDuration"),
        ("LOCKOUT_THRESHOLD", "WIN-2025-1.2.2", "LockoutBadCount"),
        ("LOCKOUT_WINDOW", "WIN-2025-1.2.4", "ResetLockoutCount"),
    ])
    def test_hardening_defaults_satisfy_the_audit(self, by_id, param, check, key):
        value = get_windows_check_defaults(check)[param]
        d = dump(SECURITY_POLICY=f"[System Access]\n{key} = {value}")
        assert by_id[check].check_fn(d) is True


# ================================================================== #
#  User rights (secedit [Privilege Rights])                          #
# ================================================================== #

class TestUserRights:
    RIGHTS = """[Privilege Rights]
SeTcbPrivilege =
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeDenyBatchLogonRight = *S-1-5-32-546,*S-1-5-113"""

    def test_sid_parsing(self):
        d = dump(USER_RIGHTS=self.RIGHTS)
        assert _user_right_sids(d, "SeBackupPrivilege") == ["S-1-5-32-544", "S-1-5-32-551"]
        assert _user_right_sids(d, "SeTcbPrivilege") == []

    def test_modes(self):
        d = dump(USER_RIGHTS=self.RIGHTS)
        assert _rights_empty(d, "SeTcbPrivilege")
        assert _rights_exact(d, "SeDebugPrivilege", ["Administrators"])
        assert not _rights_exact(d, "SeBackupPrivilege", ["Administrators"])  # extra Backup Operators
        assert _rights_include(d, "SeDenyBatchLogonRight", ["Guests"])
        assert not _rights_include(d, "SeDenyBatchLogonRight", ["Guests", "Remote Desktop Users"])

    def test_falls_back_to_full_security_policy_export(self):
        d = dump(USER_RIGHTS="SECEDIT_EXPORT_FAILED", SECURITY_POLICY=self.RIGHTS)
        assert _user_right_sids(d, "SeDebugPrivilege") == ["S-1-5-32-544"]

    def test_failed_export_is_an_error_not_no_one(self, by_id):
        # Regression: an empty export used to read as "No One" = compliant.
        d = dump(USER_RIGHTS="SECEDIT_EXPORT_FAILED", SECURITY_POLICY="SECEDIT_EXPORT_FAILED")
        [finding] = evaluate_compliance(d, [by_id["WIN-2025-2.2.4"]])["findings"]
        assert finding["status"] == "error"
        assert finding["compliant"] is False


# ================================================================== #
#  Advanced audit policy (auditpol CSV)                              #
# ================================================================== #

# 'Other Logon/Logoff Events' deliberately precedes 'Logon': a substring match
# would then answer 'Logon' with the wrong row.
AUDITPOL = """Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
SRV,System,Other Logon/Logoff Events,{0CCE921C},Success and Failure,
SRV,System,Logon,{0CCE9215},Success,
SRV,System,Credential Validation,{0CCE923F},Success and Failure,
SRV,System,Account Lockout,{0CCE9217},No Auditing,"""


class TestAuditPolicy:
    def test_exact_subcategory_wins_over_substring(self):
        # 'Logon' must not be answered by 'Other Logon/Logoff Events'.
        assert _audit_policy_setting(dump(AUDIT_POLICY=AUDITPOL), "Logon") == "Success"

    def test_success_does_not_satisfy_success_and_failure(self):
        d = dump(AUDIT_POLICY=AUDITPOL)
        assert _audit_matches(d, "Logon", "Success")
        assert not _audit_matches(d, "Logon", "Success and Failure")
        assert _audit_matches(d, "Credential Validation", "Success and Failure")

    def test_no_auditing_and_absent_subcategory_fail(self):
        d = dump(AUDIT_POLICY=AUDITPOL)
        assert not _audit_matches(d, "Account Lockout", "Failure")
        assert not _audit_matches(d, "Special Logon", "Success")

    def test_rules(self, by_id):
        d = dump(AUDIT_POLICY=AUDITPOL)
        assert by_id["WIN-2025-17.1.1"].check_fn(d) is True    # Credential Validation S&F
        assert by_id["WIN-2025-17.5.4"].check_fn(d) is False   # Logon needs S&F
        assert by_id["WIN-2025-17.5.1"].check_fn(d) is False   # Account Lockout: no auditing


# ================================================================== #
#  Firewall (Get-NetFirewallProfile)                                 #
# ================================================================== #

def _fw(**overrides):
    base = {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "Block",
            "NotifyOnListen": "False", "LogFileName": r"%SystemRoot%\System32\logfiles\firewall\domainfw.log",
            "LogMaxSizeKilobytes": 16384, "LogBlocked": "True", "LogAllowed": "True"}
    base.update(overrides)
    return dump(FIREWALL_PROFILES=json.dumps([base]))


class TestFirewall:
    def test_compliant_profile(self, by_id):
        d = _fw()
        for sub in range(1, 8):
            assert by_id[f"WIN-2025-9.1.{sub}"].check_fn(d) is True, sub

    @pytest.mark.parametrize("value, expected", [
        ("True", True), ("False", False), ("NotConfigured", False),
        (True, True), (1, True), (2, False), (0, False), (99, False),
    ])
    def test_gpo_boolean_interpretation(self, value, expected):
        assert _fw_enabled(_fw(Enabled=value), "Domain") is expected

    def test_missing_key_is_not_compliant(self):
        assert _fw_bool({"Name": "Domain"}, "Enabled", True) is False

    @pytest.mark.parametrize("action, expected", [("Block", True), ("Allow", False), (4, True), (2, False)])
    def test_inbound_action(self, action, expected):
        assert _fw_inbound_block(_fw(DefaultInboundAction=action), "Domain") is expected

    def test_log_size_not_configured_is_not_huge(self):
        assert _fw_int_gte(_fw(LogMaxSizeKilobytes=18446744073709551615), "Domain",
                           "LogMaxSizeKilobytes", 16384) is False
        assert _fw_int_gte(_fw(LogMaxSizeKilobytes=4096), "Domain", "LogMaxSizeKilobytes", 16384) is False

    def test_missing_profile_fails(self, by_id):
        assert by_id["WIN-2025-9.2.1"].check_fn(_fw()) is False   # only Domain present


# ================================================================== #
#  Guest account                                                     #
# ================================================================== #

class TestGuestAccount:
    @pytest.mark.parametrize("users, expected", [
        ([{"Name": "Guest", "Enabled": False}], True),
        ([{"Name": "Guest", "Enabled": True}], False),
        ([{"Name": "Guest", "Enabled": "False"}], True),
        ([{"Name": "Administrator", "Enabled": True}], True),   # no Guest account at all
    ])
    def test_guest_status(self, users, expected):
        assert _guest_disabled(dump(LOCAL_USERS=json.dumps(users))) is expected

    def test_unreadable_user_list_fails(self):
        assert _guest_disabled(dump(LOCAL_USERS="PS_ERROR: denied")) is False


# ================================================================== #
#  Collection failures -> ERROR, never scored                        #
# ================================================================== #

class TestCollectionFailures:
    @pytest.mark.parametrize("body", ["", "(no output)", "PS_ERROR: Access is denied",
                                      "COLLECTION_ERROR: timeout", "SECEDIT_EXPORT_FAILED"])
    def test_section_failure_detected(self, body):
        assert section_failure(dump(SECURITY_POLICY=body), "SECURITY_POLICY")

    def test_unparseable_json_section_is_a_failure(self):
        assert section_failure(dump(REGISTRY="<html>error</html>"), "REGISTRY")
        assert section_failure(dump(REGISTRY="{}"), "REGISTRY") is None

    def test_failed_sections_are_reported_as_errors_and_not_scored(self, rules):
        d = dump(REGISTRY="PS_ERROR: denied", SECURITY_POLICY="SECEDIT_EXPORT_FAILED",
                 USER_RIGHTS="SECEDIT_EXPORT_FAILED", AUDIT_POLICY="CMD_ERROR: auditpol",
                 FIREWALL_PROFILES="PS_ERROR: denied", LOCAL_USERS="PS_ERROR: denied")
        result = evaluate_compliance(d, rules)
        s = result["summary"]
        assert s["total_rules_scored"] == 0
        assert s["passed_scored"] == 0
        assert s["error_checks"] == len(rules) - s["manual_checks"]
        assert all(f["status"] in ("error", "skipped") for f in result["findings"])


# ================================================================== #
#  evaluate_compliance                                               #
# ================================================================== #

class TestEvaluateCompliance:
    def test_summary_is_consistent(self, rules):
        d = dump(SECURITY_POLICY=_COMPLIANT_POLICY, AUDIT_POLICY=AUDITPOL, REGISTRY="{}")
        s = evaluate_compliance(d, rules)["summary"]
        assert s["manual_checks"] == 17
        assert s["passed_scored"] + s["failed_scored"] == s["total_rules_scored"]
        assert s["total_rules_scored"] + s["manual_checks"] + s["error_checks"] == len(rules)

    def test_findings_have_required_fields(self, rules):
        for f in evaluate_compliance(dump(SECURITY_POLICY=_COMPLIANT_POLICY), rules)["findings"]:
            for key in ("id", "title", "section", "severity", "level", "compliant",
                        "manual", "error", "status", "evidence", "remediation"):
                assert key in f, f"{f['id']} missing {key}"

    def test_manual_controls_are_skipped(self, rules):
        findings = evaluate_compliance("", rules)["findings"]
        manual = [f for f in findings if f["manual"]]
        assert len(manual) == 17
        assert all(f["status"] == "skipped" and not f["compliant"] for f in manual)


# ================================================================== #
#  Hardening templates and parameters                                #
# ================================================================== #

class TestHardening:
    def test_every_template_maps_to_a_rule(self, by_id):
        assert set(get_all_supported_checks()) <= set(by_id)

    def test_unhardened_rules_are_the_expected_families(self, rules):
        # User rights need a secedit import; manual/HKU controls have no fix;
        # 2.3.5.2 is a value *removal* that is deliberately left to an operator.
        missing = {r.id for r in rules if r.id not in WINDOWS_HARDENING_TEMPLATES}
        for rid in missing:
            rule = next(r for r in rules if r.id == rid)
            assert rule.manual or rule.section.startswith("2.2.") or rid == "WIN-2025-2.3.5.2", rid

    def test_template_shape(self):
        for check_id, t in WINDOWS_HARDENING_TEMPLATES.items():
            assert t.check_id == check_id and t.description
            if t.manual_only:
                assert not t.statements
            else:
                assert t.statements and t.verify_statements, check_id

    def test_parameter_substitution(self):
        stmts = get_windows_template_statements("WIN-2025-2.3.1.3", {"NEW_ADMIN_NAME": "LocalOps"})
        assert any("'LocalOps'" in s for s in stmts)
        assert not any("{NEW_ADMIN_NAME}" in s for s in stmts)

    def test_parameter_injection_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            get_windows_template_statements(
                "WIN-2025-2.3.1.3", {"NEW_ADMIN_NAME": "x'; Remove-Item C:\\ -Recurse #"})

    def test_unknown_template(self):
        assert get_windows_hardening_template("NOPE") is None
        assert get_windows_template_statements("NOPE") == []
        assert get_windows_verify_statements("NOPE") == []

    def test_parameter_map_is_consistent(self):
        for check_id, params in WINDOWS_CHECK_PARAMETER_MAP.items():
            assert check_id in WINDOWS_HARDENING_TEMPLATES, check_id
            for p in params:
                assert p in WINDOWS_PARAMETER_REGISTRY, f"{check_id} -> {p}"

    def test_fixability_categories(self):
        result = categorize_windows_checks_by_fixability(
            ["WIN-2025-1.1.1", "WIN-2025-1.2.2", "WIN-2025-2.3.1.3", "WIN-2025-2.2.1", "NOPE"])
        assert set(result["auto_fixable"]) == {"WIN-2025-1.1.1", "WIN-2025-1.2.2"}
        assert result["needs_params"] == ["WIN-2025-2.3.1.3"]
        assert set(result["not_supported"]) == {"WIN-2025-2.2.1", "NOPE"}
        assert not is_windows_check_auto_fixable("WIN-2025-2.3.1.4")
