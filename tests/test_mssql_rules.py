"""
MSSQL CIS Benchmark rule tests.

Exercises the version-aware rule sets (2016 / 2019 / 2022), per-rule pass/fail
against realistic audit dumps, fail-closed behaviour on unreadable data, and
the hardening template / parameter-metadata registries the rules map onto.
"""

import pytest

from app.modules.mssql.audit.rules import (
    _config_is_one,
    _config_is_zero,
    _config_val,
    _detect_distro,
    _detect_version,
    _ev_section,
    _section,
    build_all_mssql_cis_rules,
    build_mssql_2016_cis_rules,
    build_mssql_2019_cis_rules,
    build_mssql_2022_cis_rules,
    build_mssql_cis_rules_for_distro,
    evaluate_compliance,
    filter_rules_by_profile,
)
from app.modules.mssql.hardening.command_templates import (
    MSSQL_HARDENING_TEMPLATES,
    get_all_supported_checks,
    get_mssql_hardening_template,
    get_mssql_template_statements,
    get_mssql_verify_statements,
)
from app.modules.mssql.hardening.parameter_metadata import (
    MSSQL_CHECK_PARAMETER_MAP,
    MSSQL_PARAMETER_REGISTRY,
    aggregate_mssql_parameters_for_checks,
    categorize_mssql_checks_by_fixability,
    get_mssql_auto_fix_preview,
    get_mssql_check_defaults,
    get_mssql_parameter_metadata,
    is_mssql_check_auto_fixable,
)


# ================================================================== #
#  Audit dumps                                                       #
# ================================================================== #

_CONFIGURATIONS = """===SECTION:CONFIGURATIONS===
Ad Hoc Distributed Queries | 0 | Enable or disable Ad Hoc Distributed Queries
clr enabled | 0 | CLR user code execution
clr strict security | 1 | CLR strict security
cross db ownership chaining | 0 | Allow cross db ownership chaining
Database Mail XPs | 0 | Enable or disable Database Mail XPs
default trace enabled | 1 | Enable or disable the default trace
Ole Automation Procedures | 0 | Ole Automation Procedures
remote access | 0 | Allow remote access
remote admin connections | 0 | Allow remote DAC connections
scan for startup procs | 0 | Scan for startup stored procedures
xp_cmdshell | 0 | Enable or disable command shell"""

_VERSION_2019 = """===SECTION:VERSION===
Microsoft SQL Server 2019 (RTM-CU18) (KB5017593) - 15.0.4261.1 (X64)
Enterprise Edition (64-bit) on Windows Server 2019 Standard 10.0 (Build 17763:)"""

# SQL Server 2019 with a deliberate mix of compliant and non-compliant settings.
MOCK_MSSQL_2019_DUMP = f"""
{_VERSION_2019}
{_CONFIGURATIONS}
===SECTION:AUTH_MODE===
Mixed Mode (SQL Server and Windows Authentication)
===SECTION:SA_LOGIN===
sa | False | SQL_LOGIN
===SECTION:SA_SID===
sa | 0x01
===SECTION:SQL_LOGINS===
sa | False | True | True | SQL_LOGIN
appuser | False | True | True | SQL_LOGIN
##MS_PolicyTsqlExecutionLogin## | True | False | False | SQL_LOGIN
===SECTION:SYSADMIN_MEMBERS===
sa | SQL_LOGIN | False
DOMAIN\\sqladmin | WINDOWS_LOGIN | False
===SECTION:SYSADMIN_SQL_LOGINS===
sa | False
===SECTION:DATABASES===
master | False
msdb | True
AppDB | False
ReportDB | True
===SECTION:TCP_PORT===
1433
===SECTION:SERVER_AUDITS===
SecurityAudit | ABC-DEF-123 | STARTED | True | FILE | CONTINUE
===SECTION:AUDIT_SPECIFICATIONS===
LoginAuditSpec | SecurityAudit | True | FAILED_LOGIN_GROUP | FAILURE
LoginAuditSpec | SecurityAudit | True | SUCCESSFUL_LOGIN_GROUP | SUCCESS
===SECTION:ERRORLOG_COUNT===
12
===SECTION:GUEST_CONNECT===
AppDB | 0
ReportDB | 1
===SECTION:ORPHANED_USERS===
ReportDB | old_report_user
===SECTION:CONTAINED_DBS===
ContainedApp | 1 | PARTIAL | True
===SECTION:CONTAINED_DB_USERS===
ContainedApp | sqlcontaineduser | SQL
===SECTION:LOGIN_AUDIT_LEVEL===
2
===SECTION:CLR_ASSEMBLIES===
AppDB | MyUnsafeAssembly | UNSAFE
===SECTION:SYMMETRIC_KEYS===
AppDB | LegacyKey | TRIPLE_DES
===SECTION:ASYMMETRIC_KEYS===
AppDB | WeakRSAKey | 1024 | RSA_1024
===SECTION:BUILTIN_LOGINS===
BUILTIN\\Administrators | WINDOWS_GROUP | False
SQLHOST\\LocalDbaGroup | WINDOWS_GROUP | False
NT SERVICE\\SQLSERVERAGENT | WINDOWS_LOGIN | False
===SECTION:AGENT_PROXIES===
CmdExecProxy | 0x00
===SECTION:MSDB_ADMIN_ROLES===
(no rows returned)
===SECTION:HIDE_INSTANCE===
0
===SECTION:SA_NAME_CHECK===
sa | 1 | SQL_LOGIN
===SECTION:PUBLIC_SERVER_PERMS===
(no rows returned)
===SECTION:BACKUP_ENCRYPTION===
AppDB | 2026-09-01 | NULL
===SECTION:NETWORK_ENCRYPTION===
0
===SECTION:TDE_DATABASES===
AppDB | True
ReportDB | False
""".strip()

# Every scored control compliant.
MOCK_MSSQL_2019_COMPLIANT = f"""
{_VERSION_2019}
{_CONFIGURATIONS}
===SECTION:AUTH_MODE===
Windows Authentication Mode
===SECTION:SA_LOGIN===
(no rows returned)
===SECTION:SA_SID===
renamed_admin | 0x01
===SECTION:SQL_LOGINS===
(no rows returned)
===SECTION:SYSADMIN_MEMBERS===
DOMAIN\\sqladmin | WINDOWS_LOGIN | False
===SECTION:SYSADMIN_SQL_LOGINS===
(no rows returned)
===SECTION:DATABASES===
master | False
msdb | True
AppDB | False
===SECTION:TCP_PORT===
14330
===SECTION:SERVER_AUDITS===
SecurityAudit | ABC-DEF-123 | STARTED | True | FILE | CONTINUE
===SECTION:AUDIT_SPECIFICATIONS===
LoginAuditSpec | SecurityAudit | True | FAILED_LOGIN_GROUP | FAILURE
LoginAuditSpec | SecurityAudit | True | SUCCESSFUL_LOGIN_GROUP | SUCCESS
===SECTION:ERRORLOG_COUNT===
24
===SECTION:GUEST_CONNECT===
(no rows returned)
===SECTION:ORPHANED_USERS===
(no rows returned)
===SECTION:CONTAINED_DBS===
(no rows returned)
===SECTION:CONTAINED_DB_USERS===
(no rows returned)
===SECTION:LOGIN_AUDIT_LEVEL===
3
===SECTION:CLR_ASSEMBLIES===
(no rows returned)
===SECTION:SYMMETRIC_KEYS===
AppDB | DataKey | AES_256
===SECTION:ASYMMETRIC_KEYS===
AppDB | SigningKey | 2048 | RSA_2048
===SECTION:BUILTIN_LOGINS===
NT SERVICE\\SQLSERVERAGENT | WINDOWS_LOGIN | False
===SECTION:AGENT_PROXIES===
(no rows returned)
===SECTION:MSDB_ADMIN_ROLES===
(no rows returned)
===SECTION:HIDE_INSTANCE===
1
===SECTION:SA_NAME_CHECK===
(no rows returned)
===SECTION:PUBLIC_SERVER_PERMS===
(no rows returned)
===SECTION:BACKUP_ENCRYPTION===
(no rows returned)
===SECTION:NETWORK_ENCRYPTION===
1
===SECTION:TDE_DATABASES===
AppDB | True
""".strip()

MOCK_MSSQL_2016_DUMP = MOCK_MSSQL_2019_COMPLIANT.replace(
    _VERSION_2019,
    """===SECTION:VERSION===
Microsoft SQL Server 2016 (SP3-GDR) (KB5021129) - 13.0.6430.49 (X64)
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 (Build 14393:)""",
).replace("clr strict security | 1 | CLR strict security\n", "")

# Expected result of every scored 2019/2022 rule against MOCK_MSSQL_2019_DUMP.
EXPECTED_2019 = {
    "MSSQL-AHDQ": True, "MSSQL-CLR": True, "MSSQL-XDBOC": True, "MSSQL-DBMAIL": True,
    "MSSQL-OLEAUTO": True, "MSSQL-REMACC": True, "MSSQL-REMADMIN": True,
    "MSSQL-STARTPROC": True, "MSSQL-CLRSTRICT": True, "MSSQL-DEFTRACE": True,
    "MSSQL-PUBLICSERVER": True, "MSSQL-MSDBADMIN": True, "MSSQL-CHECKPOL": True,
    "MSSQL-ERRLOG": True, "MSSQL-LOGINAUDIT": True, "MSSQL-SRVAUDIT": True,
    "MSSQL-TRUSTWORTHY": False,   # ReportDB is TRUSTWORTHY (msdb is exempt)
    "MSSQL-PORT": False,          # default port 1433
    "MSSQL-HIDEINST": False,
    "MSSQL-SADISABLE": False,     # sa enabled
    "MSSQL-SARENAME": False,      # sid 0x01 still named sa
    "MSSQL-AUTOCLOSE": False,
    "MSSQL-NOSA": False,
    "MSSQL-AUTHMODE": False,      # mixed mode
    "MSSQL-GUEST": False,         # guest can CONNECT to ReportDB
    "MSSQL-ORPHAN": False,
    "MSSQL-CONTAINEDAUTH": False,
    "MSSQL-BUILTIN": False,
    "MSSQL-LOCALGROUP": False,    # SQLHOST\LocalDbaGroup (NT SERVICE\ is allowed)
    "MSSQL-PROXY": False,
    "MSSQL-CHECKEXP": False,
    "MSSQL-CLRSAFE": False,       # UNSAFE assembly
    "MSSQL-SYMKEY": False,        # TRIPLE_DES
    "MSSQL-ASYMKEY": False,       # 1024-bit
    "MSSQL-BACKUPENC": False,
    "MSSQL-NETENC": False,
    "MSSQL-TDE": False,           # ReportDB not encrypted
}

MANUAL_2022 = {
    "MSSQL-PATCH", "MSSQL-SINGLEFUNC", "MSSQL-PROTOCOLS", "MSSQL-SVCACCT-MSSQL",
    "MSSQL-SVCACCT-AGENT", "MSSQL-SVCACCT-FT", "MSSQL-SYSADMIN", "MSSQL-MUSTCHANGE",
    "MSSQL-SANITIZE", "MSSQL-BROWSER",
}


@pytest.fixture(scope="session")
def all_rules():
    return build_all_mssql_cis_rules()


@pytest.fixture(scope="session")
def rule_map(all_rules):
    return {r.id: r for r in all_rules}


@pytest.fixture(scope="session")
def scored_rules(all_rules):
    return [r for r in all_rules if not r.manual]


# ================================================================== #
#  Rule-set structure per version                                    #
# ================================================================== #

class TestRuleSets:
    def test_2022_rule_count(self):
        assert len(build_mssql_2022_cis_rules()) == 47

    def test_2019_is_identical_to_2022(self):
        assert [r.id for r in build_mssql_2019_cis_rules()] == [r.id for r in build_mssql_2022_cis_rules()]

    def test_default_entry_point_is_newest_superset(self, all_rules):
        assert [r.id for r in all_rules] == [r.id for r in build_mssql_2022_cis_rules()]

    def test_2016_drops_adds_and_renumbers(self):
        rules = {r.id: r for r in build_mssql_2016_cis_rules()}
        assert len(rules) == 45
        assert not {"MSSQL-CLRSTRICT", "MSSQL-SYSADMIN", "MSSQL-MSDBADMIN"} & set(rules)
        assert rules["MSSQL-XPCMDSHELL"].section == "2.15"
        assert rules["MSSQL-AUTOCLOSE"].section == "2.16"
        assert rules["MSSQL-NOSA"].section == "2.17"

    def test_2016_renumbering_does_not_leak_into_2022(self):
        rules = {r.id: r for r in build_mssql_2022_cis_rules()}
        assert rules["MSSQL-AUTOCLOSE"].section == "2.15"
        assert rules["MSSQL-NOSA"].section == "2.16"

    @pytest.mark.parametrize("builder", [build_mssql_2016_cis_rules, build_mssql_2022_cis_rules])
    def test_unique_ids_and_sections(self, builder):
        rules = builder()
        assert len({r.id for r in rules}) == len(rules)
        assert len({r.section for r in rules}) == len(rules)

    def test_manual_controls(self, all_rules):
        assert {r.id for r in all_rules if r.manual} == MANUAL_2022

    def test_rule_attributes(self, all_rules):
        for r in all_rules:
            assert r.id.startswith("MSSQL-")
            assert r.severity in ("high", "medium", "low", "info")
            assert r.level in ("L1", "L2")
            assert r.title and r.remediation
            assert callable(r.check_fn) and callable(r.evidence_fn)

    def test_l1_profile_filter(self, all_rules):
        l1 = filter_rules_by_profile(all_rules, "L1")
        assert l1 and all(r.level == "L1" for r in l1)
        assert filter_rules_by_profile(all_rules, "FULL") == all_rules


# ================================================================== #
#  Version detection and dispatch                                    #
# ================================================================== #

class TestVersionDetection:
    @pytest.mark.parametrize("text, major, distro", [
        ("Microsoft SQL Server 2016 (SP3)", 13, "mssql_2016"),
        ("Microsoft SQL Server 2017 (RTM-CU31)", 14, "mssql_2019"),
        ("Microsoft SQL Server 2019 (RTM-CU18)", 15, "mssql_2019"),
        ("Microsoft SQL Server 2022 (RTM-CU10)", 16, "mssql_2022"),
        ("SQL build 15.0.4261.1", 15, "mssql_2019"),
        ("something unrecognised", 0, "mssql_2022"),
    ])
    def test_detect(self, text, major, distro):
        dump = f"===SECTION:VERSION===\n{text}"
        assert _detect_version(dump) == major
        assert _detect_distro(dump) == distro

    def test_dispatch_by_distro(self):
        assert len(build_mssql_cis_rules_for_distro("mssql_2016")) == 45
        assert len(build_mssql_cis_rules_for_distro("mssql_2019")) == 47
        assert len(build_mssql_cis_rules_for_distro("unknown")) == 47


class TestHelpers:
    def test_section_extraction(self):
        assert "Mixed Mode" in _section(MOCK_MSSQL_2019_DUMP, "AUTH_MODE")
        assert _section(MOCK_MSSQL_2019_DUMP, "NO_SUCH_SECTION") == ""

    def test_config_helpers(self):
        assert _config_val(MOCK_MSSQL_2019_DUMP, "clr enabled") == "0"
        assert _config_is_zero(MOCK_MSSQL_2019_DUMP, "clr enabled")
        assert _config_is_one(MOCK_MSSQL_2019_DUMP, "default trace enabled")
        assert _config_val(MOCK_MSSQL_2019_DUMP, "no such option") == ""

    def test_evidence_truncation(self):
        assert len(_ev_section(MOCK_MSSQL_2019_DUMP, "DATABASES", 10)) <= 13


# ================================================================== #
#  Per-rule evaluation                                               #
# ================================================================== #

class TestRuleEvaluation:
    def test_expectations_cover_every_scored_rule(self, scored_rules):
        assert set(EXPECTED_2019) == {r.id for r in scored_rules}

    @pytest.mark.parametrize("rule_id, expected", sorted(EXPECTED_2019.items()))
    def test_rule_against_mixed_dump(self, rule_map, rule_id, expected):
        assert rule_map[rule_id].check_fn(MOCK_MSSQL_2019_DUMP) is expected

    @pytest.mark.parametrize("rule_id", sorted(EXPECTED_2019))
    def test_rule_passes_on_compliant_dump(self, rule_map, rule_id):
        assert rule_map[rule_id].check_fn(MOCK_MSSQL_2019_COMPLIANT) is True

    def test_xp_cmdshell_on_2016(self):
        rule = {r.id: r for r in build_mssql_2016_cis_rules()}["MSSQL-XPCMDSHELL"]
        assert rule.check_fn(MOCK_MSSQL_2016_DUMP) is True
        enabled = MOCK_MSSQL_2016_DUMP.replace("xp_cmdshell | 0", "xp_cmdshell | 1")
        assert rule.check_fn(enabled) is False

    def test_system_sql_logins_are_ignored_by_check_policy(self, rule_map):
        # '##MS_...##' certificate logins have CHECK_POLICY off by design.
        assert rule_map["MSSQL-CHECKPOL"].check_fn(MOCK_MSSQL_2019_DUMP) is True
        weak = MOCK_MSSQL_2019_DUMP.replace(
            "appuser | False | True | True", "appuser | False | False | True")
        assert rule_map["MSSQL-CHECKPOL"].check_fn(weak) is False

    def test_server_audit_needs_both_login_groups(self, rule_map):
        failed_only = MOCK_MSSQL_2019_DUMP.replace("SUCCESSFUL_LOGIN_GROUP", "OTHER_GROUP")
        assert rule_map["MSSQL-SRVAUDIT"].check_fn(failed_only) is False


# ================================================================== #
#  Fail-closed: unreadable data is never evidence of compliance      #
# ================================================================== #

_ALL_SECTIONS = sorted({
    line[len("===SECTION:"):-3]
    for line in MOCK_MSSQL_2019_DUMP.splitlines()
    if line.startswith("===SECTION:")
})


class TestFailClosed:
    def test_query_errors_never_pass(self, scored_rules):
        dump = "\n".join(f"===SECTION:{n}===\nQUERY_ERROR: permission denied" for n in _ALL_SECTIONS)
        passing = [r.id for r in scored_rules if r.check_fn(dump)]
        assert passing == []

    def test_empty_dump_never_passes(self, scored_rules):
        assert [r.id for r in scored_rules if r.check_fn("")] == []

    def test_evaluation_does_not_crash_on_no_rows(self, all_rules):
        dump = "\n".join(f"===SECTION:{n}===\n(no rows returned)" for n in _ALL_SECTIONS)
        result = evaluate_compliance(dump, all_rules)
        assert result["summary"]["total_rules_scored"] == len(EXPECTED_2019)
        for f in result["findings"]:
            assert isinstance(f["compliant"], bool)
            assert isinstance(f["evidence"], str)


# ================================================================== #
#  evaluate_compliance summary                                       #
# ================================================================== #

class TestComplianceSummary:
    def test_mixed_dump_counts(self, all_rules):
        s = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)["summary"]
        assert s["total_rules_scored"] == 37
        assert s["manual_checks"] == 10
        assert s["passed_scored"] == sum(EXPECTED_2019.values())
        assert s["passed_scored"] + s["failed_scored"] == s["total_rules_scored"]

    def test_compliant_dump_is_100_percent(self, all_rules):
        s = evaluate_compliance(MOCK_MSSQL_2019_COMPLIANT, all_rules)["summary"]
        assert s["compliance_pct"] == 100.0
        assert s["weighted_compliance_pct"] == 100.0

    def test_manual_findings_are_skipped_not_scored(self, all_rules):
        findings = evaluate_compliance(MOCK_MSSQL_2019_COMPLIANT, all_rules)["findings"]
        manual = [f for f in findings if f["manual"]]
        assert {f["id"] for f in manual} == MANUAL_2022
        assert all(f["status"] == "skipped" and f["compliant"] is False for f in manual)

    def test_findings_have_required_fields(self, all_rules):
        for f in evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)["findings"]:
            for key in ("id", "title", "description", "section", "severity",
                        "level", "compliant", "manual", "status", "evidence", "remediation"):
                assert key in f, f"{f.get('id')} missing {key}"

    def test_every_rule_produces_string_evidence(self, all_rules):
        for r in all_rules:
            ev = r.evidence_fn(MOCK_MSSQL_2019_DUMP)
            assert isinstance(ev, str) and ev, r.id


# ================================================================== #
#  Hardening templates                                               #
# ================================================================== #

class TestHardeningTemplates:
    def test_every_rule_of_every_version_has_a_template(self):
        ids = {r.id for r in build_mssql_2022_cis_rules()} | {r.id for r in build_mssql_2016_cis_rules()}
        assert ids == set(get_all_supported_checks())
        assert len(MSSQL_HARDENING_TEMPLATES) == 48

    def test_manual_rules_have_manual_templates(self, all_rules):
        for r in all_rules:
            if r.manual:
                assert MSSQL_HARDENING_TEMPLATES[r.id].manual_only, r.id

    def test_template_attributes(self):
        for check_id, t in MSSQL_HARDENING_TEMPLATES.items():
            assert t.check_id == check_id
            assert t.description
            if t.manual_only:
                assert t.statements == [] and t.verify_statements == []
            else:
                assert t.statements and t.verify_statements, check_id

    def test_statement_substitution(self):
        stmts = get_mssql_template_statements("MSSQL-TRUSTWORTHY", {"DB_NAME": "ReportDB"})
        assert any("ReportDB" in s for s in stmts)
        assert not any("{DB_NAME}" in s for s in stmts)
        assert any("ReportDB" in s for s in get_mssql_verify_statements("MSSQL-TRUSTWORTHY", {"DB_NAME": "ReportDB"}))

    def test_multi_parameter_substitution(self):
        stmts = get_mssql_template_statements("MSSQL-CLRSAFE", {"DB_NAME": "AppDB", "ASSEMBLY_NAME": "MyAssembly"})
        assert any("MyAssembly" in s for s in stmts)
        assert any("AppDB" in s for s in stmts)

    def test_default_parameter_substitution(self):
        stmts = get_mssql_template_statements("MSSQL-LOGINAUDIT", {"AUDIT_LEVEL": "3"})
        assert any("3" in s for s in stmts)

    def test_nonexistent_template(self):
        assert get_mssql_hardening_template("FAKE-001") is None
        assert get_mssql_template_statements("FAKE-001") == []
        assert get_mssql_verify_statements("FAKE-001") == []


# ================================================================== #
#  Parameter metadata                                                #
# ================================================================== #

AUTO_FIXABLE = [
    "MSSQL-AHDQ", "MSSQL-CLR", "MSSQL-XDBOC", "MSSQL-DBMAIL", "MSSQL-OLEAUTO",
    "MSSQL-REMACC", "MSSQL-REMADMIN", "MSSQL-STARTPROC", "MSSQL-XPCMDSHELL",
    "MSSQL-CLRSTRICT", "MSSQL-DEFTRACE", "MSSQL-SADISABLE", "MSSQL-HIDEINST",
    "MSSQL-ERRLOG", "MSSQL-LOGINAUDIT",
]
NEEDS_PARAMS = [
    "MSSQL-SARENAME", "MSSQL-TRUSTWORTHY", "MSSQL-AUTOCLOSE", "MSSQL-GUEST",
    "MSSQL-CHECKPOL", "MSSQL-CHECKEXP", "MSSQL-CLRSAFE", "MSSQL-PROXY",
]


class TestParameterMetadata:
    def test_mapped_checks_have_templates_and_known_params(self):
        for check_id, params in MSSQL_CHECK_PARAMETER_MAP.items():
            assert get_mssql_hardening_template(check_id) is not None, check_id
            for p in params:
                assert p in MSSQL_PARAMETER_REGISTRY, f"{check_id} -> {p}"

    def test_registry_attributes(self):
        for name, meta in MSSQL_PARAMETER_REGISTRY.items():
            assert meta.name == name
            assert meta.input_type in ("text", "number", "select", "ip", "textarea")
            assert meta.label and meta.description
            assert get_mssql_parameter_metadata(name) is meta

    @pytest.mark.parametrize("check_id", AUTO_FIXABLE)
    def test_auto_fixable(self, check_id):
        assert is_mssql_check_auto_fixable(check_id)

    @pytest.mark.parametrize("check_id", NEEDS_PARAMS)
    def test_needs_params(self, check_id):
        assert not is_mssql_check_auto_fixable(check_id)

    def test_defaults(self):
        assert get_mssql_check_defaults("MSSQL-ERRLOG") == {"NUM_ERROR_LOGS": "12"}
        assert get_mssql_check_defaults("MSSQL-LOGINAUDIT") == {"AUDIT_LEVEL": "2"}

    def test_categorize(self):
        result = categorize_mssql_checks_by_fixability(
            ["MSSQL-CLR", "MSSQL-GUEST", "MSSQL-PATCH", "MSSQL-TDE"])
        assert result["auto_fixable"] == ["MSSQL-CLR"]
        assert result["needs_params"] == ["MSSQL-GUEST"]
        assert set(result["not_supported"]) == {"MSSQL-PATCH", "MSSQL-TDE"}

    def test_categorize_all_mapped_are_supported(self):
        mapped = list(MSSQL_CHECK_PARAMETER_MAP)
        result = categorize_mssql_checks_by_fixability(mapped)
        assert result["not_supported"] == []
        assert len(result["auto_fixable"]) + len(result["needs_params"]) == len(mapped)

    def test_aggregate_parameters(self):
        agg = aggregate_mssql_parameters_for_checks(["MSSQL-TRUSTWORTHY", "MSSQL-GUEST"])
        assert set(agg["DB_NAME"]["checks"]) == {"MSSQL-TRUSTWORTHY", "MSSQL-GUEST"}

    def test_auto_fix_preview(self):
        preview = get_mssql_auto_fix_preview(["MSSQL-HIDEINST", "MSSQL-CLRSTRICT"])
        assert len(preview) == 2
        assert all("check_id" in item and "defaults" in item for item in preview)


# ================================================================== #
#  Audit → hardening integration                                     #
# ================================================================== #

class TestHardeningIntegration:
    def test_failed_rules_all_map_to_templates(self, all_rules):
        findings = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)["findings"]
        failed = [f["id"] for f in findings if not f["compliant"]]
        assert failed
        for fid in failed:
            assert get_mssql_hardening_template(fid) is not None, fid
        cats = categorize_mssql_checks_by_fixability(failed)
        assert sum(len(v) for v in cats.values()) == len(failed)
