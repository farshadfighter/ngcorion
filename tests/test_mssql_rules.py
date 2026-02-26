"""
MSSQL CIS Benchmark Rule Tests

Simulates a hypothetical SQL Server 2019 instance with a realistic audit dump,
then exercises all 44 rules, hardening templates, and parameter metadata.
"""

import pytest
from app.modules.mssql.audit.rules import (
    build_all_mssql_cis_rules,
    filter_rules_by_profile,
    evaluate_compliance,
    _section,
    _config_val,
    _config_is_zero,
    _config_is_one,
    _detect_version,
    MSSQLCISRule,
)
from app.modules.mssql.hardening.command_templates import (
    MSSQL_HARDENING_TEMPLATES,
    get_mssql_hardening_template,
    get_all_supported_checks,
    get_mssql_template_statements,
    get_mssql_verify_statements,
)
from app.modules.mssql.hardening.parameter_metadata import (
    MSSQL_CHECK_PARAMETER_MAP,
    MSSQL_PARAMETER_REGISTRY,
    get_mssql_parameter_metadata,
    get_mssql_parameters_for_check,
    is_mssql_check_auto_fixable,
    get_mssql_check_defaults,
    categorize_mssql_checks_by_fixability,
    aggregate_mssql_parameters_for_checks,
    get_mssql_auto_fix_preview,
)


# ================================================================== #
#  Hypothetical SQL Server 2019 audit dump                           #
# ================================================================== #

# This simulates a mostly-compliant SQL Server 2019 instance with
# several deliberate failures to verify rule detection.
MOCK_MSSQL_2019_DUMP = """
===SECTION:VERSION===
Microsoft SQL Server 2019 (RTM-CU18) (KB5017593) - 15.0.4261.1 (X64)
Sep 12 2022 15:07:06
Copyright (C) 2019 Microsoft Corporation
Enterprise Edition (64-bit) on Windows Server 2019 Standard 10.0 (Build 17763:)
===SECTION:SERVER_PROPS===
15.0.4261.1 | RTM-CU18 | Enterprise Edition (64-bit) | 3 | 0 | 0 | SQL_Latin1_General_CP1_CI_AS
===SECTION:CONFIGURATIONS===
Ad Hoc Distributed Queries | 0 | Enable or disable Ad Hoc Distributed Queries
backup compression default | 0 | Enable backup compression by default
clr enabled | 0 | CLR user code execution
clr strict security | 1 | CLR strict security
cross db ownership chaining | 0 | Allow cross db ownership chaining
Database Mail XPs | 0 | Enable or disable Database Mail XPs
default trace enabled | 1 | Enable or disable the default trace
Ole Automation Procedures | 0 | Ole Automation Procedures
remote access | 0 | Allow remote access
remote admin connections | 0 | Allow remote DAC connections
scan for startup procs | 0 | Scan for startup stored procedures
SQL Mail XPs | 0 | SQL Mail XPs
xp_cmdshell | 0 | Enable or disable command shell
===SECTION:AUTH_MODE===
Mixed Mode (SQL Server and Windows Authentication)
===SECTION:SA_LOGIN===
sa | True | SQL_LOGIN | DISABLED
===SECTION:SQL_LOGINS===
sa | True | True | True | SQL_LOGIN
appuser | False | True | True | SQL_LOGIN
reportuser | False | True | False | SQL_LOGIN
===SECTION:SYSADMIN_MEMBERS===
sa | SQL_LOGIN | True
DOMAIN\\sqladmin | WINDOWS_LOGIN | False
===SECTION:CONTROL_SERVER===
(no rows returned)
===SECTION:DATABASES===
master | False | False | False | False | ONLINE | MULTI_USER
tempdb | False | False | False | False | ONLINE | MULTI_USER
model | False | False | False | False | ONLINE | MULTI_USER
msdb | True | False | False | False | ONLINE | MULTI_USER
AppDB | False | False | False | False | ONLINE | MULTI_USER
ReportDB | True | False | False | False | ONLINE | MULTI_USER
===SECTION:SERVER_AUDITS===
SecurityAudit | ABC-DEF-123 | STARTED | True | FILE | CONTINUE
===SECTION:AUDIT_SPECIFICATIONS===
LoginAuditSpec | SecurityAudit | True | FAILED_LOGIN_GROUP | FAILURE
LoginAuditSpec | SecurityAudit | True | SUCCESSFUL_LOGIN_GROUP | SUCCESS
===SECTION:ERRORLOG_COUNT===
12
===SECTION:LINKED_SERVERS===
(no rows returned)
===SECTION:SERVICE_ACCOUNTS===
SQL Server (MSSQLSERVER) | NT Service\\MSSQLSERVER | Running | Automatic
SQL Server Agent (MSSQLSERVER) | NT Service\\SQLSERVERAGENT | Running | Automatic
===SECTION:ENDPOINTS===
TSQL Local Machine | SHARED_MEMORY | STARTED | True
TSQL Named Pipes | NAMED_PIPES | STARTED | False
TSQL Default TCP | TCP | STARTED | False
===SECTION:TDE_STATUS===
master | NULL | NULL | NULL | NULL | NULL
model | NULL | NULL | NULL | NULL | NULL
msdb | NULL | NULL | NULL | NULL | NULL
AppDB | 3 | Encrypted | CERTIFICATE | AES_256 | 256
ReportDB | NULL | NULL | NULL | NULL | NULL
===SECTION:PUBLIC_PERMS===
(no rows returned)
===SECTION:GUEST_CONNECT===
AppDB | 0
ReportDB | 1
===SECTION:ORPHANED_USERS===
ReportDB | old_report_user
===SECTION:CONTAINED_DBS===
ContainedApp | 1 | PARTIAL | True
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
===SECTION:AGENT_PROXIES===
CmdExecProxy | 0x00
===SECTION:HIDE_INSTANCE===
0
===SECTION:SA_NAME_CHECK===
sa | 1 | SQL_LOGIN
===SECTION:MUST_CHANGE===
appuser | 0
reportuser | 0
===SECTION:CONTAINED_DB_USERS===
ContainedApp | sqlcontaineduser | SQL
===SECTION:PUBLIC_SERVER_PERMS===
(no rows returned)
""".strip()


# A fully-compliant dump for pass-rate testing
MOCK_MSSQL_2019_COMPLIANT = """
===SECTION:VERSION===
Microsoft SQL Server 2019 (RTM-CU18) (KB5017593) - 15.0.4261.1 (X64)
Sep 12 2022 15:07:06
Copyright (C) 2019 Microsoft Corporation
Enterprise Edition (64-bit) on Windows Server 2019 Standard 10.0 (Build 17763:)
===SECTION:SERVER_PROPS===
15.0.4261.1 | RTM-CU18 | Enterprise Edition (64-bit) | 3 | 1 | 0 | SQL_Latin1_General_CP1_CI_AS
===SECTION:CONFIGURATIONS===
Ad Hoc Distributed Queries | 0 | Enable or disable Ad Hoc Distributed Queries
backup compression default | 0 | Enable backup compression by default
clr enabled | 0 | CLR user code execution
clr strict security | 1 | CLR strict security
cross db ownership chaining | 0 | Allow cross db ownership chaining
Database Mail XPs | 0 | Enable or disable Database Mail XPs
default trace enabled | 1 | Enable or disable the default trace
Ole Automation Procedures | 0 | Ole Automation Procedures
remote access | 0 | Allow remote access
remote admin connections | 0 | Allow remote DAC connections
scan for startup procs | 0 | Scan for startup stored procedures
SQL Mail XPs | 0 | SQL Mail XPs
xp_cmdshell | 0 | Enable or disable command shell
===SECTION:AUTH_MODE===
Windows Authentication Mode
===SECTION:SA_LOGIN===
(no rows returned)
===SECTION:SQL_LOGINS===
(no rows returned)
===SECTION:SYSADMIN_MEMBERS===
sqladmin_renamed | SQL_LOGIN | False
===SECTION:CONTROL_SERVER===
(no rows returned)
===SECTION:DATABASES===
master | False | False | False | False | ONLINE | MULTI_USER
tempdb | False | False | False | False | ONLINE | MULTI_USER
model | False | False | False | False | ONLINE | MULTI_USER
msdb | True | False | False | False | ONLINE | MULTI_USER
===SECTION:SERVER_AUDITS===
SecurityAudit | ABC-DEF-123 | STARTED | True | FILE | CONTINUE
===SECTION:AUDIT_SPECIFICATIONS===
LoginAuditSpec | SecurityAudit | True | FAILED_LOGIN_GROUP | FAILURE
LoginAuditSpec | SecurityAudit | True | SUCCESSFUL_LOGIN_GROUP | SUCCESS
===SECTION:ERRORLOG_COUNT===
24
===SECTION:LINKED_SERVERS===
(no rows returned)
===SECTION:SERVICE_ACCOUNTS===
SQL Server (MSSQLSERVER) | NT Service\\MSSQLSERVER | Running | Automatic
===SECTION:ENDPOINTS===
TSQL Default TCP | TCP | STARTED | False
===SECTION:TDE_STATUS===
master | NULL | NULL | NULL | NULL | NULL
model | NULL | NULL | NULL | NULL | NULL
msdb | NULL | NULL | NULL | NULL | NULL
===SECTION:PUBLIC_PERMS===
(no rows returned)
===SECTION:GUEST_CONNECT===
(no rows returned)
===SECTION:ORPHANED_USERS===
(no rows returned)
===SECTION:CONTAINED_DBS===
(no rows returned)
===SECTION:LOGIN_AUDIT_LEVEL===
2
===SECTION:CLR_ASSEMBLIES===
(no rows returned)
===SECTION:SYMMETRIC_KEYS===
(no rows returned)
===SECTION:ASYMMETRIC_KEYS===
(no rows returned)
===SECTION:BUILTIN_LOGINS===
(no rows returned)
===SECTION:AGENT_PROXIES===
(no rows returned)
===SECTION:HIDE_INSTANCE===
1
===SECTION:SA_NAME_CHECK===
(no rows returned)
===SECTION:MUST_CHANGE===
(no rows returned)
===SECTION:CONTAINED_DB_USERS===
(no rows returned)
===SECTION:PUBLIC_SERVER_PERMS===
(no rows returned)
""".strip()


# SQL Server 2016 dump (pre-CLR strict security)
MOCK_MSSQL_2016_DUMP = """
===SECTION:VERSION===
Microsoft SQL Server 2016 (SP3-GDR) (KB5021129) - 13.0.6430.49 (X64)
Jan  6 2023 12:57:09
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 (Build 14393:)
===SECTION:SERVER_PROPS===
13.0.6430.49 | SP3 | Standard Edition (64-bit) | 2 | 0 | 0 | SQL_Latin1_General_CP1_CI_AS
===SECTION:CONFIGURATIONS===
Ad Hoc Distributed Queries | 0 | Enable or disable Ad Hoc Distributed Queries
clr enabled | 0 | CLR user code execution
cross db ownership chaining | 0 | Allow cross db ownership chaining
Database Mail XPs | 0 | Enable or disable Database Mail XPs
default trace enabled | 1 | Enable or disable the default trace
Ole Automation Procedures | 0 | Ole Automation Procedures
remote access | 0 | Allow remote access
remote admin connections | 0 | Allow remote DAC connections
scan for startup procs | 0 | Scan for startup stored procedures
SQL Mail XPs | 0 | SQL Mail XPs
xp_cmdshell | 0 | Enable or disable command shell
===SECTION:AUTH_MODE===
Windows Authentication Mode
===SECTION:SA_LOGIN===
(no rows returned)
===SECTION:SQL_LOGINS===
(no rows returned)
===SECTION:SYSADMIN_MEMBERS===
sqladmin_renamed | SQL_LOGIN | False
===SECTION:CONTROL_SERVER===
(no rows returned)
===SECTION:DATABASES===
master | False | False | False | False | ONLINE | MULTI_USER
tempdb | False | False | False | False | ONLINE | MULTI_USER
model | False | False | False | False | ONLINE | MULTI_USER
msdb | True | False | False | False | ONLINE | MULTI_USER
===SECTION:SERVER_AUDITS===
SecurityAudit | X-Y-Z | STARTED | True | FILE | CONTINUE
===SECTION:AUDIT_SPECIFICATIONS===
LoginAuditSpec | SecurityAudit | True | FAILED_LOGIN_GROUP | FAILURE
===SECTION:ERRORLOG_COUNT===
15
===SECTION:LINKED_SERVERS===
(no rows returned)
===SECTION:SERVICE_ACCOUNTS===
SQL Server (MSSQLSERVER) | NT Service\\MSSQLSERVER | Running | Automatic
===SECTION:ENDPOINTS===
TSQL Default TCP | TCP | STARTED | False
===SECTION:TDE_STATUS===
master | NULL | NULL | NULL | NULL | NULL
===SECTION:PUBLIC_PERMS===
(no rows returned)
===SECTION:GUEST_CONNECT===
(no rows returned)
===SECTION:ORPHANED_USERS===
(no rows returned)
===SECTION:CONTAINED_DBS===
(no rows returned)
===SECTION:LOGIN_AUDIT_LEVEL===
2
===SECTION:CLR_ASSEMBLIES===
(no rows returned)
===SECTION:SYMMETRIC_KEYS===
(no rows returned)
===SECTION:ASYMMETRIC_KEYS===
(no rows returned)
===SECTION:BUILTIN_LOGINS===
(no rows returned)
===SECTION:AGENT_PROXIES===
(no rows returned)
===SECTION:HIDE_INSTANCE===
1
===SECTION:SA_NAME_CHECK===
(no rows returned)
===SECTION:MUST_CHANGE===
(no rows returned)
===SECTION:CONTAINED_DB_USERS===
(no rows returned)
===SECTION:PUBLIC_SERVER_PERMS===
(no rows returned)
""".strip()


# ================================================================== #
#  Fixtures                                                          #
# ================================================================== #

@pytest.fixture(scope="session")
def all_rules():
    return build_all_mssql_cis_rules()


@pytest.fixture(scope="session")
def rule_map(all_rules):
    return {r.id: r for r in all_rules}


# ================================================================== #
#  Test: Rule count and structure                                    #
# ================================================================== #

class TestRuleCount:
    def test_total_rule_count(self, all_rules):
        assert len(all_rules) == 44

    def test_unique_rule_ids(self, all_rules):
        ids = [r.id for r in all_rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x)>1]}"

    def test_unique_sections(self, all_rules):
        """Each CIS section number should appear at most once (with known exceptions)."""
        sections = [r.section for r in all_rules]
        dupes = [s for s in sections if sections.count(s) > 1]
        # Known legitimate duplicates:
        # 2.10 — TRUSTWORTHY (011) + Protocols (027) map to same CIS section
        # 3.2 — SA disabled (014) + Guest CONNECT (032)
        # 3.3 — SA renamed (015) + Orphaned users (033)
        # 5.2 — Audit configured (020) + Default trace (040)
        # 5.3 — Audit enabled (021) + Login audit level (041)
        # 7.2 — Port (026) + Asymmetric key (044)
        # 4.1 — sysadmin role (016) + MUST_CHANGE (039)
        # 6.2 — CHECK_EXPIRATION (024) + CLR assembly (042)
        # 7.1 — TDE (025) + Symmetric keys (043)
        known_shared = {"2.10", "3.2", "3.3", "4.1", "5.2", "5.3", "6.2", "7.1", "7.2"}
        dupes_filtered = [d for d in set(dupes) if d not in known_shared]
        assert len(dupes_filtered) == 0, f"Unexpected duplicate sections: {dupes_filtered}"

    def test_l1_filter(self, all_rules):
        l1_only = filter_rules_by_profile(all_rules, "L1")
        assert all(r.level == "L1" for r in l1_only)
        assert len(l1_only) < len(all_rules)

    def test_full_filter(self, all_rules):
        full = filter_rules_by_profile(all_rules, "FULL")
        assert len(full) == len(all_rules)

    def test_rule_attributes(self, all_rules):
        for r in all_rules:
            assert r.id.startswith("MSSQL-")
            assert r.level in ("L1", "L2")
            assert r.severity in ("high", "medium", "low", "info")
            assert callable(r.check_fn)
            assert callable(r.evidence_fn)
            assert r.title
            assert r.description
            assert r.remediation


# ================================================================== #
#  Test: Version detection                                           #
# ================================================================== #

class TestVersionDetection:
    def test_detect_2019(self):
        assert _detect_version(MOCK_MSSQL_2019_DUMP) == 15

    def test_detect_2016(self):
        assert _detect_version(MOCK_MSSQL_2016_DUMP) == 13

    def test_detect_unknown(self):
        fake = "===SECTION:VERSION===\nSome random text\n"
        assert _detect_version(fake) == 0

    def test_detect_from_product_version(self):
        fake = "===SECTION:VERSION===\n16.0.1000.6 build info\n"
        assert _detect_version(fake) == 16


# ================================================================== #
#  Test: Helper functions                                            #
# ================================================================== #

class TestHelpers:
    def test_section_extraction(self):
        content = _section(MOCK_MSSQL_2019_DUMP, "AUTH_MODE")
        assert "Mixed Mode" in content

    def test_section_missing(self):
        assert _section(MOCK_MSSQL_2019_DUMP, "NONEXISTENT") == ""

    def test_config_val(self):
        assert _config_val(MOCK_MSSQL_2019_DUMP, "xp_cmdshell") == "0"
        assert _config_val(MOCK_MSSQL_2019_DUMP, "clr strict security") == "1"
        assert _config_val(MOCK_MSSQL_2019_DUMP, "nonexistent_option") == ""

    def test_config_is_zero(self):
        assert _config_is_zero(MOCK_MSSQL_2019_DUMP, "xp_cmdshell") is True
        assert _config_is_zero(MOCK_MSSQL_2019_DUMP, "default trace enabled") is False

    def test_config_is_one(self):
        assert _config_is_one(MOCK_MSSQL_2019_DUMP, "default trace enabled") is True
        assert _config_is_one(MOCK_MSSQL_2019_DUMP, "xp_cmdshell") is False


# ================================================================== #
#  Test: Individual rule evaluation against 2019 mock                #
# ================================================================== #

class TestRuleEvaluation2019:
    """
    Tests against MOCK_MSSQL_2019_DUMP — a partially-compliant server.
    Deliberate failures:
      - AUTH_MODE = Mixed Mode (MSSQL-L1-013 FAIL)
      - SA exists and named 'sa' (MSSQL-L2-015 FAIL, MSSQL-L1-030 FAIL)
      - ReportDB TRUSTWORTHY=True (MSSQL-L1-011 FAIL)
      - reportuser CHECK_EXPIRATION=False (MSSQL-L1-024 FAIL)
      - No TDE on ReportDB (MSSQL-L2-025 technically passes — any encrypted DB is enough)
      - Guest CONNECT on ReportDB (MSSQL-L1-032 FAIL)
      - Orphaned user (MSSQL-L1-033 FAIL)
      - ContainedApp AUTO_CLOSE=True (MSSQL-L1-029 FAIL)
      - ContainedApp SQL auth user (MSSQL-L1-034 FAIL)
      - UNSAFE CLR assembly (MSSQL-L1-042 FAIL)
      - TRIPLE_DES symmetric key (MSSQL-L1-043 FAIL)
      - 1024-bit asymmetric key (MSSQL-L1-044 FAIL)
      - BUILTIN\\Administrators login (MSSQL-L1-036 FAIL, MSSQL-L1-037 FAIL)
      - Agent proxy public access (MSSQL-L1-038 FAIL)
      - Hide instance = 0 (MSSQL-L1-028 FAIL)
      - MUST_CHANGE = 0 (MSSQL-L1-039 FAIL)
    """

    # -- Should PASS ------------------------------------------------ #

    def test_001_patches(self, rule_map):
        assert rule_map["MSSQL-L1-001"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_002_adhoc_queries(self, rule_map):
        assert rule_map["MSSQL-L1-002"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_003_clr_enabled(self, rule_map):
        assert rule_map["MSSQL-L1-003"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_004_cross_db(self, rule_map):
        assert rule_map["MSSQL-L1-004"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_005_db_mail(self, rule_map):
        assert rule_map["MSSQL-L1-005"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_006_ole_auto(self, rule_map):
        assert rule_map["MSSQL-L1-006"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_007_remote_access(self, rule_map):
        assert rule_map["MSSQL-L1-007"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_008_remote_admin(self, rule_map):
        assert rule_map["MSSQL-L2-008"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_009_startup_procs(self, rule_map):
        assert rule_map["MSSQL-L1-009"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_010_xp_cmdshell(self, rule_map):
        assert rule_map["MSSQL-L1-010"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_012_sql_mail(self, rule_map):
        assert rule_map["MSSQL-L2-012"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_014_sa_disabled(self, rule_map):
        assert rule_map["MSSQL-L1-014"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_016_sysadmin_members(self, rule_map):
        assert rule_map["MSSQL-L1-016"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_017_control_server(self, rule_map):
        assert rule_map["MSSQL-L1-017"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_018_public_perms(self, rule_map):
        assert rule_map["MSSQL-L2-018"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_019_errorlog_count(self, rule_map):
        assert rule_map["MSSQL-L1-019"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_020_audit_configured(self, rule_map):
        assert rule_map["MSSQL-L1-020"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_021_audit_enabled(self, rule_map):
        assert rule_map["MSSQL-L1-021"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_022_login_audit_spec(self, rule_map):
        assert rule_map["MSSQL-L2-022"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_023_check_policy(self, rule_map):
        assert rule_map["MSSQL-L1-023"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_025_tde(self, rule_map):
        # At least one DB encrypted → passes
        assert rule_map["MSSQL-L2-025"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_026_port(self, rule_map):
        # Manual/informational — always passes when SERVER_PROPS present
        assert rule_map["MSSQL-L1-026"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_027_protocols(self, rule_map):
        # Manual — always passes
        assert rule_map["MSSQL-L1-027"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_031_clr_strict(self, rule_map):
        assert rule_map["MSSQL-L1-031"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_035_public_server_perms(self, rule_map):
        assert rule_map["MSSQL-L1-035"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_040_default_trace(self, rule_map):
        assert rule_map["MSSQL-L1-040"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    def test_041_login_audit_level(self, rule_map):
        assert rule_map["MSSQL-L1-041"].check_fn(MOCK_MSSQL_2019_DUMP) is True

    # -- Should FAIL ------------------------------------------------ #

    def test_011_trustworthy_fail(self, rule_map):
        # ReportDB has TRUSTWORTHY=True
        assert rule_map["MSSQL-L1-011"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_013_auth_mode_fail(self, rule_map):
        assert rule_map["MSSQL-L1-013"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_015_sa_renamed_fail(self, rule_map):
        # SA still named 'sa'
        assert rule_map["MSSQL-L2-015"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_024_check_expiration_fail(self, rule_map):
        # reportuser has CHECK_EXPIRATION=False
        assert rule_map["MSSQL-L1-024"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_028_hide_instance_fail(self, rule_map):
        assert rule_map["MSSQL-L1-028"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_029_auto_close_contained_fail(self, rule_map):
        # ContainedApp has AUTO_CLOSE=True
        assert rule_map["MSSQL-L1-029"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_030_sa_name_fail(self, rule_map):
        assert rule_map["MSSQL-L1-030"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_032_guest_connect_fail(self, rule_map):
        # ReportDB | 1  → guest has CONNECT
        assert rule_map["MSSQL-L1-032"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_033_orphaned_users_fail(self, rule_map):
        assert rule_map["MSSQL-L1-033"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_034_contained_sql_auth_fail(self, rule_map):
        assert rule_map["MSSQL-L1-034"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_036_builtin_groups_fail(self, rule_map):
        assert rule_map["MSSQL-L1-036"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_037_local_groups_fail(self, rule_map):
        # Same section as 036, BUILTIN\\Administrators triggers this too
        assert rule_map["MSSQL-L1-037"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_038_agent_proxy_fail(self, rule_map):
        assert rule_map["MSSQL-L1-038"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_039_must_change_fail(self, rule_map):
        assert rule_map["MSSQL-L1-039"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_042_clr_assembly_fail(self, rule_map):
        assert rule_map["MSSQL-L1-042"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_043_symmetric_key_fail(self, rule_map):
        assert rule_map["MSSQL-L1-043"].check_fn(MOCK_MSSQL_2019_DUMP) is False

    def test_044_asymmetric_key_fail(self, rule_map):
        assert rule_map["MSSQL-L1-044"].check_fn(MOCK_MSSQL_2019_DUMP) is False


# ================================================================== #
#  Test: Compliant server evaluation                                 #
# ================================================================== #

class TestCompliantServer:
    def test_high_compliance(self, all_rules):
        result = evaluate_compliance(MOCK_MSSQL_2019_COMPLIANT, all_rules)
        summary = result["summary"]
        assert summary["total_rules_scored"] == 44
        assert summary["compliance_pct"] >= 90.0, (
            f"Expected ≥90% compliance, got {summary['compliance_pct']}%"
        )

    def test_no_crash_on_evaluation(self, all_rules):
        """Every rule's check_fn and evidence_fn should not crash."""
        result = evaluate_compliance(MOCK_MSSQL_2019_COMPLIANT, all_rules)
        for f in result["findings"]:
            assert isinstance(f["compliant"], bool)
            assert isinstance(f["evidence"], str)


# ================================================================== #
#  Test: 2016 version-aware rules                                    #
# ================================================================== #

class TestVersionAwareRules:
    def test_clr_strict_skipped_on_2016(self, rule_map):
        """CLR strict security should pass on 2016 (not applicable)."""
        assert rule_map["MSSQL-L1-031"].check_fn(MOCK_MSSQL_2016_DUMP) is True

    def test_clr_strict_enforced_on_2019(self, rule_map):
        """CLR strict security is checked on 2019."""
        # In mock 2019 dump, clr strict security = 1 → should pass
        assert rule_map["MSSQL-L1-031"].check_fn(MOCK_MSSQL_2019_DUMP) is True


# ================================================================== #
#  Test: Evidence extraction                                         #
# ================================================================== #

class TestEvidenceExtraction:
    def test_all_rules_produce_evidence(self, all_rules):
        for r in all_rules:
            ev = r.evidence_fn(MOCK_MSSQL_2019_DUMP)
            assert isinstance(ev, str), f"Rule {r.id} evidence_fn returned non-string"
            assert len(ev) > 0, f"Rule {r.id} produced empty evidence"

    def test_evidence_truncation(self):
        """Evidence should be truncated at max_chars."""
        from app.modules.mssql.audit.rules import _ev_section
        ev = _ev_section(MOCK_MSSQL_2019_DUMP, "DATABASES", 50)
        assert len(ev) <= 53  # 50 + "..."

    def test_version_in_clr_strict_evidence(self, rule_map):
        ev = rule_map["MSSQL-L1-031"].evidence_fn(MOCK_MSSQL_2019_DUMP)
        assert "15" in ev  # major version


# ================================================================== #
#  Test: evaluate_compliance summary                                 #
# ================================================================== #

class TestComplianceSummary:
    def test_summary_structure(self, all_rules):
        result = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)
        s = result["summary"]
        assert "total_rules_scored" in s
        assert "passed_scored" in s
        assert "failed_scored" in s
        assert "compliance_pct" in s
        assert "weighted_compliance_pct" in s
        assert s["passed_scored"] + s["failed_scored"] == s["total_rules_scored"]

    def test_partial_compliance_2019(self, all_rules):
        result = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)
        s = result["summary"]
        assert s["total_rules_scored"] == 44
        # We expect ~26 passes out of 44 on the partially-compliant dump
        assert 20 <= s["passed_scored"] <= 35, f"Unexpected pass count: {s['passed_scored']}"
        assert s["failed_scored"] > 5

    def test_findings_have_required_fields(self, all_rules):
        result = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)
        for f in result["findings"]:
            for key in ("id", "title", "description", "section", "severity",
                        "level", "compliant", "evidence", "remediation"):
                assert key in f, f"Finding {f.get('id','?')} missing '{key}'"


# ================================================================== #
#  Test: Hardening template registry                                 #
# ================================================================== #

class TestHardeningTemplates:
    def test_template_count(self):
        assert len(MSSQL_HARDENING_TEMPLATES) == 44

    def test_every_rule_has_template(self, all_rules):
        supported = get_all_supported_checks()
        for r in all_rules:
            assert r.id in supported, f"Rule {r.id} has no hardening template"

    def test_template_attributes(self):
        for check_id, t in MSSQL_HARDENING_TEMPLATES.items():
            assert t.check_id == check_id
            assert isinstance(t.description, str) and len(t.description) > 0
            assert isinstance(t.statements, list)
            assert isinstance(t.verify_statements, list)
            if t.manual_only:
                assert len(t.statements) == 0, (
                    f"{check_id}: manual_only template should have no statements"
                )

    def test_auto_templates_have_verify(self):
        for check_id, t in MSSQL_HARDENING_TEMPLATES.items():
            if not t.manual_only and t.statements:
                assert len(t.verify_statements) > 0, (
                    f"{check_id}: non-manual template with statements must have verify_statements"
                )

    def test_template_statement_substitution(self):
        stmts = get_mssql_template_statements("MSSQL-L1-011", {"DB_NAME": "TestDB"})
        assert len(stmts) > 0
        assert "TestDB" in stmts[0]
        assert "{DB_NAME}" not in stmts[0]

    def test_verify_statement_substitution(self):
        stmts = get_mssql_verify_statements("MSSQL-L1-011", {"DB_NAME": "TestDB"})
        assert len(stmts) > 0
        assert "TestDB" in stmts[0]

    def test_nonexistent_template(self):
        assert get_mssql_hardening_template("FAKE-001") is None
        assert get_mssql_template_statements("FAKE-001") == []
        assert get_mssql_verify_statements("FAKE-001") == []

    def test_new_auto_templates(self):
        """Verify new auto-fixable templates generate statements."""
        for check_id in ["MSSQL-L1-028", "MSSQL-L1-031", "MSSQL-L1-040"]:
            t = get_mssql_hardening_template(check_id)
            assert t is not None
            assert not t.manual_only
            assert len(t.statements) > 0
            assert len(t.verify_statements) > 0

    def test_new_parameterized_templates(self):
        """Verify new parameterized templates substitute correctly."""
        stmts = get_mssql_template_statements("MSSQL-L1-029", {"DB_NAME": "ContainedApp"})
        assert any("ContainedApp" in s for s in stmts)

        stmts = get_mssql_template_statements("MSSQL-L1-032", {"DB_NAME": "ReportDB"})
        assert any("ReportDB" in s for s in stmts)

        stmts = get_mssql_template_statements("MSSQL-L1-042", {
            "DB_NAME": "AppDB", "ASSEMBLY_NAME": "MyAssembly"
        })
        assert any("MyAssembly" in s for s in stmts)
        assert any("AppDB" in s for s in stmts)

        stmts = get_mssql_template_statements("MSSQL-L1-041", {"AUDIT_LEVEL": "3"})
        assert any("3" in s for s in stmts)


# ================================================================== #
#  Test: Parameter metadata                                          #
# ================================================================== #

class TestParameterMetadata:
    def test_all_mapped_checks_have_templates(self):
        for check_id in MSSQL_CHECK_PARAMETER_MAP:
            t = get_mssql_hardening_template(check_id)
            assert t is not None, f"{check_id} in PARAMETER_MAP but no template"

    def test_all_parameter_names_valid(self):
        for check_id, params in MSSQL_CHECK_PARAMETER_MAP.items():
            for p in params:
                assert p in MSSQL_PARAMETER_REGISTRY, (
                    f"Check {check_id} references unknown param '{p}'"
                )

    def test_parameter_registry_attributes(self):
        for name, meta in MSSQL_PARAMETER_REGISTRY.items():
            assert meta.name == name
            assert meta.input_type in ("text", "number", "select", "ip", "textarea")
            assert meta.label
            assert meta.description

    def test_new_parameters_exist(self):
        for name in ["BUILTIN_LOGIN", "LOCAL_GROUP_LOGIN", "PROXY_NAME",
                      "AUDIT_LEVEL", "ASSEMBLY_NAME"]:
            assert name in MSSQL_PARAMETER_REGISTRY, f"Missing param {name}"
            meta = get_mssql_parameter_metadata(name)
            assert meta is not None
            assert meta.name == name

    def test_auto_fixable_classification(self):
        auto_checks = [
            "MSSQL-L1-002", "MSSQL-L1-003", "MSSQL-L1-004", "MSSQL-L1-005",
            "MSSQL-L1-006", "MSSQL-L1-007", "MSSQL-L2-008", "MSSQL-L1-009",
            "MSSQL-L1-010", "MSSQL-L2-012", "MSSQL-L1-014",
            "MSSQL-L1-028", "MSSQL-L1-031", "MSSQL-L1-040",
        ]
        for check_id in auto_checks:
            assert is_mssql_check_auto_fixable(check_id), (
                f"{check_id} should be auto-fixable"
            )

    def test_parameterized_not_auto_fixable(self):
        param_checks = [
            "MSSQL-L1-011", "MSSQL-L2-015", "MSSQL-L1-016", "MSSQL-L1-017",
            "MSSQL-L1-029", "MSSQL-L1-032", "MSSQL-L1-036", "MSSQL-L1-037",
            "MSSQL-L1-038", "MSSQL-L1-042",
        ]
        for check_id in param_checks:
            assert not is_mssql_check_auto_fixable(check_id), (
                f"{check_id} should NOT be auto-fixable (needs params)"
            )

    def test_defaults_with_default_values(self):
        # MSSQL-L1-019 has NUM_ERROR_LOGS default=12, so auto-fixable
        assert is_mssql_check_auto_fixable("MSSQL-L1-019")
        defaults = get_mssql_check_defaults("MSSQL-L1-019")
        assert "NUM_ERROR_LOGS" in defaults
        assert defaults["NUM_ERROR_LOGS"] == "12"

        # MSSQL-L1-041 has AUDIT_LEVEL default=2, so auto-fixable
        assert is_mssql_check_auto_fixable("MSSQL-L1-041")
        defaults = get_mssql_check_defaults("MSSQL-L1-041")
        assert "AUDIT_LEVEL" in defaults
        assert defaults["AUDIT_LEVEL"] == "2"

    def test_categorize_all_mapped(self):
        all_mapped = list(MSSQL_CHECK_PARAMETER_MAP.keys())
        result = categorize_mssql_checks_by_fixability(all_mapped)
        assert len(result["not_supported"]) == 0, (
            f"Mapped checks should never be not_supported: {result['not_supported']}"
        )
        total = (len(result["auto_fixable"]) + len(result["needs_params"]))
        assert total == len(all_mapped)

    def test_categorize_unmapped_checks(self):
        """Manual-only checks not in map should be not_supported."""
        result = categorize_mssql_checks_by_fixability(["MSSQL-L1-001", "MSSQL-L1-013"])
        assert "MSSQL-L1-001" in result["not_supported"]
        assert "MSSQL-L1-013" in result["not_supported"]

    def test_aggregate_parameters(self):
        agg = aggregate_mssql_parameters_for_checks(["MSSQL-L1-029", "MSSQL-L1-032"])
        assert "DB_NAME" in agg
        assert "MSSQL-L1-029" in agg["DB_NAME"]["checks"]
        assert "MSSQL-L1-032" in agg["DB_NAME"]["checks"]

    def test_auto_fix_preview(self):
        preview = get_mssql_auto_fix_preview(["MSSQL-L1-028", "MSSQL-L1-031"])
        assert len(preview) == 2
        for item in preview:
            assert "check_id" in item
            assert "defaults" in item


# ================================================================== #
#  Test: Edge cases and robustness                                   #
# ================================================================== #

class TestEdgeCases:
    def test_empty_dump(self, all_rules):
        """Rules should not crash on empty dump."""
        result = evaluate_compliance("", all_rules)
        assert result["summary"]["total_rules_scored"] == 44
        # Most should fail on empty dump
        assert result["summary"]["failed_scored"] > 0

    def test_query_error_sections(self, all_rules):
        """Rules should handle QUERY_ERROR gracefully."""
        dump = "\n".join(
            f"===SECTION:{name}===\nQUERY_ERROR: something went wrong"
            for name in [
                "VERSION", "SERVER_PROPS", "CONFIGURATIONS", "AUTH_MODE",
                "SA_LOGIN", "SQL_LOGINS", "SYSADMIN_MEMBERS", "CONTROL_SERVER",
                "DATABASES", "SERVER_AUDITS", "AUDIT_SPECIFICATIONS",
                "ERRORLOG_COUNT", "LINKED_SERVERS", "SERVICE_ACCOUNTS",
                "ENDPOINTS", "TDE_STATUS", "PUBLIC_PERMS",
                "GUEST_CONNECT", "ORPHANED_USERS", "CONTAINED_DBS",
                "LOGIN_AUDIT_LEVEL", "CLR_ASSEMBLIES", "SYMMETRIC_KEYS",
                "ASYMMETRIC_KEYS", "BUILTIN_LOGINS", "AGENT_PROXIES",
                "HIDE_INSTANCE", "SA_NAME_CHECK", "MUST_CHANGE",
                "CONTAINED_DB_USERS", "PUBLIC_SERVER_PERMS",
            ]
        )
        result = evaluate_compliance(dump, all_rules)
        assert result["summary"]["total_rules_scored"] == 44
        # Should not crash — all findings should have valid structure
        for f in result["findings"]:
            assert isinstance(f["compliant"], bool)
            assert isinstance(f["evidence"], str)

    def test_no_rows_sections(self, all_rules):
        """Rules should handle (no rows returned) for all sections."""
        dump = "\n".join(
            f"===SECTION:{name}===\n(no rows returned)"
            for name in [
                "VERSION", "SERVER_PROPS", "CONFIGURATIONS", "AUTH_MODE",
                "SA_LOGIN", "SQL_LOGINS", "SYSADMIN_MEMBERS", "CONTROL_SERVER",
                "DATABASES", "SERVER_AUDITS", "AUDIT_SPECIFICATIONS",
                "ERRORLOG_COUNT", "LINKED_SERVERS", "SERVICE_ACCOUNTS",
                "ENDPOINTS", "TDE_STATUS", "PUBLIC_PERMS",
                "GUEST_CONNECT", "ORPHANED_USERS", "CONTAINED_DBS",
                "LOGIN_AUDIT_LEVEL", "CLR_ASSEMBLIES", "SYMMETRIC_KEYS",
                "ASYMMETRIC_KEYS", "BUILTIN_LOGINS", "AGENT_PROXIES",
                "HIDE_INSTANCE", "SA_NAME_CHECK", "MUST_CHANGE",
                "CONTAINED_DB_USERS", "PUBLIC_SERVER_PERMS",
            ]
        )
        result = evaluate_compliance(dump, all_rules)
        assert result["summary"]["total_rules_scored"] == 44
        for f in result["findings"]:
            assert isinstance(f["compliant"], bool)


# ================================================================== #
#  Test: Full integration — failed rules → hardening lookup          #
# ================================================================== #

class TestHardeningIntegration:
    def test_failed_rules_find_templates(self, all_rules):
        """Every failed rule from the 2019 dump should have a hardening template."""
        result = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)
        failed_ids = [f["id"] for f in result["findings"] if not f["compliant"]]
        assert len(failed_ids) > 0, "Expected some failures"
        for fid in failed_ids:
            t = get_mssql_hardening_template(fid)
            assert t is not None, f"Failed rule {fid} has no hardening template"

    def test_failed_rules_categorization(self, all_rules):
        """Failed rules can be categorized into auto/param/unsupported."""
        result = evaluate_compliance(MOCK_MSSQL_2019_DUMP, all_rules)
        failed_ids = [f["id"] for f in result["findings"] if not f["compliant"]]
        cats = categorize_mssql_checks_by_fixability(failed_ids)
        total = (len(cats["auto_fixable"]) + len(cats["needs_params"])
                 + len(cats["not_supported"]))
        assert total == len(failed_ids)
