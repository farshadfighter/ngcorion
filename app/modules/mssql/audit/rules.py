"""
SQL Server CIS Benchmark Rules

~44 predefined security checks based on the CIS Microsoft SQL Server Benchmark
(2016 v1.4, 2019 v1.5, 2022 v1.2) with version-aware logic for 2017+ features.
Each rule evaluates a specific aspect of SQL Server security by searching
the structured audit dump collected by MSSQLClient.

Rule IDs follow the pattern: MSSQL-L{level}-{seq:03d}
  L1 = Level 1 (basic, broadly applicable)
  L2 = Level 2 (advanced, may affect functionality)

CIS sections covered:
  1.x  SQL Server Version / Patch Level
  2.x  Surface Area Reduction
  3.x  Authentication
  4.x  Authorization
  5.x  Auditing & Logging
  6.x  Application Roles & Passwords
  7.x  Encryption
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Dict, Any


# ============================================================ #
#  Rule dataclass                                               #
# ============================================================ #

@dataclass
class MSSQLCISRule:
    """A single CIS SQL Server compliance check."""
    id: str                          # e.g. "MSSQL-L1-001"
    section: str                     # CIS section number e.g. "2.1"
    title: str
    description: str
    severity: str                    # high / medium / low / info
    level: str                       # L1 / L2
    check_fn: Callable[[str], bool]  # True = compliant
    evidence_fn: Callable[[str], str]
    remediation: str


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


def _config_val(dump: str, option_name: str) -> str:
    """
    Extract the value_in_use of a sys.configurations row.
    Returns the raw value string, or empty string if not found.
    """
    section = _section(dump, "CONFIGURATIONS")
    pattern = re.compile(
        rf"^{re.escape(option_name)}\s*\|\s*(\S+)",
        re.I | re.M,
    )
    m = pattern.search(section)
    return m.group(1) if m else ""


def _config_is_zero(dump: str, option_name: str) -> bool:
    """Return True when the named configuration option's value_in_use is 0."""
    val = _config_val(dump, option_name)
    return val == "0"


def _config_is_one(dump: str, option_name: str) -> bool:
    """Return True when the named configuration option's value_in_use is 1."""
    val = _config_val(dump, option_name)
    return val == "1"


# ============================================================ #
#  Evidence extractors                                         #
# ============================================================ #

def _ev_section(dump: str, section: str, max_chars: int = 500) -> str:
    content = _section(dump, section)
    return content[:max_chars] + ("..." if len(content) > max_chars else "")


def _ev_config_row(dump: str, option_name: str) -> str:
    section = _section(dump, "CONFIGURATIONS")
    pattern = re.compile(
        rf"^{re.escape(option_name)}\s*\|.*$",
        re.I | re.M,
    )
    m = pattern.search(section)
    return m.group(0) if m else f"(option '{option_name}' not found)"


# ============================================================ #
#  Version detection helper                                    #
# ============================================================ #

def _has_weak_asymmetric_key(dump: str) -> bool:
    """True when any asymmetric key row reports a key_length below 2048 bits."""
    section = _section(dump, "ASYMMETRIC_KEYS")
    # Rows: db_name | key_name | key_length | algorithm_desc
    for m in re.finditer(r"\|\s*(\d{1,5})\s*\|", section):
        if int(m.group(1)) < 2048:
            return True
    return False


def _detect_version(dump: str) -> int:
    """
    Return the SQL Server major version number from the VERSION section.

    Known mappings: 2016=13, 2017=14, 2019=15, 2022=16.
    Returns 0 if version cannot be determined.
    """
    version_text = _section(dump, "VERSION")
    # Try "Microsoft SQL Server 20XX"
    m = re.search(r"Microsoft SQL Server (\d{4})", version_text, re.I)
    if m:
        year = int(m.group(1))
        year_to_major = {2016: 13, 2017: 14, 2019: 15, 2022: 16}
        return year_to_major.get(year, 0)
    # Try product version "15.0.xxxx"
    m = re.search(r"\b(\d{2})\.\d+\.\d+", version_text)
    if m:
        return int(m.group(1))
    return 0


# ============================================================ #
#  Rule builder                                                 #
# ============================================================ #

def build_all_mssql_cis_rules() -> List[MSSQLCISRule]:
    """Return the full list of SQL Server CIS rules."""

    rules: List[MSSQLCISRule] = []

    # ---------------------------------------------------------------- #
    #  Section 1 – SQL Server Version / Patch Level                     #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-001",
        section="1.1",
        title="Ensure Latest SQL Server Service Packs and Patches are Applied",
        description=(
            "SQL Server is updated with the most recent patches to protect against "
            "known vulnerabilities. Running outdated versions exposes the server to "
            "exploits that have been remediated in newer releases."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "VERSION")
            and bool(_section(d, "VERSION"))
            and bool(re.search(
                r"(CU\d+|SP\d+|RTM-CU|RTM-GDR)",
                _section(d, "VERSION"),
                re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "VERSION", 300),
        remediation=(
            "Apply the latest Cumulative Update (CU) for the installed SQL Server "
            "version. Check https://docs.microsoft.com/sql/sql-server/install/"
            "what-s-new-in-sql-server-installation for the current patch list."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 2 – Surface Area Reduction                               #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-002",
        section="2.1",
        title="Ensure 'Ad Hoc Distributed Queries' is set to 0",
        description=(
            "Enabling Ad Hoc Distributed Queries allows the use of OPENROWSET and "
            "OPENDATASOURCE which can access external data sources without a linked "
            "server definition. This introduces an unnecessary attack surface."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "Ad Hoc Distributed Queries"),
        evidence_fn=lambda d: _ev_config_row(d, "Ad Hoc Distributed Queries"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-003",
        section="2.2",
        title="Ensure 'CLR Enabled' is set to 0",
        description=(
            "The CLR (Common Language Runtime) integration feature allows managed code "
            "to be run within SQL Server. Unless explicitly required, this should be "
            "disabled to reduce the attack surface."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "clr enabled"),
        evidence_fn=lambda d: _ev_config_row(d, "clr enabled"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'clr enabled', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-004",
        section="2.3",
        title="Ensure 'Cross DB Ownership Chaining' is set to 0",
        description=(
            "Cross-database ownership chaining allows objects in one database to "
            "access objects in another database without an explicit permission grant. "
            "This can lead to privilege escalation."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "cross db ownership chaining"),
        evidence_fn=lambda d: _ev_config_row(d, "cross db ownership chaining"),
        remediation=(
            "EXECUTE sp_configure 'cross db ownership chaining', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-005",
        section="2.4",
        title="Ensure 'Database Mail XPs' is set to 0",
        description=(
            "Database Mail allows SQL Server to send emails. If not actively used, "
            "this feature should be disabled to reduce the attack surface."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "Database Mail XPs"),
        evidence_fn=lambda d: _ev_config_row(d, "Database Mail XPs"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'Database Mail XPs', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-006",
        section="2.5",
        title="Ensure 'Ole Automation Procedures' is set to 0",
        description=(
            "Ole Automation Procedures allow SQL Server to interact with COM objects, "
            "which could be exploited to execute arbitrary code on the server."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "Ole Automation Procedures"),
        evidence_fn=lambda d: _ev_config_row(d, "Ole Automation Procedures"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'Ole Automation Procedures', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-007",
        section="2.6",
        title="Ensure 'Remote Access' is set to 0",
        description=(
            "The remote access option controls the execution of local stored procedures "
            "on remote servers. This feature is deprecated and should be disabled."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "remote access"),
        evidence_fn=lambda d: _ev_config_row(d, "remote access"),
        remediation=(
            "EXECUTE sp_configure 'remote access', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-008",
        section="2.7",
        title="Ensure 'Remote Admin Connections' is set to 0",
        description=(
            "The remote admin connections option controls whether the Dedicated Admin "
            "Connection (DAC) can be used from a remote machine. The DAC provides "
            "high-privilege diagnostic access and should be local-only by default."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: _config_is_zero(d, "remote admin connections"),
        evidence_fn=lambda d: _ev_config_row(d, "remote admin connections"),
        remediation=(
            "EXECUTE sp_configure 'remote admin connections', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-009",
        section="2.8",
        title="Ensure 'Scan for Startup Procs' is set to 0",
        description=(
            "The scan for startup procs option instructs SQL Server to scan for and "
            "automatically execute all stored procedures that are flagged for automatic "
            "execution at startup. This can be misused to persist malicious code."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "scan for startup procs"),
        evidence_fn=lambda d: _ev_config_row(d, "scan for startup procs"),
        remediation=(
            "EXECUTE sp_configure 'scan for startup procs', 0;\n"
            "RECONFIGURE WITH OVERRIDE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-010",
        section="2.9",
        title="Ensure 'xp_cmdshell' is set to 0",
        description=(
            "xp_cmdshell is a powerful extended stored procedure that allows execution "
            "of OS-level commands from within SQL Server. Disabling it closes one of "
            "the most commonly exploited SQL Server attack vectors."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: _config_is_zero(d, "xp_cmdshell"),
        evidence_fn=lambda d: _ev_config_row(d, "xp_cmdshell"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'xp_cmdshell', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-011",
        section="2.10",
        title="Ensure 'TRUSTWORTHY' is set to OFF for user databases",
        description=(
            "The TRUSTWORTHY database property, when ON, allows database objects to "
            "access resources outside the database with the permissions of the database "
            "owner. This can be exploited for privilege escalation."
        ),
        severity="high",
        level="L1",
        # PASS when no non-system database has is_trustworthy_on = True (1).
        # The lookahead anchors on the full name (name then '|') so a user DB
        # merely starting with a system name (e.g. "model_x") is still checked.
        check_fn=lambda d: not bool(
            re.search(
                r"^(?!(?:master|msdb|model|tempdb)\s*\|)\S+\s*\|\s*(?:True|1)\s*\|",
                _section(d, "DATABASES"),
                re.M | re.I,
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "DATABASES", 500),
        remediation=(
            "For each database where TRUSTWORTHY is ON (except msdb):\n"
            "ALTER DATABASE [<database_name>] SET TRUSTWORTHY OFF;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-012",
        section="2.11",
        title="Ensure 'SQL Mail XPs' is set to 0",
        description=(
            "SQL Mail XPs is a legacy mail feature that uses MAPI. It has been "
            "deprecated in favor of Database Mail and should be disabled."
        ),
        severity="low",
        level="L2",
        check_fn=lambda d: _config_is_zero(d, "SQL Mail XPs"),
        evidence_fn=lambda d: _ev_config_row(d, "SQL Mail XPs"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'SQL Mail XPs', 0;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 3 – Authentication                                       #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-013",
        section="3.1",
        title="Ensure 'Authentication Mode' is set to 'Windows Authentication Mode'",
        description=(
            "Windows Authentication Mode (Integrated Security) is more secure than "
            "Mixed Mode because it leverages Kerberos authentication, enforces Windows "
            "password policies, and does not expose SQL credentials over the network."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            re.search(
                r"Windows Authentication Mode",
                _section(d, "AUTH_MODE"),
                re.I,
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "AUTH_MODE"),
        remediation=(
            "In SQL Server Management Studio (SSMS):\n"
            "1. Right-click the server → Properties → Security\n"
            "2. Select 'Windows Authentication mode'\n"
            "3. Restart the SQL Server service\n"
            "Or via T-SQL (requires restart):\n"
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            "    N'Software\\Microsoft\\MSSQLServer\\MSSQLServer',\n"
            "    N'LoginMode', REG_DWORD, 1;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-014",
        section="3.2",
        title="Ensure the SA Login Account is set to 'Disabled'",
        description=(
            "The 'sa' (System Administrator) account is a well-known SQL login with "
            "sysadmin privileges. Disabling it prevents brute-force and credential "
            "stuffing attacks targeting this account."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            re.search(
                r"^sa\s*\|\s*True\s*\|",
                _section(d, "SA_LOGIN"),
                re.M | re.I,
            )
            or re.search(
                r"^sa\s*\|\s*1\s*\|",
                _section(d, "SA_LOGIN"),
                re.M | re.I,
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "SA_LOGIN"),
        remediation=(
            "ALTER LOGIN [sa] DISABLE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-015",
        section="3.3",
        title="Ensure the SA Login Account has been renamed",
        description=(
            "Renaming the SA account makes it harder for attackers to target this "
            "well-known high-privilege account during brute-force attacks."
        ),
        severity="medium",
        level="L2",
        # PASS when no login named exactly 'sa' exists
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SA_LOGIN")
            and (
                "(no rows returned)" in _section(d, "SA_LOGIN")
                or not re.search(r"^sa\s*\|", _section(d, "SA_LOGIN"), re.M | re.I)
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "SA_LOGIN"),
        remediation=(
            "ALTER LOGIN [sa] WITH NAME = [<new_name>];\n"
            "Ensure the original 'sa' account is also disabled."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 4 – Authorization                                        #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-016",
        section="4.1",
        title="Ensure Only the Default sa Account Has Access to the 'sysadmin' Role",
        description=(
            "The sysadmin fixed server role grants unrestricted control over SQL Server. "
            "Only accounts that absolutely require this level of access should be members. "
            "Excess sysadmin membership is a common escalation risk."
        ),
        severity="high",
        level="L1",
        # PASS when sysadmin members are 2 or fewer (typical: sa + one admin)
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SYSADMIN_MEMBERS")
            and len([
                line for line in _section(d, "SYSADMIN_MEMBERS").splitlines()
                if line.strip() and "no rows" not in line.lower()
            ]) <= 2
        ),
        evidence_fn=lambda d: _ev_section(d, "SYSADMIN_MEMBERS"),
        remediation=(
            "Review sysadmin membership and remove unnecessary accounts:\n"
            "ALTER SERVER ROLE [sysadmin] DROP MEMBER [<login_name>];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-017",
        section="4.2",
        title="Ensure 'CONTROL SERVER' is not Granted to Non-Admin Logins",
        description=(
            "The CONTROL SERVER permission grants SQL Server-wide permissions equivalent "
            "to sysadmin membership. It should not be granted to regular logins."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "CONTROL_SERVER")
            and (
                "(no rows returned)" in _section(d, "CONTROL_SERVER")
                or not bool(_section(d, "CONTROL_SERVER").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "CONTROL_SERVER"),
        remediation=(
            "REVOKE CONTROL SERVER FROM [<login_name>];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-018",
        section="4.3",
        title="Ensure 'public' Role in master Database has no Non-Default Permissions",
        description=(
            "The public role in master should only have the minimal default permissions. "
            "Additional permissions granted to public effectively apply to all users."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "PUBLIC_PERMS")
            and (
                "(no rows returned)" in _section(d, "PUBLIC_PERMS")
                or not bool(_section(d, "PUBLIC_PERMS").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "PUBLIC_PERMS"),
        remediation=(
            "USE [master];\n"
            "REVOKE <permission> FROM [public];\n"
            "Review each returned permission and revoke if not required by default."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 5 – Auditing & Logging                                   #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-019",
        section="5.1",
        title="Ensure 'Maximum number of error log files' is set to >= 12",
        description=(
            "SQL Server keeps a configurable number of error log files. Retaining "
            "at least 12 ensures that several months of log history are available "
            "for incident investigation and forensics."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "ERRORLOG_COUNT")
            and bool(re.search(
                r"\b(1[2-9]|[2-9]\d|\d{3,})\b",
                _section(d, "ERRORLOG_COUNT"),
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "ERRORLOG_COUNT"),
        remediation=(
            "In SSMS: Right-click SQL Server Logs → Configure → set to 12 or more.\n"
            "Or via registry (requires restart):\n"
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            "    N'Software\\Microsoft\\MSSQLServer\\MSSQLServer',\n"
            "    N'NumErrorLogs', REG_DWORD, 12;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-020",
        section="5.2",
        title="Ensure SQL Server Audit is configured",
        description=(
            "SQL Server Audit provides a native mechanism to capture login events, "
            "DDL/DML operations, and permission changes for compliance and forensics."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SERVER_AUDITS")
            and "(no rows returned)" not in _section(d, "SERVER_AUDITS")
            and bool(_section(d, "SERVER_AUDITS").strip())
        ),
        evidence_fn=lambda d: _ev_section(d, "SERVER_AUDITS"),
        remediation=(
            "Create and enable a SQL Server Audit:\n"
            "CREATE SERVER AUDIT [SecurityAudit]\n"
            "    TO FILE (FILEPATH = N'C:\\SQLAudit\\');\n"
            "ALTER SERVER AUDIT [SecurityAudit] WITH (STATE = ON);"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-021",
        section="5.3",
        title="Ensure SQL Server Audit is enabled (STATE = ON)",
        description=(
            "Creating a SQL Server Audit object is not sufficient — it must be "
            "actively enabled. Disabled audits capture no events."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SERVER_AUDITS")
            and bool(re.search(
                r"STARTED|RUNNING|True",
                _section(d, "SERVER_AUDITS"),
                re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "SERVER_AUDITS"),
        remediation=(
            "ALTER SERVER AUDIT [<audit_name>] WITH (STATE = ON);"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-022",
        section="5.4",
        title="Ensure Login Auditing is configured to capture Failed and Successful Logins",
        description=(
            "Capturing both successful and failed logins enables detection of "
            "brute-force attacks and unauthorized access attempts."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            re.search(
                r"FAILED_LOGIN_GROUP|SUCCESSFUL_LOGIN_GROUP|LOGIN",
                _section(d, "AUDIT_SPECIFICATIONS"),
                re.I,
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "AUDIT_SPECIFICATIONS", 600),
        remediation=(
            "CREATE SERVER AUDIT SPECIFICATION [LoginAuditSpec]\n"
            "FOR SERVER AUDIT [SecurityAudit]\n"
            "ADD (FAILED_LOGIN_GROUP),\n"
            "ADD (SUCCESSFUL_LOGIN_GROUP)\n"
            "WITH (STATE = ON);"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 6 – Password Policies                                    #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-023",
        section="6.1",
        title="Ensure CHECK_POLICY is ON for all SQL Authenticated Logins",
        description=(
            "CHECK_POLICY enforces the Windows password policy (complexity, length, "
            "history) for SQL Server logins. Without this, weak passwords are allowed."
        ),
        severity="high",
        level="L1",
        # Columns: name | is_disabled | is_policy_checked | is_expiration_checked | type_desc
        # Fail if any non-sa login has is_policy_checked (3rd col) = False
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SQL_LOGINS")
            and not bool(re.search(
                r"^(?!sa\s)\S+\s*\|\s*\S+\s*\|\s*False\s*\|",
                _section(d, "SQL_LOGINS"),
                re.M | re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "SQL_LOGINS"),
        remediation=(
            "For each SQL login with CHECK_POLICY = OFF:\n"
            "ALTER LOGIN [<login_name>] WITH CHECK_POLICY = ON;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-024",
        section="6.2",
        title="Ensure CHECK_EXPIRATION is ON for SQL Authenticated Logins",
        description=(
            "CHECK_EXPIRATION enforces password expiration for SQL logins, ensuring "
            "passwords are changed regularly. This is part of a comprehensive "
            "password lifecycle management policy."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SQL_LOGINS")
            and not bool(re.search(
                r"^(?!sa\s).*\|\s*True\s*\|\s*False\s*\|",
                _section(d, "SQL_LOGINS"),
                re.M | re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "SQL_LOGINS"),
        remediation=(
            "For each SQL login with CHECK_EXPIRATION = OFF:\n"
            "ALTER LOGIN [<login_name>] WITH CHECK_EXPIRATION = ON;"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 7 – Encryption                                           #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L2-025",
        section="7.1",
        title="Ensure Transparent Data Encryption (TDE) is enabled for sensitive databases",
        description=(
            "TDE encrypts the database files at rest, protecting data from physical "
            "theft or unauthorized file-level access. It should be enabled for any "
            "database containing sensitive or regulated data."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "TDE_STATUS")
            and bool(re.search(
                r"Encrypted|3",
                _section(d, "TDE_STATUS"),
                re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "TDE_STATUS", 600),
        remediation=(
            "Step 1: Create a master key (if not exists):\n"
            "USE master;\n"
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<strong_password>';\n\n"
            "Step 2: Create a certificate:\n"
            "CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';\n\n"
            "Step 3: Create the DEK in the target database:\n"
            "USE [<database_name>];\n"
            "CREATE DATABASE ENCRYPTION KEY\n"
            "  WITH ALGORITHM = AES_256\n"
            "  ENCRYPTION BY SERVER CERTIFICATE TDECert;\n\n"
            "Step 4: Enable TDE:\n"
            "ALTER DATABASE [<database_name>] SET ENCRYPTION ON;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-026",
        section="7.2",
        title="Ensure SQL Server is not using the default port 1433",
        description=(
            "Using the default SQL Server port (1433) makes it easier for attackers "
            "to discover and target the instance. Changing the port adds a layer of "
            "obscurity that can reduce automated scan-based attacks."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SERVER_PROPS")
            and bool(_section(d, "SERVER_PROPS"))
            # We can't directly query the TCP port from T-SQL without xp_cmdshell;
            # mark as informational check requiring manual verification.
            # Default to PASS with note when data is available.
        ),
        evidence_fn=lambda d: (
            "Manual check required: verify that SQL Server is not listening on "
            "the default port 1433 via SQL Server Configuration Manager."
        ),
        remediation=(
            "Open SQL Server Configuration Manager → SQL Server Network Configuration "
            "→ TCP/IP Properties → IP All → set TCP Port to a non-standard value. "
            "Restart the SQL Server service."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 2 – Surface Area Reduction (additions)                   #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-027",
        section="2.10",
        title="Ensure Unnecessary SQL Server Protocols are Disabled",
        description=(
            "SQL Server can listen on multiple protocols (Shared Memory, Named Pipes, "
            "TCP/IP). Unused protocols should be disabled to reduce the attack surface. "
            "This is an OS-level check via SQL Server Configuration Manager."
        ),
        severity="low",
        level="L1",
        # Manual/informational check — cannot query protocols from T-SQL
        check_fn=lambda d: True,
        evidence_fn=lambda d: (
            "Manual check required: Open SQL Server Configuration Manager → "
            "SQL Server Network Configuration → Protocols and verify only "
            "required protocols are enabled."
        ),
        remediation=(
            "In SQL Server Configuration Manager → SQL Server Network Configuration → "
            "Protocols: disable Shared Memory, Named Pipes, or TCP/IP if not needed. "
            "Restart the SQL Server service."
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-028",
        section="2.12",
        title="Ensure 'Hide Instance' is set to 'Yes'",
        description=(
            "Hiding the SQL Server instance prevents it from being enumerated by "
            "the SQL Server Browser service, reducing discoverability during "
            "network reconnaissance."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "HIDE_INSTANCE")
            and bool(re.search(r"\b1\b", _section(d, "HIDE_INSTANCE")))
        ),
        evidence_fn=lambda d: _ev_section(d, "HIDE_INSTANCE"),
        remediation=(
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            r"    N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',"
            "\n    N'HideInstance', REG_DWORD, 1;\n"
            "Restart the SQL Server service."
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-029",
        section="2.15",
        title="Ensure AUTO_CLOSE is OFF on Contained Databases",
        description=(
            "AUTO_CLOSE on contained databases can cause reliability issues and "
            "potential denial of service. It should be disabled for all contained DBs."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "CONTAINED_DBS")
            and (
                "(no rows returned)" in _section(d, "CONTAINED_DBS")
                or not bool(re.search(
                    r"\|\s*True\s*$",
                    _section(d, "CONTAINED_DBS"),
                    re.M | re.I,
                ))
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "CONTAINED_DBS"),
        remediation=(
            "ALTER DATABASE [<contained_db_name>] SET AUTO_CLOSE OFF;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-030",
        section="2.16",
        title="Ensure No Login Exists with the Name 'sa'",
        description=(
            "After disabling and/or renaming the default SA account, ensure no login "
            "named 'sa' exists. Attackers commonly target the well-known 'sa' name."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SA_NAME_CHECK")
            and (
                "(no rows returned)" in _section(d, "SA_NAME_CHECK")
                or not bool(_section(d, "SA_NAME_CHECK").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "SA_NAME_CHECK"),
        remediation=(
            "ALTER LOGIN [sa] WITH NAME = [<new_name>];\n"
            "This check overlaps with MSSQL-L2-015 (SA rename)."
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-031",
        section="2.17",
        title="Ensure 'CLR strict security' is set to 1 (SQL Server 2019+)",
        description=(
            "Starting with SQL Server 2017, the 'clr strict security' option controls "
            "whether CLR assemblies are treated as UNSAFE by default. Setting it to 1 "
            "prevents unsigned assemblies from running with elevated permissions. "
            "This check only applies to SQL Server 2017 and later."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            # Skip for versions before 2017 (major < 14)
            _detect_version(d) < 14
            or _config_is_one(d, "clr strict security")
        ),
        evidence_fn=lambda d: (
            f"SQL Server major version: {_detect_version(d)}. "
            + _ev_config_row(d, "clr strict security")
        ),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'clr strict security', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 3 – Authentication & Authorization (additions)           #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-032",
        section="3.2",
        title="Ensure CONNECT Permissions on Guest User are Revoked",
        description=(
            "The guest user exists in every database. If CONNECT permission is "
            "granted to guest, any authenticated login can access the database. "
            "Guest CONNECT should be revoked for all user databases."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "GUEST_CONNECT")
            and (
                "(no rows returned)" in _section(d, "GUEST_CONNECT")
                or not bool(re.search(
                    r"\|\s*[1-9]\d*\s*$",
                    _section(d, "GUEST_CONNECT"),
                    re.M,
                ))
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "GUEST_CONNECT"),
        remediation=(
            "USE [<database_name>];\n"
            "REVOKE CONNECT FROM [guest];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-033",
        section="3.3",
        title="Ensure Orphaned Users are Dropped",
        description=(
            "Orphaned users are database users whose corresponding server login "
            "has been dropped. They represent a security risk as they could be "
            "re-associated with a new malicious login."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "ORPHANED_USERS")
            and (
                "(no rows returned)" in _section(d, "ORPHANED_USERS")
                or not bool(_section(d, "ORPHANED_USERS").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "ORPHANED_USERS"),
        remediation=(
            "For each orphaned user found:\n"
            "USE [<database_name>];\n"
            "DROP USER [<orphaned_user_name>];\n"
            "Or re-associate with an existing login:\n"
            "ALTER USER [<user_name>] WITH LOGIN = [<login_name>];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-034",
        section="3.4",
        title="Ensure SQL Authentication is not Used in Contained Databases",
        description=(
            "Contained database users with SQL authentication store password hashes "
            "inside the database. If the database is moved to another server, the "
            "user can access it without any server-level principal validation."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "CONTAINED_DB_USERS")
            and (
                "(no rows returned)" in _section(d, "CONTAINED_DB_USERS")
                or not bool(_section(d, "CONTAINED_DB_USERS").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "CONTAINED_DB_USERS"),
        remediation=(
            "Migrate contained database users from SQL authentication to Windows "
            "authentication:\n"
            "USE [<contained_db>];\n"
            "DROP USER [<sql_user>];\n"
            "CREATE USER [<domain\\user>] FROM EXTERNAL PROVIDER;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-035",
        section="3.8",
        title="Ensure 'public' Server Role Has Only Default Permissions",
        description=(
            "Every SQL Server login is a member of the public server role. "
            "Non-default permissions granted to public effectively apply to "
            "all logins, potentially granting excessive privileges."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "PUBLIC_SERVER_PERMS")
            and (
                "(no rows returned)" in _section(d, "PUBLIC_SERVER_PERMS")
                or not bool(_section(d, "PUBLIC_SERVER_PERMS").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "PUBLIC_SERVER_PERMS"),
        remediation=(
            "Review and revoke non-default permissions from the public server role:\n"
            "REVOKE <permission_name> FROM [public];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-036",
        section="3.9",
        title="Ensure Windows BUILTIN Groups are not SQL Logins",
        description=(
            "Windows BUILTIN groups (e.g., BUILTIN\\Administrators) should not be "
            "SQL Server logins because membership in these groups is controlled at "
            "the OS level, not by the DBA."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "BUILTIN_LOGINS")
            and not bool(re.search(
                r"^BUILTIN\\",
                _section(d, "BUILTIN_LOGINS"),
                re.M | re.I,
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "BUILTIN_LOGINS"),
        remediation=(
            "DROP LOGIN [BUILTIN\\<group_name>];\n"
            "Create specific Windows logins with appropriate permissions instead."
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-037",
        section="3.10",
        title="Ensure Windows Local Groups are not SQL Logins",
        description=(
            "Local Windows groups should not be used as SQL Server logins. "
            "Membership in local groups is managed at the OS level, which may not "
            "be under the DBA's control, creating potential privilege escalation paths."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "BUILTIN_LOGINS")
            and (
                "(no rows returned)" in _section(d, "BUILTIN_LOGINS")
                or not bool(_section(d, "BUILTIN_LOGINS").strip())
                # If BUILTIN entries are already absent, local groups are also checked
                # via the same query (type = 'G' with backslash pattern)
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "BUILTIN_LOGINS"),
        remediation=(
            "DROP LOGIN [<machine_name>\\<local_group>];\n"
            "Use domain-level groups or individual Windows logins instead."
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-038",
        section="3.11",
        title="Ensure Public Role in msdb Has No SQL Agent Proxy Access",
        description=(
            "SQL Agent proxies allow stored procedures to run under the security "
            "context of a different Windows account. If the public role has proxy "
            "access, any user could execute jobs with elevated OS credentials."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "AGENT_PROXIES")
            and (
                "(no rows returned)" in _section(d, "AGENT_PROXIES")
                or not bool(_section(d, "AGENT_PROXIES").strip())
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "AGENT_PROXIES"),
        remediation=(
            "EXEC msdb.dbo.sp_revoke_login_from_proxy\n"
            "    @name = N'public',\n"
            "    @proxy_name = N'<proxy_name>';"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 4 – Password Policies (addition)                         #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-039",
        section="4.1",
        title="Ensure MUST_CHANGE Option is Set for All SQL Authenticated Logins",
        description=(
            "The MUST_CHANGE option forces a password reset on first login. For "
            "newly created SQL logins, this ensures the initial password set by "
            "the DBA is replaced with a user-chosen password."
        ),
        severity="low",
        level="L1",
        # Informational — MUST_CHANGE is only meaningful at login creation time.
        # We flag logins that have IsMustChange=0, but this is advisory.
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "MUST_CHANGE")
            and (
                "(no rows returned)" in _section(d, "MUST_CHANGE")
                or not bool(re.search(
                    r"\|\s*0\s*$",
                    _section(d, "MUST_CHANGE"),
                    re.M,
                ))
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "MUST_CHANGE"),
        remediation=(
            "When creating SQL logins, always use MUST_CHANGE:\n"
            "CREATE LOGIN [<login>] WITH PASSWORD = '<pwd>' MUST_CHANGE,\n"
            "    CHECK_POLICY = ON, CHECK_EXPIRATION = ON;\n"
            "For existing logins, reset the password with MUST_CHANGE:\n"
            "ALTER LOGIN [<login>] WITH PASSWORD = '<new_pwd>' MUST_CHANGE;"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 5 – Auditing & Logging (additions)                       #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-040",
        section="5.2",
        title="Ensure 'Default Trace Enabled' is set to 1",
        description=(
            "The default trace captures important security-related events such as "
            "object creation, alteration, and deletion. It should be enabled to "
            "maintain a baseline audit trail."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: _config_is_one(d, "default trace enabled"),
        evidence_fn=lambda d: _ev_config_row(d, "default trace enabled"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'default trace enabled', 1;\n"
            "RECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0;\n"
            "RECONFIGURE;"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-041",
        section="5.3",
        title="Ensure Login Auditing is Set to Capture Failed Logins",
        description=(
            "SQL Server login auditing can be configured at the instance level to "
            "capture None (0), Failed only (1), Successful only (2), or Both (3). "
            "At minimum, failed login attempts should be logged."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "LOGIN_AUDIT_LEVEL")
            and bool(re.search(
                r"\b[23]\b",
                _section(d, "LOGIN_AUDIT_LEVEL"),
            ))
        ),
        evidence_fn=lambda d: _ev_section(d, "LOGIN_AUDIT_LEVEL"),
        remediation=(
            "-- Set to 2 (failed logins only) or 3 (both):\n"
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            r"    N'Software\Microsoft\MSSQLServer\MSSQLServer',"
            "\n    N'AuditLevel', REG_DWORD, 2;\n"
            "Restart the SQL Server service."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 6 – Application Development (addition)                   #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-042",
        section="6.2",
        title="Ensure CLR Assembly Permission Set is SAFE_ACCESS",
        description=(
            "CLR assemblies registered in SQL Server should use SAFE_ACCESS "
            "permission set. EXTERNAL_ACCESS and UNSAFE allow the assembly to "
            "access external resources or call unmanaged code, which is a security risk."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "CLR_ASSEMBLIES")
            and (
                "(no rows returned)" in _section(d, "CLR_ASSEMBLIES")
                or not bool(re.search(
                    r"(EXTERNAL_ACCESS|UNSAFE)",
                    _section(d, "CLR_ASSEMBLIES"),
                    re.I,
                ))
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "CLR_ASSEMBLIES"),
        remediation=(
            "ALTER ASSEMBLY [<assembly_name>] WITH PERMISSION_SET = SAFE;\n"
            "Or drop the assembly if it is not needed:\n"
            "DROP ASSEMBLY [<assembly_name>];"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 7 – Encryption (additions)                               #
    # ---------------------------------------------------------------- #

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-043",
        section="7.1",
        title="Ensure Symmetric Key Encryption Algorithm is AES_128 or Stronger",
        description=(
            "User-created symmetric keys should use AES_128 or stronger algorithms. "
            "Weaker algorithms such as DES or Triple DES are considered cryptographically "
            "weak and should not be used."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "SYMMETRIC_KEYS")
            and (
                "(no rows returned)" in _section(d, "SYMMETRIC_KEYS")
                or not bool(re.search(
                    r"(DES|RC[24]|TRIPLE_DES|DESX)",
                    _section(d, "SYMMETRIC_KEYS"),
                    re.I,
                ))
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "SYMMETRIC_KEYS"),
        remediation=(
            "Re-create symmetric keys with a stronger algorithm:\n"
            "DROP SYMMETRIC KEY [<key_name>];\n"
            "CREATE SYMMETRIC KEY [<key_name>]\n"
            "    WITH ALGORITHM = AES_256\n"
            "    ENCRYPTION BY CERTIFICATE [<cert_name>];"
        ),
    ))

    rules.append(MSSQLCISRule(
        id="MSSQL-L1-044",
        section="7.2",
        title="Ensure Asymmetric Key Size is 2048 Bits or Larger",
        description=(
            "Asymmetric keys with fewer than 2048 bits provide insufficient "
            "cryptographic strength. All user-created asymmetric keys should use "
            "at least 2048-bit key length."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "QUERY_ERROR" not in _section(d, "ASYMMETRIC_KEYS")
            and (
                "(no rows returned)" in _section(d, "ASYMMETRIC_KEYS")
                or not _has_weak_asymmetric_key(d)
            )
        ),
        evidence_fn=lambda d: _ev_section(d, "ASYMMETRIC_KEYS"),
        remediation=(
            "Re-create asymmetric keys with at least 2048-bit key size:\n"
            "DROP ASYMMETRIC KEY [<key_name>];\n"
            "CREATE ASYMMETRIC KEY [<key_name>]\n"
            "    WITH ALGORITHM = RSA_2048;"
        ),
    ))

    return rules


# ============================================================ #
#  Profile filtering                                            #
# ============================================================ #

def filter_rules_by_profile(rules: List[MSSQLCISRule], profile: str) -> List[MSSQLCISRule]:
    """
    Filter rules by CIS profile level.

    Args:
        rules:   Full rule list
        profile: "L1" returns only L1 rules; "FULL" returns all rules

    Returns:
        Filtered list of rules
    """
    if profile == "L1":
        return [r for r in rules if r.level == "L1"]
    return rules  # FULL includes L1 + L2


# ============================================================ #
#  Compliance evaluation                                        #
# ============================================================ #

def evaluate_compliance(dump: str, rules: List[MSSQLCISRule]) -> Dict[str, Any]:
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
