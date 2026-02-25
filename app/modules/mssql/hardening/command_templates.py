"""
SQL Server Hardening Command Templates (T-SQL)

Remediation T-SQL statements for each CIS SQL Server check. Unlike SSH-based
modules (Linux, MongoDB), MSSQL hardening executes T-SQL directly against the
SQL Server instance via pymssql.

Each template contains:
- statements:        T-SQL statements executed in order (placeholders substituted)
- verify_statements: T-SQL returning 'PASS' or 'FAIL' as the first column value
- requires_restart:  True when the SQL Server service must restart for the change
- manual_only:       True when automated remediation is not feasible (manual steps)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class MSSQLHardeningTemplate:
    """Template for hardening a specific CIS SQL Server check."""
    check_id: str
    description: str
    statements: List[str]
    verify_statements: List[str] = field(default_factory=list)
    requires_restart: bool = False
    manual_only: bool = False


# Registry: check_id → MSSQLHardeningTemplate
MSSQL_HARDENING_TEMPLATES: Dict[str, MSSQLHardeningTemplate] = {}


def _register(t: MSSQLHardeningTemplate) -> None:
    MSSQL_HARDENING_TEMPLATES[t.check_id] = t


# ===================================================================
# AUTO-FIXABLE: sp_configure surface-area options (set to 0)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-002",
    description="Disable 'Ad Hoc Distributed Queries' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-003",
    description="Disable 'CLR Enabled' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'clr enabled', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'clr enabled'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-004",
    description="Disable 'Cross DB Ownership Chaining' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'cross db ownership chaining', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'cross db ownership chaining'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-005",
    description="Disable 'Database Mail XPs' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'Database Mail XPs', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'Database Mail XPs'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-006",
    description="Disable 'Ole Automation Procedures' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'Ole Automation Procedures', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'Ole Automation Procedures'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-007",
    description="Disable 'Remote Access' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'remote access', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'remote access'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-008",
    description="Disable 'Remote Admin Connections' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'remote admin connections', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'remote admin connections'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-009",
    description="Disable 'Scan for Startup Procs' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'scan for startup procs', 0",
        "RECONFIGURE WITH OVERRIDE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'scan for startup procs'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-010",
    description="Disable 'xp_cmdshell' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'xp_cmdshell', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'xp_cmdshell'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-012",
    description="Disable 'SQL Mail XPs' (sp_configure = 0)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'SQL Mail XPs', 0",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'SQL Mail XPs'",
    ],
))

# ===================================================================
# AUTO-FIXABLE: Login / account security
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-014",
    description="Disable the SA login account",
    statements=[
        "ALTER LOGIN [sa] DISABLE",
    ],
    verify_statements=[
        "SELECT CASE is_disabled WHEN 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = 'sa'",
    ],
))

# ===================================================================
# PARAMETERIZED: Database-level settings
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-011",
    description="Set TRUSTWORTHY = OFF for database {DB_NAME}",
    statements=[
        "ALTER DATABASE [{DB_NAME}] SET TRUSTWORTHY OFF",
    ],
    verify_statements=[
        "SELECT CASE is_trustworthy_on WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.databases WHERE name = '{DB_NAME}'",
    ],
))

# ===================================================================
# PARAMETERIZED: Login / role management
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-015",
    description="Rename the SA login to {NEW_SA_NAME}",
    statements=[
        "ALTER LOGIN [sa] WITH NAME = [{NEW_SA_NAME}]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = 'sa'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-016",
    description="Remove login {SYSADMIN_LOGIN} from the sysadmin server role",
    statements=[
        "ALTER SERVER ROLE [sysadmin] DROP MEMBER [{SYSADMIN_LOGIN}]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_role_members srm "
        "JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id "
        "JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id "
        "WHERE r.name = 'sysadmin' AND sp.name = '{SYSADMIN_LOGIN}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-017",
    description="Revoke CONTROL SERVER permission from login {CONTROL_LOGIN}",
    statements=[
        "REVOKE CONTROL SERVER FROM [{CONTROL_LOGIN}]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_permissions perm "
        "JOIN sys.server_principals sp ON perm.grantee_principal_id = sp.principal_id "
        "WHERE perm.permission_name = 'CONTROL SERVER' "
        "AND perm.state IN ('G', 'W') AND sp.name = '{CONTROL_LOGIN}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-023",
    description="Enable password policy (CHECK_POLICY = ON) for SQL login {LOGIN_NAME}",
    statements=[
        "ALTER LOGIN [{LOGIN_NAME}] WITH CHECK_POLICY = ON",
    ],
    verify_statements=[
        "SELECT CASE WHEN sl.is_policy_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals sp "
        "JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id "
        "WHERE sp.name = '{LOGIN_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-024",
    description="Enable password expiration (CHECK_EXPIRATION = ON) for SQL login {LOGIN_NAME}",
    statements=[
        "ALTER LOGIN [{LOGIN_NAME}] WITH CHECK_EXPIRATION = ON",
    ],
    verify_statements=[
        "SELECT CASE WHEN sl.is_expiration_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals sp "
        "JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id "
        "WHERE sp.name = '{LOGIN_NAME}'",
    ],
))

# ===================================================================
# PARAMETERIZED: Auditing & error log retention
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-019",
    description="Set SQL Server error log retention to {NUM_ERROR_LOGS} files",
    statements=[
        r"EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer', "
        r"N'NumErrorLogs', REG_DWORD, {NUM_ERROR_LOGS}",
    ],
    verify_statements=[
        r"DECLARE @n INT; "
        r"EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer', "
        r"N'NumErrorLogs', @n OUTPUT; "
        r"SELECT CASE WHEN ISNULL(@n, 0) >= {NUM_ERROR_LOGS} THEN 'PASS' ELSE 'FAIL' END AS result",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-020",
    description="Create SQL Server Audit '{AUDIT_NAME}' writing to path '{AUDIT_FILE_PATH}'",
    statements=[
        "IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = '{AUDIT_NAME}') "
        "    CREATE SERVER AUDIT [{AUDIT_NAME}] TO FILE (FILEPATH = N'{AUDIT_FILE_PATH}')",
        "ALTER SERVER AUDIT [{AUDIT_NAME}] WITH (STATE = ON)",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) > 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_audits WHERE name = '{AUDIT_NAME}' AND is_state_enabled = 1",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-021",
    description="Enable existing SQL Server Audit '{AUDIT_NAME}' (STATE = ON)",
    statements=[
        "ALTER SERVER AUDIT [{AUDIT_NAME}] WITH (STATE = ON)",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) > 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_audits WHERE name = '{AUDIT_NAME}' AND is_state_enabled = 1",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-022",
    description=(
        "Create login audit specification '{SPEC_NAME}' "
        "for SQL Server Audit '{AUDIT_NAME}'"
    ),
    statements=[
        "IF NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = '{SPEC_NAME}') "
        "    CREATE SERVER AUDIT SPECIFICATION [{SPEC_NAME}] "
        "    FOR SERVER AUDIT [{AUDIT_NAME}] "
        "    ADD (FAILED_LOGIN_GROUP), "
        "    ADD (SUCCESSFUL_LOGIN_GROUP) "
        "    WITH (STATE = ON)",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) > 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_audit_specifications "
        "WHERE name = '{SPEC_NAME}' AND is_state_enabled = 1",
    ],
))

# ===================================================================
# MANUAL ONLY: Require SSMS / restart / out-of-band steps
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-001",
    description="Apply latest SQL Server patches – manual process via Windows Update / WSUS",
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-013",
    description=(
        "Change authentication mode to Windows-only "
        "(requires SSMS server properties change + SQL Server service restart)"
    ),
    statements=[],
    requires_restart=True,
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-018",
    description=(
        "Revoke non-default 'public' role permissions in master "
        "– requires manual review of each permission"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L2-025",
    description=(
        "Enable Transparent Data Encryption (TDE) "
        "– requires multi-database T-SQL steps; see remediation guidance"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-026",
    description=(
        "Change SQL Server TCP port "
        "– requires SQL Server Configuration Manager + service restart"
    ),
    statements=[],
    requires_restart=True,
    manual_only=True,
))


# ===================================================================
# Helper functions
# ===================================================================

def get_mssql_hardening_template(check_id: str) -> Optional[MSSQLHardeningTemplate]:
    """Return the hardening template for the given check ID, or None."""
    return MSSQL_HARDENING_TEMPLATES.get(check_id)


def get_all_supported_checks() -> Set[str]:
    """Return the set of all check IDs that have a hardening template."""
    return set(MSSQL_HARDENING_TEMPLATES.keys())


def get_mssql_template_statements(
    check_id: str,
    parameters: Dict[str, str] = None,
) -> List[str]:
    """Return T-SQL statements with {PARAM} placeholders substituted."""
    template = get_mssql_hardening_template(check_id)
    if not template:
        return []
    parameters = parameters or {}
    result = []
    for stmt in template.statements:
        for name, value in parameters.items():
            stmt = stmt.replace(f"{{{name}}}", str(value))
        result.append(stmt)
    return result


def get_mssql_verify_statements(
    check_id: str,
    parameters: Dict[str, str] = None,
) -> List[str]:
    """Return verification T-SQL statements with {PARAM} placeholders substituted."""
    template = get_mssql_hardening_template(check_id)
    if not template:
        return []
    parameters = parameters or {}
    result = []
    for stmt in template.verify_statements:
        for name, value in parameters.items():
            stmt = stmt.replace(f"{{{name}}}", str(value))
        result.append(stmt)
    return result
