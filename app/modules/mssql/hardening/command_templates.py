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
# NEW CHECKS: Surface Area (Section 2 additions)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-027",
    description=(
        "Disable unnecessary SQL Server protocols "
        "– requires SQL Server Configuration Manager; manual only"
    ),
    statements=[],
    requires_restart=True,
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-028",
    description="Set Hide Instance to Yes via registry",
    statements=[
        r"EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', "
        r"N'HideInstance', REG_DWORD, 1",
    ],
    verify_statements=[
        r"DECLARE @h INT; "
        r"EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', "
        r"N'HideInstance', @h OUTPUT; "
        r"SELECT CASE WHEN ISNULL(@h, 0) = 1 THEN 'PASS' ELSE 'FAIL' END AS result",
    ],
    requires_restart=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-029",
    description="Set AUTO_CLOSE OFF for contained database {DB_NAME}",
    statements=[
        "ALTER DATABASE [{DB_NAME}] SET AUTO_CLOSE OFF",
    ],
    verify_statements=[
        "SELECT CASE is_auto_close_on WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.databases WHERE name = '{DB_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-030",
    description=(
        "Rename the 'sa' login – already handled by MSSQL-L2-015; manual review"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-031",
    description="Enable 'CLR strict security' (sp_configure = 1, SQL Server 2017+)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'clr strict security', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'clr strict security'",
    ],
))

# ===================================================================
# NEW CHECKS: Authentication & Authorization (Section 3 additions)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-032",
    description="Revoke CONNECT from guest user in database {DB_NAME}",
    statements=[
        "USE [{DB_NAME}]",
        "REVOKE CONNECT FROM [guest]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM [{DB_NAME}].sys.database_permissions dp "
        "JOIN [{DB_NAME}].sys.database_principals pr "
        "ON dp.grantee_principal_id = pr.principal_id "
        "WHERE pr.name = 'guest' AND dp.permission_name = 'CONNECT' "
        "AND dp.state IN ('G', 'W')",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-033",
    description=(
        "Drop orphaned users – requires per-database manual review"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-034",
    description=(
        "Migrate contained DB users from SQL auth to Windows auth – manual review"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-035",
    description=(
        "Revoke non-default public server role permissions – manual review required"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-036",
    description="Drop BUILTIN group SQL login {BUILTIN_LOGIN}",
    statements=[
        "DROP LOGIN [{BUILTIN_LOGIN}]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = '{BUILTIN_LOGIN}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-037",
    description="Drop local Windows group SQL login {LOCAL_GROUP_LOGIN}",
    statements=[
        "DROP LOGIN [{LOCAL_GROUP_LOGIN}]",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = '{LOCAL_GROUP_LOGIN}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-038",
    description="Revoke public proxy access for proxy {PROXY_NAME}",
    statements=[
        "EXEC msdb.dbo.sp_revoke_login_from_proxy "
        "@name = N'public', @proxy_name = N'{PROXY_NAME}'",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM msdb.dbo.sysproxylogin spl "
        "JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id "
        "WHERE spl.sid = 0x00 AND sp.name = '{PROXY_NAME}'",
    ],
))

# ===================================================================
# NEW CHECKS: Password Policies (Section 4 addition)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-039",
    description=(
        "Set MUST_CHANGE for SQL logins – advisory; must be done at password reset time"
    ),
    statements=[],
    manual_only=True,
))

# ===================================================================
# NEW CHECKS: Auditing (Section 5 additions)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-040",
    description="Enable 'Default Trace Enabled' (sp_configure = 1)",
    statements=[
        "EXECUTE sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'default trace enabled', 1",
        "RECONFIGURE",
        "EXECUTE sp_configure 'show advanced options', 0",
        "RECONFIGURE",
    ],
    verify_statements=[
        "SELECT CASE CAST(value_in_use AS INT) WHEN 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.configurations WHERE name = 'default trace enabled'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-041",
    description="Set Login Auditing to capture failed logins (AuditLevel = 2)",
    statements=[
        r"EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer', "
        r"N'AuditLevel', REG_DWORD, {AUDIT_LEVEL}",
    ],
    verify_statements=[
        r"DECLARE @al INT; "
        r"EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', "
        r"N'Software\Microsoft\MSSQLServer\MSSQLServer', "
        r"N'AuditLevel', @al OUTPUT; "
        r"SELECT CASE WHEN ISNULL(@al, 0) >= 2 THEN 'PASS' ELSE 'FAIL' END AS result",
    ],
    requires_restart=True,
))

# ===================================================================
# NEW CHECKS: Application Development (Section 6 addition)
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-042",
    description="Set CLR Assembly {ASSEMBLY_NAME} permission set to SAFE in database {DB_NAME}",
    statements=[
        "USE [{DB_NAME}]",
        "ALTER ASSEMBLY [{ASSEMBLY_NAME}] WITH PERMISSION_SET = SAFE",
    ],
    verify_statements=[
        "SELECT CASE permission_set_desc WHEN 'SAFE_ACCESS' THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM [{DB_NAME}].sys.assemblies WHERE name = '{ASSEMBLY_NAME}'",
    ],
))

# ===================================================================
# NEW CHECKS: Encryption (Section 7 additions) — manual only
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-043",
    description=(
        "Re-create symmetric keys with AES_128+ algorithm – "
        "requires key drop and re-creation; manual only"
    ),
    statements=[],
    manual_only=True,
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-L1-044",
    description=(
        "Re-create asymmetric keys with ≥ 2048-bit size – "
        "requires key drop and re-creation; manual only"
    ),
    statements=[],
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
