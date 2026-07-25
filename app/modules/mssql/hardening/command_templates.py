"""
SQL Server Hardening Command Templates (T-SQL)

Remediation T-SQL for each CIS SQL Server check. Templates are keyed by the same
stable, version-agnostic check IDs the audit rules use (``MSSQL-AHDQ`` …), so a
single template serves 2016 / 2019 / 2022 — the version differences live only in
which checks a given rule set includes.

Each template contains:
- statements:        T-SQL executed in order (placeholders substituted)
- verify_statements: T-SQL returning 'PASS' / 'FAIL' as the first column value
- requires_restart:  True when the SQL Server service must restart for the change
- manual_only:       True when automated remediation is not feasible

Per the CIS spec constraints, DROP LOGIN / DROP USER are NEVER performed
automatically (orphaned users, BUILTIN / local groups, 'sa' removal are
manual_only), and any change that needs a service restart or out-of-band step
(protocols, port, auth mode, network/at-rest encryption) is manual_only.
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


# Registry: check_id -> MSSQLHardeningTemplate
MSSQL_HARDENING_TEMPLATES: Dict[str, MSSQLHardeningTemplate] = {}


def _register(t: MSSQLHardeningTemplate) -> None:
    MSSQL_HARDENING_TEMPLATES[t.check_id] = t


def _sp_configure_template(check_id: str, option: str, value: int,
                           advanced: bool = True,
                           reconfigure: str = "RECONFIGURE") -> None:
    """Register an auto-fixable sp_configure toggle template."""
    stmts: List[str] = []
    if advanced:
        stmts += ["EXECUTE sp_configure 'show advanced options', 1", "RECONFIGURE"]
    stmts += [f"EXECUTE sp_configure '{option}', {value}", reconfigure]
    if advanced:
        stmts += ["EXECUTE sp_configure 'show advanced options', 0", "RECONFIGURE"]
    _register(MSSQLHardeningTemplate(
        check_id=check_id,
        description=f"Set '{option}' to {value} (sp_configure)",
        statements=stmts,
        verify_statements=[
            f"SELECT CASE CAST(value_in_use AS INT) WHEN {value} THEN 'PASS' ELSE 'FAIL' END AS result "
            f"FROM sys.configurations WHERE name = '{option}'",
        ],
    ))


# ===================================================================
# AUTO-FIXABLE: sp_configure surface-area / auditing options
# ===================================================================

_sp_configure_template("MSSQL-AHDQ", "Ad Hoc Distributed Queries", 0)
_sp_configure_template("MSSQL-CLR", "clr enabled", 0)
_sp_configure_template("MSSQL-XDBOC", "cross db ownership chaining", 0, advanced=False)
_sp_configure_template("MSSQL-DBMAIL", "Database Mail XPs", 0)
_sp_configure_template("MSSQL-OLEAUTO", "Ole Automation Procedures", 0)
_sp_configure_template("MSSQL-REMACC", "remote access", 0, advanced=False)
_sp_configure_template("MSSQL-REMADMIN", "remote admin connections", 0, advanced=False)
_sp_configure_template("MSSQL-STARTPROC", "scan for startup procs", 0, advanced=False,
                       reconfigure="RECONFIGURE WITH OVERRIDE")
_sp_configure_template("MSSQL-XPCMDSHELL", "xp_cmdshell", 0)
_sp_configure_template("MSSQL-CLRSTRICT", "clr strict security", 1)
_sp_configure_template("MSSQL-DEFTRACE", "default trace enabled", 1)


# ===================================================================
# AUTO-FIXABLE: login / database security
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-SADISABLE",
    description="Disable the 'sa' login account",
    statements=["ALTER LOGIN [sa] DISABLE"],
    verify_statements=[
        "SELECT CASE is_disabled WHEN 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = 'sa'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-SARENAME",
    description="Rename the 'sa' login to {NEW_SA_NAME}",
    statements=["ALTER LOGIN [sa] WITH NAME = [{NEW_SA_NAME}]"],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals WHERE name = 'sa'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-TRUSTWORTHY",
    description="Set TRUSTWORTHY OFF for database {DB_NAME}",
    statements=["ALTER DATABASE [{DB_NAME}] SET TRUSTWORTHY OFF"],
    verify_statements=[
        "SELECT CASE is_trustworthy_on WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.databases WHERE name = '{DB_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-AUTOCLOSE",
    description="Set AUTO_CLOSE OFF for contained database {DB_NAME}",
    statements=["ALTER DATABASE [{DB_NAME}] SET AUTO_CLOSE OFF"],
    verify_statements=[
        "SELECT CASE is_auto_close_on WHEN 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.databases WHERE name = '{DB_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-GUEST",
    description="Revoke CONNECT from the guest user in database {DB_NAME}",
    statements=["USE [{DB_NAME}]", "REVOKE CONNECT FROM [guest]"],
    verify_statements=[
        "USE [{DB_NAME}]; "
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.database_permissions dp "
        "JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id "
        "WHERE pr.name = 'guest' AND dp.permission_name = 'CONNECT' AND dp.state IN ('G', 'W')",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-CHECKPOL",
    description="Enable password policy (CHECK_POLICY = ON) for SQL login {LOGIN_NAME}",
    statements=["ALTER LOGIN [{LOGIN_NAME}] WITH CHECK_POLICY = ON"],
    verify_statements=[
        "SELECT CASE WHEN sl.is_policy_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals sp "
        "JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id "
        "WHERE sp.name = '{LOGIN_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-CHECKEXP",
    description="Enable password expiration (CHECK_EXPIRATION = ON) for SQL login {LOGIN_NAME}",
    statements=["ALTER LOGIN [{LOGIN_NAME}] WITH CHECK_EXPIRATION = ON"],
    verify_statements=[
        "SELECT CASE WHEN sl.is_expiration_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.server_principals sp "
        "JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id "
        "WHERE sp.name = '{LOGIN_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-CLRSAFE",
    description="Set CLR assembly {ASSEMBLY_NAME} permission set to SAFE in database {DB_NAME}",
    statements=[
        "USE [{DB_NAME}]",
        "ALTER ASSEMBLY [{ASSEMBLY_NAME}] WITH PERMISSION_SET = SAFE",
    ],
    verify_statements=[
        "USE [{DB_NAME}]; "
        "SELECT CASE permission_set_desc WHEN 'SAFE_ACCESS' THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM sys.assemblies WHERE name = '{ASSEMBLY_NAME}'",
    ],
))

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-PROXY",
    description="Revoke public role access to SQL Agent proxy {PROXY_NAME}",
    statements=[
        "EXEC msdb.dbo.sp_revoke_login_from_proxy @name = N'public', @proxy_name = N'{PROXY_NAME}'",
    ],
    verify_statements=[
        "SELECT CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS result "
        "FROM msdb.dbo.sysproxylogin spl "
        "JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id "
        "WHERE spl.sid = 0x00 AND sp.name = '{PROXY_NAME}'",
    ],
))


# ===================================================================
# AUTO-FIXABLE via registry
# ===================================================================

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-ERRLOG",
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
    check_id="MSSQL-LOGINAUDIT",
    description="Set Login Auditing to capture failed logins (AuditLevel = {AUDIT_LEVEL})",
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

_register(MSSQLHardeningTemplate(
    check_id="MSSQL-HIDEINST",
    description="Set 'Hide Instance' to Yes via registry",
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


# ===================================================================
# MANUAL ONLY: restart / out-of-band / DROP / policy review
# ===================================================================

_MANUAL: Dict[str, str] = {
    "MSSQL-PATCH": "Apply the latest SQL Server CU/GDR via Windows Update / WSUS",
    "MSSQL-SINGLEFUNC": "Dedicate the host to SQL Server; move other server roles elsewhere",
    "MSSQL-PROTOCOLS": "Disable unused protocols in SQL Server Configuration Manager (restart required)",
    "MSSQL-AUTHMODE": "Set Windows Authentication mode via SSMS server properties (restart required)",
    "MSSQL-NOSA": "Rename the 'sa' login (see MSSQL-SARENAME); never DROP LOGIN automatically",
    "MSSQL-ORPHAN": "Review and DROP USER each orphaned user per database (manual)",
    "MSSQL-CONTAINEDAUTH": "Migrate contained SQL users to Windows authentication (manual)",
    "MSSQL-SVCACCT-MSSQL": "Run the MSSQL service under a least-privilege account (manual)",
    "MSSQL-SVCACCT-AGENT": "Run the SQL Agent service under a least-privilege account (manual)",
    "MSSQL-SVCACCT-FT": "Run the Full-Text service under a least-privilege account (manual)",
    "MSSQL-PUBLICSERVER": "Review and REVOKE non-default public server-role permissions (manual)",
    "MSSQL-BUILTIN": "Remove BUILTIN group logins (DROP LOGIN) after review (manual)",
    "MSSQL-LOCALGROUP": "Remove local Windows group logins (DROP LOGIN) after review (manual)",
    "MSSQL-SYSADMIN": "Remove non-administrative logins from the sysadmin role (manual review)",
    "MSSQL-MSDBADMIN": "Remove unnecessary members from msdb admin roles (manual review)",
    "MSSQL-MUSTCHANGE": "Set MUST_CHANGE at SQL login password reset time (manual)",
    "MSSQL-SRVAUDIT": "Create a Server Audit + login specification (CREATE SERVER AUDIT; manual)",
    "MSSQL-SANITIZE": "Sanitize application/database user input at the application tier (manual)",
    "MSSQL-SYMKEY": "Re-create weak symmetric keys with AES (key drop/re-create; manual)",
    "MSSQL-ASYMKEY": "Re-create small asymmetric keys with >= 2048 bits (manual)",
    "MSSQL-BACKUPENC": "Take encrypted backups (WITH ENCRYPTION); manual policy change",
    "MSSQL-NETENC": "Enable Force Encryption + certificate in Configuration Manager (restart required)",
    "MSSQL-TDE": "Enable TDE per database (multi-step key/cert setup; manual)",
    "MSSQL-BROWSER": "Configure the SQL Server Browser service state to match deployment (manual)",
    "MSSQL-PORT": "Change the SQL Server TCP port in Configuration Manager (restart required)",
}

_RESTART_MANUAL = {"MSSQL-PROTOCOLS", "MSSQL-AUTHMODE", "MSSQL-NETENC", "MSSQL-PORT"}

for _cid, _desc in _MANUAL.items():
    _register(MSSQLHardeningTemplate(
        check_id=_cid,
        description=_desc,
        statements=[],
        manual_only=True,
        requires_restart=_cid in _RESTART_MANUAL,
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
