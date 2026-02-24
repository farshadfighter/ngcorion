"""
SQL Server Audit Client

Connects directly to a SQL Server instance via pymssql and collects
configuration data for CIS SQL Server Benchmark compliance evaluation.

Collection strategy:
1. Query sys.configurations for server-level settings
2. Query sys.server_principals for login/permission checks
3. Query sys.databases for database-level properties
4. Query sys.server_audits and audit specifications for audit status
5. Query sys.dm_server_services for service account info
6. Query SERVERPROPERTY() for server metadata
7. Query @@VERSION for patch level

All data is combined into a single structured dump string with section
markers, which rules.py then evaluates using regex patterns.
"""

import re
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


# Patterns to redact from audit output before storing
_REDACT_PATTERNS = [
    (re.compile(r"(password\s*=\s*)'[^']*'", re.I), r"\1'<REDACTED>'"),
    (re.compile(r"(PASSWORD\s*=\s*N?')[^']*'", re.I), r"\1<REDACTED>'"),
    (re.compile(r"(pwd\s*=\s*)[^\s;]+", re.I), r"\1<REDACTED>"),
]


def redact_sensitive_mssql_data(text: str) -> str:
    """Remove sensitive data from audit dump before database storage."""
    if not text:
        return text
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class MSSQLClient:
    """
    Direct SQL Server audit client using pymssql.

    Connects to the SQL Server instance and runs T-SQL queries against
    system views and DMVs to collect CIS Benchmark compliance data.

    Args:
        ip:          Target SQL Server IP or hostname
        port:        SQL Server TCP port (default 1433)
        username:    SQL Server login (sa or sysadmin account)
        password:    SQL Server password
        timeout:     Connection timeout in seconds
    """

    QUERY_TIMEOUT = 30

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 1433,
        timeout: int = 30,
    ):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self._conn = None

    # ------------------------------------------------------------------ #
    #  Context manager                                                     #
    # ------------------------------------------------------------------ #

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, *_):
        self._disconnect()
        return False

    def _connect(self):
        try:
            import pymssql
        except ImportError:
            raise RuntimeError(
                "pymssql is not installed. Run: pip install pymssql"
            )

        logger.info(f"Connecting to SQL Server at {self.ip}:{self.port}")
        try:
            self._conn = pymssql.connect(
                server=self.ip,
                port=self.port,
                user=self.username,
                password=self.password,
                database="master",
                login_timeout=self.timeout,
                timeout=self.QUERY_TIMEOUT,
                as_dict=False,
            )
            logger.info(f"Connected to SQL Server at {self.ip}")
        except Exception as exc:
            msg = str(exc).lower()
            if "login failed" in msg or "authentication" in msg:
                raise PermissionError(
                    f"SQL Server authentication failed for {self.ip}: {exc}"
                )
            raise ConnectionError(
                f"SQL Server connection failed to {self.ip}:{self.port}: {exc}"
            )

    def _disconnect(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------ #
    #  Query execution helper                                              #
    # ------------------------------------------------------------------ #

    def _query(self, sql: str) -> str:
        """Execute a T-SQL query and return results as a formatted string."""
        if not self._conn:
            raise RuntimeError("Not connected to SQL Server")
        try:
            cursor = self._conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            if not rows:
                return "(no rows returned)"
            lines = []
            for row in rows:
                lines.append(" | ".join(str(c) if c is not None else "NULL" for c in row))
            return "\n".join(lines)
        except Exception as exc:
            logger.debug(f"Query failed [{sql[:80]}...]: {exc}")
            return f"QUERY_ERROR: {str(exc)[:200]}"

    # ------------------------------------------------------------------ #
    #  Main data collection                                                #
    # ------------------------------------------------------------------ #

    def collect_audit_data(self) -> str:
        """
        Collect all SQL Server audit data via T-SQL queries.

        Returns:
            A single structured string with section markers, suitable for
            rule evaluation. Example:

                ===SECTION:VERSION===
                Microsoft SQL Server 2019 (RTM-CU18) ...
                ===SECTION:SERVER_PROPS===
                ...
        """
        sections: Dict[str, str] = {}

        # ---- 1. Version and patch level -------------------------------- #
        sections["VERSION"] = self._query("SELECT @@VERSION")

        sections["SERVER_PROPS"] = self._query("""
            SELECT
                SERVERPROPERTY('ProductVersion')    AS ProductVersion,
                SERVERPROPERTY('ProductLevel')      AS ProductLevel,
                SERVERPROPERTY('Edition')           AS Edition,
                SERVERPROPERTY('EngineEdition')     AS EngineEdition,
                SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly,
                SERVERPROPERTY('IsSingleUser')      AS IsSingleUser,
                SERVERPROPERTY('Collation')         AS Collation
        """)

        # ---- 2. Server-level configuration options --------------------- #
        sections["CONFIGURATIONS"] = self._query("""
            SELECT name, value_in_use, description
            FROM sys.configurations
            ORDER BY name
        """)

        # ---- 3. Authentication mode ------------------------------------ #
        sections["AUTH_MODE"] = self._query("""
            SELECT
                CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                    WHEN 1 THEN 'Windows Authentication Mode'
                    WHEN 0 THEN 'Mixed Mode (SQL Server and Windows Authentication)'
                    ELSE 'Unknown'
                END AS authentication_mode
        """)

        # ---- 4. SA login status ---------------------------------------- #
        sections["SA_LOGIN"] = self._query("""
            SELECT
                name,
                is_disabled,
                type_desc,
                CASE is_disabled WHEN 1 THEN 'DISABLED' ELSE 'ENABLED' END AS status
            FROM sys.server_principals
            WHERE name = 'sa'
        """)

        # ---- 5. All SQL logins with password policy -------------------- #
        sections["SQL_LOGINS"] = self._query("""
            SELECT
                sp.name,
                sp.is_disabled,
                sl.is_policy_checked,
                sl.is_expiration_checked,
                sp.type_desc
            FROM sys.server_principals sp
            LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
            WHERE sp.type IN ('S', 'U', 'G')
            ORDER BY sp.name
        """)

        # ---- 6. Sysadmin role members ---------------------------------- #
        sections["SYSADMIN_MEMBERS"] = self._query("""
            SELECT
                sp.name,
                sp.type_desc,
                sp.is_disabled
            FROM sys.server_role_members srm
            JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
            JOIN sys.server_principals r  ON srm.role_principal_id = r.principal_id
            WHERE r.name = 'sysadmin'
            ORDER BY sp.name
        """)

        # ---- 7. Server-level permissions (CONTROL SERVER) -------------- #
        sections["CONTROL_SERVER"] = self._query("""
            SELECT
                sp.name,
                sp.type_desc,
                perm.permission_name,
                perm.state_desc
            FROM sys.server_permissions perm
            JOIN sys.server_principals sp ON perm.grantee_principal_id = sp.principal_id
            WHERE perm.permission_name = 'CONTROL SERVER'
              AND perm.state IN ('G', 'W')
        """)

        # ---- 8. Database properties ------------------------------------ #
        sections["DATABASES"] = self._query("""
            SELECT
                name,
                is_trustworthy_on,
                is_db_chaining_on,
                is_auto_close_on,
                is_auto_shrink_on,
                state_desc,
                user_access_desc
            FROM sys.databases
            ORDER BY name
        """)

        # ---- 9. Audit configurations ----------------------------------- #
        sections["SERVER_AUDITS"] = self._query("""
            SELECT
                name,
                audit_guid,
                status_desc,
                is_state_enabled,
                type_desc,
                on_failure_desc
            FROM sys.server_audits
        """)

        sections["AUDIT_SPECIFICATIONS"] = self._query("""
            SELECT
                sa.name             AS spec_name,
                a.name              AS audit_name,
                sa.is_state_enabled,
                d.audit_action_name,
                d.audited_result
            FROM sys.server_audit_specifications sa
            JOIN sys.server_audits a ON sa.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d
                ON sa.server_specification_id = d.server_specification_id
            ORDER BY sa.name, d.audit_action_name
        """)

        # ---- 10. Error log configuration ------------------------------- #
        sections["ERRORLOG_COUNT"] = self._query(
            "DECLARE @num_logs INT;"
            " EXEC xp_instance_regread"
            " N'HKEY_LOCAL_MACHINE',"
            r" N'Software\Microsoft\MSSQLServer\MSSQLServer',"
            " N'NumErrorLogs', @num_logs OUTPUT;"
            " SELECT ISNULL(@num_logs, 6) AS num_error_logs"
        )

        # ---- 11. Linked servers ---------------------------------------- #
        sections["LINKED_SERVERS"] = self._query("""
            SELECT
                name,
                is_linked,
                is_remote_login_enabled,
                is_rpc_out_enabled,
                product
            FROM sys.servers
            WHERE is_linked = 1
        """)

        # ---- 12. Service account info (if xp_cmdshell available) ------- #
        sections["SERVICE_ACCOUNTS"] = self._query("""
            SELECT
                servicename,
                service_account,
                status_desc,
                startup_type_desc
            FROM sys.dm_server_services
        """)

        # ---- 13. Endpoints (check for non-standard/open endpoints) ----- #
        sections["ENDPOINTS"] = self._query("""
            SELECT
                name,
                protocol_desc,
                state_desc,
                is_admin_endpoint
            FROM sys.endpoints
            WHERE state = 0
            ORDER BY name
        """)

        # ---- 14. Transparent Data Encryption status -------------------- #
        sections["TDE_STATUS"] = self._query("""
            SELECT
                db.name,
                dek.encryption_state,
                CASE dek.encryption_state
                    WHEN 0 THEN 'No encryption'
                    WHEN 1 THEN 'Unencrypted'
                    WHEN 2 THEN 'Encryption in progress'
                    WHEN 3 THEN 'Encrypted'
                    WHEN 4 THEN 'Key change in progress'
                    WHEN 5 THEN 'Decryption in progress'
                    ELSE 'Unknown'
                END AS encryption_state_desc,
                dek.encryptor_type,
                dek.key_algorithm,
                dek.key_length
            FROM sys.databases db
            LEFT JOIN sys.dm_database_encryption_keys dek
                ON db.database_id = dek.database_id
            WHERE db.name NOT IN ('tempdb')
            ORDER BY db.name
        """)

        # ---- 15. Public role permissions on master --------------------- #
        sections["PUBLIC_PERMS"] = self._query("""
            SELECT
                dp.class_desc,
                dp.permission_name,
                dp.state_desc,
                OBJECT_NAME(dp.major_id) AS object_name
            FROM sys.database_permissions dp
            WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
              AND dp.state IN ('G', 'W')
              AND dp.type NOT IN ('CO')
        """)

        # ---- 16. Assemble structured dump ------------------------------ #
        parts = []
        for section_key, content in sections.items():
            parts.append(f"===SECTION:{section_key}===")
            parts.append(content or "(empty)")

        return "\n".join(parts)
