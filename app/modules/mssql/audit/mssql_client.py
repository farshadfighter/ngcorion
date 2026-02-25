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

        # ---- 16. Guest CONNECT permissions per user database ------------ #
        sections["GUEST_CONNECT"] = self._query("""
            DECLARE @result TABLE (db_name NVARCHAR(256), has_guest_connect INT)
            DECLARE @sql NVARCHAR(MAX)
            DECLARE @dbname NVARCHAR(256)
            DECLARE db_cursor CURSOR FOR
                SELECT name FROM sys.databases
                WHERE name NOT IN ('master', 'tempdb', 'msdb', 'model')
                  AND state_desc = 'ONLINE'
            OPEN db_cursor
            FETCH NEXT FROM db_cursor INTO @dbname
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = 'SELECT ''' + @dbname + ''', COUNT(*) FROM '
                    + QUOTENAME(@dbname)
                    + '.sys.database_permissions dp '
                    + 'JOIN ' + QUOTENAME(@dbname)
                    + '.sys.database_principals pr '
                    + 'ON dp.grantee_principal_id = pr.principal_id '
                    + 'WHERE pr.name = ''guest'' '
                    + 'AND dp.permission_name = ''CONNECT'' '
                    + 'AND dp.state IN (''G'', ''W'')'
                INSERT INTO @result EXEC sp_executesql @sql
                FETCH NEXT FROM db_cursor INTO @dbname
            END
            CLOSE db_cursor
            DEALLOCATE db_cursor
            SELECT db_name, has_guest_connect FROM @result
        """)

        # ---- 17. Orphaned users per database --------------------------- #
        sections["ORPHANED_USERS"] = self._query("""
            DECLARE @result2 TABLE (db_name NVARCHAR(256), user_name NVARCHAR(256))
            DECLARE @sql2 NVARCHAR(MAX)
            DECLARE @dbname2 NVARCHAR(256)
            DECLARE db_cursor2 CURSOR FOR
                SELECT name FROM sys.databases
                WHERE name NOT IN ('master', 'tempdb', 'msdb', 'model')
                  AND state_desc = 'ONLINE'
            OPEN db_cursor2
            FETCH NEXT FROM db_cursor2 INTO @dbname2
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql2 = 'SELECT ''' + @dbname2 + ''', dp.name FROM '
                    + QUOTENAME(@dbname2)
                    + '.sys.database_principals dp '
                    + 'LEFT JOIN sys.server_principals sp '
                    + 'ON dp.sid = sp.sid '
                    + 'WHERE dp.type = ''S'' '
                    + 'AND dp.name NOT IN (''dbo'', ''guest'', ''INFORMATION_SCHEMA'', ''sys'') '
                    + 'AND dp.authentication_type = 1 '
                    + 'AND sp.sid IS NULL'
                INSERT INTO @result2 EXEC sp_executesql @sql2
                FETCH NEXT FROM db_cursor2 INTO @dbname2
            END
            CLOSE db_cursor2
            DEALLOCATE db_cursor2
            SELECT db_name, user_name FROM @result2
        """)

        # ---- 18. Contained database settings --------------------------- #
        sections["CONTAINED_DBS"] = self._query("""
            SELECT name, containment, containment_desc, is_auto_close_on
            FROM sys.databases
            WHERE containment <> 0
        """)

        # ---- 19. Login audit level from registry ----------------------- #
        sections["LOGIN_AUDIT_LEVEL"] = self._query(
            "DECLARE @audit_level INT;"
            " EXEC xp_instance_regread"
            " N'HKEY_LOCAL_MACHINE',"
            r" N'Software\Microsoft\MSSQLServer\MSSQLServer',"
            " N'AuditLevel', @audit_level OUTPUT;"
            " SELECT ISNULL(@audit_level, 0) AS audit_level"
        )

        # ---- 20. CLR assemblies with non-SAFE permission sets ---------- #
        sections["CLR_ASSEMBLIES"] = self._query("""
            DECLARE @result3 TABLE (db_name NVARCHAR(256), assembly_name NVARCHAR(256), permission_set_desc NVARCHAR(60))
            DECLARE @sql3 NVARCHAR(MAX)
            DECLARE @dbname3 NVARCHAR(256)
            DECLARE db_cursor3 CURSOR FOR
                SELECT name FROM sys.databases
                WHERE state_desc = 'ONLINE'
            OPEN db_cursor3
            FETCH NEXT FROM db_cursor3 INTO @dbname3
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql3 = 'SELECT ''' + @dbname3 + ''', name, permission_set_desc FROM '
                    + QUOTENAME(@dbname3)
                    + '.sys.assemblies '
                    + 'WHERE is_user_defined = 1'
                BEGIN TRY
                    INSERT INTO @result3 EXEC sp_executesql @sql3
                END TRY
                BEGIN CATCH
                END CATCH
                FETCH NEXT FROM db_cursor3 INTO @dbname3
            END
            CLOSE db_cursor3
            DEALLOCATE db_cursor3
            SELECT db_name, assembly_name, permission_set_desc FROM @result3
        """)

        # ---- 21. Symmetric keys with weak algorithms ------------------- #
        sections["SYMMETRIC_KEYS"] = self._query("""
            DECLARE @result4 TABLE (db_name NVARCHAR(256), key_name NVARCHAR(256), algorithm_desc NVARCHAR(60))
            DECLARE @sql4 NVARCHAR(MAX)
            DECLARE @dbname4 NVARCHAR(256)
            DECLARE db_cursor4 CURSOR FOR
                SELECT name FROM sys.databases
                WHERE state_desc = 'ONLINE'
            OPEN db_cursor4
            FETCH NEXT FROM db_cursor4 INTO @dbname4
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql4 = 'SELECT ''' + @dbname4 + ''', name, algorithm_desc FROM '
                    + QUOTENAME(@dbname4)
                    + '.sys.symmetric_keys '
                    + 'WHERE name NOT LIKE ''##%'''
                BEGIN TRY
                    INSERT INTO @result4 EXEC sp_executesql @sql4
                END TRY
                BEGIN CATCH
                END CATCH
                FETCH NEXT FROM db_cursor4 INTO @dbname4
            END
            CLOSE db_cursor4
            DEALLOCATE db_cursor4
            SELECT db_name, key_name, algorithm_desc FROM @result4
        """)

        # ---- 22. Asymmetric keys with key sizes ----------------------- #
        sections["ASYMMETRIC_KEYS"] = self._query("""
            DECLARE @result5 TABLE (db_name NVARCHAR(256), key_name NVARCHAR(256), key_length INT, algorithm_desc NVARCHAR(60))
            DECLARE @sql5 NVARCHAR(MAX)
            DECLARE @dbname5 NVARCHAR(256)
            DECLARE db_cursor5 CURSOR FOR
                SELECT name FROM sys.databases
                WHERE state_desc = 'ONLINE'
            OPEN db_cursor5
            FETCH NEXT FROM db_cursor5 INTO @dbname5
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql5 = 'SELECT ''' + @dbname5 + ''', name, key_length, algorithm_desc FROM '
                    + QUOTENAME(@dbname5)
                    + '.sys.asymmetric_keys'
                BEGIN TRY
                    INSERT INTO @result5 EXEC sp_executesql @sql5
                END TRY
                BEGIN CATCH
                END CATCH
                FETCH NEXT FROM db_cursor5 INTO @dbname5
            END
            CLOSE db_cursor5
            DEALLOCATE db_cursor5
            SELECT db_name, key_name, key_length, algorithm_desc FROM @result5
        """)

        # ---- 23. BUILTIN/local group logins ---------------------------- #
        sections["BUILTIN_LOGINS"] = self._query("""
            SELECT name, type_desc, is_disabled
            FROM sys.server_principals
            WHERE type = 'G'
              AND (name LIKE 'BUILTIN%' OR name LIKE '%\%')
            ORDER BY name
        """)

        # ---- 24. SQL Agent proxy access for public role ---------------- #
        sections["AGENT_PROXIES"] = self._query("""
            SELECT sp.name AS proxy_name, spl.sid
            FROM msdb.dbo.sysproxylogin spl
            JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id
            WHERE spl.sid = 0x00
        """)

        # ---- 25. Hide Instance registry setting ------------------------ #
        sections["HIDE_INSTANCE"] = self._query(
            "DECLARE @hide INT;"
            " EXEC xp_instance_regread"
            " N'HKEY_LOCAL_MACHINE',"
            r" N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',"
            " N'HideInstance', @hide OUTPUT;"
            " SELECT ISNULL(@hide, 0) AS hide_instance"
        )

        # ---- 26. SA name check (any login still named 'sa') ----------- #
        sections["SA_NAME_CHECK"] = self._query("""
            SELECT name, principal_id, type_desc
            FROM sys.server_principals
            WHERE name = 'sa'
        """)

        # ---- 27. SQL logins without MUST_CHANGE flag ------------------- #
        sections["MUST_CHANGE"] = self._query("""
            SELECT
                sp.name,
                LOGINPROPERTY(sp.name, 'IsMustChange') AS is_must_change
            FROM sys.server_principals sp
            JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
            WHERE sp.type = 'S'
              AND sp.name NOT IN ('sa', '##MS_PolicyEventProcessingLogin##',
                                  '##MS_PolicyTsqlExecutionLogin##')
              AND sp.is_disabled = 0
        """)

        # ---- 28. Contained DB users with SQL authentication ------------ #
        sections["CONTAINED_DB_USERS"] = self._query("""
            DECLARE @result6 TABLE (db_name NVARCHAR(256), user_name NVARCHAR(256), authentication_type_desc NVARCHAR(60))
            DECLARE @sql6 NVARCHAR(MAX)
            DECLARE @dbname6 NVARCHAR(256)
            DECLARE db_cursor6 CURSOR FOR
                SELECT name FROM sys.databases
                WHERE containment <> 0 AND state_desc = 'ONLINE'
            OPEN db_cursor6
            FETCH NEXT FROM db_cursor6 INTO @dbname6
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql6 = 'SELECT ''' + @dbname6 + ''', name, authentication_type_desc FROM '
                    + QUOTENAME(@dbname6)
                    + '.sys.database_principals '
                    + 'WHERE authentication_type = 2'
                BEGIN TRY
                    INSERT INTO @result6 EXEC sp_executesql @sql6
                END TRY
                BEGIN CATCH
                END CATCH
                FETCH NEXT FROM db_cursor6 INTO @dbname6
            END
            CLOSE db_cursor6
            DEALLOCATE db_cursor6
            SELECT db_name, user_name, authentication_type_desc FROM @result6
        """)

        # ---- 29. Public server role non-default permissions ------------ #
        sections["PUBLIC_SERVER_PERMS"] = self._query("""
            SELECT
                perm.permission_name,
                perm.state_desc,
                perm.class_desc,
                COALESCE(ep.name, '') AS endpoint_name
            FROM sys.server_permissions perm
            LEFT JOIN sys.endpoints ep ON perm.major_id = ep.endpoint_id AND perm.class = 105
            WHERE perm.grantee_principal_id = SUSER_ID('public')
              AND perm.state IN ('G', 'W')
              AND NOT (perm.permission_name = 'CONNECT' AND perm.class = 105)
              AND perm.permission_name <> 'VIEW ANY DATABASE'
        """)

        # ---- Assemble structured dump ---------------------------------- #
        parts = []
        for section_key, content in sections.items():
            parts.append(f"===SECTION:{section_key}===")
            parts.append(content or "(empty)")

        return "\n".join(parts)
