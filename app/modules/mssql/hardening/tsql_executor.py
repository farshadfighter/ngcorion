"""
SQL Server T-SQL Executor for Hardening

Executes CIS remediation T-SQL statements directly against a SQL Server instance
using pymssql. This is the MSSQL equivalent of the SSH executor used by Linux /
MongoDB modules — but instead of shell commands, we run T-SQL statements.

Architecture:
  MSSQLHardeningExecutionResult  – result dataclass for a single check
  MSSQLTSQLExecutor              – single-connection executor (context manager)
  MSSQLHardeningBatchExecutor    – high-level batch orchestrator
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_mssql_hardening_template,
    get_mssql_template_statements,
    get_mssql_verify_statements,
)

logger = logging.getLogger(__name__)

STATEMENT_TIMEOUT = 30

# Characters that would break out of the [bracket] / 'quote' contexts the
# templates substitute into. Values are sysadmin-supplied, so this guards
# against accidental statement corruption, not a privilege boundary.
_UNSAFE_TEXT_CHARS = ("'", "]", ";", "\n", "\r", "--")

_PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]*\}")


def _validate_mssql_parameters(parameters: Dict[str, str]) -> Optional[str]:
    """Return an error string when a parameter value is unusable, else None."""
    from .parameter_metadata import get_mssql_parameter_metadata

    for name, value in parameters.items():
        value = str(value)
        meta = get_mssql_parameter_metadata(name)
        if meta and meta.input_type in ("number", "select"):
            allowed = meta.options if meta.options else None
            if allowed is not None:
                if value not in allowed:
                    return f"Parameter {name}: value '{value}' not in {allowed}"
                continue
            try:
                int(value)
            except ValueError:
                return f"Parameter {name}: '{value}' is not a number"
        else:
            for bad in _UNSAFE_TEXT_CHARS:
                if bad in value:
                    return (
                        f"Parameter {name} contains unsupported character/sequence "
                        f"{bad!r}"
                    )
    return None


# ============================================================ #
#  Result dataclass                                            #
# ============================================================ #

class MSSQLHardeningExecutionResult:
    """Result of a single CIS check hardening execution."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.success: bool = False
        self.statements_executed: List[str] = []
        self.statement_outputs: Dict[str, str] = {}
        self.verification_result: Optional[str] = None
        self.error_message: Optional[str] = None
        self.requires_restart: bool = False
        self.manual_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "success": self.success,
            "statements_executed": self.statements_executed,
            "statement_outputs": self.statement_outputs,
            "verification_result": self.verification_result,
            "error_message": self.error_message,
            "requires_restart": self.requires_restart,
            "manual_only": self.manual_only,
        }


# ============================================================ #
#  Single-connection executor                                  #
# ============================================================ #

class MSSQLTSQLExecutor:
    """
    Single-connection T-SQL executor for SQL Server hardening.

    Use as a context manager:

        with MSSQLTSQLExecutor(ip, username, password) as executor:
            result = executor.execute_hardening("MSSQL-L1-010")
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 1433,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self._conn = None

    # ---------------------------------------------------------------- #
    #  Connection management                                            #
    # ---------------------------------------------------------------- #

    def connect(self) -> None:
        """Establish connection to SQL Server with retry logic."""
        if self._conn:
            return
        try:
            import pymssql
        except ImportError:
            raise RuntimeError("pymssql is not installed. Run: pip install pymssql")

        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    f"Connecting to SQL Server {self.ip}:{self.port} for hardening "
                    f"(attempt {attempt}/{self.max_retries})"
                )
                self._conn = pymssql.connect(
                    server=self.ip,
                    port=self.port,
                    user=self.username,
                    password=self.password,
                    database="master",
                    login_timeout=self.timeout,
                    timeout=STATEMENT_TIMEOUT,
                    as_dict=False,
                )
                logger.info(f"Connected to SQL Server at {self.ip}")
                return

            except pymssql.OperationalError as exc:
                msg = str(exc).lower()
                if "login failed" in msg or "authentication" in msg:
                    raise PermissionError(
                        f"SQL Server authentication failed for {self.ip}: {exc}"
                    )
                last_exception = exc
                logger.warning(
                    f"Connection to {self.ip} failed (attempt {attempt}/{self.max_retries}): {exc}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except OSError as exc:
                if hasattr(exc, "errno") and exc.errno in (111, 113):
                    raise ConnectionError(
                        f"SQL Server connection refused at {self.ip}:{self.port}: {exc}"
                    )
                last_exception = exc
                logger.warning(
                    f"OS error connecting to {self.ip} (attempt {attempt}/{self.max_retries}): {exc}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except Exception as exc:
                last_exception = exc
                logger.warning(
                    f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): "
                    f"{type(exc).__name__}: {exc}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        raise ConnectionError(
            f"SQL Server connection failed to {self.ip}:{self.port} "
            f"after {self.max_retries} attempts: {last_exception}"
        )

    def disconnect(self) -> None:
        """Close the SQL Server connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception as e:
                logger.warning(f"[MSSQL Hardening] disconnect from {self.ip} failed: {e}")
            self._conn = None
            logger.info(f"Disconnected from SQL Server {self.ip}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()
        return False

    # ---------------------------------------------------------------- #
    #  Health check                                                      #
    # ---------------------------------------------------------------- #

    def is_connected(self) -> bool:
        """Check if the SQL Server connection is alive."""
        if not self._conn:
            return False
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchall()
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------- #
    #  Statement execution                                              #
    # ---------------------------------------------------------------- #

    _EXECUTE_MAX_ATTEMPTS = 2

    def _execute(self, sql: str) -> str:
        """
        Execute a single T-SQL statement and return output as a formatted string.

        Returns "(ok)" for DML/DDL statements, or the formatted result rows
        for SELECT statements. Retries once on deadlock or connection-drop errors.
        """
        if not self._conn:
            raise RuntimeError("Not connected to SQL Server")

        for attempt in range(1, self._EXECUTE_MAX_ATTEMPTS + 1):
            try:
                cursor = self._conn.cursor()
                cursor.execute(sql)
                try:
                    rows = cursor.fetchall()
                except Exception:
                    rows = None

                if not rows:
                    return "(ok)"

                lines = []
                for row in rows:
                    lines.append(" | ".join(str(c) if c is not None else "NULL" for c in row))
                return "\n".join(lines)

            except Exception as exc:
                exc_msg = str(exc).lower()
                is_deadlock = "1205" in exc_msg or "deadlock" in exc_msg
                is_conn_drop = (
                    "connection" in exc_msg and ("closed" in exc_msg or "reset" in exc_msg)
                ) or "adaptive server" in exc_msg
                retryable = is_deadlock or is_conn_drop

                if retryable and attempt < self._EXECUTE_MAX_ATTEMPTS:
                    logger.warning(
                        f"Statement retryable error (attempt {attempt}): {exc}"
                    )
                    try:
                        self.disconnect()
                        self.connect()
                    except Exception as reconn_exc:
                        logger.error(f"Reconnect failed during statement retry: {reconn_exc}")
                        raise exc from reconn_exc
                    continue

                logger.debug(f"Statement failed [{sql[:80]}]: {exc}")
                raise

    def backup_config(self) -> str:
        """
        Snapshot the server's ``sp_configure`` settings before hardening.

        SQL Server has no single "running config" to dump; the settings CIS
        hardening changes live in ``sys.configurations``. We render the current
        values as replayable ``EXEC sp_configure`` statements so the snapshot
        doubles as a rollback script. Read-only — it does not RECONFIGURE.
        """
        from app.modules.shared.hardening_backup import bundle_header

        if not self._conn:
            raise RuntimeError("Not connected to SQL Server")

        logger.info(f"Backing up SQL Server configuration from {self.ip}")
        props = self._execute(
            "SELECT "
            "CONVERT(varchar, SERVERPROPERTY('MachineName')) + ' | ' + "
            "CONVERT(varchar, SERVERPROPERTY('ProductVersion')) + ' | ' + "
            "CONVERT(varchar, SERVERPROPERTY('Edition')) + ' | ' + "
            "CASE SERVERPROPERTY('IsIntegratedSecurityOnly') "
            "WHEN 1 THEN 'Windows Authentication only' ELSE 'Mixed Mode (SQL + Windows)' END"
        )
        # One replayable statement per configuration option, at its current value.
        replay = self._execute(
            "SELECT 'EXEC sp_configure ''' + name + ''', ' "
            "+ CONVERT(varchar(20), value_in_use) + '; ' "
            "FROM sys.configurations ORDER BY name"
        )
        if not replay or not replay.strip():
            raise RuntimeError("SQL Server configuration backup returned no content")

        header = bundle_header("mssql", self.ip, label="sp_configure Snapshot")
        body = (
            f"# Server: {props}\n"
            "#\n"
            "# Rollback: enable advanced options first, then replay the statements below.\n"
            "# EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            "#\n"
            f"{replay}\n"
            "# RECONFIGURE;\n"
        )
        backup = header + body
        logger.info(f"SQL Server configuration backup completed: {len(backup)} bytes from {self.ip}")
        return backup

    # ---------------------------------------------------------------- #
    #  Hardening execution                                              #
    # ---------------------------------------------------------------- #

    def execute_hardening(
        self,
        check_id: str,
        parameters: Dict[str, str] = None,
    ) -> MSSQLHardeningExecutionResult:
        """
        Execute remediation T-SQL statements for a single CIS check.

        Args:
            check_id:   MSSQL CIS check ID (e.g. "MSSQL-L1-010")
            parameters: {PARAM} placeholder values for template substitution

        Returns:
            MSSQLHardeningExecutionResult with execution details
        """
        result = MSSQLHardeningExecutionResult(check_id)

        # Merge template defaults under the caller's values and drop empty
        # strings: the UI may submit optional params as "" and a missing value
        # would leave the {PLACEHOLDER} unsubstituted, sending broken T-SQL
        # (e.g. "ALTER DATABASE [{DB_NAME}]") to the server.
        from .parameter_metadata import get_mssql_check_defaults
        merged = dict(get_mssql_check_defaults(check_id))
        for k, v in (parameters or {}).items():
            if v is not None and str(v).strip() != "":
                merged[k] = v
        parameters = merged

        template = get_mssql_hardening_template(check_id)
        if not template:
            result.error_message = f"No hardening template found for {check_id}"
            logger.warning(result.error_message)
            return result

        result.requires_restart = template.requires_restart
        result.manual_only = template.manual_only

        if template.manual_only:
            result.error_message = (
                f"Check {check_id} requires manual remediation: {template.description}"
            )
            logger.info(result.error_message)
            return result

        if not self._conn:
            result.error_message = "Not connected to SQL Server"
            return result

        param_error = _validate_mssql_parameters(parameters)
        if param_error:
            result.error_message = param_error
            logger.warning(f"[{check_id}] {param_error}")
            return result

        logger.info(f"Executing hardening for {check_id}: {template.description}")

        try:
            statements = get_mssql_template_statements(check_id, parameters)
            verify_stmts = get_mssql_verify_statements(check_id, parameters)

            # A leftover {PLACEHOLDER} means a required parameter was not
            # supplied — refuse to run rather than send broken T-SQL.
            leftover = sorted({
                m for stmt in statements + verify_stmts
                for m in _PLACEHOLDER_RE.findall(stmt)
            })
            if leftover:
                result.error_message = (
                    f"Missing required parameter(s): {', '.join(leftover)}"
                )
                logger.warning(f"[{check_id}] {result.error_message}")
                return result

            execution_errors = []

            for stmt in statements:
                try:
                    output = self._execute(stmt)
                    result.statements_executed.append(stmt)
                    result.statement_outputs[stmt[:100]] = output
                    logger.debug(f"  [{check_id}] executed: {stmt[:70]}")
                except Exception as exc:
                    error_msg = f"ERROR: {str(exc)[:200]}"
                    result.statement_outputs[stmt[:100]] = error_msg
                    execution_errors.append(str(exc)[:200])
                    logger.error(f"  [{check_id}] failed: {stmt[:70]} — {exc}")

            # Run verification
            if verify_stmts:
                verification_outputs = []
                for vstmt in verify_stmts:
                    try:
                        voutput = self._execute(vstmt)
                        verification_outputs.append(voutput)
                    except Exception as exc:
                        verification_outputs.append(f"ERROR: {str(exc)[:200]}")

                result.verification_result = "\n".join(verification_outputs)

                # Fail closed: "FAIL" wins over "PASS", and a verification that
                # produced neither (errored, or the SELECT returned no rows) is
                # not a success — the DB row must never be flipped to PASS on
                # an unconfirmed fix.
                if "FAIL" in result.verification_result:
                    result.success = False
                elif "PASS" in result.verification_result:
                    result.success = True
                else:
                    result.success = False
                    result.error_message = (
                        "Verification produced no PASS/FAIL signal — fix not confirmed"
                    )
            else:
                result.success = len(execution_errors) == 0

            # A USE [db] in the remediation or verification leaves the
            # connection parked in that database; reset so later checks in
            # the same batch run against master.
            if any("USE [" in stmt.upper() for stmt in statements + verify_stmts):
                try:
                    self._execute("USE [master]")
                except Exception as e:
                    logger.warning(
                        "[MSSQL Hardening] could not reset the connection to master "
                        f"after {check_id}: {e}"
                    )

            if execution_errors and not result.success:
                result.error_message = "; ".join(execution_errors[:3])

            logger.info(
                f"Hardening {check_id}: {'SUCCESS' if result.success else 'FAIL'}"
            )

        except Exception as exc:
            result.error_message = str(exc)[:500]
            result.success = False
            logger.error(f"Hardening {check_id} raised exception: {exc}")

        return result

    def execute_batch(
        self,
        checks: List[Dict[str, Any]],
    ) -> List[MSSQLHardeningExecutionResult]:
        """
        Execute hardening for multiple checks over the same SQL Server connection.

        Args:
            checks: List of {"check_id": str, "parameters": dict} dicts
        """
        results = []
        for check in checks:
            check_id = check.get("check_id", "")
            parameters = check.get("parameters", {})
            result = self.execute_hardening(check_id, parameters)
            results.append(result)
            time.sleep(0.2)
        return results


# ============================================================ #
#  High-level batch executor                                   #
# ============================================================ #

class MSSQLHardeningBatchExecutor:
    """
    High-level executor that manages the full SQL Server connection lifecycle.

    Methods return JSON-serialisable dicts suitable for the API response.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 1433,
        max_retries: int = 3,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.max_retries = max_retries

    def _make_executor(self) -> MSSQLTSQLExecutor:
        return MSSQLTSQLExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            port=self.port,
            max_retries=self.max_retries,
        )

    def execute_auto_harden(
        self,
        check_ids: List[str],
        default_overrides: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening for all auto-fixable checks.

        Only processes checks that need no user-supplied parameters
        (or whose parameters all have defaults).
        """
        from .parameter_metadata import is_mssql_check_auto_fixable, get_mssql_check_defaults

        auto_fixable = [cid for cid in check_ids if is_mssql_check_auto_fixable(cid)]
        skipped = [cid for cid in check_ids if cid not in auto_fixable]

        results = []
        successful = 0
        failed = 0

        with self._make_executor() as executor:
            for check_id in auto_fixable:
                params = get_mssql_check_defaults(check_id)
                if default_overrides:
                    params.update(default_overrides)

                result = executor.execute_hardening(check_id, params)
                results.append(result.to_dict())

                if result.success:
                    successful += 1
                else:
                    failed += 1

        return {
            "total_requested": len(check_ids),
            "auto_fixable": len(auto_fixable),
            "skipped": skipped,
            "successful": successful,
            "failed": failed,
            "results": results,
        }

    def execute_selected(
        self,
        checks: List[Dict[str, Any]],
        create_backup: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of {"check_id": str, "parameters": dict} dicts
            create_backup: Snapshot sp_configure before applying changes. Returned
                under ``backup_content`` / ``backup_error``.
        """
        results = []
        successful = 0
        failed = 0
        backup_content: Optional[str] = None
        backup_error: Optional[str] = None

        with self._make_executor() as executor:
            if create_backup:
                try:
                    backup_content = executor.backup_config()
                except Exception as exc:  # noqa: BLE001
                    backup_error = str(exc)
                    logger.error(f"SQL Server pre-hardening backup failed on {self.ip}: {exc}")

            for check in checks:
                check_id = check.get("check_id", "")
                parameters = check.get("parameters", {})
                result = executor.execute_hardening(check_id, parameters)
                results.append(result.to_dict())

                if result.success:
                    successful += 1
                else:
                    failed += 1

        return {
            "total": len(checks),
            "successful": successful,
            "failed": failed,
            "results": results,
            "backup_content": backup_content,
            "backup_error": backup_error,
        }

    def execute_single(
        self,
        check_id: str,
        parameters: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """Execute hardening for a single check and return a result dict."""
        with self._make_executor() as executor:
            result = executor.execute_hardening(check_id, parameters)
            return result.to_dict()
