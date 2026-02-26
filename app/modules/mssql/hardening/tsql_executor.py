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
import time
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_mssql_hardening_template,
    get_mssql_template_statements,
    get_mssql_verify_statements,
)

logger = logging.getLogger(__name__)

STATEMENT_TIMEOUT = 30


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
            except Exception:
                pass
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
        parameters = parameters or {}

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

        logger.info(f"Executing hardening for {check_id}: {template.description}")

        try:
            statements = get_mssql_template_statements(check_id, parameters)
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
            verify_stmts = get_mssql_verify_statements(check_id, parameters)
            if verify_stmts:
                verification_outputs = []
                for vstmt in verify_stmts:
                    try:
                        voutput = self._execute(vstmt)
                        verification_outputs.append(voutput)
                    except Exception as exc:
                        verification_outputs.append(f"ERROR: {str(exc)[:200]}")

                result.verification_result = "\n".join(verification_outputs)

                if "PASS" in result.verification_result:
                    result.success = True
                elif "FAIL" in result.verification_result:
                    result.success = False
                else:
                    # No PASS/FAIL signal — success if no errors during execution
                    result.success = len(execution_errors) == 0
            else:
                result.success = len(execution_errors) == 0

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
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of {"check_id": str, "parameters": dict} dicts
        """
        results = []
        successful = 0
        failed = 0

        with self._make_executor() as executor:
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
