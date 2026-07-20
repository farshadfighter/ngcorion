"""
Windows Server PowerShell Executor for Hardening

Executes CIS remediation PowerShell commands directly against a Windows Server
instance using WinRM (pywinrm). This is the Windows equivalent of the T-SQL
executor used by the MSSQL module.

Architecture:
  WindowsHardeningExecutionResult  – result dataclass for a single check
  WindowsWinRMExecutor             – single-session executor (context manager)
  WindowsHardeningBatchExecutor    – high-level batch orchestrator
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_windows_hardening_template,
    get_windows_template_statements,
    get_windows_verify_statements,
)

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 60

# Characters that would break out of the '...' contexts the templates
# substitute into, or start a PowerShell subexpression. Values come from an
# admin, so this guards against statement corruption, not a privilege boundary.
_UNSAFE_TEXT_CHARS = ("'", "`", "$", ";", "\n", "\r", "{", "}")

_PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]*\}")


def _validate_windows_parameters(parameters: Dict[str, str]) -> Optional[str]:
    """Return an error string when a parameter value is unusable, else None."""
    from .parameter_metadata import get_windows_parameter_metadata

    for name, value in parameters.items():
        value = str(value)
        meta = get_windows_parameter_metadata(name)
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
                        f"Parameter {name} contains unsupported character "
                        f"{bad!r}"
                    )
    return None


# ============================================================ #
#  Result dataclass                                            #
# ============================================================ #

class WindowsHardeningExecutionResult:
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
#  Single-session executor                                     #
# ============================================================ #

class WindowsWinRMExecutor:
    """
    Single-session WinRM executor for Windows Server hardening.

    Use as a context manager:

        with WindowsWinRMExecutor(ip, username, password) as executor:
            result = executor.execute_hardening("WIN-L1-048")
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 5986,
        timeout: int = 30,
        max_retries: int = 3,
        transport: str = "ntlm",
        verify_ssl: bool = False,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.transport = transport
        self.verify_ssl = verify_ssl
        self._session = None

    # ---------------------------------------------------------------- #
    #  Connection management                                            #
    # ---------------------------------------------------------------- #

    def connect(self) -> None:
        """Establish WinRM session with retry logic."""
        if self._session:
            return
        try:
            import winrm
        except ImportError:
            raise RuntimeError("pywinrm is not installed. Run: pip install pywinrm")

        cert_validation = "ignore" if not self.verify_ssl else "validate"
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    f"Connecting to Windows Server {self.ip}:{self.port} for hardening "
                    f"(attempt {attempt}/{self.max_retries})"
                )
                self._session = winrm.Session(
                    f"https://{self.ip}:{self.port}/wsman",
                    auth=(self.username, self.password),
                    transport=self.transport,
                    server_cert_validation=cert_validation,
                    operation_timeout_sec=self.timeout,
                    read_timeout_sec=self.timeout + 10,
                )

                # Validate connection
                result = self._session.run_ps("$env:COMPUTERNAME")
                if result.status_code != 0:
                    stderr = result.std_err.decode("utf-8", errors="replace") if result.std_err else ""
                    if any(kw in stderr.lower() for kw in ("unauthorized", "401", "403")):
                        raise PermissionError(f"WinRM auth failed for {self.ip}: {stderr[:200]}")
                    raise ConnectionError(f"WinRM test failed on {self.ip}: {stderr[:200]}")

                logger.info(f"Connected to Windows Server at {self.ip}")
                return

            except PermissionError:
                raise

            except Exception as exc:
                exc_msg = str(exc).lower()
                if any(kw in exc_msg for kw in ("unauthorized", "401", "403", "access denied", "logon failure")):
                    raise PermissionError(f"WinRM auth failed for {self.ip}: {exc}")

                last_exception = exc
                logger.warning(f"Connection to {self.ip} failed (attempt {attempt}/{self.max_retries}): {exc}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        raise ConnectionError(
            f"WinRM connection failed to {self.ip}:{self.port} "
            f"after {self.max_retries} attempts: {last_exception}"
        )

    def disconnect(self) -> None:
        """Clear the WinRM session (stateless HTTP)."""
        self._session = None
        logger.info(f"Disconnected from Windows Server {self.ip}")

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
        if not self._session:
            return False
        try:
            result = self._session.run_ps("$env:COMPUTERNAME")
            return result.status_code == 0
        except Exception:
            return False

    # ---------------------------------------------------------------- #
    #  PowerShell execution                                             #
    # ---------------------------------------------------------------- #

    _EXECUTE_MAX_ATTEMPTS = 2

    def _execute(self, ps_script: str) -> str:
        """
        Execute a single PowerShell script and return output.

        Returns stdout text, or raises on persistent errors.
        """
        if not self._session:
            raise RuntimeError("Not connected to Windows Server")

        for attempt in range(1, self._EXECUTE_MAX_ATTEMPTS + 1):
            try:
                result = self._session.run_ps(ps_script)
                stdout = result.std_out.decode("utf-8", errors="replace").strip()
                stderr = result.std_err.decode("utf-8", errors="replace").strip()

                if result.status_code != 0 and not stdout:
                    if stderr:
                        raise RuntimeError(f"PowerShell error: {stderr[:300]}")
                    return "(ok)"

                return stdout if stdout else "(ok)"

            except RuntimeError:
                raise

            except Exception as exc:
                exc_msg = str(exc).lower()
                is_transient = any(kw in exc_msg for kw in ("timeout", "connection", "reset", "winrm"))

                if is_transient and attempt < self._EXECUTE_MAX_ATTEMPTS:
                    logger.warning(f"Statement retryable error (attempt {attempt}): {exc}")
                    try:
                        self.disconnect()
                        self.connect()
                    except Exception as reconn_exc:
                        logger.error(f"Reconnect failed: {reconn_exc}")
                        raise exc from reconn_exc
                    continue

                logger.debug(f"Statement failed [{ps_script[:80]}]: {exc}")
                raise

    # ---------------------------------------------------------------- #
    #  Hardening execution                                              #
    # ---------------------------------------------------------------- #

    def execute_hardening(
        self,
        check_id: str,
        parameters: Dict[str, str] = None,
    ) -> WindowsHardeningExecutionResult:
        """
        Execute remediation PowerShell for a single CIS check.

        Args:
            check_id:   Windows CIS check ID (e.g. "WIN-L1-048")
            parameters: {PARAM} placeholder values for template substitution

        Returns:
            WindowsHardeningExecutionResult with execution details
        """
        result = WindowsHardeningExecutionResult(check_id)

        # Merge template defaults under the caller's values and drop empty
        # strings: the UI may submit optional params as "" and a missing value
        # would leave the {PLACEHOLDER} unsubstituted, sending broken
        # PowerShell (e.g. "net accounts /maxpwage:{MAX_PASSWORD_AGE}").
        from .parameter_metadata import get_windows_check_defaults
        merged = dict(get_windows_check_defaults(check_id))
        for k, v in (parameters or {}).items():
            if v is not None and str(v).strip() != "":
                merged[k] = v
        parameters = merged

        template = get_windows_hardening_template(check_id)
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

        if not self._session:
            result.error_message = "Not connected to Windows Server"
            return result

        param_error = _validate_windows_parameters(parameters)
        if param_error:
            result.error_message = param_error
            logger.warning(f"[{check_id}] {param_error}")
            return result

        logger.info(f"Executing hardening for {check_id}: {template.description}")

        try:
            statements = get_windows_template_statements(check_id, parameters)
            verify_stmts = get_windows_verify_statements(check_id, parameters)

            # A leftover {PLACEHOLDER} means a required parameter was not
            # supplied — refuse to run rather than send broken PowerShell.
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

                # Fail closed: "FAIL" wins over "PASS", and a verification
                # that produced neither (errored or returned nothing) is not
                # a success — the DB row must never be flipped to PASS on an
                # unconfirmed fix.
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
    ) -> List[WindowsHardeningExecutionResult]:
        """Execute hardening for multiple checks over the same WinRM session."""
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

class WindowsHardeningBatchExecutor:
    """
    High-level executor that manages the full WinRM connection lifecycle.

    Methods return JSON-serialisable dicts suitable for the API response.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 5986,
        max_retries: int = 3,
        transport: str = "ntlm",
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.max_retries = max_retries
        self.transport = transport

    def _make_executor(self) -> WindowsWinRMExecutor:
        return WindowsWinRMExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            port=self.port,
            max_retries=self.max_retries,
            transport=self.transport,
        )

    def execute_auto_harden(
        self,
        check_ids: List[str],
        default_overrides: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """Execute automatic hardening for all auto-fixable checks."""
        from .parameter_metadata import is_windows_check_auto_fixable, get_windows_check_defaults

        auto_fixable = [cid for cid in check_ids if is_windows_check_auto_fixable(cid)]
        skipped = [cid for cid in check_ids if cid not in auto_fixable]

        results = []
        successful = 0
        failed = 0

        with self._make_executor() as executor:
            for check_id in auto_fixable:
                params = get_windows_check_defaults(check_id)
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
        """Execute hardening for selected checks with user-provided parameters."""
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
