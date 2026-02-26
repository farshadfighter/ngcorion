"""
Windows Server Audit Client (WinRM)

Connects to a Windows Server instance via WinRM over HTTPS and collects
configuration data for CIS Windows Server Benchmark compliance evaluation.

Collection strategy:
1. Connect via pywinrm (HTTPS/NTLM by default)
2. Execute PowerShell commands to collect security policy, registry, services
3. Combine all data into a structured dump with ===SECTION:NAME=== markers
4. Rules engine evaluates the dump using JSON/regex parsing

This mirrors the pattern of mssql/audit/mssql_client.py but uses WinRM
instead of pymssql for connectivity.
"""

import re
import logging
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# Patterns to redact from audit output before storing
_REDACT_PATTERNS = [
    (re.compile(r"(password\s*[=:]\s*)'?[^\s';\n]+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(credential\s*[=:]\s*)'?[^\s';\n]+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(secret\s*[=:]\s*)'?[^\s';\n]+", re.I), r"\1<REDACTED>"),
    (re.compile(r"(-Password\s+)'?[^\s';\n]+", re.I), r"\1<REDACTED>"),
]


def redact_sensitive_windows_data(text: str) -> str:
    """Remove sensitive data from audit dump before database storage."""
    if not text:
        return text
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class WindowsWinRMClient:
    """
    WinRM-based audit client for Windows Server.

    Connects to the Windows Server instance via HTTPS WinRM and runs
    PowerShell commands to collect CIS Benchmark compliance data.

    Args:
        ip:          Target Windows Server IP or hostname
        username:    Windows admin account (domain\\user or local user)
        password:    Windows password
        port:        WinRM HTTPS port (default 5986)
        timeout:     Connection/operation timeout in seconds
        max_retries: Max connection attempts
        transport:   WinRM transport: ntlm, kerberos, credssp, basic
        verify_ssl:  Validate server SSL certificate (False for self-signed)
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2
    COMMAND_TIMEOUT = 60

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
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.max_retries = max_retries
        self.transport = transport
        self.verify_ssl = verify_ssl
        self._session = None

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
        """Establish WinRM session with retry logic."""
        try:
            import winrm
        except ImportError:
            raise RuntimeError(
                "pywinrm is not installed. Run: pip install pywinrm"
            )

        last_exception = None
        cert_validation = "ignore" if not self.verify_ssl else "validate"

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    f"Connecting to Windows Server at {self.ip}:{self.port} "
                    f"via WinRM/{self.transport} "
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

                # Validate connection by running a test command
                result = self._session.run_ps("$env:COMPUTERNAME")
                if result.status_code != 0:
                    stderr = result.std_err.decode("utf-8", errors="replace") if result.std_err else ""
                    if any(kw in stderr.lower() for kw in ("unauthorized", "401", "403", "access")):
                        raise PermissionError(
                            f"WinRM authentication failed for {self.ip}: {stderr[:200]}"
                        )
                    raise ConnectionError(
                        f"WinRM test command failed on {self.ip}: {stderr[:200]}"
                    )

                hostname = result.std_out.decode("utf-8", errors="replace").strip()
                logger.info(
                    f"Connected to Windows Server {hostname} at {self.ip}"
                )
                return

            except PermissionError:
                raise  # Do not retry auth failures

            except Exception as exc:
                exc_msg = str(exc).lower()
                # Check for auth errors that should not be retried
                if any(kw in exc_msg for kw in (
                    "unauthorized", "401", "403", "access denied",
                    "logon failure", "authentication",
                )):
                    raise PermissionError(
                        f"WinRM authentication failed for {self.ip}: {exc}"
                    )

                last_exception = exc
                logger.warning(
                    f"Connection to {self.ip} failed "
                    f"(attempt {attempt}/{self.max_retries}): {exc}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        raise ConnectionError(
            f"WinRM connection failed to {self.ip}:{self.port} "
            f"after {self.max_retries} attempts: {last_exception}"
        )

    def _disconnect(self):
        """Clear the WinRM session reference (stateless HTTP, no real teardown)."""
        self._session = None

    # ------------------------------------------------------------------ #
    #  Health check                                                        #
    # ------------------------------------------------------------------ #

    def is_connected(self) -> bool:
        """Check if the WinRM session is functional."""
        if not self._session:
            return False
        try:
            result = self._session.run_ps("$env:COMPUTERNAME")
            return result.status_code == 0
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  Command execution helpers                                           #
    # ------------------------------------------------------------------ #

    _RUN_MAX_ATTEMPTS = 2

    def _run_ps(self, script: str) -> str:
        """
        Execute a PowerShell script via WinRM and return stdout.

        Retries once on transient connection errors.
        """
        if not self._session:
            raise RuntimeError("Not connected to Windows Server")

        for attempt in range(1, self._RUN_MAX_ATTEMPTS + 1):
            try:
                result = self._session.run_ps(script)
                stdout = result.std_out.decode("utf-8", errors="replace").strip()
                stderr = result.std_err.decode("utf-8", errors="replace").strip()

                if result.status_code != 0 and not stdout:
                    return f"PS_ERROR: {stderr[:300]}" if stderr else "(no output)"

                return stdout if stdout else "(no output)"

            except Exception as exc:
                exc_msg = str(exc).lower()
                is_transient = any(kw in exc_msg for kw in (
                    "timeout", "connection", "reset", "refused", "winrm",
                ))

                if is_transient and attempt < self._RUN_MAX_ATTEMPTS:
                    logger.warning(
                        f"PowerShell transient error (attempt {attempt}): {exc}"
                    )
                    try:
                        self._disconnect()
                        self._connect()
                    except Exception as reconn_exc:
                        logger.error(f"Reconnect failed: {reconn_exc}")
                        return f"PS_ERROR: {str(exc)[:200]}"
                    continue

                logger.debug(f"PowerShell failed [{script[:80]}...]: {exc}")
                return f"PS_ERROR: {str(exc)[:200]}"

        return "PS_ERROR: max retry attempts reached"

    def _run_cmd(self, command: str) -> str:
        """Execute a CMD command via WinRM and return stdout."""
        if not self._session:
            raise RuntimeError("Not connected to Windows Server")
        try:
            result = self._session.run_cmd(command)
            stdout = result.std_out.decode("utf-8", errors="replace").strip()
            return stdout if stdout else "(no output)"
        except Exception as exc:
            logger.debug(f"CMD failed [{command[:80]}]: {exc}")
            return f"CMD_ERROR: {str(exc)[:200]}"

    # ------------------------------------------------------------------ #
    #  Main data collection                                                #
    # ------------------------------------------------------------------ #

    def collect_audit_data(self) -> str:
        """
        Collect all Windows Server audit data via PowerShell/WinRM.

        Returns:
            A single structured string with section markers, suitable for
            rule evaluation. Example:

                ===SECTION:OS_VERSION===
                {"Caption":"Windows Server 2022 ...","BuildNumber":"20348"}
                ===SECTION:SECURITY_POLICY===
                [Unicode]
                ...
        """
        from .audit_commands import get_windows_audit_commands

        commands = get_windows_audit_commands()
        sections: Dict[str, str] = {}

        for section_name, script in commands.items():
            try:
                logger.debug(f"Collecting section: {section_name}")
                output = self._run_ps(script)
                sections[section_name] = output
            except Exception as exc:
                logger.warning(
                    f"Failed to collect {section_name}: {exc}"
                )
                sections[section_name] = f"COLLECTION_ERROR: {str(exc)[:200]}"

        # Assemble structured dump
        parts = []
        for section_key, content in sections.items():
            parts.append(f"===SECTION:{section_key}===")
            parts.append(content or "(empty)")

        return "\n".join(parts)
