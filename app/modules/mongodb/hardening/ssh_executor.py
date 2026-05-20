"""
MongoDB SSH Executor for Hardening

Executes CIS remediation commands on MongoDB host servers via SSH.
Reuses the same netmiko ConnectHandler(device_type="linux") approach as the
MongoDB audit client, with sudo-wrapped command execution.
"""

import logging
import shlex
import time
from typing import Any, Dict, List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from .command_templates import (
    get_mongodb_hardening_template,
    get_mongodb_template_commands,
    get_mongodb_verify_commands,
)

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 30


class MongoDBHardeningExecutionResult:
    """Result of a single CIS check hardening execution."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.check_title: str = ""
        self.success: bool = False
        self.commands_executed: List[str] = []
        self.command_outputs: Dict[str, str] = {}
        self.verification_result: Optional[str] = None
        self.error_message: Optional[str] = None
        self.requires_service_restart: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_title": self.check_title,
            "success": self.success,
            "commands_executed": self.commands_executed,
            "command_outputs": self.command_outputs,
            "verification_result": self.verification_result,
            "error_message": self.error_message,
            "requires_service_restart": self.requires_service_restart,
        }


class MongoDBSSHExecutor:
    """
    Single-connection SSH executor for MongoDB hardening.

    Use as a context manager to ensure the connection is properly closed:

        with MongoDBSSHExecutor(ip, username, password) as executor:
            result = executor.execute_hardening("MONGO-L1-006")
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        ssh_port: int = 22,
        timeout: int = 30,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh_port = ssh_port
        self.timeout = timeout
        self._conn = None

    # ---------------------------------------------------------------- #
    #  Connection management                                            #
    # ---------------------------------------------------------------- #

    def connect(self) -> None:
        """Establish SSH connection to the MongoDB host."""
        if self._conn:
            return
        logger.info(f"Connecting to {self.ip}:{self.ssh_port} for hardening")
        try:
            self._conn = ConnectHandler(
                device_type="linux",
                ip=self.ip,
                username=self.username,
                password=self.password,
                port=self.ssh_port,
                timeout=self.timeout,
                conn_timeout=self.timeout,
            )
            logger.info(f"SSH connection established to {self.ip}")
        except NetmikoTimeoutException as exc:
            raise ConnectionError(f"SSH connection timed out to {self.ip}: {exc}")
        except NetmikoAuthenticationException as exc:
            raise PermissionError(f"SSH authentication failed for {self.ip}: {exc}")
        except Exception as exc:
            raise ConnectionError(f"SSH connection failed to {self.ip}: {exc}")

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None
            logger.info(f"Disconnected from {self.ip}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()
        return False

    # ---------------------------------------------------------------- #
    #  Command execution                                                #
    # ---------------------------------------------------------------- #

    def _run(self, cmd: str, use_sudo: bool = True) -> str:
        """
        Execute a shell command via SSH and return trimmed output.

        When use_sudo=True the command is wrapped with:
            echo PASSWORD | sudo -S sh -c QUOTED_CMD 2>/dev/null
        """
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            if use_sudo:
                cmd = (
                    f"echo {shlex.quote(self.password)}"
                    f" | sudo -S sh -c {shlex.quote(cmd)} 2>/dev/null"
                )
            output = self._conn.send_command(
                cmd,
                read_timeout=COMMAND_TIMEOUT,
                expect_string=r"[\$\#]\s*$",
            )
            return (output or "").strip()
        except Exception as exc:
            logger.debug(f"Command failed [{cmd[:80]}]: {exc}")
            return ""

    # ---------------------------------------------------------------- #
    #  Hardening execution                                              #
    # ---------------------------------------------------------------- #

    def execute_hardening(
        self,
        check_id: str,
        parameters: Dict[str, str] = None,
    ) -> MongoDBHardeningExecutionResult:
        """
        Execute remediation commands for a single CIS check.

        Args:
            check_id:   MongoDB CIS check ID (e.g. "MONGO-L1-006")
            parameters: {PARAM} placeholder values for template substitution

        Returns:
            MongoDBHardeningExecutionResult with execution details
        """
        result = MongoDBHardeningExecutionResult(check_id)
        parameters = parameters or {}

        template = get_mongodb_hardening_template(check_id)
        if not template:
            result.error_message = f"No hardening template found for {check_id}"
            logger.warning(result.error_message)
            return result
        result.check_title = template.description

        if not self._conn:
            result.error_message = "Not connected to server"
            return result

        logger.info(f"Executing hardening for {check_id}: {template.description}")

        try:
            commands = get_mongodb_template_commands(check_id, parameters)

            for cmd in commands:
                try:
                    output = self._run(cmd, use_sudo=True)
                    result.commands_executed.append(cmd)
                    result.command_outputs[cmd] = output
                    logger.debug(f"  [{check_id}] cmd executed: {cmd[:70]}")
                except Exception as exc:
                    error_msg = f"ERROR: {str(exc)}"
                    result.command_outputs[cmd] = error_msg
                    logger.error(f"  [{check_id}] cmd failed: {cmd[:70]} — {exc}")

            result.requires_service_restart = template.requires_service_restart

            # Run verification
            verify_cmds = get_mongodb_verify_commands(check_id, parameters)
            if verify_cmds:
                verification_outputs = []
                for vcmd in verify_cmds:
                    try:
                        voutput = self._run(vcmd, use_sudo=True)
                        verification_outputs.append(voutput)
                    except Exception as exc:
                        verification_outputs.append(f"ERROR: {str(exc)}")

                result.verification_result = "\n".join(verification_outputs)

                if "PASS" in result.verification_result:
                    result.success = True
                elif "FAIL" in result.verification_result:
                    result.success = False
                else:
                    # No PASS/FAIL signal — assume success if commands ran
                    result.success = True
            else:
                result.success = True

            logger.info(
                f"Hardening {check_id}: {'SUCCESS' if result.success else 'FAIL'}"
            )

        except Exception as exc:
            result.error_message = str(exc)
            result.success = False
            logger.error(f"Hardening {check_id} raised exception: {exc}")

        return result

    def execute_batch(
        self,
        checks: List[Dict[str, Any]],
    ) -> List[MongoDBHardeningExecutionResult]:
        """
        Execute hardening for multiple checks over the same SSH connection.

        Args:
            checks: List of {"check_id": str, "parameters": dict} dicts
        """
        results = []
        for check in checks:
            check_id = check.get("check_id", "")
            parameters = check.get("parameters", {})
            result = self.execute_hardening(check_id, parameters)
            results.append(result)
            time.sleep(0.3)  # small pause between checks
        return results


class MongoDBHardeningBatchExecutor:
    """
    High-level executor that manages the full SSH connection lifecycle.

    Methods return JSON-serialisable dicts suitable for the API response.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        ssh_port: int = 22,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh_port = ssh_port

    def _make_executor(self) -> MongoDBSSHExecutor:
        return MongoDBSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            ssh_port=self.ssh_port,
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
        from .parameter_metadata import is_mongodb_check_auto_fixable, get_mongodb_check_defaults

        auto_fixable = [cid for cid in check_ids if is_mongodb_check_auto_fixable(cid)]
        skipped = [cid for cid in check_ids if cid not in auto_fixable]

        results = []
        successful = 0
        failed = 0

        with self._make_executor() as executor:
            for check_id in auto_fixable:
                params = get_mongodb_check_defaults(check_id)
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
