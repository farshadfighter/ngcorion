"""
MongoDB SSH Executor for Hardening

Executes CIS remediation commands on MongoDB host servers via SSH.
Uses the paramiko exec_command HardeningSSHRunner (the audit path keeps using
netmiko); commands are sudo-wrapped at the call site.
"""

import logging
import shlex
import time
from typing import Any, Dict, List, Optional

from app.core.ssh_exceptions import SSHAuthenticationError, SSHConnectionError
from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner

from .command_templates import (
    get_mongodb_hardening_template,
    get_mongodb_template_commands,
    get_mongodb_verify_commands,
)

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 30

# MongoDB config files snapshotted before hardening; missing paths are skipped.
MONGODB_BACKUP_PATHS = [
    "/etc/mongod.conf",
    "/etc/mongodb.conf",
]


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
        sudo_password: Optional[str] = None,
        ssh_port: int = 22,
        timeout: int = 30,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
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
        runner = HardeningSSHRunner(
            ip=self.ip,
            username=self.username,
            password=self.password,
            port=self.ssh_port,
            timeout=self.timeout,
        )
        try:
            runner.connect()
        except SSHAuthenticationError as exc:
            raise PermissionError(f"SSH authentication failed for {self.ip}: {exc}")
        except SSHConnectionError as exc:
            raise ConnectionError(f"SSH connection failed to {self.ip}: {exc}")
        except Exception as exc:
            raise ConnectionError(f"SSH connection failed to {self.ip}: {exc}")
        self._conn = runner
        logger.info(f"SSH connection established to {self.ip}")

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception as e:
                logger.warning(f"[MongoDB Hardening] SSH disconnect from {self.ip} failed: {e}")
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
                    f"echo {shlex.quote(self.sudo_password)}"
                    f" | sudo -S sh -c {shlex.quote(cmd)} 2>/dev/null"
                )
            # The command string is already fully formed (sudo wrapping included),
            # so use the runner's raw exec primitive rather than its sudo helper.
            output = self._conn.run(cmd, timeout=COMMAND_TIMEOUT)
            return (output or "").strip()
        except Exception as exc:
            logger.debug(f"Command failed [{cmd[:80]}]: {exc}")
            return ""

    def backup_config(self) -> str:
        """
        Snapshot the MongoDB config file(s) into one text bundle for rollback.
        Reads under sudo; raises on an empty snapshot.
        """
        from app.modules.shared.hardening_backup import bundle_header, build_file_bundle_command

        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        logger.info(f"Backing up MongoDB config from {self.ip}")
        body = self._run(build_file_bundle_command(MONGODB_BACKUP_PATHS), use_sudo=True)
        if not body or not body.strip():
            raise RuntimeError("MongoDB config backup returned no content")
        backup = bundle_header("mongodb", self.ip) + body
        logger.info(f"MongoDB config backup completed: {len(backup)} bytes from {self.ip}")
        return backup

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

        # Merge template defaults under the caller's values and drop empty
        # strings: the UI may submit optional params as "" and a missing value
        # would leave the {PLACEHOLDER} unsubstituted, writing broken YAML
        # (e.g. "port: {MONGO_PORT}") into /etc/mongod.conf.
        from .parameter_metadata import get_mongodb_check_defaults
        merged = dict(get_mongodb_check_defaults(check_id))
        for k, v in (parameters or {}).items():
            if v is not None and str(v).strip() != "":
                merged[k] = v
        parameters = merged

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

                if "FAIL" in result.verification_result:
                    result.success = False
                elif "PASS" in result.verification_result:
                    result.success = True
                else:
                    # No PASS/FAIL signal (e.g. an ERROR from a failed verify
                    # command). Cannot confirm the fix, so fail closed — do NOT
                    # report success (which would flip the audit row to PASS without
                    # the host being confirmed remediated). Matches the Linux executor.
                    result.success = False
                    result.error_message = (
                        "Verification did not return an explicit PASS marker"
                    )
            else:
                result.success = True

            # A config change that leaves mongod dead after its restart is not
            # a success, even when the config-grep verification passed — the
            # database is now down. Fail closed so the audit row keeps FAIL.
            if result.success and template.requires_service_restart:
                state = self._run(
                    "systemctl is-active mongod 2>/dev/null"
                    " || systemctl is-active mongodb 2>/dev/null"
                    " || echo 'inactive'",
                    use_sudo=True,
                )
                lines = [l.strip() for l in (state or "").splitlines() if l.strip()]
                if "active" not in lines:
                    result.success = False
                    result.error_message = (
                        "mongod is not running after the change — the "
                        "configuration may be invalid; fix not confirmed"
                    )

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
        sudo_password: Optional[str] = None,
        ssh_port: int = 22,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.ssh_port = ssh_port

    def _make_executor(self) -> MongoDBSSHExecutor:
        return MongoDBSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
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
        create_backup: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of {"check_id": str, "parameters": dict} dicts
            create_backup: Snapshot mongod.conf before applying changes. Returned
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
                    logger.error(f"MongoDB pre-hardening backup failed on {self.ip}: {exc}")

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
