"""
Apache Hardening SSH Executor

Executes hardening commands on remote servers via SSH.
Uses the paramiko exec_command HardeningSSHRunner since Apache runs on Linux.
"""

from typing import Dict, List, Any, Optional
import logging
import time

from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
from .command_templates import (
    get_apache_hardening_template,
    get_apache_template_commands_for_distro,
    get_apache_verify_commands_for_distro,
    get_apache_service_name,
    get_distro_family
)

logger = logging.getLogger(__name__)


class ApacheHardeningExecutionResult:
    """Result object for a single hardening operation."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.check_title: str = ""
        self.success: bool = False
        self.commands_executed: List[str] = []
        self.command_outputs: Dict[str, str] = {}
        self.verification_result: Optional[str] = None
        self.error_message: Optional[str] = None
        self.requires_service_restart: bool = False
        self.service_restarted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            "check_id": self.check_id,
            "check_title": self.check_title,
            "success": self.success,
            "commands_executed": self.commands_executed,
            "command_outputs": self.command_outputs,
            "verification_result": self.verification_result,
            "error_message": self.error_message,
            "requires_service_restart": self.requires_service_restart,
            "service_restarted": self.service_restarted
        }


class ApacheSSHExecutor:
    """
    Executes Apache hardening commands via SSH with sudo support.

    Uses HardeningSSHRunner (paramiko exec_command) for connection management.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        sudo_password: Optional[str] = None,
        port: int = 22,
        distro_id: Optional[str] = None
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.port = port
        self.distro_id = distro_id
        self.ssh_client: Optional[HardeningSSHRunner] = None
        self._connected = False

    def connect(self) -> None:
        """Establish SSH connection and auto-detect distro if needed."""
        if self._connected:
            return

        self.ssh_client = HardeningSSHRunner(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port
        )
        self.ssh_client.connect()

        # Auto-detect distro if not provided. Under the fast exec runner this is a
        # single lightweight `cat /etc/os-release` (no shell-prompt round-trip).
        if not self.distro_id:
            distro_info = self.ssh_client.detect_distro()
            self.distro_id = distro_info.get("id", "ubuntu")
            logger.info(f"Auto-detected distro: {self.distro_id}")

        self._connected = True

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.ssh_client:
            self.ssh_client.disconnect()
        self._connected = False

    def execute_command(self, command: str, use_sudo: bool = True) -> str:
        """
        Execute a single command via SSH.

        Args:
            command: Shell command to execute
            use_sudo: Whether to run with sudo (default True for hardening)

        Returns:
            Command output as string
        """
        if not self._connected:
            raise RuntimeError("Not connected to SSH")

        return self.ssh_client.send_command(command, use_sudo=use_sudo)

    def restart_apache_service(self) -> bool:
        """
        Restart Apache service based on detected distro.

        Returns:
            True if restart succeeded
        """
        service = get_apache_service_name(self.distro_id or "ubuntu")
        try:
            self.execute_command(f"systemctl restart {service}", use_sudo=True)
            logger.info(f"Restarted Apache service: {service}")
            return True
        except Exception as e:
            logger.error(f"Failed to restart {service}: {e}")
            return False

    def execute_hardening(
        self,
        check_id: str,
        parameters: Optional[Dict[str, str]] = None
    ) -> ApacheHardeningExecutionResult:
        """
        Execute hardening for a single CIS check.

        Steps:
        1. Get template for check_id
        2. Substitute parameters into commands
        3. Execute commands with sudo
        4. Restart Apache if needed
        5. Run verification commands
        6. Return result

        Args:
            check_id: CIS check ID to fix
            parameters: Optional parameter values for command substitution

        Returns:
            ApacheHardeningExecutionResult with success/failure details
        """
        result = ApacheHardeningExecutionResult(check_id)
        parameters = parameters or {}

        try:
            # Get template
            template = get_apache_hardening_template(check_id)
            if not template:
                result.error_message = f"No hardening template found for {check_id}"
                logger.warning(result.error_message)
                return result
            result.check_title = template.description

            # Get distro-specific commands with parameters substituted
            commands = get_apache_template_commands_for_distro(
                check_id,
                self.distro_id or "ubuntu",
                parameters
            )

            if not commands:
                result.error_message = f"No commands generated for {check_id}"
                return result

            # Execute each command
            for cmd in commands:
                result.commands_executed.append(cmd)
                try:
                    output = self.execute_command(cmd, use_sudo=True)
                    result.command_outputs[cmd] = output or "(no output)"
                    logger.info(f"Executed: {cmd[:80]}... on {self.ip}")
                except Exception as e:
                    result.error_message = f"Command failed: {str(e)}"
                    result.command_outputs[cmd] = f"ERROR: {str(e)}"
                    logger.error(f"Command failed on {self.ip}: {cmd[:80]}... - {e}")
                    return result

            # Restart Apache service if template requires it
            result.requires_service_restart = template.requires_service_restart
            if template.requires_service_restart:
                result.service_restarted = self.restart_apache_service()

            # Run verification commands
            verify_commands = get_apache_verify_commands_for_distro(
                check_id,
                self.distro_id or "ubuntu",
                parameters
            )

            if verify_commands:
                verification_outputs = []
                for vcmd in verify_commands:
                    try:
                        voutput = self.execute_command(vcmd, use_sudo=True)
                        verification_outputs.append(voutput)
                    except Exception as e:
                        verification_outputs.append(f"VERIFY_ERROR: {str(e)}")

                result.verification_result = "\n".join(verification_outputs)

                # Check for PASS/FAIL keywords
                combined = result.verification_result.upper()
                if "PASS" in combined and "FAIL" not in combined:
                    result.success = True
                elif "FAIL" in combined:
                    result.success = False
                    result.error_message = "Verification failed"
                else:
                    # No explicit PASS marker (e.g. a VERIFY_ERROR from a failed
                    # verify command). Cannot confirm the fix, so fail closed — do
                    # NOT report success (which would flip the audit row to PASS
                    # without the host being confirmed remediated). Matches the
                    # Linux executor's behaviour.
                    result.success = False
                    result.error_message = (
                        "Verification did not return an explicit PASS marker"
                    )
            else:
                # No verification commands - assume success if commands ran
                result.success = True

            logger.info(f"Hardening {check_id} {'succeeded' if result.success else 'failed'} on {self.ip}")

        except Exception as e:
            result.error_message = str(e)
            result.success = False
            logger.error(f"Hardening {check_id} failed on {self.ip}: {e}")

        return result

    def execute_batch(
        self,
        checks: List[Dict[str, Any]]
    ) -> List[ApacheHardeningExecutionResult]:
        """
        Execute hardening for multiple checks.

        Args:
            checks: List of dicts with check_id and optional parameters

        Returns:
            List of ApacheHardeningExecutionResult objects
        """
        results = []

        for check in checks:
            check_id = check.get("check_id")
            parameters = check.get("parameters", {})

            if not check_id:
                continue

            result = self.execute_hardening(check_id, parameters)
            results.append(result)

            # Small delay between checks
            time.sleep(0.3)

        return results

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class ApacheHardeningBatchExecutor:
    """
    High-level executor for batch hardening operations.

    Manages connection lifecycle and summarizes results.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        sudo_password: Optional[str] = None,
        port: int = 22,
        distro_id: Optional[str] = None
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.port = port
        self.distro_id = distro_id

    def execute_checks(
        self,
        checks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Execute batch hardening and return summarized results.

        Args:
            checks: List of dicts with check_id and optional parameters

        Returns:
            Summary dict with total, successful, failed, and detailed results
        """
        with ApacheSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port,
            distro_id=self.distro_id
        ) as executor:
            results = executor.execute_batch(checks)

        # Summarize results
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        service_restarts = sum(1 for r in results if r.service_restarted)

        return {
            "total": len(results),
            "successful": successful,
            "failed": failed,
            "service_restarts": service_restarts,
            "results": [r.to_dict() for r in results]
        }

    def execute_auto_harden(
        self,
        check_ids: List[str],
        default_parameters: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening for checks with defaults only.

        Args:
            check_ids: List of check IDs to fix
            default_parameters: Optional override parameters

        Returns:
            Summary of execution with results
        """
        from .parameter_metadata import (
            get_apache_check_defaults,
            is_apache_check_auto_fixable
        )

        # Filter to only auto-fixable checks
        auto_fixable = [cid for cid in check_ids if is_apache_check_auto_fixable(cid)]
        skipped = [cid for cid in check_ids if cid not in auto_fixable]

        results = []
        successful = 0
        failed = 0

        with ApacheSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port,
            distro_id=self.distro_id
        ) as executor:
            detected_distro = executor.distro_id

            for check_id in auto_fixable:
                # Get defaults for this check
                params = get_apache_check_defaults(check_id)
                if default_parameters:
                    params.update(default_parameters)

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
            "distro_id": detected_distro,
            "results": results
        }

    def execute_selected(
        self,
        checks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of dicts with check_id and parameters

        Returns:
            Summary of execution with results
        """
        results = []
        successful = 0
        failed = 0

        with ApacheSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port,
            distro_id=self.distro_id
        ) as executor:
            detected_distro = executor.distro_id

            for check in checks:
                check_id = check.get("check_id")
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
            "distro_id": detected_distro,
            "results": results
        }

    def execute_single(
        self,
        check_id: str,
        parameters: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Execute hardening for a single check.

        Args:
            check_id: CIS check ID
            parameters: Parameter values

        Returns:
            Execution result dict
        """
        with ApacheSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port,
            distro_id=self.distro_id
        ) as executor:
            result = executor.execute_hardening(check_id, parameters)
            result_dict = result.to_dict()
            result_dict["distro_id"] = executor.distro_id
            return result_dict
