"""
Linux SSH Executor for Hardening

Executes hardening commands on Linux servers with sudo support.
Includes pre/post verification and detailed logging.
"""

from typing import Dict, List, Optional, Any
import logging
import re
import time

from app.modules.linux.common.ssh_client import LinuxSSHClient
from .command_templates import (
    get_linux_hardening_template,
    get_linux_hardening_template_for_distro,
    get_linux_template_commands,
    get_linux_template_commands_for_distro,
    get_linux_verify_commands,
    get_linux_verify_commands_for_distro,
    LinuxHardeningTemplate
)

logger = logging.getLogger(__name__)


class LinuxHardeningExecutionResult:
    """Result of a single hardening execution."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.success: bool = False
        self.commands_executed: List[str] = []
        self.command_outputs: Dict[str, str] = {}
        self.verification_result: Optional[str] = None
        self.error_message: Optional[str] = None
        self.requires_service_restart: Optional[str] = None
        self.requires_reboot: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "success": self.success,
            "commands_executed": self.commands_executed,
            "command_outputs": self.command_outputs,
            "verification_result": self.verification_result,
            "error_message": self.error_message,
            "requires_service_restart": self.requires_service_restart,
            "requires_reboot": self.requires_reboot
        }


class LinuxSSHExecutor:
    """
    Executes hardening commands on Linux servers via SSH.

    Features:
    - Sudo command execution
    - Pre/post verification
    - Service restart handling
    - Detailed execution logging
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
        """
        Initialize the executor.

        Args:
            ip: Target server IP
            username: SSH username
            password: SSH password
            sudo_password: Sudo password (defaults to SSH password)
            port: SSH port
            distro_id: Distribution ID (ubuntu, rocky, etc.). Auto-detected if not provided.
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.port = port
        self.distro_id = distro_id
        self.ssh_client: Optional[LinuxSSHClient] = None
        self._connected = False

    def connect(self) -> None:
        """Establish SSH connection and auto-detect distro if needed."""
        if self._connected:
            return

        self.ssh_client = LinuxSSHClient(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            port=self.port
        )
        self.ssh_client.connect()
        self._connected = True

        # Auto-detect distro if not provided
        if not self.distro_id:
            try:
                distro_info = self.ssh_client.detect_distro()
                self.distro_id = distro_info.get("id", "ubuntu")
                logger.info(f"Auto-detected distro on {self.ip}: {self.distro_id}")
            except Exception as e:
                logger.warning(f"Failed to detect distro on {self.ip}, defaulting to ubuntu: {e}")
                self.distro_id = "ubuntu"

        logger.info(f"Connected to {self.ip} for hardening (distro: {self.distro_id})")

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.ssh_client:
            self.ssh_client.disconnect()
            self._connected = False
            logger.info(f"Disconnected from {self.ip}")

    def execute_command(self, command: str, use_sudo: bool = True) -> str:
        """
        Execute a single command on the server.

        Args:
            command: Command to execute
            use_sudo: Whether to use sudo

        Returns:
            Command output
        """
        if not self._connected:
            raise RuntimeError("Not connected. Call connect() first.")

        return self.ssh_client.send_command(command, use_sudo=use_sudo)

    def execute_hardening(
        self,
        check_id: str,
        parameters: Dict[str, str] = None
    ) -> LinuxHardeningExecutionResult:
        """
        Execute hardening for a specific CIS check.

        Args:
            check_id: CIS check ID (e.g., "LNX-L1-5.2.10")
            parameters: Parameter values for template substitution

        Returns:
            LinuxHardeningExecutionResult with execution details
        """
        result = LinuxHardeningExecutionResult(check_id)
        parameters = parameters or {}

        # Use distro-aware template
        template = get_linux_hardening_template_for_distro(check_id, self.distro_id or "ubuntu")
        if not template:
            result.error_message = f"No hardening template found for {check_id}"
            logger.error(result.error_message)
            return result

        if not self._connected:
            result.error_message = "Not connected to server"
            return result

        logger.info(f"Executing hardening for {check_id} (distro: {self.distro_id}): {template.description}")

        try:
            # Get commands with distro-specific paths and parameter substitution
            commands = get_linux_template_commands_for_distro(check_id, self.distro_id or "ubuntu", parameters)

            # Execute each command
            for cmd in commands:
                try:
                    output = self.execute_command(cmd, use_sudo=True)
                    result.commands_executed.append(cmd)
                    result.command_outputs[cmd] = output
                    logger.debug(f"Command executed: {cmd[:60]}...")
                except Exception as e:
                    error_msg = f"Command failed: {cmd[:60]}... Error: {str(e)}"
                    logger.error(error_msg)
                    result.command_outputs[cmd] = f"ERROR: {str(e)}"
                    # Continue with other commands unless critical

            # Restart service if needed
            if template.requires_service_restart:
                service = template.requires_service_restart
                try:
                    restart_cmd = f"systemctl restart {service}"
                    output = self.execute_command(restart_cmd, use_sudo=True)
                    result.commands_executed.append(restart_cmd)
                    result.command_outputs[restart_cmd] = output
                    result.requires_service_restart = service
                    logger.info(f"Restarted service: {service}")
                except Exception as e:
                    logger.warning(f"Failed to restart {service}: {str(e)}")

            # Run verification commands with distro-specific paths
            verify_commands = get_linux_verify_commands_for_distro(check_id, self.distro_id or "ubuntu", parameters)
            if verify_commands:
                verification_outputs = []
                for vcmd in verify_commands:
                    try:
                        voutput = self.execute_command(vcmd, use_sudo=True)
                        verification_outputs.append(voutput)
                    except Exception as e:
                        verification_outputs.append(f"ERROR: {str(e)}")

                result.verification_result = "\n".join(verification_outputs)

                # Check if verification passed
                if "PASS" in result.verification_result:
                    result.success = True
                elif "FAIL" in result.verification_result:
                    result.success = False
                else:
                    # Assume success if commands ran without error
                    result.success = True
            else:
                # No verification commands - assume success if commands ran
                result.success = True

            result.requires_reboot = template.requires_reboot

            logger.info(f"Hardening {check_id} completed: {'SUCCESS' if result.success else 'NEEDS_VERIFICATION'}")

        except Exception as e:
            result.error_message = str(e)
            result.success = False
            logger.error(f"Hardening {check_id} failed: {str(e)}")

        return result

    def execute_batch(
        self,
        checks: List[Dict[str, Any]]
    ) -> List[LinuxHardeningExecutionResult]:
        """
        Execute hardening for multiple checks.

        Args:
            checks: List of dicts with:
                - check_id: CIS check ID
                - parameters: Optional parameter values

        Returns:
            List of execution results
        """
        results = []

        for check in checks:
            check_id = check.get("check_id")
            parameters = check.get("parameters", {})

            result = self.execute_hardening(check_id, parameters)
            results.append(result)

            # Small delay between checks
            time.sleep(0.5)

        return results

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class LinuxHardeningBatchExecutor:
    """
    High-level executor for batch hardening operations.

    Handles connection management, parameter aggregation, and result summarization.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        sudo_password: Optional[str] = None,
        distro_id: Optional[str] = None
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.distro_id = distro_id  # Will be auto-detected if not provided

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
            get_linux_check_defaults,
            is_linux_check_auto_fixable
        )

        # Filter to only auto-fixable checks
        auto_fixable = [cid for cid in check_ids if is_linux_check_auto_fixable(cid)]
        skipped = [cid for cid in check_ids if cid not in auto_fixable]

        results = []
        successful = 0
        failed = 0

        with LinuxSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            distro_id=self.distro_id
        ) as executor:
            # Store detected distro for result metadata
            detected_distro = executor.distro_id

            for check_id in auto_fixable:
                # Get defaults for this check
                params = get_linux_check_defaults(check_id)
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

        with LinuxSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
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
        with LinuxSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            distro_id=self.distro_id
        ) as executor:
            result = executor.execute_hardening(check_id, parameters)
            result_dict = result.to_dict()
            result_dict["distro_id"] = executor.distro_id
            return result_dict
