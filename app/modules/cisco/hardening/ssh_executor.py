"""
Cisco Hardening SSH Executor

Executes hardening commands on Cisco devices via SSH.

Responsibilities:
- Backup running configuration
- Execute configuration commands
- Verify fixes by re-running CIS checks
- Handle errors and command failures
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

from app.modules.cisco.audit.ssh_client import CiscoSSHClient
from app.modules.cisco.audit.rules import CISRule
from app.core.ssh_exceptions import SSHConnectionError

logger = logging.getLogger(__name__)


class HardeningExecutionError(Exception):
    """Raised when command execution fails."""
    pass


class HardeningVerificationError(Exception):
    """Raised when post-execution verification fails."""
    pass


class CiscoHardeningExecutor:
    """
    Executes hardening commands on Cisco devices.

    Uses CiscoSSHClient for SSH connectivity and command execution.
    """

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        secret: Optional[str] = None
    ):
        """
        Initialize executor with SSH credentials.

        Args:
            ip: Device IP address
            username: SSH username
            password: SSH password
            secret: Enable secret (optional)
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.ssh_client: Optional[CiscoSSHClient] = None

    def __enter__(self):
        """
        Context manager entry - establish SSH connection.

        Raises:
            SSHConnectionError subclasses: Propagated from CiscoSSHClient.connect()
        """
        self.ssh_client = CiscoSSHClient(
            ip=self.ip,
            username=self.username,
            password=self.password,
            secret=self.secret
        )
        # Connect explicitly - SSH exceptions will propagate
        self.ssh_client.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close SSH connection."""
        if self.ssh_client:
            self.ssh_client.close()
        return False

    def backup_config(self) -> str:
        """
        Backup running configuration.

        Returns:
            Full running config as string

        Raises:
            HardeningExecutionError: If backup fails
        """
        if not self.ssh_client:
            raise HardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Backing up config from {self.ip}")

            # Get running config
            config = self.ssh_client.send_command("show running-config")

            # Add metadata header
            timestamp = datetime.utcnow().isoformat()
            header = f"""!
! Backup taken at: {timestamp}
! By: Hardening Module
! Device: {self.ip}
!
"""
            backup = header + config

            logger.info(f"Config backup completed: {len(backup)} bytes")
            return backup

        except Exception as e:
            logger.error(f"Config backup failed: {str(e)}")
            raise HardeningExecutionError(f"Failed to backup config: {str(e)}")

    def execute_commands(
        self,
        commands: List[str],
        requires_config_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Execute commands on device.

        Args:
            commands: List of commands to execute
            requires_config_mode: Whether commands need config mode

        Returns:
            Dict with:
                - success: bool
                - output: str (all command outputs)
                - errors: List[str]

        Raises:
            HardeningExecutionError: If execution fails
        """
        if not self.ssh_client:
            raise HardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Executing {len(commands)} commands on {self.ip}")

            if requires_config_mode:
                # Strip meta-commands that conflict with Netmiko's send_config_set(),
                # which automatically handles config mode entry/exit.
                # Templates include "configure terminal", "end", "write memory"
                # but Netmiko enters/exits config mode on its own, and
                # save_config() is called separately after execution.
                #
                # Only strip the outer framing commands, NOT intermediate "exit"
                # which is needed for sub-context transitions (e.g. exit from
                # "line console 0" before entering "line vty 0 15").
                enter_commands = {"configure terminal", "config t", "conf t"}
                save_commands = {"write memory", "write mem", "wr",
                                 "copy running-config startup-config"}
                config_commands = []
                for cmd in commands:
                    cmd_lower = cmd.strip().lower()
                    if cmd_lower in enter_commands:
                        continue  # Netmiko handles config mode entry
                    if cmd_lower in save_commands:
                        continue  # save_config() handles this separately
                    config_commands.append(cmd)

                # Strip trailing "end" only (Netmiko handles config mode exit).
                # Keep intermediate "end" if somehow present mid-sequence.
                while config_commands and config_commands[-1].strip().lower() == "end":
                    config_commands.pop()

                if not config_commands:
                    logger.warning("No config commands remaining after stripping meta-commands")
                    return {
                        "success": True,
                        "output": "No configuration commands to execute",
                        "errors": []
                    }

                logger.info(
                    f"Sending {len(config_commands)} config commands "
                    f"(stripped {len(commands) - len(config_commands)} meta-commands)"
                )
                output = self.ssh_client.send_config_commands(config_commands)
            else:
                # Use send_command for non-config commands
                outputs = []
                for cmd in commands:
                    result = self.ssh_client.send_command(cmd)
                    outputs.append(f"# {cmd}\n{result}")
                output = "\n\n".join(outputs)

            # Check for command errors in output
            errors = self._check_for_errors(output)

            if errors:
                logger.warning(f"Command execution completed with errors: {errors}")
                return {
                    "success": False,
                    "output": output,
                    "errors": errors
                }

            logger.info(f"Commands executed successfully on {self.ip}")
            return {
                "success": True,
                "output": output,
                "errors": []
            }

        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            raise HardeningExecutionError(f"Failed to execute commands: {str(e)}")

    def verify_check(self, rule: CISRule) -> Tuple[bool, str]:
        """
        Re-run CIS check to verify fix worked.

        Args:
            rule: CISRule object with check() and evidence() functions

        Returns:
            Tuple of (passed: bool, evidence: str)

        Raises:
            HardeningVerificationError: If verification fails
        """
        if not self.ssh_client:
            raise HardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Verifying check {rule.id} on {self.ip}")

            # Collect fresh configuration
            config = self.ssh_client.send_command("show running-config")

            # Run the check function
            passed = rule.check(config)

            # Get evidence
            evidence = rule.evidence(config)

            logger.info(f"Verification result for {rule.id}: {'PASS' if passed else 'FAIL'}")

            return passed, evidence

        except Exception as e:
            logger.error(f"Verification failed for {rule.id}: {str(e)}")
            raise HardeningVerificationError(f"Failed to verify check: {str(e)}")

    def save_config(self) -> str:
        """
        Save running config to startup config.

        Returns:
            Command output

        Raises:
            HardeningExecutionError: If save fails
        """
        if not self.ssh_client:
            raise HardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Saving config on {self.ip}")
            output = self.ssh_client.send_command("write memory")
            logger.info("Config saved successfully")
            return output

        except Exception as e:
            logger.error(f"Config save failed: {str(e)}")
            raise HardeningExecutionError(f"Failed to save config: {str(e)}")

    def _check_for_errors(self, output: str) -> List[str]:
        """
        Check command output for errors.

        Args:
            output: Command output text

        Returns:
            List of error messages found
        """
        errors = []

        # Common Cisco error patterns
        error_patterns = [
            "Invalid input detected",
            "Incomplete command",
            "Ambiguous command",
            "% Error",
            "% Bad",
            "% Unknown command",
            "% Cannot",
            "% Failed",
        ]

        lines = output.split('\n')
        for line in lines:
            for pattern in error_patterns:
                if pattern in line:
                    errors.append(line.strip())
                    break

        return errors

    def test_connectivity(self) -> bool:
        """
        Test SSH connectivity to device.

        Returns:
            True if connected and responding

        Raises:
            HardeningExecutionError: If test fails
        """
        if not self.ssh_client:
            raise HardeningExecutionError("Not connected to device")

        try:
            # Simple command to test connectivity
            output = self.ssh_client.send_command("show version", timeout=10)
            return bool(output and len(output) > 0)

        except Exception as e:
            logger.error(f"Connectivity test failed: {str(e)}")
            raise HardeningExecutionError(f"Device not responding: {str(e)}")


def redact_secrets_in_output(output: str) -> str:
    """
    Redact secrets and passwords from command output.

    Args:
        output: Raw command output

    Returns:
        Output with secrets redacted

    Examples:
        >>> redact_secrets_in_output("enable secret MySecret123")
        'enable secret <REDACTED>'
    """
    import re

    redacted = output

    # Redact enable secret/password
    redacted = re.sub(
        r'(enable secret\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r'(enable password\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact username passwords
    redacted = re.sub(
        r'(username\s+\S+\s+(?:password|secret)\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact SNMP community strings
    redacted = re.sub(
        r'(snmp-server community\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact NTP authentication keys
    redacted = re.sub(
        r'(ntp authentication-key\s+\d+\s+md5\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact key strings
    redacted = re.sub(
        r'(key-string\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    return redacted


def format_command_output(commands: List[str], output: str) -> str:
    """
    Format command output for display.

    Args:
        commands: List of commands that were executed
        output: Raw output from device

    Returns:
        Formatted output with command prompts
    """
    formatted_lines = []

    formatted_lines.append("=" * 60)
    formatted_lines.append(f"Commands Executed: {len(commands)}")
    formatted_lines.append("=" * 60)

    for cmd in commands:
        formatted_lines.append(f"\n> {cmd}")

    formatted_lines.append("\n" + "=" * 60)
    formatted_lines.append("Device Output:")
    formatted_lines.append("=" * 60)
    formatted_lines.append(output)

    return "\n".join(formatted_lines)
