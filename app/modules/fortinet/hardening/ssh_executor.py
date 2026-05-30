"""
FortiGate Hardening SSH Executor

Executes hardening commands on FortiGate devices via SSH.

Responsibilities:
- Backup full configuration
- Execute configuration commands with VDOM support
- Verify fixes by re-running FortiGate checks
- Handle errors and command failures
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging
import re

from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient
from app.modules.fortinet.audit.rules import FortiGateControl
from app.core.ssh_exceptions import SSHConnectionError

logger = logging.getLogger(__name__)


class FortiGateHardeningExecutionError(Exception):
    """Raised when FortiGate command execution fails."""
    pass


class FortiGateHardeningVerificationError(Exception):
    """Raised when post-execution verification fails."""
    pass


class FortiGateHardeningExecutor:
    """
    Executes hardening commands on FortiGate devices.

    Uses FortiGateSSHClient for SSH connectivity and command execution.
    Supports VDOM context switching for per-VDOM commands.
    """

    # FortiGate error patterns
    ERROR_PATTERNS = [
        "command fail",
        "parse error",
        "unknown command",
        "unknown action",
        "invalid",
        "not found",
        "permission denied",
        "object already exist",
        "entry not found",
        "not allowed",
        "error:",
        "failed"
    ]

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 22,
        vdom: Optional[str] = None
    ):
        """
        Initialize executor with SSH credentials.

        Args:
            ip: Device IP address
            username: SSH username
            password: SSH password
            port: SSH port (default 22)
            vdom: Default VDOM context (optional)
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.default_vdom = vdom
        self.ssh_client: Optional[FortiGateSSHClient] = None
        self._vdom_enabled: Optional[bool] = None

    def __enter__(self):
        """
        Context manager entry - establish SSH connection.

        Raises:
            SSHConnectionError subclasses: Propagated from FortiGateSSHClient.connect()
        """
        self.ssh_client = FortiGateSSHClient(
            host=self.ip,
            username=self.username,
            password=self.password,
            port=self.port
        )
        # Connect explicitly - SSH exceptions will propagate
        self.ssh_client.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close SSH connection."""
        if self.ssh_client:
            self.ssh_client.disconnect()
        return False

    def backup_config(self) -> str:
        """
        Backup full FortiGate configuration.

        Returns:
            Full configuration as string with metadata header

        Raises:
            FortiGateHardeningExecutionError: If backup fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Backing up config from FortiGate {self.ip}")

            # Get full configuration
            config = self.ssh_client.send_command("show full-configuration", use_cache=False)

            # Add metadata header
            timestamp = datetime.utcnow().isoformat()
            header = f"""#
# FortiGate Configuration Backup
# Backup taken at: {timestamp}
# By: Hardening Module
# Device: {self.ip}
#
"""
            backup = header + config

            logger.info(f"Config backup completed: {len(backup)} bytes")
            return backup

        except Exception as e:
            logger.error(f"Config backup failed: {str(e)}")
            raise FortiGateHardeningExecutionError(f"Failed to backup config: {str(e)}")

    def _is_vdom_enabled(self) -> bool:
        """Return True if VDOMs are enabled on the device (cached after first call)."""
        if self._vdom_enabled is None:
            try:
                status = self.ssh_client.get_system_status()
                self._vdom_enabled = status.get("vdom_enabled", True)
            except Exception:
                self._vdom_enabled = True  # assume enabled if detection fails
        return self._vdom_enabled

    def _strip_global_wrapper(self, commands: List[str]) -> List[str]:
        """
        On non-VDOM devices the session is already at global scope, so
        "config global" / the matching closing "end" are invalid.  Strip them.
        """
        cmds = [c for c in commands if c.strip()]
        if cmds and cmds[0].strip().lower() == "config global":
            cmds = cmds[1:]
            # Remove the last "end" that closes the config-global block
            for i in range(len(cmds) - 1, -1, -1):
                if cmds[i].strip().lower() == "end":
                    cmds.pop(i)
                    break
        return cmds

    def execute_commands(
        self,
        commands: List[str],
        vdom: Optional[str] = None,
        vdom_context: str = "global"
    ) -> Dict[str, Any]:
        """
        Execute commands on FortiGate device.

        Args:
            commands: List of commands to execute
            vdom: Optional VDOM name (only used when vdom_context == "vdom")
            vdom_context: "global" or "vdom". For global templates the commands
                          already contain "config global" / "end" wrappers, so
                          no VDOM switching is performed here. For per-VDOM
                          templates the executor enters the target VDOM first.

        Returns:
            Dict with:
                - success: bool
                - output: str (all command outputs)
                - errors: List[str]

        Raises:
            FortiGateHardeningExecutionError: If execution fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            # On devices without VDOMs the session is already at global scope;
            # strip the "config global" / closing "end" wrapper so the inner
            # config commands reach the device cleanly.
            if vdom_context == "global" and not self._is_vdom_enabled():
                commands = self._strip_global_wrapper(commands)

            logger.info(f"Executing {len(commands)} commands on FortiGate {self.ip}")

            # Determine VDOM to enter (if any).
            # "vdom"      — use caller-supplied name or default_vdom
            # "vdom_root" — automatically use the built-in "root" VDOM on
            #               VDOM-enabled devices (password-policy and similar
            #               per-VDOM settings that the audit reads at root level)
            vdom_to_use = vdom or self.default_vdom
            if vdom_context == "vdom_root" and self._is_vdom_enabled():
                vdom_to_use = vdom_to_use or "root"

            entered_vdom = False
            if vdom_to_use and vdom_context in ("vdom", "vdom_root"):
                logger.info(f"Entering VDOM: {vdom_to_use}")
                if not self.ssh_client.enter_vdom(vdom_to_use):
                    raise FortiGateHardeningExecutionError(
                        f"Failed to enter VDOM: {vdom_to_use}"
                    )
                entered_vdom = True

            outputs = []
            errors = []

            # Execute each command
            for cmd in commands:
                try:
                    # Skip empty commands
                    if not cmd.strip():
                        continue

                    output = self.ssh_client.send_command(cmd, use_cache=False)
                    outputs.append(f"# {cmd}\n{output}")

                    # Check for errors in output
                    cmd_errors = self._check_for_errors(output)
                    if cmd_errors:
                        errors.extend(cmd_errors)

                except Exception as e:
                    error_msg = f"Command '{cmd}' failed: {str(e)}"
                    errors.append(error_msg)
                    outputs.append(f"# {cmd}\nERROR: {str(e)}")

            # Exit VDOM context only if we entered one
            if entered_vdom:
                self.ssh_client.exit_vdom()

            full_output = "\n\n".join(outputs)

            if errors:
                logger.warning(f"Command execution completed with errors: {errors}")
                return {
                    "success": False,
                    "output": full_output,
                    "errors": errors
                }

            logger.info(f"Commands executed successfully on FortiGate {self.ip}")
            return {
                "success": True,
                "output": full_output,
                "errors": []
            }

        except FortiGateHardeningExecutionError:
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            raise FortiGateHardeningExecutionError(f"Failed to execute commands: {str(e)}")

    def verify_check(
        self,
        control: FortiGateControl,
        vdom: Optional[str] = None,
        vdom_context: str = "global"
    ) -> Tuple[bool, str]:
        """
        Re-run FortiGate control check to verify fix worked.

        Args:
            control: FortiGateControl object with rules to verify
            vdom: Optional VDOM name (only used when vdom_context == "vdom")
            vdom_context: "global" or "vdom". Show commands for global checks
                          run at the top-level CLI; per-VDOM checks need the
                          correct VDOM context to return the right settings.

        Returns:
            Tuple of (passed: bool, evidence: str)

        Raises:
            FortiGateHardeningVerificationError: If verification fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Verifying check {control.id} on FortiGate {self.ip}")

            # Enter VDOM context only for per-VDOM checks.
            # "vdom_root" show commands run inside the "root" VDOM (mirrors
            # the context in which the audit reads those settings).
            # Pure global show commands run at top-level CLI.
            vdom_to_use = vdom or self.default_vdom
            if vdom_context == "vdom_root" and self._is_vdom_enabled():
                vdom_to_use = vdom_to_use or "root"

            entered_vdom = False
            if vdom_to_use and vdom_context in ("vdom", "vdom_root"):
                if not self.ssh_client.enter_vdom(vdom_to_use):
                    raise FortiGateHardeningVerificationError(
                        f"Failed to enter VDOM for verification: {vdom_to_use}"
                    )
                entered_vdom = True

            # Collect fresh output for each rule command
            all_evidence = []
            all_passed = True

            for rule in control.rules:
                # Execute the check command
                output = self.ssh_client.send_command(rule.cmd, use_cache=False)
                all_evidence.append(f"# {rule.cmd}\n{output[:500]}")  # Truncate long output

                # Evaluate the rule
                passed = self._evaluate_rule(rule, output)
                if not passed:
                    all_passed = False

            # Exit VDOM context only if we entered one
            if entered_vdom:
                self.ssh_client.exit_vdom()

            evidence = "\n\n".join(all_evidence)
            logger.info(f"Verification result for {control.id}: {'PASS' if all_passed else 'FAIL'}")

            return all_passed, evidence

        except FortiGateHardeningVerificationError:
            raise
        except Exception as e:
            logger.error(f"Verification failed for {control.id}: {str(e)}")
            raise FortiGateHardeningVerificationError(f"Failed to verify check: {str(e)}")

    def _evaluate_rule(self, rule, output: str) -> bool:
        """
        Evaluate a single FortiGate rule against command output.

        Args:
            rule: FortiGateRule object
            output: Command output to evaluate

        Returns:
            True if rule passes, False otherwise
        """
        output_lower = output.lower()

        if rule.type == "set_bool":
            # FortiOS "show" omits settings at their default value.
            # Check for absence of the opposite state rather than presence of the
            # expected state — this works whether the setting is default-on/off or
            # explicitly configured.
            key = rule.key
            expected = rule.expected
            if expected:
                # Want enabled: pass if "set <key> disable" is absent
                pattern = rf"set\s+{re.escape(key)}\s+disable"
            else:
                # Want disabled: pass if "set <key> enable" is absent
                pattern = rf"set\s+{re.escape(key)}\s+enable"
            return not bool(re.search(pattern, output, re.IGNORECASE))

        elif rule.type == "set_eq":
            # Check for "set <key> <expected>"
            key = rule.key
            expected = str(rule.expected)
            pattern = rf"set\s+{re.escape(key)}\s+{re.escape(expected)}"
            return bool(re.search(pattern, output, re.IGNORECASE))

        elif rule.type == "set_int_le":
            # Check for "set <key> <value>" where value <= expected
            key = rule.key
            expected = int(rule.expected)
            pattern = rf"set\s+{re.escape(key)}\s+(\d+)"
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                actual = int(match.group(1))
                return actual <= expected
            return False

        elif rule.type == "set_int_ge":
            # Check for "set <key> <value>" where value >= expected
            key = rule.key
            expected = int(rule.expected)
            pattern = rf"set\s+{re.escape(key)}\s+(\d+)"
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                actual = int(match.group(1))
                return actual >= expected
            return False

        elif rule.type == "regex_present":
            # Pattern should be present
            pattern = rule.pattern
            return bool(re.search(pattern, output, re.IGNORECASE | re.MULTILINE))

        elif rule.type == "regex_absent":
            # Pattern should NOT be present
            pattern = rule.pattern
            return not bool(re.search(pattern, output, re.IGNORECASE | re.MULTILINE))

        elif rule.type == "set_in":
            # Check for "set <key> <value>" where value is in any_of list
            key = rule.key
            any_of = rule.any_of or []
            pattern = rf"set\s+{re.escape(key)}\s+(\S+)"
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                actual = match.group(1).lower()
                return any(actual == str(v).lower() for v in any_of)
            return False

        else:
            # Unknown rule type - fail safe
            logger.warning(f"Unknown rule type: {rule.type}")
            return False

    def save_config(self) -> str:
        """
        Save FortiGate configuration.

        Note: FortiGate auto-saves config after 'end' commands,
        but this can be used to verify the save.

        Returns:
            Command output

        Raises:
            FortiGateHardeningExecutionError: If save fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            logger.info(f"Verifying config save on FortiGate {self.ip}")

            # FortiGate auto-saves, but we can run a backup command to verify
            output = self.ssh_client.send_command("execute backup config flash", use_cache=False)
            logger.info("Config save verified")
            return output

        except Exception as e:
            logger.error(f"Config save verification failed: {str(e)}")
            raise FortiGateHardeningExecutionError(f"Failed to verify config save: {str(e)}")

    def _check_for_errors(self, output: str) -> List[str]:
        """
        Check command output for FortiGate errors.

        Args:
            output: Command output text

        Returns:
            List of error messages found
        """
        errors = []
        output_lower = output.lower()

        for pattern in self.ERROR_PATTERNS:
            if pattern in output_lower:
                # Extract the line containing the error
                for line in output.split('\n'):
                    if pattern in line.lower():
                        errors.append(line.strip())
                        break

        return errors

    def test_connectivity(self) -> bool:
        """
        Test SSH connectivity to FortiGate device.

        Returns:
            True if connected and responding

        Raises:
            FortiGateHardeningExecutionError: If test fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            # Simple command to test connectivity
            output = self.ssh_client.send_command("get system status")
            return bool(output and "Version:" in output)

        except Exception as e:
            logger.error(f"Connectivity test failed: {str(e)}")
            raise FortiGateHardeningExecutionError(f"Device not responding: {str(e)}")

    def get_system_info(self) -> Dict[str, str]:
        """
        Get FortiGate system information.

        Returns:
            Dict with version, hostname, serial, model, etc.

        Raises:
            FortiGateHardeningExecutionError: If retrieval fails
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")

        try:
            return self.ssh_client.get_system_status()
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
            raise FortiGateHardeningExecutionError(f"Failed to get system info: {str(e)}")


def redact_fortigate_secrets(output: str) -> str:
    """
    Redact secrets and passwords from FortiGate command output.

    Args:
        output: Raw command output

    Returns:
        Output with secrets redacted

    Examples:
        >>> redact_fortigate_secrets("set password MySecret123")
        'set password <REDACTED>'
    """
    redacted = output

    # Redact password settings
    redacted = re.sub(
        r'(set\s+password\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact secret settings
    redacted = re.sub(
        r'(set\s+secret\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact PSK settings
    redacted = re.sub(
        r'(set\s+psksecret\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact SNMP community strings
    redacted = re.sub(
        r'(edit\s+"?[^"]*community[^"]*"?\s*\n\s*set\s+name\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact auth keys
    redacted = re.sub(
        r'(set\s+auth-keychain\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact private keys
    redacted = re.sub(
        r'(set\s+private-key\s+)"[^"]*"',
        r'\1"<REDACTED>"',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact API keys
    redacted = re.sub(
        r'(set\s+api-key\s+)\S+',
        r'\1<REDACTED>',
        redacted,
        flags=re.IGNORECASE
    )

    # Redact ENC: encrypted values
    redacted = re.sub(
        r'ENC\s+[A-Za-z0-9+/=]+',
        'ENC <REDACTED>',
        redacted
    )

    return redacted


def format_fortigate_command_output(commands: List[str], output: str) -> str:
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
    formatted_lines.append(f"FortiGate Commands Executed: {len(commands)}")
    formatted_lines.append("=" * 60)

    for cmd in commands:
        formatted_lines.append(f"\n> {cmd}")

    formatted_lines.append("\n" + "=" * 60)
    formatted_lines.append("Device Output:")
    formatted_lines.append("=" * 60)
    formatted_lines.append(output)

    return "\n".join(formatted_lines)
