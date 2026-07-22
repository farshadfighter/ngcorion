"""
Linux SSH Executor for Hardening

Executes hardening commands on Linux servers with sudo support.
Includes pre/post verification and detailed logging.
"""

from typing import Dict, List, Optional, Any
import logging
import re
import shlex
import time

from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
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

# A {PARAM} that survived substitution means a required value was never supplied.
_PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]*\}")

# Config files/globs a Linux CIS run may modify. Snapshotted before hardening so
# a run can be rolled back. Non-existent paths are skipped by the bundle command.
LINUX_BACKUP_PATHS = [
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf",
    "/etc/sysctl.conf", "/etc/sysctl.d/*.conf",
    "/etc/login.defs",
    "/etc/security/pwquality.conf", "/etc/security/pwquality.conf.d/*.conf",
    "/etc/security/faillock.conf", "/etc/security/limits.conf", "/etc/security/limits.d/*.conf",
    "/etc/pam.d/common-password", "/etc/pam.d/common-auth", "/etc/pam.d/common-account",
    "/etc/pam.d/password-auth", "/etc/pam.d/system-auth", "/etc/pam.d/su", "/etc/pam.d/sshd",
    "/etc/audit/auditd.conf", "/etc/audit/rules.d/*.rules",
    "/etc/issue", "/etc/issue.net", "/etc/motd",
    "/etc/modprobe.d/*.conf",
    "/etc/default/grub",
    "/etc/crontab", "/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny",
    "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/profile.d/*.sh",
]


def _first_error_line(output: str) -> str:
    """
    Pick the most useful line out of a failed command's output for the UI.

    Prefers a line that looks like an error message, falling back to the last
    non-empty line (many tools print the reason last).
    """
    lines = [ln.strip() for ln in (output or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    for line in lines:
        low = line.lower()
        if any(t in low for t in ("error", "denied", "not found", "failed",
                                  "cannot", "no such", "unknown", "refus")):
            return line[:200]
    return lines[-1][:200]


class LinuxHardeningExecutionResult:
    """Result of a single hardening execution."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.check_title: str = ""
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
            "check_title": self.check_title,
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

    _SLOW_CMD_PREFIXES = (
        "apt-get install", "apt install",
        "dnf install", "yum install",
        "pip install", "pip3 install",
    )

    def execute_command(self, command: str, use_sudo: bool = True) -> str:
        """
        Execute a single command on the server.

        Args:
            command: Command to execute
            use_sudo: Whether to use sudo

        Returns:
            Command output
        """
        return self.execute_command_with_status(command, use_sudo)[0]

    def execute_command_with_status(self, command: str, use_sudo: bool = True) -> tuple:
        """
        Execute a single command and return ``(output, exit_status)``.

        Remediation commands must be checked against the exit status: a sudo
        denial or a missing binary produces no exception and often no output,
        so without it a fix that never ran looks identical to one that worked.
        """
        if not self._connected:
            raise RuntimeError("Not connected. Call connect() first.")

        stripped = command.lstrip()
        timeout = 120 if any(stripped.startswith(p) for p in self._SLOW_CMD_PREFIXES) else 30
        if use_sudo:
            # Wrap in `sh -c` so redirections/heredocs/pipes inside the template
            # command run under sudo too. Bare `sudo -S cmd > file` performs the
            # redirection as the unprivileged login user and fails with
            # "Permission denied" for any /etc target.
            command = f"sh -c {shlex.quote(command)}"
        return self.ssh_client.send_command_with_status(
            command, use_sudo=use_sudo, timeout=timeout
        )

    def backup_config(self) -> str:
        """
        Snapshot the CIS-relevant config files into one text bundle for rollback.

        Reads under sudo so root-owned /etc files are captured. Raises if the
        connection is gone or the snapshot comes back empty (no files readable),
        so the caller can surface a backup failure rather than record a useless
        empty row.
        """
        from app.modules.shared.hardening_backup import bundle_header, build_file_bundle_command

        if not self._connected:
            raise RuntimeError("Not connected. Call connect() first.")

        logger.info(f"Backing up Linux config from {self.ip}")
        body = self.execute_command(build_file_bundle_command(LINUX_BACKUP_PATHS), use_sudo=True)
        if not body or not body.strip():
            raise RuntimeError("Linux config backup returned no content")
        backup = bundle_header("linux", self.ip) + body
        logger.info(f"Linux config backup completed: {len(backup)} bytes from {self.ip}")
        return backup

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

        # Merge template defaults under the caller's values and drop empty
        # strings: the UI may submit optional params as "" and substituting an
        # empty value would write broken config lines (e.g. "MaxAuthTries ''").
        from .parameter_metadata import get_linux_check_defaults
        merged = dict(get_linux_check_defaults(check_id))
        for k, v in (parameters or {}).items():
            if v is not None and str(v).strip() != "":
                merged[k] = v
        parameters = merged

        # Use distro-aware template
        template = get_linux_hardening_template_for_distro(check_id, self.distro_id or "ubuntu")
        if not template:
            result.error_message = f"No hardening template found for {check_id}"
            logger.error(result.error_message)
            return result
        result.check_title = template.description

        if template.manual_only:
            result.error_message = (
                f"Check {check_id} has no automated remediation and must be applied "
                f"manually.\n\n{template.manual_guidance or ''}".rstrip()
            )
            logger.info(f"Skipping {check_id}: manual remediation only")
            return result

        if not self._connected:
            result.error_message = "Not connected to server"
            return result

        logger.info(f"Executing hardening for {check_id} (distro: {self.distro_id}): {template.description}")

        try:
            # Get commands with distro-specific paths and parameter substitution
            commands = get_linux_template_commands_for_distro(check_id, self.distro_id or "ubuntu", parameters)

            # A leftover {PLACEHOLDER} means a required parameter was never
            # supplied — refuse to run rather than write a broken config line.
            leftover = sorted({m for cmd in commands for m in _PLACEHOLDER_RE.findall(cmd)})
            if leftover:
                result.error_message = (
                    "Missing required parameter(s): "
                    + ", ".join(p.strip("{}") for p in leftover)
                )
                logger.warning(f"[{check_id}] {result.error_message}")
                return result

            # Execute each command
            command_errors: List[str] = []
            for cmd in commands:
                try:
                    output, exit_status = self.execute_command_with_status(cmd, use_sudo=True)
                    result.commands_executed.append(cmd)
                    result.command_outputs[cmd] = output
                    if exit_status != 0:
                        # Don't let a command that never ran (sudo denied, missing
                        # binary, read-only /etc) look like a success. Record the
                        # real reason so the UI can show it.
                        detail = _first_error_line(output) or f"exit status {exit_status}"
                        error_msg = f"`{cmd[:80]}` failed (exit {exit_status}): {detail}"
                        logger.error(error_msg)
                        command_errors.append(error_msg)
                    else:
                        logger.debug(f"Command executed: {cmd[:60]}...")
                except Exception as e:
                    error_msg = f"Command failed: {cmd[:60]}... Error: {str(e)}"
                    logger.error(error_msg)
                    result.command_outputs[cmd] = f"ERROR: {str(e)}"
                    command_errors.append(error_msg)
                    # Continue with other commands unless critical

            # Restart service if needed
            if template.requires_service_restart:
                service = template.requires_service_restart
                try:
                    restart_cmd = f"systemctl restart {service}"
                    output, exit_status = self.execute_command_with_status(restart_cmd, use_sudo=True)
                    result.commands_executed.append(restart_cmd)
                    result.command_outputs[restart_cmd] = output
                    result.requires_service_restart = service
                    if exit_status != 0:
                        detail = _first_error_line(output) or f"exit status {exit_status}"
                        restart_error = f"Failed to restart {service}: {detail}"
                        logger.error(restart_error)
                        command_errors.append(restart_error)
                    else:
                        logger.info(f"Restarted service: {service}")
                except Exception as e:
                    logger.warning(f"Failed to restart {service}: {str(e)}")
                    command_errors.append(f"Failed to restart {service}: {e}")

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

                # Check if verification passed. A fix is only considered
                # successful when verification explicitly reports PASS.
                # "FAIL" or a verify command error means the fix failed;
                # absence of any PASS marker means we cannot confirm it, so we
                # do NOT claim success (otherwise the audit row gets flipped to
                # PASS without the host actually being remediated).
                verify_text = result.verification_result
                verify_reason = None
                if "FAIL" in verify_text or "ERROR:" in verify_text:
                    result.success = False
                    verify_reason = "verification reported FAIL"
                elif "PASS" in verify_text:
                    result.success = True
                else:
                    result.success = False
                    verify_reason = (
                        "verification produced no PASS/FAIL marker"
                        + (f" (output: {_first_error_line(verify_text)})" if verify_text.strip() else " (no output)")
                    )

                if not result.success and not result.error_message:
                    # A failed remediation command explains the failed verification —
                    # lead with it, since "verification reported FAIL" alone tells the
                    # operator nothing actionable.
                    if command_errors:
                        result.error_message = (
                            f"{'; '.join(command_errors[:3])} — {verify_reason}"
                        )
                    else:
                        result.error_message = (
                            f"Fix commands ran, but {verify_reason}. "
                            f"Verification output: {verify_text.strip()[:400] or '(empty)'}"
                        )
            else:
                # No verification commands defined — fall back to whether every
                # fix command ran without error.
                result.success = not command_errors
                if not result.success and not result.error_message:
                    result.error_message = "; ".join(command_errors[:3])

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
        distro_id: Optional[str] = None,
        port: int = 22
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.distro_id = distro_id  # Will be auto-detected if not provided
        self.port = port

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
            distro_id=self.distro_id,
            port=self.port
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
        checks: List[Dict[str, Any]],
        create_backup: bool = False
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of dicts with check_id and parameters
            create_backup: Snapshot the config files before applying any change.
                The snapshot text is returned under ``backup_content`` (or the
                reason under ``backup_error``) for the service to persist.

        Returns:
            Summary of execution with results
        """
        results = []
        successful = 0
        failed = 0
        backup_content: Optional[str] = None
        backup_error: Optional[str] = None

        with LinuxSSHExecutor(
            ip=self.ip,
            username=self.username,
            password=self.password,
            sudo_password=self.sudo_password,
            distro_id=self.distro_id,
            port=self.port
        ) as executor:
            detected_distro = executor.distro_id

            # Take the backup on the same connection, before any change is applied.
            if create_backup:
                try:
                    backup_content = executor.backup_config()
                except Exception as exc:  # noqa: BLE001
                    backup_error = str(exc)
                    logger.error(f"Linux pre-hardening backup failed on {self.ip}: {exc}")

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
            "results": results,
            "backup_content": backup_content,
            "backup_error": backup_error,
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
            distro_id=self.distro_id,
            port=self.port
        ) as executor:
            result = executor.execute_hardening(check_id, parameters)
            result_dict = result.to_dict()
            result_dict["distro_id"] = executor.distro_id
            return result_dict
