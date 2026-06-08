"""
SSH Client for Cisco Device Auditing

Handles SSH connections and command execution on Cisco IOS/IOS-XE devices.
Based on netmiko library with "turbo" command collection strategy.
"""

from typing import List, Optional
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import re
import time
import logging

# Import paramiko exceptions for algorithm/key errors
try:
    from paramiko.ssh_exception import (
        SSHException,
        BadHostKeyException,
        NoValidConnectionsError
    )
    from paramiko.transport import IncompatiblePeer
except ImportError:
    # Fallback if paramiko structure changes
    SSHException = Exception
    BadHostKeyException = Exception
    NoValidConnectionsError = Exception
    IncompatiblePeer = Exception

from app.core.ssh_exceptions import (
    SSHConnectionError,
    SSHAuthenticationError,
    SSHConnectionTimeoutError,
    SSHNetworkError,
    SSHAlgorithmMismatchError,
    SSHHostKeyError,
    map_ssh_exception
)

logger = logging.getLogger(__name__)

# Turbo Commands - Targeted snippets instead of full running-config
CISCO_TURBO_COMMANDS: List[str] = [
    # Identity / DNS
    "show run | i ^hostname|^ip domain-name|^no ip domain-lookup",

    # Access / Management (VTY/Console/Banners)
    "show run | sec line vty",
    "show run | sec line console",
    "show run | i ^banner motd|^banner login",

    # SSH hardening
    "show run | i ^ip ssh version|^ip ssh timeout|^ip ssh authentication-retries|^ip ssh server algorithm",
    "show ip ssh",

    # Service hygiene one-liners. These are default-state global services that
    # only appear in running-config once explicitly toggled (e.g. "no service
    # dhcp", "no ip identd", "service tcp-keepalives-in"). They MUST be grepped
    # explicitly — otherwise checks CIS-2.1.4/2.1.5/2.1.6 never see them and
    # report non-compliant even after hardening applies them.
    "show run | i ^no service tcp-small-servers|^no service udp-small-servers|^no service dhcp|^no service pad|^no ip bootp server|^no ip finger|^no ip identd|^service tcp-keepalives",

    # AAA / Login controls / Logging
    "show run | i ^aaa |^login block-for|^login on-failure|^login on-success",
    "show run | i ^service password-encryption|^service timestamps log datetime",
    # Grep EVERY "logging ..." line from running-config. The old narrow filter
    # (host|trap|buffered|facility) dropped lines like "logging source-interface"
    # (CIS-2.2.7) and "logging console" (CIS-2.2.3), so post-hardening verification
    # never saw them and reported FAIL even when the fix applied correctly.
    "show run | i ^logging ",
    # Operational logging levels from "show logging". Some compliant values equal
    # the IOS default and are therefore suppressed from running-config — notably
    # "logging trap informational" (CIS-2.2.5). Collect just the summary lines
    # (Console/Trap), not the buffered message dump, so defaults stay verifiable.
    "show logging | i (Console|Trap) logging",
    "show run | sec archive",
    "show archive",

    # SNMP
    "show run | i ^snmp-server ",

    # Users / enable (note: values may be masked later)
    "show run | i ^username |^enable password|^enable secret",

    # Time / NTP
    "show run | i ^clock timezone|^ntp ",

    # L2/L3 hygiene
    "show run | i ^no ip directed-broadcast|^no ip source-route|^no ip http ",
    "show run | i ^(no )?cdp run|^(no )?lldp run",

    # Interfaces evidence
    "show run | i ^interface ",
    "show run | i ip access-group ",
    "show run | i no ip proxy-arp",

    # Crypto key / boot / version evidences
    "show crypto key mypubkey rsa",
    "show version | i Configuration register|System image file is",

    # Secure boot / boot system
    "show run | i ^secure boot-(image|config)|^boot system",

    # CoPP evidence
    "show run | sec policy-map type control-plane",
]

# Redaction patterns for sensitive data
REDACT_PATTERNS = [
    # enable secret/password values
    (re.compile(r"^(enable secret)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(enable password)\s+.+$", re.M), r"\1 <REDACTED>"),

    # local users passwords/secrets
    (re.compile(r"^(username\s+\S+\s+password)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(username\s+\S+\s+secret)\s+.+$", re.M), r"\1 <REDACTED>"),

    # snmp community values
    (re.compile(r"^(snmp-server community)\s+\S+", re.M), r"\1 <REDACTED>"),

    # ntp authentication keys
    (re.compile(r"^(ntp authentication-key\s+\d+\s+md5)\s+\S+", re.M), r"\1 <REDACTED>"),

    # tacacs-server keys
    (re.compile(r"^(tacacs-server\s+host\s+\S+\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(tacacs-server\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),

    # radius-server keys
    (re.compile(r"^(radius-server\s+host\s+\S+\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),
    (re.compile(r"^(radius-server\s+key)\s+.+$", re.M), r"\1 <REDACTED>"),
]


class CiscoSSHClient:
    """
    SSH client for Cisco IOS/IOS-XE devices.

    Handles connection, command execution, and cleanup with proper error handling.
    Includes retry logic for transient failures.
    """

    # Default retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    def __init__(self,
                 ip: str,
                 username: str,
                 password: str,
                 secret: Optional[str] = None,
                 port: int = 22,
                 device_type: str = "cisco_ios",
                 timeout: int = 30,
                 fast_cli: bool = True,
                 max_retries: int = 3):
        """
        Initialize SSH client parameters.

        Args:
            ip: Target device IP address
            username: SSH username
            password: SSH password
            secret: Enable secret (optional)
            port: SSH port (default 22)
            device_type: Netmiko device type (default: cisco_ios)
            timeout: Connection/command timeout in seconds
            fast_cli: Enable fast CLI mode (reduces delays)
            max_retries: Maximum number of connection retries
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.device_type = device_type
        self.timeout = timeout
        self.fast_cli = fast_cli
        self.max_retries = max_retries
        self.connection = None
        self._in_enable_mode = False

    def connect(self) -> None:
        """
        Establish SSH connection to device with retry logic.

        Raises:
            SSHAuthenticationError: If authentication fails
            SSHConnectionTimeoutError: If connection times out after all retries
            SSHNetworkError: If device is unreachable
            SSHAlgorithmMismatchError: If SSH algorithm negotiation fails
            SSHHostKeyError: If host key verification fails
            SSHConnectionError: For other SSH failures
        """
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"SSH connection attempt {attempt}/{self.max_retries} to {self.ip}")

                self.connection = ConnectHandler(
                    device_type=self.device_type,
                    ip=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    secret=self.secret,
                    fast_cli=self.fast_cli,
                    timeout=self.timeout,
                    global_delay_factor=1,
                    banner_timeout=20,  # Longer banner timeout for slow devices
                    auth_timeout=20     # Longer auth timeout
                )

                # Enter enable mode if needed/possible. Always check current state
                # first — if SSH auto-elevates to privilege 15 we're already at '#'.
                try:
                    if self._ensure_enable_mode():
                        logger.debug(f"In enable mode on {self.ip}")
                    else:
                        logger.info(
                            f"Not in enable mode on {self.ip}: no enable secret "
                            "provided (read-only commands will still work)"
                        )
                except Exception as e:
                    logger.warning(f"Failed to enter enable mode on {self.ip}: {e}")
                    # Continue — read-only show commands still work without enable mode

                # Disable paging
                try:
                    self.connection.send_command("terminal length 0", cmd_verify=False)
                except Exception:
                    pass

                logger.info(f"Successfully connected to {self.ip}")
                return  # Success - exit retry loop

            except NetmikoAuthenticationException as e:
                # Don't retry on auth failures - credentials are wrong
                logger.error(f"Authentication failed for {self.ip}")
                raise SSHAuthenticationError(self.ip, original_error=e)

            except IncompatiblePeer as e:
                # Don't retry on algorithm mismatch - won't change
                logger.error(f"SSH algorithm mismatch with {self.ip}")
                raise SSHAlgorithmMismatchError(self.ip, original_error=e)

            except BadHostKeyException as e:
                # Don't retry on host key errors
                logger.error(f"Host key verification failed for {self.ip}")
                raise SSHHostKeyError(self.ip, original_error=e)

            except NoValidConnectionsError as e:
                # Don't retry on connection refused - service not available
                logger.error(f"Connection refused by {self.ip}")
                raise SSHNetworkError(self.ip, original_error=e)

            except NetmikoTimeoutException as e:
                last_exception = e
                logger.warning(f"Connection timeout to {self.ip} (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except OSError as e:
                # Socket-level errors - check if retryable
                if hasattr(e, 'errno') and e.errno in (111, 113):  # Connection refused, No route
                    logger.error(f"Network error connecting to {self.ip}: {e}")
                    raise SSHNetworkError(self.ip, original_error=e)
                # Other OS errors - retry
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except Exception as e:
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        # All retries exhausted - map the last exception to appropriate type
        error_msg = f"Failed to connect to {self.ip} after {self.max_retries} attempts"
        logger.error(error_msg)
        if last_exception:
            raise map_ssh_exception(last_exception, self.ip)
        else:
            raise SSHConnectionError(
                message=error_msg,
                device_ip=self.ip,
                suggestions=["Check network connectivity to the device"],
                original_error=None
            )

    def is_connected(self) -> bool:
        """Check if the SSH connection is still active."""
        if not self.connection:
            return False
        try:
            return self.connection.is_alive()
        except Exception:
            return False

    def _ensure_enable_mode(self) -> bool:
        """
        Ensure the session is in privileged (enable) mode.

        Returns:
            True if the session is in enable mode; False if it could not be
            entered because no enable secret is available.

        Raises:
            Propagates netmiko errors when an enable secret was provided but the
            elevation failed (e.g. wrong secret).

        Note on fast_cli: the enable password exchange is run with fast_cli
        temporarily disabled. fast_cli's aggressive timing can make netmiko read
        the channel before the device's "Password:" prompt — or the post-secret
        "#" prompt — is fully received, so it either never sends the secret or
        wrongly concludes elevation failed. That surfaces the misleading
        "Failed to enter enable mode. Please ensure you pass the 'secret'
        argument to ConnectHandler." error even when the secret is correct.
        Disabling fast_cli for just this exchange makes it reliable without
        slowing the bulk "show" collection.
        """
        if self._in_enable_mode:
            return True

        prev_fast_cli = self.connection.fast_cli
        self.connection.fast_cli = False
        try:
            # Already privileged? SSH users configured for privilege 15 land at
            # '#' without any enable step. Run this check with fast_cli disabled
            # too — under fast_cli it can misread a privileged session as
            # unprivileged and trigger a needless (and failing) enable attempt.
            if self.connection.check_enable_mode():
                self._in_enable_mode = True
                return True

            if not self.secret:
                return False

            self.connection.enable()
            self._in_enable_mode = True
            return True
        finally:
            self.connection.fast_cli = prev_fast_cli

    def collect_turbo(self) -> str:
        """
        Collect targeted command outputs (Turbo mode).

        Returns:
            str: Concatenated command outputs

        Raises:
            RuntimeError: If not connected
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        chunks: List[str] = []
        failed_commands = 0
        total_commands = len(CISCO_TURBO_COMMANDS)

        for cmd in CISCO_TURBO_COMMANDS:
            try:
                out = self.connection.send_command(
                    cmd,
                    cmd_verify=False,
                    read_timeout=30  # Per-command timeout
                )
                chunks.append(f"!! {cmd}\n{out}\n")
            except Exception as e:
                failed_commands += 1
                error_msg = str(e)
                # Truncate very long error messages
                if len(error_msg) > 200:
                    error_msg = error_msg[:200] + "..."
                chunks.append(f"!! {cmd}\n<<ERROR: {type(e).__name__}: {error_msg}>>\n")
                logger.warning(f"Command failed on {self.ip}: {cmd[:50]}... - {type(e).__name__}")

        # Log summary
        success_rate = ((total_commands - failed_commands) / total_commands) * 100
        logger.info(f"Turbo collection on {self.ip}: {total_commands - failed_commands}/{total_commands} commands succeeded ({success_rate:.1f}%)")

        return "\n".join(chunks).strip()

    def send_command(self, command: str, timeout: int = 30) -> str:
        """
        Send a single command to the device and return output.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            str: Command output

        Raises:
            RuntimeError: If not connected
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        try:
            output = self.connection.send_command(
                command,
                cmd_verify=False,
                read_timeout=timeout
            )
            return output
        except Exception as e:
            logger.error(f"Command execution failed on {self.ip}: {command} - {str(e)}")
            raise RuntimeError(f"Command execution failed: {str(e)}")

    def send_config_commands(self, commands: List[str]) -> str:
        """
        Send configuration commands to device using netmiko's send_config_set().

        This method automatically:
        - Enters configuration mode
        - Executes all commands
        - Exits configuration mode
        - Returns combined output

        Args:
            commands: List of configuration commands

        Returns:
            str: Combined output from all commands

        Raises:
            RuntimeError: If not connected or commands fail

        Example:
            >>> client.send_config_commands([
            ...     "hostname Router1",
            ...     "ip domain-name example.com"
            ... ])
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        try:
            # Ensure we're in enable mode before entering config mode. The helper
            # checks the actual device privilege state first (SSH sessions at
            # privilege 15 are already at '#') and runs the enable exchange with
            # fast_cli disabled so a correct secret is not rejected over timing.
            if not self._in_enable_mode:
                try:
                    entered = self._ensure_enable_mode()
                except Exception as e:
                    raise RuntimeError(
                        "Cannot enter configuration mode: enable mode "
                        "authentication failed. Verify the enable secret is "
                        "correct for this device."
                    ) from e
                if not entered:
                    raise RuntimeError(
                        "Cannot enter configuration mode: device is not in "
                        "privileged mode and no enable secret was provided."
                    )

            # Expand any commands that contain embedded newlines (e.g. banner templates)
            # into separate list items so send_config_set handles them line-by-line.
            expanded: list = []
            for cmd in commands:
                lines = cmd.split("\n")
                expanded.extend(lines)

            # Regex pattern for commands that may produce interactive prompts
            # (confirmation questions). Netmiko uses timing for these instead of
            # prompt detection, preventing "Pattern not detected: [>#]" errors.
            interactive_pattern = (
                r"^crypto key generate"
                r"|^banner\s+(exec|login|motd|incoming|slip-ppp)"
                r"|^no\s+interface\s+Tunnel"
            )

            output = self.connection.send_config_set(
                expanded,
                exit_config_mode=True,
                cmd_verify=False,
                read_timeout=120,
                delay_factor=2.0,
                bypass_commands=interactive_pattern,
            )

            logger.info(f"Successfully executed {len(commands)} config commands on {self.ip}")
            return output

        except RuntimeError:
            # Re-raise RuntimeErrors directly (enable mode failures, etc.)
            raise
        except Exception as e:
            logger.error(f"Config command execution failed on {self.ip}: {str(e)}")
            raise RuntimeError(f"Config command execution failed: {str(e)}")

    def close(self) -> None:
        """Alias for disconnect() for compatibility."""
        self.disconnect()

    def disconnect(self) -> None:
        """Disconnect from device."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


def redact_sensitive_data(text: str) -> str:
    """
    Redact sensitive information from command outputs.

    Args:
        text: Raw command output text

    Returns:
        str: Text with sensitive data masked
    """
    result = text
    for pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
