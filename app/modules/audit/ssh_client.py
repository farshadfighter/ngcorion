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

    # Legacy/Small services off
    "show run | i ^no service tcp-small-servers|^no service udp-small-servers|^no service pad|^no ip bootp server|^no ip finger",

    # AAA / Login controls / Logging
    "show run | i ^aaa |^login block-for|^login on-failure|^login on-success",
    "show run | i ^service password-encryption|^service timestamps log datetime",
    "show run | i ^logging (host|trap|buffered|facility)",
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
            device_type: Netmiko device type (default: cisco_ios)
            timeout: Connection/command timeout in seconds
            fast_cli: Enable fast CLI mode (reduces delays)
            max_retries: Maximum number of connection retries
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
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
            NetmikoAuthenticationException: If authentication fails
            NetmikoTimeoutException: If connection times out after all retries
            Exception: For other connection failures
        """
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"SSH connection attempt {attempt}/{self.max_retries} to {self.ip}")

                self.connection = ConnectHandler(
                    device_type=self.device_type,
                    ip=self.ip,
                    username=self.username,
                    password=self.password,
                    secret=self.secret,
                    fast_cli=self.fast_cli,
                    timeout=self.timeout,
                    global_delay_factor=1,
                    banner_timeout=20,  # Longer banner timeout for slow devices
                    auth_timeout=20     # Longer auth timeout
                )

                # Try to enter enable mode if secret provided
                if self.secret:
                    try:
                        self.connection.enable()
                        self._in_enable_mode = True
                        logger.debug(f"Entered enable mode on {self.ip}")
                    except Exception as e:
                        logger.warning(f"Failed to enter enable mode on {self.ip}: {e}")
                        # Continue even if enable fails - some commands still work

                # Disable paging
                try:
                    self.connection.send_command("terminal length 0", cmd_verify=False)
                except Exception:
                    pass

                logger.info(f"Successfully connected to {self.ip}")
                return  # Success - exit retry loop

            except NetmikoAuthenticationException:
                # Don't retry on auth failures - credentials are wrong
                logger.error(f"Authentication failed for {self.ip}")
                raise

            except NetmikoTimeoutException as e:
                last_exception = e
                logger.warning(f"Connection timeout to {self.ip} (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except Exception as e:
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        # All retries exhausted
        error_msg = f"Failed to connect to {self.ip} after {self.max_retries} attempts"
        logger.error(error_msg)
        raise last_exception or Exception(error_msg)

    def is_connected(self) -> bool:
        """Check if the SSH connection is still active."""
        if not self.connection:
            return False
        try:
            return self.connection.is_alive()
        except Exception:
            return False

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
