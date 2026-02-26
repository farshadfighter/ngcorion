"""
Linux SSH Client for CIS Benchmark Auditing

Handles SSH connections and command execution on Linux servers with sudo support.
Uses netmiko with device_type="linux" for consistent patterns with Cisco/FortiGate.

Supported distributions:
- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- Rocky Linux 8 / 9 / 10
- Red Hat Enterprise Linux 8 / 9 / 10
"""

from typing import List, Dict, Optional, Any
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import re
import time
import logging

try:
    from paramiko.ssh_exception import (
        SSHException,
        BadHostKeyException,
        NoValidConnectionsError
    )
    from paramiko.transport import IncompatiblePeer
except ImportError:
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


# Redaction patterns for sensitive Linux data
LINUX_REDACT_PATTERNS = [
    # Password hashes in /etc/shadow
    (re.compile(r"^(\S+:)\$[^:]+:", re.M), r"\1<HASH_REDACTED>:"),
    # SSH private key content
    (re.compile(r"-----BEGIN.*PRIVATE KEY-----[\s\S]*?-----END.*PRIVATE KEY-----"), "<PRIVATE_KEY_REDACTED>"),
    # Passwords in config files
    (re.compile(r"(password\s*[=:]\s*)(\S+)", re.I), r"\1<REDACTED>"),
    # API keys and tokens
    (re.compile(r"(api[_-]?key\s*[=:]\s*)(\S+)", re.I), r"\1<REDACTED>"),
    (re.compile(r"(token\s*[=:]\s*)(\S+)", re.I), r"\1<REDACTED>"),
]


class LinuxSSHClient:
    """
    SSH client for Linux servers with sudo support.

    Features:
    - Password-based SSH authentication
    - Sudo command execution with password piping
    - Retry logic for transient failures
    - Distro detection
    - Audit data collection
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        sudo_password: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        max_retries: int = 3
    ):
        """
        Initialize Linux SSH client.

        Args:
            ip: Target server IP address
            username: SSH username
            password: SSH password
            sudo_password: Password for sudo (defaults to SSH password if not provided)
            port: SSH port (default: 22)
            timeout: Connection/command timeout in seconds
            max_retries: Maximum connection retry attempts
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.connection = None
        self._distro_info: Optional[Dict[str, str]] = None

    def connect(self) -> None:
        """
        Establish SSH connection to Linux server.

        Raises:
            SSHAuthenticationError: If authentication fails
            SSHConnectionTimeoutError: If connection times out
            SSHNetworkError: If server is unreachable
            SSHAlgorithmMismatchError: If SSH algorithm negotiation fails
            SSHHostKeyError: If host key verification fails
            SSHConnectionError: For other SSH failures
        """
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"SSH connection attempt {attempt}/{self.max_retries} to {self.ip}")

                self.connection = ConnectHandler(
                    device_type="linux",
                    ip=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    global_delay_factor=1,
                    banner_timeout=20,
                    auth_timeout=20
                )

                logger.info(f"Successfully connected to {self.ip}")
                return

            except NetmikoAuthenticationException as e:
                logger.error(f"Authentication failed for {self.ip}")
                raise SSHAuthenticationError(self.ip, original_error=e)

            except IncompatiblePeer as e:
                logger.error(f"SSH algorithm mismatch with {self.ip}")
                raise SSHAlgorithmMismatchError(self.ip, original_error=e)

            except BadHostKeyException as e:
                logger.error(f"Host key verification failed for {self.ip}")
                raise SSHHostKeyError(self.ip, original_error=e)

            except NoValidConnectionsError as e:
                logger.error(f"Connection refused by {self.ip}")
                raise SSHNetworkError(self.ip, original_error=e)

            except NetmikoTimeoutException as e:
                last_exception = e
                logger.warning(f"Connection timeout to {self.ip} (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except OSError as e:
                if hasattr(e, 'errno') and e.errno in (111, 113):
                    logger.error(f"Network error connecting to {self.ip}: {e}")
                    raise SSHNetworkError(self.ip, original_error=e)
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

            except Exception as e:
                last_exception = e
                logger.warning(f"Connection error to {self.ip} (attempt {attempt}/{self.max_retries}): {type(e).__name__}")
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        error_msg = f"Failed to connect to {self.ip} after {self.max_retries} attempts"
        logger.error(error_msg)
        if last_exception:
            raise map_ssh_exception(last_exception, self.ip)
        else:
            raise SSHConnectionError(
                message=error_msg,
                device_ip=self.ip,
                suggestions=["Check network connectivity to the server"],
                original_error=None
            )

    def is_connected(self) -> bool:
        """Check if SSH connection is active."""
        if not self.connection:
            return False
        try:
            return self.connection.is_alive()
        except Exception:
            return False

    def send_command(self, command: str, use_sudo: bool = False, timeout: int = 30) -> str:
        """
        Execute a command on the Linux server.

        Args:
            command: Command to execute
            use_sudo: Whether to run with sudo
            timeout: Command timeout in seconds

        Returns:
            Command output as string

        Raises:
            RuntimeError: If not connected or command fails
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        if not self.is_connected():
            raise RuntimeError("SSH connection is no longer active.")

        try:
            if use_sudo:
                # Use sudo with password via stdin
                # The -S flag makes sudo read password from stdin
                full_command = f"echo '{self.sudo_password}' | sudo -S {command}"
                output = self.connection.send_command(
                    full_command,
                    cmd_verify=False,
                    read_timeout=timeout
                )
                # Remove the password prompt from output if present
                output = re.sub(r"^\[sudo\].*?:\s*", "", output, flags=re.M)
            else:
                output = self.connection.send_command(
                    command,
                    cmd_verify=False,
                    read_timeout=timeout
                )
            return output
        except Exception as e:
            logger.error(f"Command execution failed on {self.ip}: {command[:50]}... - {str(e)}")
            raise RuntimeError(f"Command execution failed: {str(e)}")

    def send_commands(self, commands: List[str], use_sudo: bool = False) -> Dict[str, str]:
        """
        Execute multiple commands and return results.

        Args:
            commands: List of commands to execute
            use_sudo: Whether to run all commands with sudo

        Returns:
            Dict mapping command to output
        """
        results = {}
        for cmd in commands:
            try:
                results[cmd] = self.send_command(cmd, use_sudo=use_sudo)
            except Exception as e:
                results[cmd] = f"<<ERROR: {type(e).__name__}: {str(e)[:200]}>>"
                logger.warning(f"Command failed on {self.ip}: {cmd[:50]}... - {type(e).__name__}")
        return results

    def detect_distro(self) -> Dict[str, str]:
        """
        Detect Linux distribution and version.

        Returns:
            Dict with:
            - id: Distribution ID (ubuntu, rocky, centos, rhel)
            - version: Version string (22.04, 8, etc.)
            - version_id: Full version ID
            - name: Distribution name
            - profile: CIS profile identifier (ubuntu_22, rocky_8, etc.)
        """
        if self._distro_info:
            return self._distro_info

        output = self.send_command("cat /etc/os-release")

        distro_info = {
            "id": "unknown",
            "version": "unknown",
            "version_id": "unknown",
            "name": "Unknown Linux",
            "profile": "linux_generic"
        }

        # Parse os-release file
        id_match = re.search(r'^ID="?([^"\n]+)"?', output, re.M)
        if id_match:
            distro_info["id"] = id_match.group(1).lower()

        version_match = re.search(r'^VERSION_ID="?([^"\n]+)"?', output, re.M)
        if version_match:
            distro_info["version_id"] = version_match.group(1)
            # Extract major version
            version_parts = distro_info["version_id"].split(".")
            distro_info["version"] = version_parts[0] if version_parts else distro_info["version_id"]

        name_match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', output, re.M)
        if name_match:
            distro_info["name"] = name_match.group(1)

        # Build profile identifier
        distro_id = distro_info["id"]
        version = distro_info["version_id"]

        if distro_id == "ubuntu":
            if version.startswith("20"):
                distro_info["profile"] = "ubuntu_20"
            elif version.startswith("22"):
                distro_info["profile"] = "ubuntu_22"
            elif version.startswith("24"):
                distro_info["profile"] = "ubuntu_24"
            else:
                distro_info["profile"] = "ubuntu_generic"
        elif distro_id in ("rocky", "rockylinux"):
            distro_info["id"] = "rocky"
            if version.startswith("8"):
                distro_info["profile"] = "rocky_8"
            elif version.startswith("9"):
                distro_info["profile"] = "rocky_9"
            elif version.startswith("10"):
                distro_info["profile"] = "rocky_10"
            else:
                distro_info["profile"] = "rocky_generic"
        elif distro_id in ("rhel", "redhat"):
            distro_info["id"] = "rhel"
            if version.startswith("8"):
                distro_info["profile"] = "rhel_8"
            elif version.startswith("9"):
                distro_info["profile"] = "rhel_9"
            elif version.startswith("10"):
                distro_info["profile"] = "rhel_10"
            else:
                distro_info["profile"] = f"rhel_{distro_info['version']}"
        elif distro_id == "centos":
            distro_info["profile"] = f"centos_{distro_info['version']}"
        else:
            distro_info["profile"] = "linux_generic"

        self._distro_info = distro_info
        logger.info(f"Detected distro on {self.ip}: {distro_info['name']} (profile: {distro_info['profile']})")
        return distro_info

    def collect_audit_data(self, commands: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Collect audit data by running a list of commands.

        Args:
            commands: List of command dicts with:
                - cmd: Command string
                - sudo: Whether to use sudo (default: False)
                - key: Optional key for results dict (default: cmd)

        Returns:
            Dict mapping command/key to output
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        results = {}
        failed_count = 0
        total_count = len(commands)

        for cmd_info in commands:
            cmd = cmd_info.get("cmd", "")
            use_sudo = cmd_info.get("sudo", False)
            key = cmd_info.get("key", cmd)

            try:
                output = self.send_command(cmd, use_sudo=use_sudo)
                results[key] = output
            except Exception as e:
                failed_count += 1
                error_msg = str(e)[:200] if len(str(e)) > 200 else str(e)
                results[key] = f"<<ERROR: {type(e).__name__}: {error_msg}>>"
                logger.warning(f"Audit command failed on {self.ip}: {cmd[:50]}... - {type(e).__name__}")

        success_rate = ((total_count - failed_count) / total_count) * 100 if total_count > 0 else 0
        logger.info(f"Audit collection on {self.ip}: {total_count - failed_count}/{total_count} commands succeeded ({success_rate:.1f}%)")

        return results

    def disconnect(self) -> None:
        """Disconnect from server."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None

    def close(self) -> None:
        """Alias for disconnect()."""
        self.disconnect()

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


def redact_sensitive_linux_data(text: str) -> str:
    """
    Redact sensitive information from Linux command outputs.

    Args:
        text: Raw command output text

    Returns:
        Text with sensitive data masked
    """
    result = text
    for pattern, replacement in LINUX_REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def get_package_manager(distro_id: str) -> str:
    """
    Get the package manager for a distribution.

    Args:
        distro_id: Distribution ID from detect_distro()

    Returns:
        Package manager command (apt, dnf, yum)
    """
    if distro_id in ("ubuntu", "debian"):
        return "apt"
    elif distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux"):
        return "dnf"
    else:
        return "apt"  # Default to apt


def get_firewall_tool(distro_id: str) -> str:
    """
    Get the firewall tool for a distribution.

    Args:
        distro_id: Distribution ID from detect_distro()

    Returns:
        Firewall tool (ufw, firewalld)
    """
    if distro_id in ("ubuntu", "debian"):
        return "ufw"
    elif distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux"):
        return "firewalld"
    else:
        return "ufw"


def get_security_framework(distro_id: str) -> str:
    """
    Get the mandatory access control framework for a distribution.

    Args:
        distro_id: Distribution ID from detect_distro()

    Returns:
        Security framework (apparmor, selinux)
    """
    if distro_id in ("ubuntu", "debian"):
        return "apparmor"
    elif distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux"):
        return "selinux"
    else:
        return "apparmor"
