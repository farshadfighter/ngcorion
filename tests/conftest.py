"""
Shared fixtures for Linux CIS Audit/Hardening tests.

Provides:
- Mock SSH client
- Mock audit data for Ubuntu and Rocky
- Test utilities
"""

import sys
from pathlib import Path

# Add project root to Python path for imports
TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import json
import os
from typing import Dict, Any, List
from unittest.mock import Mock, MagicMock, patch


# Mock data directory
MOCK_DATA_DIR = TESTS_DIR / "mock_data"


# ==================== DATA LOADING FIXTURES ====================

@pytest.fixture(scope="session")
def ubuntu_os_release() -> str:
    """Load Ubuntu /etc/os-release content."""
    path = MOCK_DATA_DIR / "ubuntu_os_release.txt"
    return path.read_text()


@pytest.fixture(scope="session")
def rocky_os_release() -> str:
    """Load Rocky Linux /etc/os-release content."""
    path = MOCK_DATA_DIR / "rocky_os_release.txt"
    return path.read_text()


@pytest.fixture(scope="session")
def ubuntu_audit_data() -> Dict[str, str]:
    """Load Ubuntu mock audit command outputs."""
    path = MOCK_DATA_DIR / "ubuntu_audit_outputs.json"
    with open(path, 'r') as f:
        return json.load(f)


@pytest.fixture(scope="session")
def rocky_audit_data() -> Dict[str, str]:
    """Load Rocky Linux mock audit command outputs."""
    path = MOCK_DATA_DIR / "rocky_audit_outputs.json"
    with open(path, 'r') as f:
        return json.load(f)


# ==================== MOCK SSH CLIENT ====================

class MockLinuxSSHClient:
    """
    Mock SSH client that returns predefined command outputs.

    Mimics the behavior of LinuxSSHClient without real SSH connections.
    """

    def __init__(
        self,
        ip: str = "192.168.1.100",
        username: str = "admin",
        password: str = "password",
        sudo_password: str = None,
        mock_outputs: Dict[str, str] = None,
        distro_id: str = "ubuntu"
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.mock_outputs = mock_outputs or {}
        self.distro_id = distro_id
        self._connected = False
        self._distro_info = None

    def connect(self) -> None:
        """Simulate SSH connection."""
        self._connected = True

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected

    def send_command(self, command: str, use_sudo: bool = False, timeout: int = 30) -> str:
        """
        Return mock output for a command.

        Looks up command in mock_outputs, returns empty string if not found.
        """
        if not self._connected:
            raise RuntimeError("Not connected. Call connect() first.")

        # Try exact match first
        if command in self.mock_outputs:
            return self.mock_outputs[command]

        # Return empty string for unknown commands
        return ""

    def detect_distro(self) -> Dict[str, str]:
        """Return mock distro detection results."""
        if self._distro_info:
            return self._distro_info

        if self.distro_id == "ubuntu":
            self._distro_info = {
                "id": "ubuntu",
                "version": "22",
                "version_id": "22.04",
                "name": "Ubuntu 22.04.3 LTS",
                "profile": "ubuntu_22"
            }
        elif self.distro_id == "rocky":
            self._distro_info = {
                "id": "rocky",
                "version": "8",
                "version_id": "8.8",
                "name": "Rocky Linux 8.8 (Green Obsidian)",
                "profile": "rocky_8"
            }
        else:
            self._distro_info = {
                "id": self.distro_id,
                "version": "unknown",
                "version_id": "unknown",
                "name": f"Unknown ({self.distro_id})",
                "profile": "linux_generic"
            }

        return self._distro_info

    def collect_audit_data(self, commands: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Simulate collecting audit data.

        Returns predefined outputs for each command's key.
        """
        if not self._connected:
            raise RuntimeError("Not connected. Call connect() first.")

        results = {}
        for cmd_info in commands:
            key = cmd_info.get("key", cmd_info.get("cmd", ""))

            # Look up by key in mock_outputs
            if key in self.mock_outputs:
                results[key] = self.mock_outputs[key]
            else:
                results[key] = ""

        return results

    def disconnect(self) -> None:
        """Simulate disconnect."""
        self._connected = False

    def close(self) -> None:
        """Alias for disconnect."""
        self.disconnect()

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


@pytest.fixture
def mock_ubuntu_ssh_client(ubuntu_audit_data) -> MockLinuxSSHClient:
    """Create a mock SSH client configured for Ubuntu."""
    return MockLinuxSSHClient(
        ip="192.168.1.100",
        username="admin",
        password="password",
        mock_outputs=ubuntu_audit_data,
        distro_id="ubuntu"
    )


@pytest.fixture
def mock_rocky_ssh_client(rocky_audit_data) -> MockLinuxSSHClient:
    """Create a mock SSH client configured for Rocky Linux."""
    return MockLinuxSSHClient(
        ip="192.168.1.101",
        username="admin",
        password="password",
        mock_outputs=rocky_audit_data,
        distro_id="rocky"
    )


@pytest.fixture
def mock_ssh_client_class():
    """Provide MockLinuxSSHClient class for tests that need to create multiple instances."""
    return MockLinuxSSHClient


# ==================== RULE AND COMMAND FIXTURES ====================

@pytest.fixture(scope="session")
def all_cis_rules():
    """Load all CIS rules."""
    from app.modules.linux.audit.rules import build_linux_cis_rules
    return build_linux_cis_rules()


@pytest.fixture(scope="session")
def ubuntu_audit_commands():
    """Get audit commands for Ubuntu."""
    from app.modules.linux.audit.audit_commands import get_linux_audit_commands
    return get_linux_audit_commands("ubuntu")


@pytest.fixture(scope="session")
def rocky_audit_commands():
    """Get audit commands for Rocky Linux."""
    from app.modules.linux.audit.audit_commands import get_linux_audit_commands
    return get_linux_audit_commands("rocky")


@pytest.fixture(scope="session")
def all_hardening_templates():
    """Load all hardening templates."""
    from app.modules.linux.hardening.command_templates import LINUX_HARDENING_TEMPLATES
    return LINUX_HARDENING_TEMPLATES


# ==================== TEST UTILITY FUNCTIONS ====================

def create_failing_audit_data(base_data: Dict[str, str], failing_keys: List[str]) -> Dict[str, str]:
    """
    Create audit data where specified keys indicate failures.

    Args:
        base_data: Base audit data dictionary
        failing_keys: Keys to modify to indicate failures

    Returns:
        Modified audit data
    """
    data = base_data.copy()

    for key in failing_keys:
        if key.startswith("modprobe_"):
            # Make module loadable (not blocked)
            data[key] = "insmod /lib/modules/..."
        elif key.startswith("lsmod_"):
            # Make module loaded
            module = key.replace("lsmod_", "")
            data[key] = f"{module}                 16384  0"
        elif key.startswith("svc_"):
            # Make service enabled
            data[key] = "enabled"
        elif key == "aslr":
            # Disable ASLR
            data[key] = "kernel.randomize_va_space = 0"
        elif key == "ip_forward":
            # Enable IP forwarding (bad)
            data[key] = "net.ipv4.ip_forward = 1"

    return data


@pytest.fixture
def create_failing_data():
    """Factory fixture for creating failing audit data."""
    return create_failing_audit_data


# ==================== DISTRO COMPARISON HELPERS ====================

@pytest.fixture
def distro_differences():
    """Document key differences between Ubuntu and Rocky."""
    return {
        "package_manager": {
            "ubuntu": "apt",
            "rocky": "dnf"
        },
        "firewall": {
            "ubuntu": "ufw",
            "rocky": "firewalld"
        },
        "mac_framework": {
            "ubuntu": "apparmor",
            "rocky": "selinux"
        },
        "pam_password_file": {
            "ubuntu": "/etc/pam.d/common-password",
            "rocky": "/etc/pam.d/system-auth"
        },
        "pam_auth_file": {
            "ubuntu": "/etc/pam.d/common-auth",
            "rocky": "/etc/pam.d/password-auth"
        },
        "cron_service": {
            "ubuntu": "cron",
            "rocky": "crond"
        },
        "http_service": {
            "ubuntu": "apache2",
            "rocky": "httpd"
        }
    }
