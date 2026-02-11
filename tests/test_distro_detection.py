"""
Test Linux distribution detection.

Tests the distro detection logic that parses /etc/os-release
and assigns the correct profile.
"""

import sys
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import re


class TestDistroDetection:
    """Test distribution detection from /etc/os-release."""

    def test_parse_ubuntu_os_release(self, ubuntu_os_release):
        """Test parsing Ubuntu os-release file."""
        # Parse ID
        id_match = re.search(r'^ID=([^\n]+)', ubuntu_os_release, re.M)
        assert id_match is not None
        assert id_match.group(1) == "ubuntu"

        # Parse VERSION_ID
        version_match = re.search(r'^VERSION_ID="?([^"\n]+)"?', ubuntu_os_release, re.M)
        assert version_match is not None
        assert version_match.group(1) == "22.04"

        # Parse PRETTY_NAME
        name_match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', ubuntu_os_release, re.M)
        assert name_match is not None
        assert "Ubuntu" in name_match.group(1)
        assert "22.04" in name_match.group(1)

    def test_parse_rocky_os_release(self, rocky_os_release):
        """Test parsing Rocky Linux os-release file."""
        # Parse ID
        id_match = re.search(r'^ID="?([^"\n]+)"?', rocky_os_release, re.M)
        assert id_match is not None
        assert id_match.group(1) == "rocky"

        # Parse VERSION_ID
        version_match = re.search(r'^VERSION_ID="?([^"\n]+)"?', rocky_os_release, re.M)
        assert version_match is not None
        assert version_match.group(1) == "8.8"

        # Parse PRETTY_NAME
        name_match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', rocky_os_release, re.M)
        assert name_match is not None
        assert "Rocky" in name_match.group(1)

    def test_mock_ssh_client_detects_ubuntu(self, mock_ubuntu_ssh_client):
        """Test mock SSH client detects Ubuntu correctly."""
        mock_ubuntu_ssh_client.connect()
        distro = mock_ubuntu_ssh_client.detect_distro()

        assert distro["id"] == "ubuntu"
        assert distro["version"] == "22"
        assert distro["version_id"] == "22.04"
        assert distro["profile"] == "ubuntu_22"
        assert "Ubuntu" in distro["name"]

        mock_ubuntu_ssh_client.disconnect()

    def test_mock_ssh_client_detects_rocky(self, mock_rocky_ssh_client):
        """Test mock SSH client detects Rocky Linux correctly."""
        mock_rocky_ssh_client.connect()
        distro = mock_rocky_ssh_client.detect_distro()

        assert distro["id"] == "rocky"
        assert distro["version"] == "8"
        assert distro["version_id"] == "8.8"
        assert distro["profile"] == "rocky_8"
        assert "Rocky" in distro["name"]

        mock_rocky_ssh_client.disconnect()

    def test_distro_profile_assignment(self, mock_ssh_client_class):
        """Test profile assignment for various distro versions."""
        test_cases = [
            ("ubuntu", "ubuntu_22", "22.04"),
            ("ubuntu", "ubuntu_24", "24.04"),
            ("rocky", "rocky_8", "8.8"),
            ("rocky", "rocky_9", "9.0"),
            ("unknown", "linux_generic", "unknown"),
        ]

        for distro_id, expected_profile_prefix, version in test_cases:
            client = mock_ssh_client_class(distro_id=distro_id)
            client.connect()
            distro = client.detect_distro()

            # Check profile starts with expected prefix or is generic
            if distro_id == "unknown":
                assert distro["profile"] == "linux_generic"
            else:
                assert distro["profile"].startswith(distro_id)

            client.disconnect()

    def test_distro_id_normalization(self, mock_ssh_client_class):
        """Test that distro IDs are normalized correctly."""
        # Rocky Linux might appear as "rocky" or "rockylinux"
        rocky_client = mock_ssh_client_class(distro_id="rocky")
        rocky_client.connect()
        distro = rocky_client.detect_distro()
        assert distro["id"] == "rocky"

    def test_distro_caching(self, mock_ubuntu_ssh_client):
        """Test that distro detection results are cached."""
        mock_ubuntu_ssh_client.connect()

        # First call
        distro1 = mock_ubuntu_ssh_client.detect_distro()

        # Second call should return cached result
        distro2 = mock_ubuntu_ssh_client.detect_distro()

        # Should be the same object (cached)
        assert distro1 is distro2

        mock_ubuntu_ssh_client.disconnect()


class TestDistroHelpers:
    """Test distro-related helper functions."""

    def test_get_package_manager(self):
        """Test package manager detection."""
        from app.modules.audit.linux_ssh_client import get_package_manager

        assert get_package_manager("ubuntu") == "apt"
        assert get_package_manager("debian") == "apt"
        assert get_package_manager("rocky") == "dnf"
        assert get_package_manager("rhel") == "dnf"
        assert get_package_manager("centos") == "dnf"
        assert get_package_manager("fedora") == "dnf"
        # Default fallback
        assert get_package_manager("unknown") == "apt"

    def test_get_firewall_tool(self):
        """Test firewall tool detection."""
        from app.modules.audit.linux_ssh_client import get_firewall_tool

        assert get_firewall_tool("ubuntu") == "ufw"
        assert get_firewall_tool("debian") == "ufw"
        assert get_firewall_tool("rocky") == "firewalld"
        assert get_firewall_tool("rhel") == "firewalld"
        assert get_firewall_tool("centos") == "firewalld"

    def test_get_security_framework(self):
        """Test MAC framework detection."""
        from app.modules.audit.linux_ssh_client import get_security_framework

        assert get_security_framework("ubuntu") == "apparmor"
        assert get_security_framework("debian") == "apparmor"
        assert get_security_framework("rocky") == "selinux"
        assert get_security_framework("rhel") == "selinux"
        assert get_security_framework("centos") == "selinux"
