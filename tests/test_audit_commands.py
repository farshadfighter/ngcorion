"""
Test Linux CIS audit command generation.

Tests that:
- Commands are generated correctly for each distro
- Distro-specific commands use correct tools
- Command counts match expectations
"""

import pytest


class TestAuditCommandGeneration:
    """Test audit command list generation."""

    def test_ubuntu_command_count(self, ubuntu_audit_commands):
        """Test Ubuntu generates expected number of commands."""
        # From memory: ~165 commands for Ubuntu
        assert len(ubuntu_audit_commands) >= 150
        assert len(ubuntu_audit_commands) <= 180

    def test_rocky_command_count(self, rocky_audit_commands):
        """Test Rocky generates expected number of commands."""
        # From memory: ~164 commands for Rocky
        assert len(rocky_audit_commands) >= 150
        assert len(rocky_audit_commands) <= 180

    def test_command_structure(self, ubuntu_audit_commands):
        """Test all commands have required structure."""
        for cmd in ubuntu_audit_commands:
            assert "cmd" in cmd, "Command must have 'cmd' field"
            assert "key" in cmd, "Command must have 'key' field"
            assert "section" in cmd, "Command must have 'section' field"
            assert "sudo" in cmd, "Command must have 'sudo' field"

            # Key should be unique identifier
            assert isinstance(cmd["key"], str)
            assert len(cmd["key"]) > 0

            # Sudo should be boolean
            assert isinstance(cmd["sudo"], bool)

    def test_unique_keys(self, ubuntu_audit_commands, rocky_audit_commands):
        """Test that all command keys are unique within each distro."""
        ubuntu_keys = [cmd["key"] for cmd in ubuntu_audit_commands]
        rocky_keys = [cmd["key"] for cmd in rocky_audit_commands]

        # Check for duplicates
        assert len(ubuntu_keys) == len(set(ubuntu_keys)), "Ubuntu has duplicate keys"
        assert len(rocky_keys) == len(set(rocky_keys)), "Rocky has duplicate keys"


class TestDistroSpecificCommands:
    """Test distro-specific command variations."""

    def test_ubuntu_uses_apt(self, ubuntu_audit_commands):
        """Test Ubuntu commands use apt package manager."""
        apt_commands = [cmd for cmd in ubuntu_audit_commands if "apt" in cmd["cmd"]]
        assert len(apt_commands) > 0, "Ubuntu should have apt commands"

        # Should not have dnf commands
        dnf_commands = [cmd for cmd in ubuntu_audit_commands if "dnf " in cmd["cmd"] and "|| dnf" not in cmd["cmd"]]
        assert len(dnf_commands) == 0, "Ubuntu should not have dnf-only commands"

    def test_rocky_uses_dnf(self, rocky_audit_commands):
        """Test Rocky commands use dnf package manager."""
        dnf_commands = [cmd for cmd in rocky_audit_commands if "dnf" in cmd["cmd"]]
        assert len(dnf_commands) > 0, "Rocky should have dnf commands"

    def test_ubuntu_uses_ufw(self, ubuntu_audit_commands):
        """Test Ubuntu commands check ufw firewall."""
        ufw_commands = [cmd for cmd in ubuntu_audit_commands if "ufw" in cmd["cmd"]]
        assert len(ufw_commands) > 0, "Ubuntu should have ufw commands"

    def test_rocky_uses_firewalld(self, rocky_audit_commands):
        """Test Rocky commands check firewalld."""
        firewalld_commands = [cmd for cmd in rocky_audit_commands if "firewall-cmd" in cmd["cmd"]]
        assert len(firewalld_commands) > 0, "Rocky should have firewalld commands"

    def test_ubuntu_uses_apparmor(self, ubuntu_audit_commands):
        """Test Ubuntu commands check AppArmor."""
        apparmor_commands = [cmd for cmd in ubuntu_audit_commands if "apparmor" in cmd["cmd"].lower() or "aa-status" in cmd["cmd"]]
        assert len(apparmor_commands) > 0, "Ubuntu should have AppArmor commands"

    def test_rocky_uses_selinux(self, rocky_audit_commands):
        """Test Rocky commands check SELinux."""
        selinux_commands = [cmd for cmd in rocky_audit_commands if "selinux" in cmd["cmd"].lower() or "getenforce" in cmd["cmd"] or "sestatus" in cmd["cmd"]]
        assert len(selinux_commands) > 0, "Rocky should have SELinux commands"

    def test_ubuntu_pam_paths(self, ubuntu_audit_commands):
        """Test Ubuntu uses correct PAM paths."""
        pam_commands = [cmd for cmd in ubuntu_audit_commands
                        if "/etc/pam.d/common-password" in cmd["cmd"]
                        or "/etc/pam.d/common-auth" in cmd["cmd"]]
        assert len(pam_commands) > 0, "Ubuntu should use common-password/common-auth PAM paths"

    def test_rocky_pam_paths(self, rocky_audit_commands):
        """Test Rocky uses correct PAM paths."""
        pam_commands = [cmd for cmd in rocky_audit_commands
                        if "/etc/pam.d/system-auth" in cmd["cmd"]
                        or "/etc/pam.d/password-auth" in cmd["cmd"]]
        assert len(pam_commands) > 0, "Rocky should use system-auth/password-auth PAM paths"

    def test_ubuntu_http_service(self, ubuntu_audit_commands):
        """Test Ubuntu checks apache2 service."""
        apache_commands = [cmd for cmd in ubuntu_audit_commands if "apache2" in cmd["key"]]
        assert len(apache_commands) > 0, "Ubuntu should check apache2"

    def test_rocky_http_service(self, rocky_audit_commands):
        """Test Rocky checks httpd service."""
        httpd_commands = [cmd for cmd in rocky_audit_commands if "httpd" in cmd["key"]]
        assert len(httpd_commands) > 0, "Rocky should check httpd"


class TestCommandSections:
    """Test commands cover all CIS sections."""

    def test_section_1_commands(self, ubuntu_audit_commands):
        """Test Section 1 (Initial Setup) commands exist."""
        section_1 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("1.")]
        assert len(section_1) >= 20, "Should have many Section 1 commands"

    def test_section_2_commands(self, ubuntu_audit_commands):
        """Test Section 2 (Services) commands exist."""
        section_2 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("2.")]
        assert len(section_2) >= 15, "Should have Section 2 commands"

    def test_section_3_commands(self, ubuntu_audit_commands):
        """Test Section 3 (Network) commands exist."""
        section_3 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("3.")]
        assert len(section_3) >= 10, "Should have Section 3 commands"

    def test_section_4_commands(self, ubuntu_audit_commands):
        """Test Section 4 (Logging) commands exist."""
        section_4 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("4.")]
        assert len(section_4) >= 10, "Should have Section 4 commands"

    def test_section_5_commands(self, ubuntu_audit_commands):
        """Test Section 5 (Access Control) commands exist."""
        section_5 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("5.")]
        assert len(section_5) >= 15, "Should have Section 5 commands"

    def test_section_6_commands(self, ubuntu_audit_commands):
        """Test Section 6 (System Maintenance) commands exist."""
        section_6 = [cmd for cmd in ubuntu_audit_commands if cmd["section"].startswith("6.")]
        assert len(section_6) >= 5, "Should have Section 6 commands"


class TestSudoRequirements:
    """Test that commands have appropriate sudo requirements."""

    def test_privileged_commands_require_sudo(self, ubuntu_audit_commands):
        """Test privileged commands require sudo."""
        # Commands that should require sudo
        privileged_keys = [
            "grub_config", "grub_permissions", "apparmor_status",
            "shadow_file", "audit_rules", "auditd_config"
        ]

        for cmd in ubuntu_audit_commands:
            if cmd["key"] in privileged_keys:
                assert cmd["sudo"] is True, f"{cmd['key']} should require sudo"

    def test_unprivileged_commands_no_sudo(self, ubuntu_audit_commands):
        """Test unprivileged commands don't require sudo."""
        # Commands that should not require sudo
        unprivileged_keys = [
            "fstab", "passwd_file", "group_file", "aslr",
            "ip_forward", "rsyslog_enabled"
        ]

        for cmd in ubuntu_audit_commands:
            if cmd["key"] in unprivileged_keys:
                assert cmd["sudo"] is False, f"{cmd['key']} should not require sudo"


class TestQuickAuditCommands:
    """Test quick audit command generation."""

    def test_quick_audit_exists(self):
        """Test quick audit command function exists."""
        from app.modules.audit.linux_audit_commands import get_quick_audit_commands
        commands = get_quick_audit_commands("ubuntu")
        assert len(commands) > 0

    def test_quick_audit_is_smaller(self, ubuntu_audit_commands):
        """Test quick audit has fewer commands than full audit."""
        from app.modules.audit.linux_audit_commands import get_quick_audit_commands
        quick_commands = get_quick_audit_commands("ubuntu")
        assert len(quick_commands) < len(ubuntu_audit_commands)
        # Quick audit should be significantly smaller
        assert len(quick_commands) < 20

    def test_quick_audit_covers_essentials(self):
        """Test quick audit covers essential checks."""
        from app.modules.audit.linux_audit_commands import get_quick_audit_commands
        commands = get_quick_audit_commands("ubuntu")
        keys = [cmd["key"] for cmd in commands]

        # Should have critical security checks
        assert "aslr" in keys or any("aslr" in k for k in keys)
        assert "sshd_config" in keys
        assert "login_defs" in keys
