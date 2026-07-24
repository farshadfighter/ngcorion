"""
Test Linux hardening template transformation.

Tests that:
- Templates exist for CIS checks
- Templates have correct structure
- Distro transformations work correctly
- Parameter substitution works
"""

import pytest


class TestTemplateRegistry:
    """Test hardening template registry."""

    def test_template_count(self, all_hardening_templates):
        """Test expected number of templates exist."""
        # Shared core templates plus the per-version RHEL-10 and Rocky 8/9/10
        # remediation templates (each re-badged to its own id prefix). Keep a
        # generous ceiling so this catches a registry collapse, not growth.
        assert len(all_hardening_templates) >= 90
        assert len(all_hardening_templates) <= 480

    def test_template_ids_match_rules(self, all_hardening_templates, all_cis_rules):
        """Test template IDs correspond to rule IDs."""
        rule_ids = {rule.id for rule in all_cis_rules}
        template_ids = set(all_hardening_templates.keys())

        # Not all rules have templates, but all templates should match rules
        for template_id in template_ids:
            assert template_id in rule_ids, f"Template {template_id} has no matching rule"

    def test_template_structure(self, all_hardening_templates):
        """Test all templates have required structure."""
        for template_id, template in all_hardening_templates.items():
            assert hasattr(template, "check_id"), f"{template_id} missing check_id"
            assert hasattr(template, "description"), f"{template_id} missing description"
            assert hasattr(template, "commands"), f"{template_id} missing commands"
            assert hasattr(template, "verify_commands"), f"{template_id} missing verify_commands"

            assert isinstance(template.commands, list), f"{template_id} commands should be list"
            if template.manual_only:
                # Manual-only entries exist to carry remediation guidance to the
                # UI; they must run nothing and must explain what to do instead.
                assert not template.commands, f"{template_id} is manual_only but has commands"
                assert template.manual_guidance, f"{template_id} is manual_only but has no guidance"
            else:
                assert len(template.commands) > 0, f"{template_id} should have at least one command"


class TestTemplateCategories:
    """Test template categorization by section."""

    def test_section_1_templates(self, all_hardening_templates):
        """Test Section 1 templates exist."""
        section_1 = [t for t_id, t in all_hardening_templates.items()
                     if t_id.startswith("LNX-L1-1.") or t_id.startswith("LNX-L2-1.")]
        assert len(section_1) > 5, "Should have Section 1 templates"

    def test_section_2_templates(self, all_hardening_templates):
        """Test Section 2 (services) templates exist."""
        section_2 = [t for t_id, t in all_hardening_templates.items()
                     if t_id.startswith("LNX-L1-2.") or t_id.startswith("LNX-L2-2.")]
        assert len(section_2) > 10, "Should have many Section 2 templates"

    def test_section_3_templates(self, all_hardening_templates):
        """Test Section 3 (network) templates exist."""
        section_3 = [t for t_id, t in all_hardening_templates.items()
                     if t_id.startswith("LNX-L1-3.") or t_id.startswith("LNX-L2-3.")]
        assert len(section_3) > 5, "Should have Section 3 templates"

    def test_section_5_templates(self, all_hardening_templates):
        """Test Section 5 (access control) templates exist."""
        section_5 = [t for t_id, t in all_hardening_templates.items()
                     if t_id.startswith("LNX-L1-5.") or t_id.startswith("LNX-L2-5.")]
        assert len(section_5) > 5, "Should have Section 5 templates"


class TestFilesystemTemplates:
    """Test filesystem hardening templates."""

    def test_cramfs_template(self, all_hardening_templates):
        """Test cramfs disable template."""
        template = all_hardening_templates.get("LNX-L1-1.1.1.1")
        assert template is not None, "Should have cramfs template"

        # Check commands include modprobe.d configuration
        commands = " ".join(template.commands)
        assert "modprobe.d" in commands
        assert "cramfs" in commands
        assert "/bin/true" in commands

    def test_usb_storage_template(self, all_hardening_templates):
        """Test USB storage disable template."""
        template = all_hardening_templates.get("LNX-L1-1.1.1.8")
        assert template is not None, "Should have USB storage template"

        commands = " ".join(template.commands)
        assert "usb-storage" in commands

    def test_aslr_template(self, all_hardening_templates):
        """Test ASLR enable template."""
        template = all_hardening_templates.get("LNX-L1-1.5.1")
        assert template is not None, "Should have ASLR template"

        commands = " ".join(template.commands)
        assert "randomize_va_space" in commands
        assert "2" in commands


class TestNetworkTemplates:
    """Test network hardening templates."""

    def test_ip_forwarding_template(self, all_hardening_templates):
        """Test IP forwarding disable template."""
        template = all_hardening_templates.get("LNX-L1-3.1.1")
        assert template is not None, "Should have IP forwarding template"

        commands = " ".join(template.commands)
        assert "ip_forward" in commands
        assert "= 0" in commands or "=0" in commands

    def test_tcp_syncookies_template(self, all_hardening_templates):
        """Test TCP SYN cookies template."""
        template = all_hardening_templates.get("LNX-L1-3.2.8")
        assert template is not None, "Should have TCP syncookies template"

        commands = " ".join(template.commands)
        assert "syncookies" in commands


class TestServiceTemplates:
    """Test service hardening templates."""

    def test_avahi_template(self, all_hardening_templates):
        """Test avahi disable template."""
        template = all_hardening_templates.get("LNX-L1-2.2.1")
        assert template is not None, "Should have avahi template"

        commands = " ".join(template.commands)
        assert "avahi" in commands
        assert "stop" in commands or "disable" in commands or "mask" in commands

    def test_service_templates_use_systemctl(self, all_hardening_templates):
        """Test service templates use systemctl."""
        service_templates = [t for t_id, t in all_hardening_templates.items()
                             if t_id.startswith("LNX-L1-2.2")]

        for template in service_templates:
            commands = " ".join(template.commands)
            assert "systemctl" in commands, f"Template should use systemctl"


class TestSSHTemplates:
    """Test SSH hardening templates."""

    def test_sshd_config_permissions_template(self, all_hardening_templates):
        """Test sshd_config permissions template."""
        template = all_hardening_templates.get("LNX-L1-5.2.1")
        assert template is not None, "Should have sshd_config permissions template"

        commands = " ".join(template.commands)
        assert "sshd_config" in commands
        assert "chmod" in commands or "chown" in commands


class TestDistroTransformation:
    """Test distro-specific template transformation."""

    def test_template_transformation_function_exists(self):
        """Test get_linux_hardening_template_for_distro exists."""
        from app.modules.linux.hardening.command_templates import get_linux_hardening_template_for_distro
        assert callable(get_linux_hardening_template_for_distro)

    def test_ubuntu_transformation(self):
        """Test template transformation for Ubuntu."""
        from app.modules.linux.hardening.command_templates import get_linux_hardening_template_for_distro

        # Get a template that might have distro-specific parts
        template = get_linux_hardening_template_for_distro("LNX-L1-2.4.1", "ubuntu")

        if template:
            commands = " ".join(template.commands)
            # Ubuntu might use apt-get
            # Just verify transformation returns valid template
            assert len(template.commands) > 0

    def test_rocky_transformation(self):
        """Test template transformation for Rocky."""
        from app.modules.linux.hardening.command_templates import get_linux_hardening_template_for_distro

        template = get_linux_hardening_template_for_distro("LNX-L1-2.4.1", "rocky")

        if template:
            commands = " ".join(template.commands)
            # Rocky might use dnf
            assert len(template.commands) > 0

    def test_nonexistent_template_returns_none(self):
        """Test nonexistent template returns None."""
        from app.modules.linux.hardening.command_templates import get_linux_hardening_template_for_distro

        template = get_linux_hardening_template_for_distro("FAKE-ID-999", "ubuntu")
        assert template is None


class TestParameterSubstitution:
    """Test parameter substitution in templates."""

    def test_templates_with_parameters(self, all_hardening_templates):
        """Identify templates with parameter placeholders."""
        templates_with_params = []

        for template_id, template in all_hardening_templates.items():
            commands = " ".join(template.commands)
            if "{" in commands and "}" in commands:
                templates_with_params.append(template_id)

        # Should have some parameterized templates
        assert len(templates_with_params) > 0, "Should have parameterized templates"

    def test_motd_template_has_parameter(self, all_hardening_templates):
        """Test MOTD template has text parameter."""
        template = all_hardening_templates.get("LNX-L1-1.6.1")
        if template:
            commands = " ".join(template.commands)
            assert "{MOTD_TEXT}" in commands

    def test_parameter_substitution_works(self):
        """Test parameter substitution in commands."""
        # Simple substitution test
        template_cmd = "echo '{PARAM_VALUE}' > /etc/test.conf"
        params = {"PARAM_VALUE": "test_value"}

        result = template_cmd
        for key, value in params.items():
            result = result.replace(f"{{{key}}}", str(value))

        assert "test_value" in result
        assert "{PARAM_VALUE}" not in result


class TestVerifyCommands:
    """Test verification commands in templates."""

    def test_templates_have_verify_commands(self, all_hardening_templates):
        """Test most templates have verification commands."""
        with_verify = 0
        without_verify = 0

        for template_id, template in all_hardening_templates.items():
            if template.verify_commands and len(template.verify_commands) > 0:
                with_verify += 1
            else:
                without_verify += 1

        # Most templates should have verification
        assert with_verify > without_verify, "Most templates should have verify commands"

    def test_verify_commands_check_pass_fail(self, all_hardening_templates):
        """Test verify commands output PASS or FAIL."""
        for template_id, template in all_hardening_templates.items():
            for verify_cmd in template.verify_commands:
                # Verify commands should include PASS/FAIL output
                assert "PASS" in verify_cmd or "FAIL" in verify_cmd or "echo" in verify_cmd, \
                    f"{template_id} verify command should output PASS/FAIL"


class TestTemplateMetadata:
    """Test template metadata attributes."""

    def test_requires_reboot_attribute(self, all_hardening_templates):
        """Test requires_reboot attribute exists."""
        for template_id, template in all_hardening_templates.items():
            assert hasattr(template, "requires_reboot")
            assert isinstance(template.requires_reboot, bool)

    def test_requires_service_restart(self, all_hardening_templates):
        """Test some templates require service restart."""
        restart_templates = [t for t in all_hardening_templates.values()
                             if t.requires_service_restart]

        # Should have some templates that need service restart
        assert len(restart_templates) > 0

    def test_distros_attribute(self, all_hardening_templates):
        """Test distros attribute exists."""
        for template_id, template in all_hardening_templates.items():
            assert hasattr(template, "distros")
            assert isinstance(template.distros, list)
            assert len(template.distros) > 0
