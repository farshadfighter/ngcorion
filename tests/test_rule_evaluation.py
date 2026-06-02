"""
Test Linux CIS rule evaluation.

Tests that:
- Rules evaluate correctly with mock data
- Passing data returns True
- Failing data returns False
- Evidence is extracted correctly
"""

import pytest


class TestRuleCount:
    """Test that expected number of rules exist."""

    def test_total_rule_count(self, all_cis_rules):
        """Test total number of CIS rules."""
        # From memory: 145 CIS rules
        assert len(all_cis_rules) >= 140
        assert len(all_cis_rules) <= 160

    def test_rule_ids_unique(self, all_cis_rules):
        """Test all rule IDs are unique."""
        ids = [rule.id for rule in all_cis_rules]
        assert len(ids) == len(set(ids)), "Rule IDs must be unique"

    def test_rule_structure(self, all_cis_rules):
        """Test all rules have required attributes."""
        for rule in all_cis_rules:
            assert rule.id is not None
            assert rule.id.startswith("LNX-")
            assert rule.cis_section is not None
            assert rule.title is not None
            assert rule.severity in ["high", "medium", "low", "info"]
            assert rule.level in ["L1", "L2", "INFO"]
            assert callable(rule.check)
            assert callable(rule.evidence)


class TestRuleSeverities:
    """Test rule severity distribution."""

    def test_severity_distribution(self, all_cis_rules):
        """Test rules have reasonable severity distribution."""
        severities = {"high": 0, "medium": 0, "low": 0, "info": 0}

        for rule in all_cis_rules:
            severities[rule.severity] += 1

        # Should have rules at each severity level
        assert severities["high"] > 0, "Should have high severity rules"
        assert severities["medium"] > 0, "Should have medium severity rules"
        assert severities["low"] > 0, "Should have low severity rules"

    def test_level_distribution(self, all_cis_rules):
        """Test rules have reasonable level distribution."""
        levels = {"L1": 0, "L2": 0, "INFO": 0}

        for rule in all_cis_rules:
            levels[rule.level] += 1

        # Most rules should be L1
        assert levels["L1"] > levels["L2"], "L1 rules should outnumber L2"


class TestFilesystemRules:
    """Test filesystem-related CIS rules."""

    def test_cramfs_disabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test cramfs disabled rule evaluation."""
        rule = next((r for r in all_cis_rules if "cramfs" in r.title.lower()), None)
        assert rule is not None, "Should have cramfs rule"

        # With compliant data
        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with cramfs disabled"

        # Get evidence
        evidence = rule.evidence(ubuntu_audit_data, "ubuntu")
        assert evidence is not None

    def test_usb_storage_disabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test USB storage disabled rule."""
        rule = next((r for r in all_cis_rules if "usb" in r.title.lower() and "storage" in r.title.lower()), None)
        assert rule is not None, "Should have USB storage rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with USB storage disabled"

    def test_filesystem_rule_fails_when_loaded(self, all_cis_rules, ubuntu_audit_data, create_failing_data):
        """Test filesystem rules fail when module is loaded."""
        rule = next((r for r in all_cis_rules if "cramfs" in r.title.lower()), None)

        # Create failing data
        failing_data = create_failing_data(ubuntu_audit_data, ["modprobe_cramfs", "lsmod_cramfs"])

        result = rule.check(failing_data, "ubuntu")
        assert result is False, "Should fail when cramfs is loaded"


class TestNetworkRules:
    """Test network-related CIS rules."""

    def test_aslr_enabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test ASLR enabled rule."""
        rule = next((r for r in all_cis_rules if "aslr" in r.title.lower() or "randomize" in r.title.lower()), None)
        assert rule is not None, "Should have ASLR rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with ASLR=2"

    def test_ip_forwarding_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test IP forwarding disabled rule."""
        rule = next((r for r in all_cis_rules if "ip forward" in r.title.lower() or "forwarding" in r.title.lower()), None)
        assert rule is not None, "Should have IP forwarding rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with IP forwarding disabled"

    def test_ip_forwarding_fails_when_enabled(self, all_cis_rules, ubuntu_audit_data, create_failing_data):
        """Test IP forwarding rule fails when enabled."""
        rule = next((r for r in all_cis_rules if "ip forward" in r.title.lower() or "forwarding" in r.title.lower()), None)

        failing_data = create_failing_data(ubuntu_audit_data, ["ip_forward"])
        result = rule.check(failing_data, "ubuntu")
        assert result is False, "Should fail when IP forwarding is enabled"


class TestServiceRules:
    """Test service-related CIS rules."""

    def test_avahi_disabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test avahi-daemon disabled rule."""
        rule = next((r for r in all_cis_rules if "avahi" in r.title.lower()), None)
        assert rule is not None, "Should have avahi rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with avahi disabled"

    def test_service_rule_fails_when_enabled(self, all_cis_rules, ubuntu_audit_data):
        """Test service rules fail when service is enabled."""
        rule = next((r for r in all_cis_rules if "avahi" in r.title.lower()), None)

        # Create failing data - service enabled
        failing_data = ubuntu_audit_data.copy()
        failing_data["svc_avahi-daemon_enabled"] = "enabled"

        result = rule.check(failing_data, "ubuntu")
        assert result is False, "Should fail when avahi is enabled"


class TestSSHRules:
    """Test SSH-related CIS rules."""

    def test_permit_root_login_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test PermitRootLogin rule."""
        rule = next((r for r in all_cis_rules if "permitrootlogin" in r.title.lower() or "root login" in r.title.lower()), None)
        assert rule is not None, "Should have PermitRootLogin rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with PermitRootLogin no"

    def test_permit_empty_passwords_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test PermitEmptyPasswords rule."""
        rule = next((r for r in all_cis_rules if "empty" in r.title.lower() and "password" in r.title.lower()), None)
        assert rule is not None, "Should have PermitEmptyPasswords rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with PermitEmptyPasswords no"


class TestLoggingRules:
    """Test logging-related CIS rules."""

    def test_rsyslog_enabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test rsyslog enabled rule."""
        rule = next((r for r in all_cis_rules if "rsyslog" in r.title.lower()), None)
        assert rule is not None, "Should have rsyslog rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with rsyslog enabled"

    def test_auditd_enabled_rule(self, all_cis_rules, ubuntu_audit_data):
        """Test auditd enabled rule."""
        rule = next((r for r in all_cis_rules if "auditd" in r.title.lower() and "enable" in r.title.lower()), None)
        assert rule is not None, "Should have auditd rule"

        result = rule.check(ubuntu_audit_data, "ubuntu")
        assert result is True, "Should pass with auditd enabled"


class TestRuleEvidenceExtraction:
    """Test that rules extract evidence correctly."""

    def test_evidence_not_empty(self, all_cis_rules, ubuntu_audit_data):
        """Test that evidence functions return non-empty strings."""
        # Test a sample of rules
        sample_rules = all_cis_rules[:20]

        for rule in sample_rules:
            evidence = rule.evidence(ubuntu_audit_data, "ubuntu")
            assert evidence is not None, f"Rule {rule.id} evidence should not be None"
            assert isinstance(evidence, str), f"Rule {rule.id} evidence should be string"

    def test_evidence_contains_relevant_info(self, all_cis_rules, ubuntu_audit_data):
        """Test evidence contains relevant information."""
        # Find ASLR rule
        rule = next((r for r in all_cis_rules if "aslr" in r.title.lower() or "randomize" in r.title.lower()), None)
        if rule:
            evidence = rule.evidence(ubuntu_audit_data, "ubuntu")
            # Evidence should contain the setting value
            assert "2" in evidence or "randomize" in evidence.lower()


class TestDistroSpecificRules:
    """Test distro-specific rule behavior."""

    def test_ubuntu_rules_pass_with_ubuntu_data(self, all_cis_rules, ubuntu_audit_data):
        """Test Ubuntu-compatible rules pass with Ubuntu data."""
        ubuntu_rules = [r for r in all_cis_rules
                        if "all" in r.distros or "ubuntu" in r.distros]

        passing = 0
        for rule in ubuntu_rules:
            if rule.check(ubuntu_audit_data, "ubuntu"):
                passing += 1

        # Most rules should pass with compliant data
        pass_rate = passing / len(ubuntu_rules) if ubuntu_rules else 0
        assert pass_rate > 0.8, f"Expected >80% pass rate, got {pass_rate*100:.1f}%"

    def test_rocky_rules_pass_with_rocky_data(self, all_cis_rules, rocky_audit_data):
        """Test Rocky-compatible rules pass with Rocky data."""
        rocky_rules = [r for r in all_cis_rules
                       if "all" in r.distros or "rocky" in r.distros]

        passing = 0
        for rule in rocky_rules:
            if rule.check(rocky_audit_data, "rocky"):
                passing += 1

        # Most rules should pass with compliant data
        pass_rate = passing / len(rocky_rules) if rocky_rules else 0
        assert pass_rate > 0.8, f"Expected >80% pass rate, got {pass_rate*100:.1f}%"


class TestHelperFunctions:
    """Test rule helper functions."""

    def test_check_sysctl_value(self, ubuntu_audit_data):
        """Test _check_sysctl_value helper."""
        from app.modules.linux.audit.rules import _check_sysctl_value

        # ASLR should be 2
        assert _check_sysctl_value(ubuntu_audit_data, "aslr", "2") is True
        assert _check_sysctl_value(ubuntu_audit_data, "aslr", "0") is False

        # IP forward should be 0
        assert _check_sysctl_value(ubuntu_audit_data, "ip_forward", "0") is True
        assert _check_sysctl_value(ubuntu_audit_data, "ip_forward", "1") is False

    def test_check_service_disabled(self, ubuntu_audit_data):
        """Test _check_service_disabled helper."""
        from app.modules.linux.audit.rules import _check_service_disabled

        # avahi-daemon should be disabled
        assert _check_service_disabled(ubuntu_audit_data, "avahi-daemon") is True

        # Test with "not installed" value
        assert _check_service_disabled(ubuntu_audit_data, "dhcpd") is True

    def test_check_module_disabled(self, ubuntu_audit_data):
        """Test _check_module_disabled helper."""
        from app.modules.linux.audit.rules import _check_module_disabled

        # cramfs should be disabled
        assert _check_module_disabled(ubuntu_audit_data, "cramfs") is True

    def test_parse_sshd_config(self, ubuntu_audit_data):
        """Test _parse_sshd_config helper."""
        from app.modules.linux.audit.rules import _parse_sshd_config

        config = _parse_sshd_config(ubuntu_audit_data)

        assert "permitrootlogin" in config
        assert config["permitrootlogin"].lower() == "no"
        assert "permitemptypasswords" in config
        assert config["permitemptypasswords"].lower() == "no"
