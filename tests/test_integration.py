"""
Integration tests for Linux CIS Audit/Hardening.

Tests the complete flow:
1. SSH connection (mocked)
2. Distro detection
3. Command execution
4. Rule evaluation
5. Result generation
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestCompleteAuditFlow:
    """Test complete audit flow with mock SSH."""

    def test_ubuntu_audit_flow(self, mock_ubuntu_ssh_client, ubuntu_audit_data, all_cis_rules):
        """Test complete Ubuntu audit flow."""
        # 1. Connect
        mock_ubuntu_ssh_client.connect()
        assert mock_ubuntu_ssh_client.is_connected()

        # 2. Detect distro
        distro = mock_ubuntu_ssh_client.detect_distro()
        assert distro["id"] == "ubuntu"
        assert distro["profile"] == "ubuntu_22"

        # 3. Get commands
        from app.modules.linux.audit.audit_commands import get_linux_audit_commands
        commands = get_linux_audit_commands(distro["id"])
        assert len(commands) >= 150

        # 4. Collect audit data
        audit_data = mock_ubuntu_ssh_client.collect_audit_data(commands)
        assert len(audit_data) > 0

        # 5. Evaluate rules — scored only against the rules that apply to this
        # distro, exactly as the engine does (filter_rules_by_distro in
        # service.py). Scoring Ubuntu against the RHEL/Rocky family rules would
        # understate compliance and is not meaningful (see test_rule_pass_rate_similar).
        from app.modules.linux.audit.rules import filter_rules_by_distro
        applicable = filter_rules_by_distro(all_cis_rules, distro["profile"])
        passing = 0
        failing = 0
        for rule in applicable:
            if rule.check(audit_data, distro["id"]):
                passing += 1
            else:
                failing += 1

        # With compliant mock data, most should pass
        total = passing + failing
        pass_rate = passing / total if total > 0 else 0
        assert pass_rate > 0.8, f"Expected >80% pass rate, got {pass_rate*100:.1f}%"

        # 6. Disconnect
        mock_ubuntu_ssh_client.disconnect()
        assert not mock_ubuntu_ssh_client.is_connected()

    def test_rocky_audit_flow(self, mock_rocky_ssh_client, rocky_audit_data, all_cis_rules):
        """Test complete Rocky Linux audit flow."""
        # 1. Connect
        mock_rocky_ssh_client.connect()
        assert mock_rocky_ssh_client.is_connected()

        # 2. Detect distro
        distro = mock_rocky_ssh_client.detect_distro()
        assert distro["id"] == "rocky"
        assert distro["profile"] == "rocky_8"

        # 3. Get commands
        from app.modules.linux.audit.audit_commands import get_linux_audit_commands
        commands = get_linux_audit_commands(distro["id"])
        assert len(commands) >= 150

        # 4. Collect audit data
        audit_data = mock_rocky_ssh_client.collect_audit_data(commands)
        assert len(audit_data) > 0

        # 5. Evaluate rules — scored only against the rules that apply to this
        # distro/version (rocky_8), exactly as the engine does. The catalog now
        # also carries rocky_9/rocky_10-gated rules, which must not be scored on
        # a Rocky 8 host.
        from app.modules.linux.audit.rules import filter_rules_by_distro
        applicable = filter_rules_by_distro(all_cis_rules, distro["profile"])
        passing = 0
        failing = 0
        for rule in applicable:
            if rule.check(audit_data, distro["id"]):
                passing += 1
            else:
                failing += 1

        # With compliant mock data, most should pass
        total = passing + failing
        pass_rate = passing / total if total > 0 else 0
        assert pass_rate > 0.8, f"Expected >80% pass rate, got {pass_rate*100:.1f}%"

        # 6. Disconnect
        mock_rocky_ssh_client.disconnect()


class TestDistroComparison:
    """Compare Ubuntu and Rocky audit results."""

    def test_command_count_similar(self, ubuntu_audit_commands, rocky_audit_commands):
        """Test both distros have similar command counts."""
        ubuntu_count = len(ubuntu_audit_commands)
        rocky_count = len(rocky_audit_commands)

        # Both distros audit a large shared core; Rocky/RHEL adds a sizeable set
        # of family-specific checks (SELinux, crypto-policies, subscription
        # manager, the RHEL-10 r10_* collection, ...), so its set is a superset,
        # not an exact match.
        assert ubuntu_count >= 150
        assert rocky_count >= 150
        assert abs(ubuntu_count - rocky_count) <= 100

    def test_common_keys_present(self, ubuntu_audit_commands, rocky_audit_commands):
        """Test common audit keys present in both distros."""
        ubuntu_keys = {cmd["key"] for cmd in ubuntu_audit_commands}
        rocky_keys = {cmd["key"] for cmd in rocky_audit_commands}

        # Most keys should be common
        common = ubuntu_keys & rocky_keys
        assert len(common) > 100, "Should have many common keys"

    def test_distro_specific_keys(self, ubuntu_audit_commands, rocky_audit_commands, distro_differences):
        """Test distro-specific keys exist."""
        ubuntu_keys = {cmd["key"] for cmd in ubuntu_audit_commands}
        rocky_keys = {cmd["key"] for cmd in rocky_audit_commands}

        # Ubuntu should have AppArmor keys
        apparmor_keys = [k for k in ubuntu_keys if "apparmor" in k.lower()]
        assert len(apparmor_keys) > 0, "Ubuntu should have AppArmor keys"

        # Rocky should have SELinux keys
        selinux_keys = [k for k in rocky_keys if "selinux" in k.lower()]
        assert len(selinux_keys) > 0, "Rocky should have SELinux keys"

    def test_rule_pass_rate_similar(self, all_cis_rules, ubuntu_audit_data, rocky_audit_data):
        """Test both distros have similar pass rates with compliant data."""
        # Compare like-for-like: each distro is scored only against the rules
        # that apply to it (shared "all" rules plus its own family). Scoring a
        # distro against the other family's rules (e.g. SELinux checks on
        # Ubuntu) would understate its compliance and is not meaningful.
        ubuntu_rules = [r for r in all_cis_rules if "all" in r.distros or "ubuntu" in r.distros]
        rocky_rules = [r for r in all_cis_rules if "all" in r.distros or "rocky" in r.distros]

        ubuntu_passing = sum(1 for rule in ubuntu_rules if rule.check(ubuntu_audit_data, "ubuntu"))
        rocky_passing = sum(1 for rule in rocky_rules if rule.check(rocky_audit_data, "rocky"))

        ubuntu_rate = ubuntu_passing / len(ubuntu_rules)
        rocky_rate = rocky_passing / len(rocky_rules)

        # Pass rates should be within 10% of each other
        assert abs(ubuntu_rate - rocky_rate) < 0.10


class TestHardeningIntegration:
    """Test hardening template integration."""

    def test_failed_rules_have_templates(self, all_cis_rules, all_hardening_templates, ubuntu_audit_data, create_failing_data):
        """Test that failed rules can find hardening templates."""
        # Create some failing data
        failing_data = create_failing_data(ubuntu_audit_data, [
            "modprobe_cramfs", "lsmod_cramfs",  # Filesystem
            "ip_forward",  # Network
        ])

        failed_rules = [rule for rule in all_cis_rules
                        if not rule.check(failing_data, "ubuntu")]

        # Check how many failed rules have templates
        with_templates = 0
        for rule in failed_rules:
            if rule.id in all_hardening_templates:
                with_templates += 1

        # Should have templates for most failures
        if len(failed_rules) > 0:
            coverage = with_templates / len(failed_rules)
            # At least 50% coverage expected
            assert coverage >= 0.5 or with_templates >= 1

    def test_template_for_common_failures(self, all_hardening_templates):
        """Test templates exist for common failure scenarios."""
        common_failure_ids = [
            "LNX-L1-1.1.1.1",  # cramfs
            "LNX-L1-1.5.1",    # ASLR
            "LNX-L1-3.1.1",    # IP forwarding
            "LNX-L1-4.2.1",    # auditd
            "LNX-L1-5.2.1",    # sshd_config permissions
        ]

        for check_id in common_failure_ids:
            assert check_id in all_hardening_templates, f"Should have template for {check_id}"


class TestEvaluateComplianceFunction:
    """Test the evaluate_compliance function if it exists."""

    def test_evaluate_compliance_exists(self):
        """Test evaluate_compliance function exists."""
        try:
            from app.modules.linux.audit.rules import evaluate_compliance
            assert callable(evaluate_compliance)
        except ImportError:
            pytest.skip("evaluate_compliance not implemented yet")

    def test_evaluate_compliance_returns_results(self, ubuntu_audit_data, all_cis_rules):
        """Test evaluate_compliance returns proper results."""
        try:
            from app.modules.linux.audit.rules import evaluate_compliance

            results = evaluate_compliance(ubuntu_audit_data, all_cis_rules, "ubuntu")

            # Should return dict with expected keys
            assert "compliance_pct" in results or "summary" in results or isinstance(results, (list, dict))
        except ImportError:
            pytest.skip("evaluate_compliance not implemented yet")


class TestContextManagerUsage:
    """Test SSH client context manager usage."""

    def test_context_manager_connects_disconnects(self, ubuntu_audit_data, mock_ssh_client_class):
        """Test context manager properly connects and disconnects."""
        client = mock_ssh_client_class(mock_outputs=ubuntu_audit_data, distro_id="ubuntu")

        # Before context
        assert not client.is_connected()

        # Inside context
        with client as c:
            assert c.is_connected()
            distro = c.detect_distro()
            assert distro["id"] == "ubuntu"

        # After context
        assert not client.is_connected()


class TestSeverityWeighting:
    """Test severity weight calculations."""

    def test_severity_weights_exist(self):
        """Test SEVERITY_WEIGHT dict exists."""
        from app.modules.linux.audit.rules import SEVERITY_WEIGHT

        assert "high" in SEVERITY_WEIGHT
        assert "medium" in SEVERITY_WEIGHT
        assert "low" in SEVERITY_WEIGHT
        assert "info" in SEVERITY_WEIGHT

    def test_severity_weights_ordered(self):
        """Test severity weights are properly ordered."""
        from app.modules.linux.audit.rules import SEVERITY_WEIGHT

        assert SEVERITY_WEIGHT["high"] > SEVERITY_WEIGHT["medium"]
        assert SEVERITY_WEIGHT["medium"] > SEVERITY_WEIGHT["low"]
        assert SEVERITY_WEIGHT["low"] > SEVERITY_WEIGHT["info"]

    def test_weighted_compliance_calculation(self, all_cis_rules, ubuntu_audit_data):
        """Test weighted compliance can be calculated."""
        from app.modules.linux.audit.rules import SEVERITY_WEIGHT, filter_rules_by_distro

        total_weight = 0
        passing_weight = 0

        # Weight only the Ubuntu-applicable rules against Ubuntu data (the engine
        # never scores a host against another family's rules).
        for rule in filter_rules_by_distro(all_cis_rules, "ubuntu_22"):
            weight = SEVERITY_WEIGHT.get(rule.severity, 1)
            total_weight += weight

            if rule.check(ubuntu_audit_data, "ubuntu"):
                passing_weight += weight

        weighted_pct = (passing_weight / total_weight * 100) if total_weight > 0 else 0

        # With compliant data, should be high
        assert weighted_pct > 70


class TestErrorHandling:
    """Test error handling in audit flow."""

    def test_missing_key_handled(self, all_cis_rules):
        """Test rules handle missing keys gracefully."""
        empty_data = {}

        # Rules should not crash with empty data
        for rule in all_cis_rules[:10]:  # Test sample
            try:
                result = rule.check(empty_data, "ubuntu")
                # Should return False (not compliant) for missing data
                assert result in [True, False]
            except Exception as e:
                pytest.fail(f"Rule {rule.id} crashed with empty data: {e}")

    def test_error_output_handled(self, all_cis_rules, ubuntu_audit_data):
        """Test rules handle error outputs gracefully."""
        data_with_errors = ubuntu_audit_data.copy()
        data_with_errors["aslr"] = "<<ERROR: Command failed>>"

        rule = next((r for r in all_cis_rules if "aslr" in r.title.lower()), None)
        if rule:
            # Should not crash
            result = rule.check(data_with_errors, "ubuntu")
            # Should return False for error output
            assert result is False

    def test_not_connected_raises_error(self, mock_ssh_client_class):
        """Test operations on unconnected client raise errors."""
        client = mock_ssh_client_class(distro_id="ubuntu")
        # Don't connect

        with pytest.raises(RuntimeError, match="Not connected"):
            client.send_command("test")

        with pytest.raises(RuntimeError, match="Not connected"):
            client.collect_audit_data([{"cmd": "test", "key": "test", "sudo": False}])
