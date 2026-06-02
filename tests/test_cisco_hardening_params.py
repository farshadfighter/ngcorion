"""
Regression tests for Cisco "Harden All" parameter/auto-fix handling.

Covers the three bugs fixed together:

A1. auto_harden_with_defaults decided fixability/defaults from the mis-keyed
    parameter_metadata (IOS-L1 ids) instead of the CIS-aware command templates,
    causing "Missing required parameters" errors during Harden All.
A2. The manual "Fix All" parameter form (parameter_metadata) returned nothing for
    CIS-X.X.X check ids.
B.  Some CIS->template mappings could never satisfy their own verify (e.g. CIS-1.1.6
    mapped to a 'transport input ssh' template while its check needs 'login
    authentication').

These tests use only the pure template/parser/metadata logic — no SSH/device, no DB.
"""

import re

import pytest

from app.modules.cisco.hardening.command_templates import (
    CIS_SECTION_TO_IOS,
    has_template,
    get_template,
)
from app.modules.cisco.hardening.command_parser import RemediationParser, apply_defaults
from app.modules.cisco.hardening import parameter_metadata as pm
from app.modules.cisco.hardening.service import HardeningService

# Reuse the mapping validator's config synthesis so the test and the standalone
# triage script can never drift apart.
from scripts.validate_cisco_mappings import synthesize_config, NEEDS_LIVE_SHOW_OUTPUT


def _auto_fixable(check_number):
    """Mirror the predicate auto_harden_with_defaults uses."""
    return has_template(check_number) and not get_template(check_number).get("required_params")


def _all_templated_cis_ids():
    return sorted(cid for cid in CIS_SECTION_TO_IOS if has_template(cid))


# --------------------------------------------------------------------------- A1

@pytest.mark.parametrize("check_number", _all_templated_cis_ids())
def test_auto_fixable_checks_substitute_without_missing_params(check_number):
    """A1 core invariant: any check Harden All treats as auto-fixable (no template
    required_params) must fully substitute using only the template defaults — i.e.
    it can never raise 'Missing required parameters'."""
    if not _auto_fixable(check_number):
        pytest.skip("requires user input -> skipped by Harden All")
    rule = HardeningService._get_rule_by_check_number(check_number)
    parsed = RemediationParser.parse_remediation(rule.remediation, check_number)
    commands = RemediationParser.substitute_parameters(
        parsed.commands, apply_defaults({}, parsed.defaults)
    )
    leftover = set()
    for cmd in commands:
        leftover |= set(RemediationParser.extract_parameters(cmd))
    assert not leftover, f"{check_number} left unsubstituted placeholders: {leftover}"


def test_param_required_checks_are_skipped_not_errored():
    """Checks with genuine user input are categorized as needing input (skipped),
    not attempted (which previously errored)."""
    for cn in ["CIS-1.1.2", "CIS-1.2.1", "CIS-1.5.4"]:
        assert not _auto_fixable(cn), f"{cn} should require user input"


def test_default_covered_checks_are_auto_fixable():
    for cn in ["CIS-1.1.4", "CIS-1.3.1", "CIS-2.1.1.1.4", "CIS-2.1.2", "CIS-2.1.3"]:
        assert _auto_fixable(cn), f"{cn} should be auto-fixable with template defaults"


# --------------------------------------------------------------------------- A2

def test_manual_form_returns_params_for_cis_ids():
    """A2: get_parameters_for_check must be template-driven for CIS ids (it used to
    return [] for every CIS-X.X.X id because CHECK_PARAMETER_MAP is IOS-L1-keyed)."""
    params = pm.get_parameters_for_check("CIS-1.2.1")
    names = {p.name for p in params}
    assert names == {"USERNAME", "USER_SECRET"}
    assert all(p.required and p.default is None for p in params)


def test_metadata_consistent_with_auto_harden():
    """parameter_metadata's auto-fixability must agree with the Harden All predicate."""
    for cn in _all_templated_cis_ids():
        assert pm.is_check_auto_fixable(cn) == _auto_fixable(cn), cn
        # A check needs params iff it is not auto-fixable.
        assert pm.check_has_required_params(cn) == (not _auto_fixable(cn)), cn


def test_get_check_defaults_match_template():
    assert pm.get_check_defaults("CIS-2.1.1.1.4") == {"TIMEOUT_SEC": "60"}
    assert pm.get_check_defaults("CIS-1.1.2") == {}


# ---------------------------------------------------------------------------- B

@pytest.mark.parametrize("check_number", _all_templated_cis_ids())
def test_template_can_satisfy_its_check(check_number):
    """B: the mapped template, once applied, must satisfy the check's verify."""
    if check_number in NEEDS_LIVE_SHOW_OUTPUT:
        pytest.skip("check reads non-running-config show output; verified live")
    rule = HardeningService._get_rule_by_check_number(check_number)
    config = synthesize_config(check_number)
    assert rule.check(config), (
        f"{check_number} -> {CIS_SECTION_TO_IOS[check_number]} template does not satisfy its check"
    )


def test_cis_1_1_6_now_applies_login_authentication():
    """B regression: CIS-1.1.6 used to map to a 'transport input ssh' template."""
    rule = HardeningService._get_rule_by_check_number("CIS-1.1.6")
    config = synthesize_config("CIS-1.1.6")
    assert re.search(r"login authentication", config)
    assert rule.check(config)
