"""CIS Cisco 2.1.1.1.4 expects `ip ssh time-out`, not `ip ssh timeout`.

The hyphenated spelling is what IOS accepts and what the benchmark quotes. The
change is scoped to this one check: the legacy IOS-L1-0112 rule keeps matching
the hyphen-less form that older running-configs emit, so both spellings are
still recognised somewhere and neither rule silently stops seeing its evidence.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.modules.cisco.audit.rules import (
    RE,
    build_all_cisco_cis_rules,
    build_cis_benchmark_rules,
)
from app.modules.cisco.audit.cis_benchmark_map import CIS_BENCHMARK_SECTIONS
from app.modules.cisco.audit.ssh_client import CISCO_TURBO_COMMANDS
from app.modules.cisco.hardening.command_templates import (
    CIS_SECTION_TO_IOS,
    COMMAND_TEMPLATES,
)


CHECK_ID = "CIS-2.1.1.1.4"


@pytest.fixture(scope="module")
def rules():
    # CIS-* ids come from the benchmark builder; IOS-L1-* from the legacy one.
    return {
        rule.id: rule
        for rule in [*build_cis_benchmark_rules(), *build_all_cisco_cis_rules()]
    }


def test_check_matches_the_hyphenated_command(rules):
    rule = rules[CHECK_ID]
    assert rule.check("ip ssh time-out 60\n") is True
    assert rule.evidence("ip ssh time-out 60\n") == "ip ssh time-out 60"


def test_check_no_longer_matches_the_unhyphenated_command(rules):
    """`ip ssh timeout 60` is not what this control asks for any more."""
    rule = rules[CHECK_ID]
    assert rule.check("ip ssh timeout 60\n") is False
    assert rule.evidence("ip ssh timeout 60\n") == "not set"


def test_check_fails_when_unset(rules):
    assert rules[CHECK_ID].check("hostname R1\n") is False


def test_title_and_remediation_quote_the_new_spelling(rules):
    rule = rules[CHECK_ID]
    assert "time-out" in rule.title
    assert rule.remediation == "Configure: ip ssh time-out 60"


def test_benchmark_map_recommendation_matches():
    section = next(
        row for row in CIS_BENCHMARK_SECTIONS if row["section"] == "2.1.1.1.4"
    )
    assert section["rule_id"] == CHECK_ID
    assert "time-out" in section["recommendation"]


def test_collection_greps_both_spellings():
    """The rule can only match a line the collector actually returns."""
    ssh_command = next(c for c in CISCO_TURBO_COMMANDS if "ip ssh version" in c)
    assert "^ip ssh time-out" in ssh_command
    # Kept so IOS-L1-0112 still sees its own evidence.
    assert "^ip ssh timeout" in ssh_command


def test_remediation_template_uses_the_new_spelling():
    template_id = CIS_SECTION_TO_IOS[CHECK_ID]
    commands = COMMAND_TEMPLATES[template_id]["commands"]
    assert any(c.startswith("ip ssh time-out ") for c in commands)
    assert not any(c.startswith("ip ssh timeout ") for c in commands)


# ----------------------------------------------------------------------
# Scope: nothing else moved
# ----------------------------------------------------------------------

def test_legacy_rule_is_untouched(rules):
    """IOS-L1-0112 is a separate control with its own template; it must keep
    matching the spelling it always did."""
    rule = rules["IOS-L1-0112"]
    assert rule.check("ip ssh timeout 60\n") is True
    assert rule.remediation == "Configure: ip ssh timeout 60"

    template = COMMAND_TEMPLATES["IOS-L1-0112"]
    assert any(c.startswith("ip ssh timeout ") for c in template["commands"])


def test_both_regexes_exist_and_are_distinct():
    assert RE.ssh_timeout.pattern != RE.ssh_time_out.pattern
    assert RE.ssh_time_out.search("ip ssh time-out 30")
    assert not RE.ssh_time_out.search("ip ssh timeout 30")
