"""
FortiGate CIS catalogue + evaluation tests (no DB required).

Covers:
  - the catalogue is exactly the 53 CIS benchmark items (28 Automated / 25 Manual),
  - every control has a valid scope and unique id / CIS section,
  - cis_map stays 1:1 with the catalogue,
  - auto-remediation templates map to real Automated controls with valid params,
  - the "show omits defaults" evaluation idioms behave correctly.
"""

import re

from app.modules.fortinet.audit.rules import (
    FortiGateRule,
    get_fortinet_controls,
    get_unique_commands,
)
from app.modules.fortinet.audit.ssh_client import SCOPE_GLOBAL, SCOPE_VDOM, SCOPE_VDOM_ROOT
from app.modules.fortinet.audit.cis_map import CIS_BENCHMARK_SECTIONS
from app.modules.fortinet.audit.service import FortinetAuditService as Svc
from app.modules.fortinet.hardening.command_templates import FORTIGATE_COMMAND_TEMPLATES
from app.modules.fortinet.hardening.command_parser import FortiGateRemediationParser as Parser
from app.modules.fortinet.hardening.parameter_metadata import (
    FORTIGATE_CHECK_PARAMETER_MAP,
    FORTIGATE_PARAMETER_REGISTRY,
)

CONTROLS = get_fortinet_controls()
BY_ID = {c.id: c for c in CONTROLS}
VALID_SCOPES = {SCOPE_GLOBAL, SCOPE_VDOM, SCOPE_VDOM_ROOT}


# --------------------------------------------------------------------------
# Catalogue shape
# --------------------------------------------------------------------------
def test_exactly_53_controls():
    assert len(CONTROLS) == 53


def test_automated_manual_split():
    automated = [c for c in CONTROLS if c.cis_type == "Automated"]
    manual = [c for c in CONTROLS if c.cis_type == "Manual"]
    assert len(automated) == 28
    assert len(manual) == 25
    assert all(c.is_manual for c in manual)
    assert not any(c.is_manual for c in automated)


def test_unique_ids_and_sections():
    ids = [c.id for c in CONTROLS]
    secs = [c.cis_id for c in CONTROLS]
    assert len(set(ids)) == 53
    assert len(set(secs)) == 53


def test_every_control_has_valid_scope_and_section_name():
    for c in CONTROLS:
        assert c.scope in VALID_SCOPES, f"{c.id} bad scope {c.scope}"
        assert c.cis_section, f"{c.id} missing section name"
        assert c.rules, f"{c.id} has no rules"


def test_scope_distribution():
    from collections import Counter
    dist = Counter(c.scope for c in CONTROLS)
    assert dist[SCOPE_GLOBAL] == 29
    assert dist[SCOPE_VDOM] == 23
    assert dist[SCOPE_VDOM_ROOT] == 1


def test_cis_map_is_one_to_one_with_catalogue():
    map_secs = {r["section"] for r in CIS_BENCHMARK_SECTIONS}
    map_ids = {r["rule_id"] for r in CIS_BENCHMARK_SECTIONS}
    assert map_secs == {c.cis_id for c in CONTROLS}
    assert map_ids == set(BY_ID)


def test_unique_commands_are_command_scope_pairs():
    pairs = get_unique_commands(CONTROLS)
    assert all(isinstance(p, tuple) and len(p) == 2 for p in pairs)
    assert all(scope in VALID_SCOPES for _, scope in pairs)


# --------------------------------------------------------------------------
# Hardening templates ↔ catalogue ↔ params
# --------------------------------------------------------------------------
def test_templates_map_to_automated_controls():
    for cid in FORTIGATE_COMMAND_TEMPLATES:
        assert cid in BY_ID, f"template {cid} has no control"
        assert BY_ID[cid].cis_type == "Automated", f"template {cid} is not Automated"


def test_template_placeholders_resolve_and_are_registered():
    ph = re.compile(r"\{([A-Z_][A-Z0-9_]*)\}")
    for cid, tpl in FORTIGATE_COMMAND_TEMPLATES.items():
        used = set()
        for cmd in tpl["commands"]:
            used |= set(ph.findall(cmd))
        for p in used:
            assert p in FORTIGATE_PARAMETER_REGISTRY, f"{cid}:{p} not registered"
            assert p in FORTIGATE_CHECK_PARAMETER_MAP.get(cid, []), f"{cid}:{p} not in param map"
        # substituting defaults + dummy required values leaves no placeholders
        parsed = Parser.parse_remediation("", cid)
        params = dict(tpl["defaults"])
        for rp in tpl["required_params"]:
            params[rp] = "X"
        for c in Parser.substitute_parameters(parsed.commands, params):
            assert not ph.search(c), f"{cid} leftover placeholder in {c!r}"


# --------------------------------------------------------------------------
# Evaluation idioms (show omits defaults)
# --------------------------------------------------------------------------
def test_default_on_setting_passes_when_omitted_fails_when_disabled():
    # FG-BL-002: pass unless admin-telnet/admin-http are explicitly enabled.
    ctl = BY_ID["FG-BL-002"]
    empty = {r.cmd: "" for r in ctl.rules}
    assert Svc._evaluate_control(ctl, empty, "global")["passed"] is True
    bad = {r.cmd: "set admin-telnet enable\n" for r in ctl.rules}
    assert Svc._evaluate_control(ctl, bad, "global")["passed"] is False


def test_numeric_default_admintimeout():
    # FG-BL-004: admintimeout default 5 <= 10 -> pass when omitted; 30 -> fail.
    rule = BY_ID["FG-BL-004"].rules[0]
    assert Svc._evaluate_rule(rule, "") is True             # default 5
    assert Svc._evaluate_rule(rule, "set admintimeout 30") is False
    assert Svc._evaluate_rule(rule, "set admintimeout 10") is True


def test_present_setting_requires_explicit_enable():
    # FG-BL-090: strong-crypto must be explicitly enabled.
    rule = BY_ID["FG-BL-090"].rules[0]
    assert Svc._evaluate_rule(rule, "") is False
    assert Svc._evaluate_rule(rule, "set strong-crypto enable") is True


def test_manual_control_excluded_from_score():
    manual = next(c for c in CONTROLS if c.is_manual)
    finding = Svc._evaluate_control(manual, {r.cmd: "" for r in manual.rules}, "root")
    assert finding["manual"] is True
