"""
Tests for the smart-dropdown upgrade of the FortiGate manual-remediation
parameter forms (no DB / no device required):

1. Every parameter of every executable manual template is classified as
   audit_evidence / device / free-text, and the metadata is consistent
   (device -> option_type registered, audit_evidence -> evidence parser).
2. parse_evidence_options extracts the failing Policy IDs / entry names from
   the exact evidence strings the audit service builds.
3. render_manual_command_blocks repeats the block once per multi-select target
   (policy-profile checks) and validates values (numbers, no line breaks).
"""

import pytest

from app.modules.fortinet.hardening.manual_remediation import (
    DEVICE_OPTION_TYPES,
    MANUAL_REMEDIATION_TEMPLATES,
    ManualParameterError,
    device_option_types_for_check,
    parse_evidence_options,
    render_manual_command_blocks,
    render_manual_commands,
    selection_object_name,
)


# ---------------------------------------------------------------------------
# 1. Catalog classification
# ---------------------------------------------------------------------------
def test_every_param_is_classified_consistently():
    for check_id, rem in MANUAL_REMEDIATION_TEMPLATES.items():
        for p in rem.parameters:
            assert p.source in (None, "audit_evidence", "device"), (check_id, p.name)
            if p.source == "device":
                assert p.option_type in DEVICE_OPTION_TYPES, (check_id, p.name)
            if p.source == "audit_evidence":
                assert p.evidence_parser in ("policy_ids", "table_names",
                                             "wan_iface_services"), (check_id, p.name)
            if p.multi:
                assert p.source == "audit_evidence", (check_id, p.name)


def test_policy_profile_checks_use_evidence_and_device_sources():
    # The client-named checks: POLICY_ID from evidence (multi), profile from device.
    expectations = {
        "FG-UTM-002": "av_profiles",
        "FG-UTM-003": "ips_sensors",
        "FG-APP-004": "app_lists",
    }
    for check_id, option_type in expectations.items():
        params = {p.name: p for p in MANUAL_REMEDIATION_TEMPLATES[check_id].parameters}
        pol = params["POLICY_ID"]
        assert pol.source == "audit_evidence" and pol.multi and pol.evidence_parser == "policy_ids"
        assert option_type in device_option_types_for_check(check_id)
    # FG-BL-082: policy IDs from evidence, no device param.
    pol = {p.name: p for p in MANUAL_REMEDIATION_TEMPLATES["FG-BL-082"].parameters}["POLICY_ID"]
    assert pol.source == "audit_evidence" and pol.multi


def test_free_text_only_for_invented_values():
    # Values the operator must invent stay free-text.
    for check_id, name in [("FG-BL-050", "SNMP_AUTH_PWD"), ("FG-BL-021", "NEW_PASSWORD"),
                           ("FG-SYS-003", None),  # not a manual template — skipped below
                           ("FG-FAB-002", "CSF_GROUP_NAME"), ("FG-BL-020", "TRUSTED_SUBNET")]:
        rem = MANUAL_REMEDIATION_TEMPLATES.get(check_id)
        if rem is None or name is None:
            continue
        p = {q.name: q for q in rem.parameters}[name]
        assert p.source is None, (check_id, name)


def test_serialized_param_exposes_dropdown_metadata():
    p = {q.name: q for q in MANUAL_REMEDIATION_TEMPLATES["FG-UTM-002"].parameters}["AV_PROFILE"]
    d = p.to_dict()
    assert d["source"] == "device"
    assert d["option_type"] == "av_profiles"
    assert d["multi"] is False


# ---------------------------------------------------------------------------
# 2. Evidence parsing
# ---------------------------------------------------------------------------
def test_parse_policy_ids_from_policy_field_evidence():
    evidence = (
        "3/9 accept policies missing av-profile:\n"
        "Policy ID 182: missing av-profile (NON-COMPLIANT)\n"
        "Policy ID 7: missing av-profile (NON-COMPLIANT)\n"
        "Policy ID 182: missing av-profile (NON-COMPLIANT)"  # dupe collapses
    )
    assert parse_evidence_options("FG-UTM-002", evidence) == {"POLICY_ID": ["182", "7"]}


def test_parse_policy_ids_from_logtraffic_evidence():
    evidence = (
        "2/5 policies NON-COMPLIANT:\n"
        "Policy ID 4: logtraffic = <not set> (NON-COMPLIANT)\n"
        "Policy ID 12: logtraffic = utm (NON-COMPLIANT)"
    )
    assert parse_evidence_options("FG-BL-082", evidence) == {"POLICY_ID": ["4", "12"]}


def test_parse_zone_names_from_table_evidence():
    evidence = "4 entries; missing 'intrazone deny': dmz-zone, lan zone (NON-COMPLIANT)"
    assert parse_evidence_options("FG-NET-001", evidence) == {"ZONE": ["dmz-zone", "lan zone"]}


def test_parse_wan_interfaces_from_fg_net_002_evidence():
    # Exact format of _wan_mgmt_evidence: one line per flagged WAN interface.
    evidence = (
        "Interface wan1 (role=wan) exposes: http, ssh (NON-COMPLIANT)\n"
        "Interface wan2 (role=wan) exposes: https (NON-COMPLIANT)"
    )
    assert parse_evidence_options("FG-NET-002", evidence) == {
        # services ride along in the label, space-separated (comma is the
        # multi-select join character)
        "INTERFACES": ["wan1 (http ssh)", "wan2 (https)"]
    }
    # compliant / unreadable evidence -> no options (UI falls back to free input)
    assert parse_evidence_options(
        "FG-NET-002",
        "12 interfaces; WAN-role interface(s) wan1 expose no management services (COMPLIANT)",
    ) == {"INTERFACES": []}


def test_selection_object_name_strips_service_label():
    assert selection_object_name("wan1 (http ssh)") == "wan1"
    assert selection_object_name("wan1") == "wan1"
    assert selection_object_name("") == ""


def test_fg_net_002_renders_one_empty_block_per_selection():
    # The catalog block is empty (dynamic) — rendering just validates/dedupes the
    # selections; the real commands are built at execute time from live config.
    rem = MANUAL_REMEDIATION_TEMPLATES["FG-NET-002"]
    assert rem.dynamic == "wan_iface_allowaccess" and rem.commands == []
    blocks = render_manual_command_blocks(
        "FG-NET-002", {"INTERFACES": "wan1 (http ssh), wan2 (https)"}
    )
    assert [t for t, _ in blocks] == ["wan1 (http ssh)", "wan2 (https)"]
    assert all(cmds == [] for _t, cmds in blocks)
    with pytest.raises(ManualParameterError):
        render_manual_command_blocks("FG-NET-002", {"INTERFACES": ""})


def test_parse_evidence_handles_missing_or_foreign_evidence():
    assert parse_evidence_options("FG-UTM-002", None) == {"POLICY_ID": []}
    assert parse_evidence_options("FG-UTM-002", "could not read firewall policies") == {"POLICY_ID": []}
    # Checks without evidence-sourced params return nothing to populate.
    assert parse_evidence_options("FG-FAB-002", "whatever") == {}
    assert parse_evidence_options("NOT-A-CHECK", "whatever") == {}


# ---------------------------------------------------------------------------
# 3. Multi-target rendering
# ---------------------------------------------------------------------------
def test_multi_policy_renders_one_block_per_id():
    blocks = render_manual_command_blocks(
        "FG-UTM-002", {"POLICY_ID": "182,7", "AV_PROFILE": "corp-av"}
    )
    assert [t for t, _ in blocks] == ["182", "7"]
    for target, cmds in blocks:
        assert f"edit {target}" in cmds
        assert 'set av-profile "corp-av"' in cmds
        assert cmds[0] == "config firewall policy" and cmds[-1] == "end"


def test_multi_zone_splits_on_commas_only():
    blocks = render_manual_command_blocks("FG-NET-001", {"ZONE": "dmz-zone, lan zone"})
    assert [t for t, _ in blocks] == ["dmz-zone", "lan zone"]
    assert 'edit "lan zone"' in blocks[1][1]


def test_single_target_checks_render_one_unlabelled_block():
    blocks = render_manual_command_blocks("FG-FAB-002", {"CSF_GROUP_NAME": "fabric-hq"})
    assert len(blocks) == 1 and blocks[0][0] is None
    # flattened wrapper stays backward compatible
    assert render_manual_commands("FG-FAB-002", {"CSF_GROUP_NAME": "fabric-hq"}) == blocks[0][1]


@pytest.mark.parametrize("params", [
    {},                              # nothing selected
    {"POLICY_ID": ""},               # blank
    {"POLICY_ID": "12; reboot"},     # non-numeric token
    {"POLICY_ID": "12\nend"},        # line break injection
])
def test_multi_policy_rejects_missing_or_malformed_ids(params):
    with pytest.raises(ManualParameterError):
        render_manual_command_blocks("FG-BL-082", params)


def test_line_breaks_rejected_in_string_params():
    with pytest.raises(ManualParameterError):
        render_manual_command_blocks(
            "FG-FAB-002", {"CSF_GROUP_NAME": 'x"\nconfig system admin'}
        )
