"""
Regression tests for two FortiGate hardening fixes (no DB / no device required):

1. FG-BL-040 scope: operational verify commands (``diagnose sys ntp status``) must
   run at the TOP-LEVEL prompt. If a prior command block left the session inside a
   config context, ``collect()`` must back out first — otherwise the device rejects
   the diagnose with "8757: Unknown action 0 / Command fail. Return code -1".

2. FG-BL-002 remediation: the fix must strip only telnet/http from each interface's
   ``allowaccess`` (per-interface), preserving every other service — NOT set the
   global ``admin-telnet``/``admin-http`` fields (which the audit doesn't measure and
   which return "Command fail. Return code -7" on builds lacking them).
"""

from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient
from app.modules.fortinet.audit.rules import get_fortinet_controls
from app.modules.fortinet.hardening.command_templates import (
    build_iface_allowaccess_commands,
    IFACE_ALLOWACCESS_FORBIDDEN,
    FORTIGATE_COMMAND_TEMPLATES,
    has_fortigate_template,
)

BY_ID = {c.id: c for c in get_fortinet_controls()}


def _fake_client(initial_depth: int):
    """A FortiGateSSHClient whose SSH transport is stubbed: it records sent
    commands and models a prompt that is ``initial_depth`` config-levels deep,
    unwinding one level per ``end``."""
    c = FortiGateSSHClient("h", "u", "p")
    state = {"depth": initial_depth}
    sent = []

    def fake_raw(cmd):
        sent.append(cmd)
        if cmd == "end" and state["depth"] > 0:
            state["depth"] -= 1
        return "ok\nFGT # "

    class FakeConn:
        def find_prompt(self):
            return "FGT (global) # " if state["depth"] > 0 else "FGT # "

    c._raw_send = fake_raw
    c._connection = FakeConn()
    c.is_vdom_enabled = lambda: True
    c._is_command_ok = lambda out: True
    return c, sent, state


def test_diagnose_runs_at_top_level_when_already_top():
    c, sent, _ = _fake_client(initial_depth=0)
    ctrl = BY_ID["FG-BL-040"]
    c.collect([r.cmd for r in ctrl.rules], scope=ctrl.scope, vdom="root", use_cache=False)
    assert sent == ["diagnose sys ntp status"]


def test_diagnose_backs_out_of_leaked_scope_first():
    # Session left one level deep in `config global` by a prior block.
    c, sent, state = _fake_client(initial_depth=1)
    ctrl = BY_ID["FG-BL-040"]
    c.collect([r.cmd for r in ctrl.rules], scope=ctrl.scope, vdom="root", use_cache=False)
    assert sent[0] == "end", "must unwind the leaked config context first"
    assert sent[-1] == "diagnose sys ntp status"
    assert state["depth"] == 0, "diagnose issued only after reaching top level"


def test_iface_allowaccess_strips_only_forbidden_services():
    interfaces = [
        {"name": "port1", "allowaccess": ["ping", "https", "ssh", "http", "telnet"]},
        {"name": "port2", "allowaccess": ["ping", "https"]},   # clean -> untouched
        {"name": "mgmt",  "allowaccess": ["http"]},            # only forbidden -> unset
        {"name": "port3", "allowaccess": ["telnet", "ssh", "fgfm"]},
    ]
    cmds = build_iface_allowaccess_commands(interfaces, ["telnet", "http"])
    assert cmds == [
        "config system interface",
        'edit "port1"', "set allowaccess ping https ssh", "next",
        'edit "mgmt"',  "unset allowaccess", "next",
        'edit "port3"', "set allowaccess ssh fgfm", "next",
        "end",
    ]
    # never touches the clean interface, never uses the wrong global fields
    assert 'edit "port2"' not in cmds
    assert not any("admin-telnet" in x or "admin-http" in x for x in cmds)


def test_iface_allowaccess_noop_when_compliant():
    clean = [{"name": "port1", "allowaccess": ["ping", "https", "ssh"]}]
    assert build_iface_allowaccess_commands(clean, ["telnet", "http"]) == []


def test_fg_bl_002_template_is_dynamic_not_static_global():
    assert IFACE_ALLOWACCESS_FORBIDDEN["FG-BL-002"] == ["telnet", "http"]
    t = FORTIGATE_COMMAND_TEMPLATES["FG-BL-002"]
    assert t["commands"] == []                 # no wrong static global block
    assert t.get("dynamic") == "iface_allowaccess"
    assert has_fortigate_template("FG-BL-002")  # still counts as auto-fixable
