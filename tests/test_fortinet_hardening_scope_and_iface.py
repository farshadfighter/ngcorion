"""
Regression tests for two FortiGate hardening fixes (no DB / no device required):

1. FG-BL-040 scope: operational verify commands (``diagnose sys ntp status``) must
   run INSIDE ``config global`` on VDOM-enabled devices (the restricted inter-VDOM
   login prompt rejects them with "8757: Unknown action 0 / Command fail. Return
   code -1"), and at the top-level prompt on flat devices. If a prior command block
   left the session inside a config context, ``collect()`` must back out first.

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
from app.modules.fortinet.hardening.command_parser import (
    FortiGateRemediationParser,
    apply_fortigate_defaults,
)
from app.modules.fortinet.hardening.parameter_metadata import (
    get_fortigate_check_defaults,
    is_fortigate_check_auto_fixable,
)
from app.modules.fortinet.hardening import ssh_executor as fg_executor_mod
from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor

CONTROLS = get_fortinet_controls()
BY_ID = {c.id: c for c in CONTROLS}


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


def test_diagnose_runs_inside_config_global_on_vdom_device():
    c, sent, _ = _fake_client(initial_depth=0)
    ctrl = BY_ID["FG-BL-040"]
    c.collect([r.cmd for r in ctrl.rules], scope=ctrl.scope, vdom="root", use_cache=False)
    assert sent == ["config global", "diagnose sys ntp status", "end"]


def test_diagnose_backs_out_of_leaked_scope_first():
    # Session left one level deep in `config global` by a prior block.
    c, sent, state = _fake_client(initial_depth=1)
    ctrl = BY_ID["FG-BL-040"]
    c.collect([r.cmd for r in ctrl.rules], scope=ctrl.scope, vdom="root", use_cache=False)
    assert sent[0] == "end", "must unwind the leaked config context first"
    assert sent[1:] == ["config global", "diagnose sys ntp status", "end"]
    assert state["depth"] == 0, "leaked context fully unwound before re-entering"


# --------------------------------------------------------------------------
# FG-BL-040: full NTP remediation template + sync-aware verification
# --------------------------------------------------------------------------
_NTP_OUT_SYNCED = (
    "synchronized: yes, ntpsync: enabled, server-mode: enabled\n\n"
    "ipv4 server(pool.ntp.org) 162.159.200.1 -- reachable(0xff) S:1 T:9\n"
    "ipv4 server(1.1.1.1) 1.1.1.1 -- reachable(0xff) S:2 T:9\n"
)
_NTP_OUT_CONFIG_OK_NOT_SYNCED = (
    "synchronized: no, ntpsync: enabled, server-mode: enabled\n\n"
    "ipv4 server(pool.ntp.org) 162.159.200.1 -- unreachable S:1 T:0\n"
)
_NTP_OUT_STILL_FORTIGUARD = (
    "synchronized: no, ntpsync: enabled, server-mode: disabled\n\n"
    "ipv4 server(ntp1.fortiguard.com) 208.91.114.21 -- reachable(0xff) S:1 T:9\n"
    "ipv4 server(ntp2.fortiguard.com) 208.91.114.22 -- reachable(0xff) S:2 T:9\n"
)


def test_fg_bl_040_template_is_full_remediation():
    # `set ntpsync enable` alone leaves server-mode disabled and the FortiGuard
    # pool active -> correctly NON-COMPLIANT. The template must push the full
    # block: custom mode + replace the servers (user-configurable, defaulted).
    tpl = FORTIGATE_COMMAND_TEMPLATES["FG-BL-040"]
    assert "set type custom" in tpl["commands"]
    assert "config ntpserver" in tpl["commands"]
    assert tpl["optional_params"] == ["NTP_SERVER_1", "NTP_SERVER_2"]
    assert tpl["defaults"] == {"NTP_SERVER_1": "pool.ntp.org", "NTP_SERVER_2": "1.1.1.1"}
    # nested config blocks are balanced (config system ntp + config ntpserver)
    assert tpl["commands"].count("end") == sum(
        1 for c in tpl["commands"] if c.startswith("config ")
    )

    # defaults substitute cleanly through the standard param mechanism
    parsed = FortiGateRemediationParser.parse_remediation("", "FG-BL-040")
    final = FortiGateRemediationParser.substitute_parameters(
        parsed.commands, apply_fortigate_defaults({}, parsed.defaults)
    )
    assert "set server pool.ntp.org" in final
    assert "set server 1.1.1.1" in final

    # user-supplied (e.g. local Iranian) servers override the defaults
    final_local = FortiGateRemediationParser.substitute_parameters(
        parsed.commands,
        apply_fortigate_defaults({"NTP_SERVER_1": "ntp.day.ir",
                                  "NTP_SERVER_2": "192.168.1.10"}, parsed.defaults),
    )
    assert "set server ntp.day.ir" in final_local
    assert "set server 192.168.1.10" in final_local

    # both params have defaults so batch auto-fix still treats it as fixable
    assert is_fortigate_check_auto_fixable("FG-BL-040")
    assert get_fortigate_check_defaults("FG-BL-040") == tpl["defaults"]


def _executor_with_ntp_outputs(outputs_sequence):
    """Executor whose ssh_client returns the given diagnose outputs in order
    (last one repeats), counting collect() calls."""
    ex = FortiGateHardeningExecutor("h", "u", "p")

    class FakeClient:
        def __init__(self):
            self.calls = 0

        def collect(self, cmds, scope=None, vdom=None, use_cache=True):
            out = outputs_sequence[min(self.calls, len(outputs_sequence) - 1)]
            self.calls += 1
            return {c: out for c in cmds}

    ex.ssh_client = FakeClient()
    return ex


def test_verify_ntp_polls_until_synchronized(monkeypatch):
    # Config lands correctly but sync takes a moment: verify must poll (bounded)
    # instead of failing on the first read.
    sleeps = []
    monkeypatch.setattr(fg_executor_mod.time, "sleep", lambda s: sleeps.append(s))
    ex = _executor_with_ntp_outputs(
        [_NTP_OUT_CONFIG_OK_NOT_SYNCED, _NTP_OUT_CONFIG_OK_NOT_SYNCED, _NTP_OUT_SYNCED]
    )
    passed, evidence = ex.verify_check(BY_ID["FG-BL-040"])
    assert passed is True
    assert ex.ssh_client.calls == 3
    assert sleeps == [fg_executor_mod.NTP_SYNC_VERIFY_DELAY_SECONDS] * 2


def test_verify_ntp_fails_with_clear_message_when_sync_never_arrives(monkeypatch):
    sleeps = []
    monkeypatch.setattr(fg_executor_mod.time, "sleep", lambda s: sleeps.append(s))
    ex = _executor_with_ntp_outputs([_NTP_OUT_CONFIG_OK_NOT_SYNCED])
    passed, evidence = ex.verify_check(BY_ID["FG-BL-040"])
    assert passed is False
    assert evidence.startswith("[NTP NOT SYNCED YET]")
    assert len(sleeps) == fg_executor_mod.NTP_SYNC_VERIFY_ATTEMPTS - 1


def test_verify_ntp_does_not_poll_when_config_is_wrong(monkeypatch):
    # Servers still FortiGuard / server-mode disabled: waiting cannot help, so
    # verification must fail immediately (single read, no misleading banner).
    sleeps = []
    monkeypatch.setattr(fg_executor_mod.time, "sleep", lambda s: sleeps.append(s))
    ex = _executor_with_ntp_outputs([_NTP_OUT_STILL_FORTIGUARD])
    passed, evidence = ex.verify_check(BY_ID["FG-BL-040"])
    assert passed is False
    assert sleeps == []
    assert ex.ssh_client.calls == 1
    assert "[NTP NOT SYNCED YET]" not in evidence


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


def test_remediation_split_pure_cli():
    c = BY_ID["FG-NET-001"]  # all CLI
    assert c.remediation_commands == [
        "config system zone", " edit <zone>", " set intrazone deny", "end",
    ]
    assert c.remediation_guidance == ""


def test_remediation_split_pure_prose():
    c = BY_ID["FG-NET-002"]  # no CLI lines
    assert c.remediation_commands == []
    assert c.remediation_guidance.startswith("On every WAN-role interface")


def test_remediation_split_mixed():
    c = BY_ID["FG-BL-050"]  # CLI + a trailing parenthetical note
    assert c.remediation_commands[0] == "config system snmp sysinfo"
    assert "end" in c.remediation_commands
    assert c.remediation_guidance.startswith("(and delete any SNMP")
    # the prose note must not leak into the copy-pasteable commands
    assert not any("delete any SNMP" in cmd for cmd in c.remediation_commands)


def test_every_manual_check_has_some_guidance_or_commands():
    # A manual check with neither commands nor guidance would render an empty
    # "View Fix" modal — guard against that.
    for c in CONTROLS:
        if has_fortigate_template(c.id):
            continue
        assert c.remediation_commands or c.remediation_guidance, c.id
