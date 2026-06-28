"""
FortiGate scope-aware SSH engine tests (no device, no DB).

Drives ``FortiGateSSHClient`` with a fake netmiko connection that records the
exact command sequence, proving that:
  - global controls are wrapped in ``config global`` / ``end``,
  - per-VDOM controls enter ``config vdom`` / ``edit <name>`` / ``end``,
  - ``vdom_root`` controls always target ``root``,
  - a flat (non-VDOM) device runs everything with no wrapper,
  - VDOM-mode detection and VDOM enumeration parse FortiOS output correctly.
"""

import pytest

from app.modules.fortinet.audit.ssh_client import (
    SCOPE_GLOBAL,
    SCOPE_VDOM,
    SCOPE_VDOM_ROOT,
    FortiGateSSHClient,
)


class FakeConn:
    """Stand-in for the netmiko ConnectHandler. Records every command sent."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.log = []

    def send_command_timing(self, command, **kwargs):
        self.log.append(command)
        return self.responses.get(command, "")

    def disconnect(self):
        pass


def _client(vdom_enabled, responses=None):
    c = FortiGateSSHClient("10.0.0.1", "admin", "pw", port=22)
    c._connection = FakeConn(responses)
    c._vdom_enabled = vdom_enabled  # bypass detection
    return c


# --------------------------------------------------------------------------
# Scope routing on a VDOM-enabled device
# --------------------------------------------------------------------------
def test_global_scope_wraps_config_global():
    c = _client(True, {"show system global": "set strong-crypto enable\n"})
    out = c.collect(["show system global"], scope=SCOPE_GLOBAL)
    log = c._connection.log
    assert "config global" in log and "end" in log
    assert log.index("config global") < log.index("show system global") < log.index("end")
    assert "strong-crypto" in out["show system global"]


def test_vdom_scope_enters_named_vdom():
    c = _client(True, {"show firewall policy": "edit 1\n"})
    c.collect(["show firewall policy"], scope=SCOPE_VDOM, vdom="prod")
    assert c._connection.log == ["config vdom", "edit prod", "show firewall policy", "end"]


def test_vdom_root_scope_forces_root():
    c = _client(True, {"show system password-policy": "set status enable\n"})
    c.collect(["show system password-policy"], scope=SCOPE_VDOM_ROOT, vdom="ignored")
    assert c._connection.log == ["config vdom", "edit root", "show system password-policy", "end"]


def test_vdom_scope_defaults_to_root_when_unspecified():
    c = _client(True)
    c.collect(["show firewall policy"], scope=SCOPE_VDOM, vdom=None)
    assert c._connection.log[:2] == ["config vdom", "edit root"]


def test_run_config_wraps_inner_block_in_scope():
    c = _client(True)
    res = c.run_config(["config system global", "set strong-crypto enable", "end"], scope=SCOPE_GLOBAL)
    log = c._connection.log
    assert log[0] == "config global"
    assert log[-1] == "end"
    assert "config system global" in log
    assert res["success"] is True


# --------------------------------------------------------------------------
# Flat (non-VDOM) device: no wrapping at all
# --------------------------------------------------------------------------
def test_flat_device_global_scope_no_wrapper():
    c = _client(False, {"show system global": "x"})
    c.collect(["show system global"], scope=SCOPE_GLOBAL)
    assert c._connection.log == ["show system global"]


def test_flat_device_vdom_scope_no_wrapper():
    c = _client(False, {"show firewall policy": "x"})
    c.collect(["show firewall policy"], scope=SCOPE_VDOM, vdom="prod")
    assert c._connection.log == ["show firewall policy"]


# --------------------------------------------------------------------------
# VDOM mode detection
# --------------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("disable", False),
    ("enable", True),
    ("multiple", True),
    ("split-task enable", True),
])
def test_vdom_mode_detection(value, expected):
    status = f"Version: FortiGate-100F v7.4.1,build2463\nVirtual domain configuration: {value}\n"
    c = FortiGateSSHClient("10.0.0.1", "admin", "pw")
    c._connection = FakeConn({"get system status": status})
    meta = c.get_system_status()
    assert meta["vdom_enabled"] is expected
    assert c.is_vdom_enabled() is expected


# --------------------------------------------------------------------------
# VDOM enumeration
# --------------------------------------------------------------------------
def test_enumerate_vdoms_parses_diagnose_and_root_first():
    out = "name=prod/prod index=1 enabled\nname=root/root index=0 enabled\nname=dmz/dmz index=2 enabled\n"
    c = _client(True, {"diagnose sys vdom list": out})
    vdoms = c.enumerate_vdoms()
    assert vdoms[0] == "root"
    assert set(vdoms) == {"root", "prod", "dmz"}


def test_enumerate_vdoms_empty_when_disabled():
    c = _client(False)
    assert c.enumerate_vdoms() == []


def test_enumerate_vdoms_defaults_to_root_when_unparseable():
    c = _client(True, {"diagnose sys vdom list": "garbage output", "show system vdom-property": ""})
    assert c.enumerate_vdoms() == ["root"]
