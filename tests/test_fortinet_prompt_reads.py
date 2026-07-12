"""
FortiGate SSH read-path tests (no device, no DB).

Covers the prompt-based fast read introduced for hardening performance:
  - prompt-anchored reads are used when the connection exposes netmiko's
    ``base_prompt`` / ``write_channel`` / ``read_until_pattern``,
  - the timing-based read remains the fallback for connections without them,
  - a prompt-read timeout falls back to a timing drain (no re-send),
  - the ``--More--`` pager drain still works in prompt mode,
  - ``_prime_session`` reuses netmiko's VDOM detection (zero extra commands),
  - ``get system status`` is session-cached (connectivity dedupe).
"""

import re

import pytest

from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient, ReadTimeout
from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor

STATUS = (
    "Version: FortiGate-100F v7.4.1,build2463,231011 (GA.F)\n"
    "Hostname: FGT-1\n"
    "Virtual domain configuration: disable\n"
)


class PromptConn:
    """netmiko-shaped fake exposing the prompt-based read surface."""

    base_prompt = "FGT-1"

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.log = []  # (mode, command)
        self._pending = None

    def write_channel(self, data):
        self._pending = data.strip()

    def read_until_pattern(self, pattern=None, read_timeout=None, **kw):
        cmd = self._pending
        self._pending = None
        self.log.append(("prompt", cmd))
        return f"{cmd}\n{self.responses.get(cmd, '')}FGT-1 # "

    def send_command_timing(self, command, **kw):
        self.log.append(("timing", command))
        return self.responses.get(command, "")

    def read_channel_timing(self, **kw):
        return ""

    def disconnect(self):
        pass


class TimingOnlyConn:
    """Old-style fake: no base_prompt/write_channel — must use timing reads."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.log = []

    def send_command_timing(self, command, **kw):
        self.log.append(("timing", command))
        return self.responses.get(command, "") + "\nFGT-1 # "

    def disconnect(self):
        pass


def _client(conn):
    c = FortiGateSSHClient("10.0.0.1", "admin", "pw")
    c._connection = conn
    c._vdom_enabled = False
    return c


# ---------------------------------------------------------------------------
# Read-mode selection
# ---------------------------------------------------------------------------
def test_prompt_read_used_when_available():
    conn = PromptConn({"get system global": "admintimeout : 10\n"})
    out = _client(conn)._raw_send("get system global")
    assert conn.log == [("prompt", "get system global")]
    assert "admintimeout : 10" in out
    assert out.rstrip().endswith("#")


def test_timing_fallback_without_base_prompt():
    conn = TimingOnlyConn({"get system global": "admintimeout : 10"})
    out = _client(conn)._raw_send("get system global")
    assert conn.log == [("timing", "get system global")]
    assert "admintimeout : 10" in out


def test_prompt_pattern_is_hostname_anchored():
    c = _client(PromptConn())
    pat = c._prompt_pattern()
    assert re.search(pat, "some output\nFGT-1 # ")
    assert re.search(pat, "some output\nFGT-1 (global) # ")
    assert re.search(pat, "some output\nFGT-1 (port1) $ ")
    # A bare '#' inside output (FortiOS comment lines) must NOT end the read.
    assert not re.search(pat, "#config-version=FGVM64-7.4.1\nset admintimeout 10\n")
    # A prompt-looking line mid-buffer (more data after it) must not match.
    assert not re.search(pat, "FGT-1 # \nmore output still streaming")


def test_prompt_timeout_falls_back_to_timing_drain():
    class TimeoutConn(PromptConn):
        def read_until_pattern(self, pattern=None, read_timeout=None, **kw):
            raise ReadTimeout("no prompt")

        def read_channel_timing(self, **kw):
            self.log.append(("drain", None))
            return "late output\nFGT-1 # "

    conn = TimeoutConn()
    out = _client(conn)._raw_send("get system global")
    assert ("drain", None) in conn.log
    assert "late output" in out
    # The command must NOT have been re-sent through the timing path.
    assert not any(mode == "timing" for mode, _ in conn.log)


def test_pager_drain_still_works_in_prompt_mode():
    class PagerConn(PromptConn):
        def read_until_pattern(self, pattern=None, read_timeout=None, **kw):
            cmd = self._pending
            self.log.append(("prompt", cmd))
            return f"{cmd}\npage-one--More--"

        def send_command_timing(self, command, **kw):
            self.log.append(("timing", command))
            return "page-two\nFGT-1 # "

    conn = PagerConn()
    out = _client(conn)._raw_send("show full-configuration")
    assert "page-one" in out and "page-two" in out
    assert "--More--" not in out
    assert ("timing", " ") in conn.log  # pager continuation


# ---------------------------------------------------------------------------
# Session priming / status caching (connection-overhead dedupe)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vdoms", [True, False])
def test_prime_session_reuses_netmiko_vdom_detection(vdoms):
    conn = PromptConn()
    conn._vdoms = vdoms
    c = FortiGateSSHClient("10.0.0.1", "admin", "pw")
    c._connection = conn
    c._prime_session()
    assert c._vdom_enabled is vdoms
    assert conn.log == []  # zero extra commands


def test_prime_session_falls_back_to_pager_block_without_vdoms_attr():
    conn = PromptConn({"get system status": STATUS})
    c = FortiGateSSHClient("10.0.0.1", "admin", "pw")
    c._connection = conn
    c._prime_session()
    sent = [cmd for _mode, cmd in conn.log]
    assert "get system status" in sent
    assert "set output standard" in sent


def test_get_system_status_is_session_cached():
    conn = PromptConn({"get system status": STATUS})
    c = _client(conn)
    c._vdom_enabled = None
    meta1 = c.get_system_status()
    meta2 = c.get_system_status()
    assert meta1 is meta2
    assert meta1["hostname"] == "FGT-1"
    assert [cmd for _m, cmd in conn.log].count("get system status") == 1


def test_executor_connectivity_uses_cached_status():
    conn = PromptConn({"get system status": STATUS})
    client = _client(conn)
    client.get_system_status()  # warmed during earlier session activity
    conn.log.clear()

    ex = FortiGateHardeningExecutor(ip="10.0.0.1", username="admin", password="pw")
    ex.ssh_client = client
    assert ex.test_connectivity() is True
    assert conn.log == []  # no new round-trips
