"""Linux shells that wrap every prompt in OSC sequences (systemd 257+'s OSC 3008 context marks).

Reported from a server: collecting the software of an Ubuntu host failed with "Command execution failed:
Pattern not detected: '\\x1b\\]3008;end=...;exit=success\\x1b\\\\\\x1b\\]3008;start=...'". netmiko took the
sequences for part of the prompt, and they carry a new ID every time. These tests run netmiko's own Linux
driver against a shell that writes them, without a network.
"""
import uuid

import pytest
from netmiko.linux.linux_ssh import LinuxSSH

from app.core.ssh_terminal import steady_prompt, strip_osc
from app.modules.linux.common import ssh_client as linux_ssh_client

ESC = "\x1b"
PROMPT = "auditor@web-01:~$ "


def _mark(**fields) -> str:
    return f"{ESC}]3008;" + ";".join(f"{k}={v}" for k, v in fields.items()) + f"{ESC}\\"


class OscShell:
    """A bash with /etc/profile.d/80-systemd-osc-context.sh: PS0 marks the start of each command, and the
    prompt command closes it and opens the next one, each with a new ID."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.pending = "Welcome to Ubuntu 25.10\r\n" + self._prompt()      # the first prompt after login

    def _prompt(self) -> str:
        return (_mark(end=uuid.uuid4(), exit="success")
                + _mark(start=uuid.uuid4(), type="shell", cwd="/home/auditor") + PROMPT)

    def write_channel(self, data: str) -> None:
        for line in data.split("\n")[:-1]:
            command = line.strip()
            if command:
                self.pending += f"{line}\r\n" + _mark(start=uuid.uuid4(), type="command") + self.outputs.get(command, "")
            else:
                self.pending += "\r\n"
            self.pending += self._prompt()

    def read_channel(self) -> str:
        data, self.pending = self.pending, ""
        return data


def _connection(outputs):
    conn = LinuxSSH(ip="10.0.0.1", username="auditor", password="x", auto_connect=False,
                    read_timeout_override=2, global_delay_factor=0.1)
    conn.channel = OscShell(outputs)
    conn.session_preparation()      # what netmiko does once connected
    return conn


OUTPUTS = {"cat /etc/os-release": 'ID=ubuntu\r\nVERSION_ID="25.10"\r\n'}


def test_strip_osc_removes_both_terminators_and_leaves_colours_alone():
    text = f"{ESC}]0;title\x07a{_mark(start='1', type='shell')}b {ESC}[01;32mgreen{ESC}[00m"
    assert strip_osc(text) == f"ab {ESC}[01;32mgreen{ESC}[00m"
    assert strip_osc("plain") == "plain"


def test_netmiko_alone_takes_the_marks_for_the_prompt():
    """The reported failure, reproduced: the prompt holds an ID that the next prompt does not."""
    conn = _connection(OUTPUTS)
    assert ESC in conn.base_prompt
    with pytest.raises(Exception, match="Pattern not detected"):
        conn.send_command("cat /etc/os-release", cmd_verify=False, read_timeout=2)


def test_steady_prompt_reads_the_real_prompt_and_clean_output():
    conn = _connection(OUTPUTS)
    steady_prompt(conn)
    assert conn.base_prompt == "auditor@web-01:~"
    out = conn.send_command("cat /etc/os-release", cmd_verify=False, read_timeout=2)
    assert out.strip().splitlines() == ["ID=ubuntu", 'VERSION_ID="25.10"']
    assert ESC not in out


def test_linux_client_connects_steadily(monkeypatch):
    """LinuxSSHClient applies it on every connection (audits, hardening, software collection)."""
    monkeypatch.setattr(linux_ssh_client, "ensure_host_key_trusted", lambda *a, **kw: None)
    monkeypatch.setattr(linux_ssh_client, "ConnectHandler", lambda **kw: _connection(OUTPUTS))
    client = linux_ssh_client.LinuxSSHClient("10.0.0.1", "auditor", "x", max_retries=1)
    client.connect()
    monkeypatch.setattr(client, "is_connected", lambda: True)
    assert client.send_command("cat /etc/os-release", timeout=2).strip().startswith("ID=ubuntu")


def test_steady_prompt_leaves_other_connections_alone():
    class Plain:
        base_prompt = "router"
    conn = Plain()
    steady_prompt(conn)             # nothing to wrap, nothing raised
    steady_prompt(None)
