"""
Tests for the hardening fast SSH path.

Covers:
- parse_os_release() (shared distro parser used by both the netmiko audit client
  and the paramiko hardening runner).
- HardeningSSHRunner command execution: raw exec stdout/stderr merge, sudo
  wrapping + prompt stripping, and timeout -> RuntimeError.
- The Cisco verify turbo subset (CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS) used to
  avoid re-fetching "show run | ..." views already present in running-config.

These exercise pure logic with a fake paramiko client (no real SSH connection).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import socket

import pytest

# The hardening runner imports paramiko; the cisco/ssh clients import netmiko.
# Skip cleanly in environments where those aren't installed.
pytest.importorskip("paramiko")
pytest.importorskip("netmiko")

from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner  # noqa: E402
from app.modules.linux.common.ssh_client import parse_os_release  # noqa: E402
from app.modules.cisco.audit.ssh_client import (  # noqa: E402
    CISCO_TURBO_COMMANDS,
    CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS,
)


# --------------------------------------------------------------------------- #
#  Fake paramiko client                                                        #
# --------------------------------------------------------------------------- #

class _FakeFile:
    def __init__(self, data: bytes = b""):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        pass


class _FakeTransport:
    def is_active(self) -> bool:
        return True


class _FakeClient:
    """Minimal paramiko.SSHClient stand-in that records exec_command calls."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", raise_exc=None):
        self.stdout = stdout
        self.stderr = stderr
        self.raise_exc = raise_exc
        self.commands = []

    def get_transport(self):
        return _FakeTransport()

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        if self.raise_exc is not None:
            raise self.raise_exc
        return _FakeFile(), _FakeFile(self.stdout), _FakeFile(self.stderr)


def _runner_with(client) -> HardeningSSHRunner:
    runner = HardeningSSHRunner(ip="10.0.0.1", username="u", password="pw")
    runner._client = client
    return runner


# --------------------------------------------------------------------------- #
#  parse_os_release                                                            #
# --------------------------------------------------------------------------- #

class TestParseOsRelease:
    def test_ubuntu(self):
        info = parse_os_release(
            'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        )
        assert info["id"] == "ubuntu"
        assert info["profile"] == "ubuntu_22"

    def test_rhel(self):
        info = parse_os_release('ID="rhel"\nVERSION_ID="9.3"\n')
        assert info["id"] == "rhel"
        assert info["profile"] == "rhel_9"

    def test_redhat_alias_normalizes_to_rhel(self):
        info = parse_os_release('ID=redhat\nVERSION_ID="8.9"\n')
        assert info["id"] == "rhel"
        assert info["profile"] == "rhel_8"

    def test_rocky(self):
        info = parse_os_release('ID="rocky"\nVERSION_ID="8.8"\n')
        assert info["id"] == "rocky"
        assert info["profile"] == "rocky_8"

    def test_unknown(self):
        info = parse_os_release("not an os-release file")
        assert info["id"] == "unknown"
        assert info["profile"] == "linux_generic"


# --------------------------------------------------------------------------- #
#  HardeningSSHRunner                                                          #
# --------------------------------------------------------------------------- #

class TestRunnerExec:
    def test_run_merges_stdout_and_stderr(self):
        client = _FakeClient(stdout=b"hello-out", stderr=b"hello-err")
        runner = _runner_with(client)
        out = runner.run("echo hi")
        assert "hello-out" in out
        assert "hello-err" in out
        assert client.commands == ["echo hi"]

    def test_send_command_sudo_wrapping_and_prompt_strip(self):
        client = _FakeClient(stdout=b"PASS\n", stderr=b"[sudo] password for u: ")
        runner = _runner_with(client)
        out = runner.send_command("grep -q x /etc/foo", use_sudo=True)
        sent = client.commands[0]
        # Password is piped to `sudo -S`, never placed on the argv.
        assert sent.startswith("echo ")
        assert "sudo -S grep -q x /etc/foo" in sent
        # Output keeps the real result; the sudo prompt is stripped.
        assert "PASS" in out
        assert "[sudo]" not in out

    def test_send_command_no_sudo_passthrough(self):
        client = _FakeClient(stdout=b"plain", stderr=b"")
        runner = _runner_with(client)
        out = runner.send_command("id", use_sudo=False)
        assert client.commands == ["id"]
        assert out == "plain"

    def test_run_timeout_raises_runtimeerror(self):
        client = _FakeClient(raise_exc=socket.timeout())
        runner = _runner_with(client)
        with pytest.raises(RuntimeError):
            runner.run("sleep 999", timeout=1)


# --------------------------------------------------------------------------- #
#  Cisco verify turbo subset                                                   #
# --------------------------------------------------------------------------- #

class TestCiscoTurboSubset:
    def test_subset_excludes_show_run(self):
        assert CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS  # non-empty
        for cmd in CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS:
            assert not cmd.strip().lower().startswith("show run")

    def test_subset_is_subset_of_full(self):
        assert set(CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS).issubset(set(CISCO_TURBO_COMMANDS))

    def test_subset_smaller_than_full(self):
        assert len(CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS) < len(CISCO_TURBO_COMMANDS)

    def test_known_supplemental_commands_present(self):
        joined = "\n".join(CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS)
        assert "show ip ssh" in joined
        assert "show crypto key mypubkey rsa" in joined
