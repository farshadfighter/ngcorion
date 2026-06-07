"""
Tests for CiscoSSHClient._ensure_enable_mode().

Regression coverage for the hardening bug where a *correct* enable secret was
rejected with netmiko's misleading "Failed to enter enable mode. Please ensure
you pass the 'secret' argument to ConnectHandler." error. Root cause was
fast_cli's aggressive timing during the enable exchange; the fix runs the whole
privilege-detection + enable exchange with fast_cli temporarily disabled and
restores it afterwards.

These tests mock netmiko's connection object, so no real device is needed.
"""

from unittest.mock import MagicMock

from app.modules.cisco.audit.ssh_client import CiscoSSHClient


def _client(secret=None):
    c = CiscoSSHClient(ip="10.0.0.1", username="u", password="pw", secret=secret)
    c.connection = MagicMock()
    # Connection starts with fast_cli enabled, mirroring connect().
    c.connection.fast_cli = True
    return c


def test_already_privileged_skips_enable():
    """Privilege-15 sessions land at '#': no enable() call, fast_cli restored."""
    c = _client(secret=None)
    c.connection.check_enable_mode.return_value = True

    assert c._ensure_enable_mode() is True
    assert c._in_enable_mode is True
    c.connection.enable.assert_not_called()
    assert c.connection.fast_cli is True  # restored


def test_enable_runs_with_fast_cli_disabled_then_restored():
    """The enable exchange must happen with fast_cli OFF, then be restored ON."""
    c = _client(secret="enablepass")
    c.connection.check_enable_mode.return_value = False

    seen = {}
    # Capture fast_cli state at the moment enable() is invoked.
    c.connection.enable.side_effect = lambda: seen.update(
        fast_cli_during_enable=c.connection.fast_cli
    )

    assert c._ensure_enable_mode() is True
    assert c._in_enable_mode is True
    c.connection.enable.assert_called_once()
    assert seen["fast_cli_during_enable"] is False   # disabled for the exchange
    assert c.connection.fast_cli is True             # restored afterwards


def test_no_secret_and_unprivileged_returns_false():
    """No secret + not privileged => cannot elevate, no exception."""
    c = _client(secret=None)
    c.connection.check_enable_mode.return_value = False

    assert c._ensure_enable_mode() is False
    assert c._in_enable_mode is False
    c.connection.enable.assert_not_called()
    assert c.connection.fast_cli is True  # restored


def test_fast_cli_restored_even_when_enable_raises():
    """A wrong secret raises, but fast_cli must still be restored (finally)."""
    c = _client(secret="wrong")
    c.connection.check_enable_mode.return_value = False
    c.connection.enable.side_effect = ValueError("Failed to enter enable mode.")

    import pytest
    with pytest.raises(ValueError):
        c._ensure_enable_mode()

    assert c._in_enable_mode is False
    assert c.connection.fast_cli is True  # restored despite the exception


def test_cached_enable_mode_is_a_noop():
    """If already flagged enabled, do nothing (no channel I/O)."""
    c = _client(secret="x")
    c._in_enable_mode = True

    assert c._ensure_enable_mode() is True
    c.connection.check_enable_mode.assert_not_called()
    c.connection.enable.assert_not_called()


def test_send_config_raises_clear_error_when_enable_fails():
    """send_config_commands surfaces a clear message, not netmiko's generic one."""
    c = _client(secret="wrong")
    c.connection.is_alive.return_value = True
    c.connection.check_enable_mode.return_value = False
    c.connection.enable.side_effect = ValueError(
        "Failed to enter enable mode. Please ensure you pass the 'secret' argument."
    )

    import pytest
    with pytest.raises(RuntimeError) as exc:
        c.send_config_commands(["aaa new-model"])

    assert "Verify the enable secret is correct" in str(exc.value)
    c.connection.send_config_set.assert_not_called()  # never reached config mode


def test_send_config_uses_enable_mode_then_sends_commands():
    """Happy path: enable succeeds, commands flow to send_config_set."""
    c = _client(secret="rightpass")
    c.connection.is_alive.return_value = True
    c.connection.check_enable_mode.return_value = False
    c.connection.send_config_set.return_value = "ok"

    out = c.send_config_commands(["aaa new-model"])

    assert out == "ok"
    c.connection.enable.assert_called_once()
    c.connection.send_config_set.assert_called_once()
