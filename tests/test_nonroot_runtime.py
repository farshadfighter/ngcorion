"""The backend runs as UID 10001; privileged host operations use file capabilities."""
import importlib
import subprocess

import pytest

from app.modules.discovery.nmap_scanner import NmapScanner


def test_udp_scan_allowed_for_non_root_when_nmap_is_capability_enabled(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 10001)
    monkeypatch.delenv("NMAP_PRIVILEGED", raising=False)
    assert NmapScanner.is_root() is False
    monkeypatch.setenv("NMAP_PRIVILEGED", "1")
    assert NmapScanner.is_root() is True


@pytest.fixture
def system_config_service(monkeypatch):
    monkeypatch.setenv("NGCORION_DATE_CMD", "/usr/local/lib/ngcorion/date")
    monkeypatch.setenv("NGCORION_LOCALTIME_LINK", "/var/lib/ngcorion/tz/localtime")
    import app.modules.system_config.service as service
    service = importlib.reload(service)
    yield service
    monkeypatch.delenv("NGCORION_DATE_CMD")
    monkeypatch.delenv("NGCORION_LOCALTIME_LINK")
    importlib.reload(service)


def _record(calls):
    def fake(command, timeout=None):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")
    return fake


def test_manual_clock_uses_the_capability_enabled_date(system_config_service, monkeypatch):
    calls = []
    monkeypatch.setattr(system_config_service, "try_command", _record(calls))
    assert system_config_service._set_manual_time("2026-01-01T10:00:00") is None
    assert calls == [["/usr/local/lib/ngcorion/date", "-s", "2026-01-01 10:00:00"]]


def test_timezone_fallback_retargets_the_app_owned_link(system_config_service, monkeypatch):
    calls = []

    def fake(command, timeout=None):
        calls.append(command)
        ok = command[0] != "timedatectl"
        return subprocess.CompletedProcess(command, 0 if ok else 1, "", "no systemd")

    monkeypatch.setattr(system_config_service, "try_command", fake)
    assert system_config_service._set_timezone("Asia/Tehran") is None
    link = calls[-1]
    assert link[0:2] == ["ln", "-sf"]
    assert link[-1] == "/var/lib/ngcorion/tz/localtime"
