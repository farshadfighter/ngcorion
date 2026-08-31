"""
Test Auto Discovery nmap command building.

Regression test for a bug where "All Ports" scans of a range/CIDR target
came back with no open ports: build_nmap_command() correctly requested all
65535 ports via -p-, but the internal nmap --host-timeout ceiling was
hard-coded to 120s regardless of scan_type, so nmap abandoned each host long
before a full port sweep could finish. "Well-Known Ports" (~1036 ports)
happened to fit inside that window, so it appeared to work fine.
"""

import sys
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.modules.discovery.nmap_scanner import NmapScanner


@pytest.fixture(autouse=True)
def _nmap_available(monkeypatch):
    """build_nmap_command() raises FileNotFoundError unless nmap is on PATH;
    stub it out so these are pure unit tests with no real nmap dependency."""
    monkeypatch.setattr(NmapScanner, "is_nmap_available", staticmethod(lambda: True))


class TestBuildNmapCommandHostTimeout:
    """--host-timeout must scale with scan_type for range/CIDR targets."""

    def test_all_ports_cidr_gets_full_port_range_and_long_timeout(self):
        cmd = NmapScanner.build_nmap_command(
            target="192.168.1.0/24",
            scan_type="all_ports",
            protocol="TCP",
            version_detection=False,
        )
        assert "-p-" in cmd
        assert "--host-timeout=900s" in cmd
        assert "--host-timeout=120s" not in cmd

    def test_well_known_ports_cidr_keeps_existing_short_timeout(self):
        """Guards against regressing the currently-working path."""
        cmd = NmapScanner.build_nmap_command(
            target="192.168.1.0/24",
            scan_type="well_known_ports",
            protocol="TCP",
            version_detection=False,
        )
        assert "-p" in cmd
        assert "-p-" not in cmd
        assert "--host-timeout=120s" in cmd

    def test_all_ports_single_ip_has_no_host_timeout(self):
        """Bare single-IP targets aren't ranges; T4 runs to completion and no
        --host-timeout ceiling should be applied at all (unchanged)."""
        cmd = NmapScanner.build_nmap_command(
            target="192.168.1.1",
            scan_type="all_ports",
            protocol="TCP",
            version_detection=False,
        )
        assert "-p-" in cmd
        assert not any(arg.startswith("--host-timeout=") for arg in cmd)

    def test_all_ports_cidr_with_version_detection_gets_longer_timeout(self):
        cmd = NmapScanner.build_nmap_command(
            target="192.168.1.0/24",
            scan_type="all_ports",
            protocol="TCP",
            version_detection=True,
        )
        assert "--host-timeout=3600s" in cmd

    def test_all_ports_udp_timeout_unaffected(self):
        """UDP branch is evaluated first and must stay untouched by the fix."""
        monkeypatched_root = pytest.MonkeyPatch()
        try:
            monkeypatched_root.setattr(NmapScanner, "is_root", staticmethod(lambda: True))
            cmd = NmapScanner.build_nmap_command(
                target="192.168.1.0/24",
                scan_type="all_ports",
                protocol="UDP",
                version_detection=False,
            )
            assert "--host-timeout=600s" in cmd
        finally:
            monkeypatched_root.undo()
