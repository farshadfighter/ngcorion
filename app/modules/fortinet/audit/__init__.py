"""
Fortinet Audit Module

CIS compliance auditing for FortiGate devices.
"""
from .router import router
from .service import FortinetAuditService
from .ssh_client import FortiGateSSHClient
from .rules import (
    get_fortinet_controls,
    get_controls_by_level,
    get_controls_by_pack,
    get_unique_commands,
    FortiGateControl,
    FortiGateRule
)
from .cis_map import CIS_BENCHMARK_SECTIONS, CIS_BENCHMARK_VERSION

__all__ = [
    "router",
    "FortinetAuditService",
    "FortiGateSSHClient",
    "get_fortinet_controls",
    "get_controls_by_level",
    "get_controls_by_pack",
    "get_unique_commands",
    "FortiGateControl",
    "FortiGateRule",
    "CIS_BENCHMARK_SECTIONS",
    "CIS_BENCHMARK_VERSION",
]
