"""
Fortinet Module

CIS compliance auditing and hardening for FortiGate devices.
Supports CIS FortiGate Benchmark.
"""
from . import audit
from . import hardening

__all__ = ["audit", "hardening"]
