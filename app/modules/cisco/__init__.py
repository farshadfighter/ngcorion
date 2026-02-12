"""
Cisco Module

CIS compliance auditing and hardening for Cisco IOS/IOS-XE devices.
Supports CIS Cisco IOS 15 Benchmark v4.1.1.
"""
from . import audit
from . import hardening

__all__ = ["audit", "hardening"]
