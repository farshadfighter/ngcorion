"""
Audit Module - Cisco CIS Security Compliance Auditing

This module provides automated security compliance auditing for network devices.
Currently supports: Cisco IOS/IOS-XE devices
"""

from . import router

__all__ = ["router"]
