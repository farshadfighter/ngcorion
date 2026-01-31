"""
Audit Module - Cisco CIS Security Compliance Auditing

This module provides automated security compliance auditing for network devices.
Currently supports: Cisco IOS/IOS-XE devices
"""

from . import cisco_router as router
from . import cisco_audit_logs_router as audit_logs_router

__all__ = ["router", "audit_logs_router"]
