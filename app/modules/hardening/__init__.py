"""
Hardening Module

Automated remediation for Cisco and FortiGate CIS audit failures.

Provides:
- Command preview functionality
- SSH-based command execution
- Configuration backup and verification
- Complete audit trail of all hardening actions
- Schema-driven input collection for all device types
"""

from . import cisco_router as router
from . import hardening_router as schema_router
from . import fortinet_router

__all__ = ["router", "schema_router", "fortinet_router"]
