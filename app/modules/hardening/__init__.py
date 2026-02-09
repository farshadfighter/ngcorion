"""
Hardening Module

Automated remediation for Cisco, FortiGate, and Linux CIS audit failures.

Provides:
- Command preview functionality
- SSH-based command execution
- Configuration backup and verification
- Complete audit trail of all hardening actions
- Schema-driven input collection for all device types

Supported platforms:
- Cisco IOS/IOS-XE
- FortiGate
- Linux (Ubuntu 22.04, Ubuntu 24.04, Rocky Linux 8)
"""

from . import cisco_router as router
from . import hardening_router as schema_router
from . import fortinet_router
from . import linux_router

__all__ = ["router", "schema_router", "fortinet_router", "linux_router"]
