"""
Hardening Module

Automated remediation for Cisco CIS audit failures.

Provides:
- Command preview functionality
- SSH-based command execution
- Configuration backup and verification
- Complete audit trail of all hardening actions
"""

from . import cisco_router as router

__all__ = ["router"]
